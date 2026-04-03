#!/usr/bin/env python3
"""
bulk-probe.py — Probe the MOTU vendor bulk interface for HTTP-over-USB.

Both the M64 and 828ES expose a Vendor Specific (class=0xFF, sub=0x04, proto=0x01)
interface with a symmetric bulk IN/OUT pair that is NOT claimed by any kernel driver.
This script claims that interface and sends raw HTTP requests directly over it.

Requires: pip install pyusb
Run as root: sudo python3 scripts/bulk-probe.py
"""

import sys
import time
import usb.core
import usb.util

MOTU_VID = 0x07FD
MOTU_PID = 0x0005

# Vendor bulk interface fingerprint: class=FF, sub=04, proto=01
VENDOR_CLASS    = 0xFF
VENDOR_SUBCLASS = 0x04
VENDOR_PROTO_BULK = 0x01

BULK_TIMEOUT_MS = 3000
READ_SIZE       = 65536   # max bytes to read per transfer

# ─── Colour helpers ───────────────────────────────────────────────────────────
RED = "\033[0;31m"; GRN = "\033[0;32m"; YLW = "\033[1;33m"
CYN = "\033[0;36m"; BLD = "\033[1m";    RST = "\033[0m"
def info(m):  print(f"{CYN}[INFO]{RST}  {m}")
def ok(m):    print(f"{GRN}[OK]{RST}    {m}")
def warn(m):  print(f"{YLW}[WARN]{RST}  {m}")
def err(m):   print(f"{RED}[ERR]{RST}   {m}")
def hdr(m):
    bar = "═" * 52
    print(f"\n{BLD}{bar}{RST}\n{BLD}  {m}{RST}\n{BLD}{bar}{RST}")


# ─── HTTP requests to try ─────────────────────────────────────────────────────
HTTP_REQUESTS = [
    # (label, raw bytes to send)
    (
        "GET /datastore  (HTTP/1.0, no framing)",
        b"GET /datastore HTTP/1.0\r\nHost: motu\r\nAccept: */*\r\n\r\n",
    ),
    (
        "GET /  (HTTP/1.0, no framing)",
        b"GET / HTTP/1.0\r\nHost: motu\r\nAccept: */*\r\n\r\n",
    ),
    (
        "GET /datastore  (HTTP/1.1)",
        b"GET /datastore HTTP/1.1\r\nHost: motu\r\nAccept: */*\r\nConnection: close\r\n\r\n",
    ),
]


# ─── Find the vendor bulk interface on a device ───────────────────────────────
def find_bulk_interface(dev: usb.core.Device) -> tuple | None:
    """
    Return (interface, ep_in, ep_out) for the first interface matching
    class=FF / sub=04 / proto=01, or None if not found.
    """
    cfg = dev.get_active_configuration()
    for intf in cfg:
        if (intf.bInterfaceClass    == VENDOR_CLASS and
                intf.bInterfaceSubClass == VENDOR_SUBCLASS and
                intf.bInterfaceProtocol == VENDOR_PROTO_BULK):
            ep_in  = usb.util.find_descriptor(
                intf, custom_match=lambda e:
                usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_IN
                and usb.util.endpoint_type(e.bmAttributes) == usb.util.ENDPOINT_TYPE_BULK
            )
            ep_out = usb.util.find_descriptor(
                intf, custom_match=lambda e:
                usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_OUT
                and usb.util.endpoint_type(e.bmAttributes) == usb.util.ENDPOINT_TYPE_BULK
            )
            if ep_in and ep_out:
                return intf, ep_in, ep_out
    return None


# ─── Probe one device ─────────────────────────────────────────────────────────
def probe_device(dev: usb.core.Device) -> None:
    name = usb.util.get_string(dev, dev.iProduct) if dev.iProduct else "MOTU"
    serial = usb.util.get_string(dev, dev.iSerialNumber) if dev.iSerialNumber else "?"
    hdr(f"{name}  (serial {serial})")

    result = find_bulk_interface(dev)
    if result is None:
        err("No vendor bulk interface (FF/04/01) found — descriptor changed?")
        return

    intf, ep_in, ep_out = result
    intf_num = intf.bInterfaceNumber
    info(f"Found vendor bulk interface #{intf_num}: "
         f"EP_OUT=0x{ep_out.bEndpointAddress:02X}  EP_IN=0x{ep_in.bEndpointAddress:02X}")

    # Detach kernel driver if one is bound (shouldn't be, but be safe)
    if dev.is_kernel_driver_active(intf_num):
        warn(f"Interface {intf_num} has a kernel driver — detaching")
        dev.detach_kernel_driver(intf_num)

    try:
        usb.util.claim_interface(dev, intf_num)
        ok(f"Claimed interface {intf_num}")
    except usb.core.USBError as e:
        err(f"Could not claim interface {intf_num}: {e}")
        return

    try:
        _run_http_probes(dev, ep_in, ep_out, name)
    finally:
        usb.util.release_interface(dev, intf_num)
        info(f"Released interface {intf_num}")


def _run_http_probes(dev, ep_in, ep_out, name: str) -> None:
    for label, payload in HTTP_REQUESTS:
        print()
        info(f"── Trying: {label}")
        info(f"   Sending {len(payload)} bytes →")
        print(f"   {payload[:120]!r}")

        # Flush any stale data on IN endpoint first
        try:
            ep_in.read(READ_SIZE, timeout=200)
        except usb.core.USBTimeoutError:
            pass
        except usb.core.USBError:
            pass

        # Send request
        try:
            written = ep_out.write(payload, timeout=BULK_TIMEOUT_MS)
        except usb.core.USBError as e:
            err(f"   Write failed: {e}")
            continue
        info(f"   Wrote {written} bytes")

        # Read response (may need multiple reads)
        response = b""
        deadline = time.monotonic() + (BULK_TIMEOUT_MS / 1000)
        while time.monotonic() < deadline:
            try:
                chunk = bytes(ep_in.read(READ_SIZE, timeout=500))
                if chunk:
                    response += chunk
                    # Stop if we have a complete HTTP response
                    if b"\r\n\r\n" in response:
                        # Give a little more time for the body
                        try:
                            body_chunk = bytes(ep_in.read(READ_SIZE, timeout=500))
                            response += body_chunk
                        except usb.core.USBTimeoutError:
                            pass
                        break
            except usb.core.USBTimeoutError:
                if response:
                    break   # Got something, stop waiting
            except usb.core.USBError as e:
                err(f"   Read error: {e}")
                break

        if response:
            ok(f"   Got {len(response)} bytes of response!")
            # Print header portion
            header_end = response.find(b"\r\n\r\n")
            if header_end != -1:
                headers = response[:header_end].decode(errors="replace")
                body_preview = response[header_end + 4: header_end + 4 + 512]
                print(f"\n{GRN}   ── HTTP Headers ──{RST}")
                for h_line in headers.splitlines():
                    print(f"   {h_line}")
                print(f"\n{GRN}   ── Body preview (first 512 bytes) ──{RST}")
                print(f"   {body_preview.decode(errors='replace')!r}")

                # Save full response
                out_path = f"scripts/bulk-response-{name.replace(' ', '_')}.bin"
                with open(out_path, "wb") as f:
                    f.write(response)
                ok(f"   Full response saved to {out_path}")
            else:
                warn("   Response received but no HTTP header boundary found (non-HTTP framing?)")
                print(f"   First 256 bytes: {response[:256].hex()}")
                hex_path = f"scripts/bulk-raw-{name.replace(' ', '_')}.bin"
                with open(hex_path, "wb") as f:
                    f.write(response)
                info(f"   Raw bytes saved to {hex_path}")
            return  # Don't try remaining requests if one succeeded
        else:
            warn("   No response received within timeout")

    print()
    warn("No HTTP response from any request variant.")
    warn("Next step: capture USB traffic with usbmon while the Windows VM accesses the web UI.")
    warn("Run: sudo python3 scripts/usbmon-capture.py")


# ─── Main ─────────────────────────────────────────────────────────────────────
def main() -> None:
    hdr("MOTU Bulk Interface HTTP Probe")

    devices = list(usb.core.find(idVendor=MOTU_VID, idProduct=MOTU_PID, find_all=True))
    if not devices:
        err(f"No MOTU devices found (VID=0x{MOTU_VID:04X} PID=0x{MOTU_PID:04X})")
        sys.exit(1)

    info(f"Found {len(devices)} MOTU device(s)")
    for dev in devices:
        probe_device(dev)


if __name__ == "__main__":
    main()
