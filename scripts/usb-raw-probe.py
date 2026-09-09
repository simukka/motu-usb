#!/usr/bin/env python3
"""
scripts/usb-raw-probe.py

Sends raw USB bulk frames to the 828ES EP4 OUT and reads responses from EP3 IN,
with full kernel driver detachment. Run as root or with appropriate udev rules.

Usage:
    sudo .venv/bin/python3 scripts/usb-raw-probe.py
    sudo .venv/bin/python3 scripts/usb-raw-probe.py --ping-only
    sudo .venv/bin/python3 scripts/usb-raw-probe.py --hex 01810800 00000000
"""

import usb.core
import usb.util
import time
import sys
import argparse
import struct

VID = 0x07fd
INTERFACE = 5    # 828ES vendor bulk interface
EP_OUT = 0x04
EP_IN  = 0x83
TIMEOUT = 3000   # ms

def find_device():
    dev = usb.core.find(idVendor=VID)
    if dev is None:
        print("ERROR: MOTU device not found")
        sys.exit(1)
    print(f"Found: {dev.manufacturer} {dev.product} (bus {dev.bus} dev {dev.address})")
    return dev

def detach_and_claim(dev, intf_num):
    # Detach every interface that has a kernel driver attached
    cfg = dev.get_active_configuration()
    for intf in cfg:
        n = intf.bInterfaceNumber
        try:
            if dev.is_kernel_driver_active(n):
                print(f"  Detaching kernel driver from interface {n}")
                dev.detach_kernel_driver(n)
        except Exception as e:
            print(f"  Could not detach interface {n}: {e}")

    intf = cfg[(intf_num, 0)]
    usb.util.claim_interface(dev, intf_num)
    print(f"Claimed interface {intf_num}  EP_OUT={EP_OUT:#04x}  EP_IN={EP_IN:#04x}")
    return intf

def release(dev, intf_num):
    usb.util.release_interface(dev, intf_num)
    # Re-attach kernel drivers so audio still works after the script exits
    try:
        dev.attach_kernel_driver(intf_num)
    except Exception:
        pass

def send_recv(dev, data: bytes, label="", read_len=512, timeout=TIMEOUT):
    if label:
        print(f"\n── {label} ──")
    print(f"  OUT ({len(data):3d} bytes): {data.hex()}")
    written = dev.write(EP_OUT, data, timeout=timeout)
    print(f"  wrote {written} bytes")
    time.sleep(0.1)
    try:
        resp = bytes(dev.read(EP_IN, read_len, timeout=timeout))
        print(f"  IN  ({len(resp):3d} bytes): {resp.hex()}")
        if len(resp) >= 4:
            seq, flags, total_len = resp[0], resp[1], struct.unpack_from('<H', resp, 2)[0]
            print(f"    seq={seq} flags={flags:#04x} total_len={total_len}")
        return resp
    except usb.core.USBTimeoutError:
        print("  IN: <timeout>")
        return None
    except Exception as e:
        print(f"  IN: ERROR {e}")
        return None

# ── Frame builders ─────────────────────────────────────────────────────────────

def ping_frame(seq=1):
    """4-byte PING: [seq, 0x81, 0x04, 0x00]

    Confirmed from usbmon capture of the official Windows driver.
    The original probe used 8 bytes (total_len=8) but Windows sends 4.
    The device responds to both, but 4 bytes is correct.
    """
    return struct.pack('<BBH', seq & 0xFF, 0x81, 4)

def connect_frame(seq=1):
    """4-byte CONNECT frame: [seq, 0x82, 0x04, 0x00]

    Confirmed from usbmon capture — Windows driver sends a 4-byte CONNECT,
    NOT an 8-byte frame.  The device responds with a PONG (8 bytes).
    """
    return struct.pack('<BBH', seq & 0xFF, 0x82, 4)

def http_connect_frame(seq=1, session=0x12345678, msg_seq=1):
    """
    PTTH frame carrying an HTTP CONNECT request.
    Based on observed wire format:
      [0]   seq      u8
      [1]   flags    u8  = 0x80 (data OUT)
      [2:4] total_len u16-LE
      [4:8] 4CC      'PTTH' LE = 48 54 54 50
      [8:12] session_id u32-LE
      [12:16] msg_seq  u32-LE
      [16:20] 0x00000001
      [20:22] 0x0000
      [22:24] payload_len u16-LE
      [24:28] 'MOTU' LE = 4D 4F 54 55
      [28:32] 0x08000000
      [32...]  HTTP payload
    """
    payload = b'CONNECT localhost:80 HTTP/1.1\r\n\r\n'
    hdr_len = 32
    total = hdr_len + len(payload)
    hdr = struct.pack('<BBHIIIHHII',
        seq,          # [0]   seq
        0x80,         # [1]   flags = data
        total,        # [2:4] total_len
        0x48545450,   # [4:8] 'PTTH' as LE u32
        session,      # [8:12] session_id
        msg_seq,      # [12:16] msg_seq
        1,            # [16:18] constant 0x0001
        0,            # [18:20] 0x0000  (note: packing as two u16)
        len(payload), # [20:22] payload_len ... need to repack
        0x4D4F5455,   # 'MOTU'
    )
    # Repack carefully to match exact field layout
    hdr = struct.pack('<BB', seq, 0x80)                  # [0:2]
    hdr += struct.pack('<H', total)                       # [2:4]
    hdr += struct.pack('<I', 0x48545450)                  # [4:8]  PTTH
    hdr += struct.pack('<I', session)                     # [8:12]
    hdr += struct.pack('<I', msg_seq)                     # [12:16]
    hdr += struct.pack('<I', 1)                           # [16:20]
    hdr += struct.pack('<H', 0)                           # [20:22]
    hdr += struct.pack('<H', len(payload))                # [22:24]
    hdr += struct.pack('<I', 0x4D4F5455)                  # [24:28] MOTU
    hdr += struct.pack('<I', 0x08000000)                  # [28:32]
    assert len(hdr) == 32
    return hdr + payload

def nrek_frame(seq=1, session=0x12345678, msg_seq=1):
    """Minimal NREK keepalive frame — same layout as PTTH but with NREK 4CC and no payload"""
    payload = b''
    total = 32 + len(payload)
    hdr  = struct.pack('<BB', seq, 0x80)
    hdr += struct.pack('<H', total)
    hdr += struct.pack('<I', 0x4B45524E)   # NREK
    hdr += struct.pack('<I', session)
    hdr += struct.pack('<I', msg_seq)
    hdr += struct.pack('<I', 1)
    hdr += struct.pack('<H', 0)
    hdr += struct.pack('<H', len(payload))
    hdr += struct.pack('<I', 0x4D4F5455)   # MOTU
    hdr += struct.pack('<I', 0x08000000)
    return hdr + payload

def raw_frame(hex_str: str):
    return bytes.fromhex(hex_str.replace(' ', ''))

# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--ping-only', action='store_true')
    parser.add_argument('--connect', action='store_true', help='Send CONNECT frame')
    parser.add_argument('--http-connect', action='store_true', help='Send PTTH HTTP CONNECT')
    parser.add_argument('--hex', nargs='+', help='Send raw hex bytes')
    parser.add_argument('--interface', type=int, default=INTERFACE)
    args = parser.parse_args()

    dev = find_device()
    detach_and_claim(dev, args.interface)

    try:
        # ── Always try a PING first to see if device responds ──────────────────
        for seq in range(1, 4):
            resp = send_recv(dev, ping_frame(seq), f"PING seq={seq}")
            if resp:
                print(f"  *** Device responded to PING! ***")
            time.sleep(0.3)

        if args.ping_only:
            return

        if args.hex:
            data = raw_frame(''.join(args.hex))
            send_recv(dev, data, "RAW HEX", read_len=65536)
            return

        if args.connect:
            send_recv(dev, connect_frame(), "CONNECT flags=0x82", read_len=512)
            time.sleep(0.5)
            # Try reading more
            try:
                resp = bytes(dev.read(EP_IN, 512, timeout=TIMEOUT))
                print(f"  Follow-up IN: {resp.hex()}")
            except usb.core.USBTimeoutError:
                print("  Follow-up IN: <timeout>")

        if args.http_connect:
            # Send PTTH CONNECT
            resp = send_recv(dev, http_connect_frame(), "PTTH HTTP CONNECT", read_len=512)
            if resp and b'200' in resp:
                print("  *** Got 200 OK! Tunnel established. ***")
                # Now send a plain HTTP GET
                time.sleep(0.1)
                http_get = b'GET /datastore HTTP/1.0\r\nHost: localhost\r\n\r\n'
                payload_frame = (
                    struct.pack('<BB', 2, 0x80) +
                    struct.pack('<H', 32 + len(http_get)) +
                    struct.pack('<I', 0x48545450) +   # PTTH
                    struct.pack('<I', 0x12345678) +
                    struct.pack('<I', 2) +
                    struct.pack('<I', 1) +
                    struct.pack('<H', 0) +
                    struct.pack('<H', len(http_get)) +
                    struct.pack('<I', 0x4D4F5455) +   # MOTU
                    struct.pack('<I', 0x08000000) +
                    http_get
                )
                send_recv(dev, payload_frame, "HTTP GET /datastore", read_len=65536)

        # ── Fallback: send both NREK and PTTH and watch what comes back ────────
        if not (args.connect or args.http_connect or args.hex):
            send_recv(dev, nrek_frame(), "NREK frame", read_len=512)
            time.sleep(0.3)
            send_recv(dev, http_connect_frame(), "PTTH HTTP CONNECT", read_len=512)

    finally:
        release(dev, args.interface)
        print("\nDone.")

if __name__ == '__main__':
    main()
