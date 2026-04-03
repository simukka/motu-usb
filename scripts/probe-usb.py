#!/usr/bin/env python3
"""
probe-usb.py — Diagnose MOTU USB interface classes for CDC/RNDIS network access.
Run as root (or with sudo) for full sysfs driver binding info.
"""

import os
import re
import subprocess
import sys
from pathlib import Path

MOTU_VID = "07fd"

# ─── Colour helpers ───────────────────────────────────────────────────────────
RED = "\033[0;31m"
GRN = "\033[0;32m"
YLW = "\033[1;33m"
CYN = "\033[0;36m"
BLD = "\033[1m"
RST = "\033[0m"


def _p(colour: str, tag: str, msg: str) -> None:
    print(f"{colour}[{tag}]{RST}  {msg}")


def info(msg):  _p(CYN, "INFO",  msg)
def ok(msg):    _p(GRN, "OK",    msg)
def warn(msg):  _p(YLW, "WARN",  msg)
def found(msg): _p(GRN, "FOUND", msg)
def miss(msg):  _p(RED, "MISS",  msg)


def hdr(msg: str) -> None:
    bar = "═" * 50
    print(f"\n{BLD}{bar}{RST}")
    print(f"{BLD}  {msg}{RST}")
    print(f"{BLD}{bar}{RST}")


# ─── USB class code decoder ───────────────────────────────────────────────────
def decode_class(cls: int, sub: int, proto: int) -> str:
    if cls == 0x01:
        return "Audio (UAC)"
    if cls == 0x02:
        return {
            0x02: "CDC - Abstract Control Model (ACM / serial)",
            0x06: "CDC-ECM - Ethernet Control Model  \u2190 NETWORK",
            0x0D: "CDC-NCM - Network Control Model  \u2190 NETWORK",
            0x0E: "CDC - Ethernet Emulation Model (EEM)  \u2190 NETWORK",
        }.get(sub, f"CDC Communications (subclass 0x{sub:02x})")
    if cls == 0x0A:
        return "CDC-Data  \u2190 NETWORK data channel"
    if cls == 0xE0:
        if sub == 0x01 and proto == 0x03:
            return "RNDIS (Wireless Controller class)  \u2190 NETWORK"
        return f"Wireless Controller (subclass 0x{sub:02x} proto 0x{proto:02x})"
    if cls == 0xEF:
        if sub == 0x02 and proto == 0x01:
            return "Misc - Interface Association Descriptor (IAD)"
        if sub == 0x04 and proto == 0x01:
            return "RNDIS over Ethernet (Misc class)  \u2190 NETWORK"
        return f"Miscellaneous (subclass 0x{sub:02x} proto 0x{proto:02x})"
    if cls == 0xFF:
        return "Vendor Specific (FF)"
    return f"Class 0x{cls:02x} sub 0x{sub:02x} proto 0x{proto:02x}"


def is_network(desc: str) -> bool:
    return any(k in desc for k in ("NETWORK", "CDC-ECM", "CDC-NCM", "RNDIS", "EEM", "CDC-Data"))


# ─── Helpers ─────────────────────────────────────────────────────────────────
def run(cmd: list[str], check: bool = False) -> str:
    result = subprocess.run(cmd, capture_output=True, text=True)
    if check and result.returncode != 0:
        sys.exit(result.stderr.strip() or f"Command failed: {' '.join(cmd)}")
    return result.stdout


def parse_hex(value: str) -> int:
    """Parse decimal or 0x-prefixed hex string to int."""
    return int(value, 16 if value.startswith("0x") else 10)


def devnode(bus: int, dev: int) -> Path:
    return Path(f"/dev/bus/usb/{bus:03d}/{dev:03d}")


def lsusb_raw(bus: int, dev: int, vid_pid: str) -> str:
    node = devnode(bus, dev)
    if os.access(node, os.R_OK):
        out = run(["lsusb", "-D", str(node)])
        if out.strip():
            return out
    warn(f"Cannot read {node} directly — falling back to lsusb -v (may need sudo)")
    return run(["lsusb", "-v", "-d", vid_pid])


# ─── Dataclass-like device record ────────────────────────────────────────────
class MotuDevice:
    def __init__(self, bus: int, dev: int, vid_pid: str, name: str):
        self.bus = bus
        self.dev = dev
        self.vid_pid = vid_pid        # e.g. "07fd:0005"
        self.name = name
        self.vid = vid_pid.split(":")[0]
        self.pid = vid_pid.split(":")[1]


# ─── 1. Find MOTU devices ─────────────────────────────────────────────────────
def section_find_devices() -> list[MotuDevice]:
    hdr(f"1. Detecting MOTU devices (VID {MOTU_VID})")

    lsusb_out = run(["lsusb"])
    lines = [l for l in lsusb_out.splitlines() if MOTU_VID.lower() in l.lower()]

    if not lines:
        miss("No MOTU devices found on USB bus. Is the device powered on and connected?")
        sys.exit(1)

    devices: list[MotuDevice] = []
    # Example line: "Bus 007 Device 009: ID 07fd:0005 Mark of the Unicorn M64"
    pattern = re.compile(
        r"Bus (\d+) Device (\d+).*?ID ([\da-fA-F]+:[\da-fA-F]+)\s+(.*)"
    )
    for line in lines:
        m = pattern.search(line)
        if not m:
            warn(f"Could not parse lsusb line: {line!r}")
            continue
        bus, dev, vid_pid, name = int(m[1]), int(m[2]), m[3], m[4].strip()
        ok(f"Bus {bus:03d} Device {dev:03d}  │  {vid_pid}  │  {name}")
        devices.append(MotuDevice(bus, dev, vid_pid, name))

    return devices


# ─── 2. Full USB descriptors ──────────────────────────────────────────────────
def section_full_descriptors(devices: list[MotuDevice]) -> None:
    hdr("2. Full USB descriptors")

    for d in devices:
        print()
        info("─" * 54)
        info(f"Device: {d.vid_pid}  Bus {d.bus:03d} Dev {d.dev:03d}")
        info("─" * 54)
        print(lsusb_raw(d.bus, d.dev, d.vid_pid))


# ─── 3. Interface class analysis ─────────────────────────────────────────────
def parse_interfaces(raw: str) -> list[dict]:
    """
    Walk lsusb -v output and return a list of dicts with keys:
    num, cls, sub, proto (all ints).
    """
    interfaces = []
    current: dict | None = None

    re_num   = re.compile(r"bInterfaceNumber\s+(\d+)")
    re_cls   = re.compile(r"bInterfaceClass\s+(0x[\da-fA-F]+|\d+)")
    re_sub   = re.compile(r"bInterfaceSubClass\s+(0x[\da-fA-F]+|\d+)")
    re_proto = re.compile(r"bInterfaceProtocol\s+(0x[\da-fA-F]+|\d+)")

    for line in raw.splitlines():
        line = line.strip()
        if m := re_num.search(line):
            if current and "cls" in current:
                interfaces.append(current)
            current = {"num": int(m[1])}
        elif current is not None:
            if m := re_cls.search(line):
                current["cls"] = parse_hex(m[1])
            elif m := re_sub.search(line):
                current["sub"] = parse_hex(m[1])
            elif m := re_proto.search(line):
                current["proto"] = parse_hex(m[1])
                # Emit as soon as we have all three fields
                if "cls" in current and "sub" in current:
                    interfaces.append(current)
                    current = None

    if current and "cls" in current:
        interfaces.append(current)

    return interfaces


def section_interface_analysis(devices: list[MotuDevice]) -> bool:
    hdr("3. Interface class analysis — looking for CDC / RNDIS / network interfaces")

    found_network = False

    for d in devices:
        print()
        info(f"Scanning interfaces on {d.vid_pid} (Bus {d.bus:03d} Dev {d.dev:03d})")
        raw = lsusb_raw(d.bus, d.dev, d.vid_pid)

        for iface in parse_interfaces(raw):
            num   = iface.get("num", "?")
            cls   = iface.get("cls", 0)
            sub   = iface.get("sub", 0)
            proto = iface.get("proto", 0)
            desc  = decode_class(cls, sub, proto)
            label = f"Interface {num}: class=0x{cls:02x} sub=0x{sub:02x} proto=0x{proto:02x} → {desc}"
            if is_network(desc):
                found(label)
                found_network = True
            else:
                info(label)

    print()
    if found_network:
        ok("At least one network-capable interface was found!")
    else:
        warn("No CDC/RNDIS/network interface classes found in USB descriptors.")
        warn("The device may use a vendor-specific protocol (class FF) for HTTP access.")

    return found_network


# ─── 4. Driver bindings (sysfs) ───────────────────────────────────────────────
def section_driver_bindings(devices: list[MotuDevice]) -> None:
    hdr("4. Current driver bindings (sysfs)")
    info("Checking /sys/bus/usb/devices/ for MOTU device bindings...")

    usb_devices = Path("/sys/bus/usb/devices")

    for d in devices:
        print()
        info(f"Looking for sysfs node: idVendor={d.vid} idProduct={d.pid}")

        matched = False
        for sysdev in sorted(usb_devices.iterdir()):
            vendor_file = sysdev / "idVendor"
            product_file = sysdev / "idProduct"
            if not vendor_file.is_file():
                continue
            if vendor_file.read_text().strip() != d.vid:
                continue
            if product_file.read_text().strip() != d.pid:
                continue

            matched = True
            devpath = sysdev.name
            ok(f"Found sysfs device: {devpath}")

            iface_re = re.compile(rf"^{re.escape(devpath)}:\d+\.\d+$")
            for iface_dir in sorted(sysdev.iterdir()):
                if not iface_dir.is_dir():
                    continue
                if not iface_re.match(iface_dir.name):
                    continue
                # e.g. "7-1.4:1.2" → interface part after the colon = "1.2"
                iface_label = iface_dir.name.split(":")[-1]
                driver_link = iface_dir / "driver"
                if driver_link.is_symlink():
                    drv = Path(os.readlink(driver_link)).name
                    print(f"  Interface {iface_label}  →  driver: {GRN}{drv}{RST}")
                else:
                    print(f"  Interface {iface_label}  →  driver: {YLW}(none — unbound){RST}")

        if not matched:
            miss(f"No sysfs node found for {d.vid_pid}")


# ─── 5. Kernel modules ───────────────────────────────────────────────────────
def section_kernel_modules() -> None:
    hdr("5. USB networking kernel modules")

    net_mods = ["cdc_ether", "cdc_ncm", "rndis_host", "cdc_eem",
                "cdc_subset", "usbnet", "snd_usb_audio"]
    lsmod_out = run(["lsmod"])
    loaded = {line.split()[0] for line in lsmod_out.splitlines() if line}

    for mod in net_mods:
        if mod in loaded:
            ok(f"{mod}  is loaded")
        else:
            warn(f"{mod}  NOT loaded")


# ─── 6. USB network interfaces ───────────────────────────────────────────────
def section_net_interfaces() -> None:
    hdr("6. USB network interfaces visible to the OS")

    ip_out = run(["ip", "link", "show"])
    pattern = re.compile(r"usb\d+|enp\w*u\d+|eth\w*usb", re.IGNORECASE)
    usb_nets = [line for line in ip_out.splitlines() if pattern.search(line)]

    if usb_nets:
        found("USB network interfaces detected:")
        print("\n".join(usb_nets))
    else:
        miss("No USB-backed network interfaces detected (usb0, enp*u*, etc.)")


# ─── Summary ─────────────────────────────────────────────────────────────────
def section_summary() -> None:
    hdr("Summary")
    print("""
Next steps depend on the interface classes found above:

  CDC-ECM / CDC-NCM found  →  Strategy 2a: bind cdc_ether / cdc_ncm to that interface
  RNDIS found              →  Strategy 2b: bind rndis_host to that interface
  Only class FF found      →  Strategy 4:  USB traffic capture required
  Unbound interface(s)     →  Try: sudo modprobe cdc_ether  (or rndis_host)

Share this output and we'll determine the exact next step.
""")


# ─── Entry point ─────────────────────────────────────────────────────────────
def main() -> None:
    devices = section_find_devices()
    section_full_descriptors(devices)
    section_interface_analysis(devices)
    section_driver_bindings(devices)
    section_kernel_modules()
    section_net_interfaces()
    section_summary()


if __name__ == "__main__":
    main()
