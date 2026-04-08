
#!/usr/bin/env python3
"""
usbmon-capture.py — Capture USB bulk traffic on MOTU vendor interfaces via usbmon.

Run on Linux while the Windows VM (or windows-driver-session.py) accesses the
device.  Saves a timestamped JSONL of all bulk packets on EP3 IN / EP4 OUT.

Uses the usbmon TEXT format from debugfs (/sys/kernel/debug/usb/usbmon/<bus>u),
which is always available when the usbmon module is loaded.  For full payloads
(not capped at 32 bytes) the binary /dev/usbmon<N> interface is preferred and
used automatically when available.

Capture workflow for Windows VM session:
  1.  sudo modprobe usbmon
  2.  Plug 828ES into Linux host (not yet passed to VM)
  3.  sudo python3 scripts/usbmon-capture.py --save captures/windows-$(date +%s).jsonl
  4.  Pass USB device to Windows VM (QEMU hostdev / VirtualBox)
  5.  Open MOTU Control software in Windows
  6.  Perform all target actions:
        - Let it connect (CONNECT + POST /host/os + initial NREK)
        - Change clock source
        - Change sample rate
        - Move a mixer fader
        - Change a routing entry
        - Toggle mute
        - Open/close MOTU Control UI
  7.  Press Ctrl+C → JSONL is written
  8.  python3 scripts/analyze-capture.py <file>.jsonl   # decode frames

Text format reference: https://www.kernel.org/doc/html/latest/usb/usbmon.html
Each line:
  <urb-id> <ts-us> <event> <type><dir>:<bus>:<dev>:<ep> <status> <length> [= <hex>]
  e.g.: ffff... 3575914555 S Bo:7:009:4 -115 31 = 47455420 2f646174...
  type: B=Bulk C=Control S=Isochronous I=Interrupt  /  dir: i=IN o=OUT

Requires: Linux kernel usbmon module
Run as root: sudo python3 scripts/usbmon-capture.py
"""

import argparse
import json
import operator
import os
import re
import signal
import struct
import sys
import time
from pathlib import Path

MOTU_VID = 0x07FD
MOTU_PID = 0x0005

# Bulk endpoint numbers (direction encoded in usbmon type+dir field)
EP_BULK_IN  = 3   # EP3 IN  (USB address 0x83)
EP_BULK_OUT = 4   # EP4 OUT (USB address 0x04)

RED = "\033[0;31m"; GRN = "\033[0;32m"; YLW = "\033[1;33m"
CYN = "\033[0;36m"; BLD = "\033[1m";    RST = "\033[0m"

def info(m):  print(f"{CYN}[INFO]{RST}  {m}", flush=True)
def ok(m):    print(f"{GRN}[OK]{RST}    {m}", flush=True)
def warn(m):  print(f"{YLW}[WARN]{RST}  {m}", flush=True)
def err(m):   print(f"{RED}[ERR]{RST}   {m}", flush=True)
def hdr(m):
    bar = "═" * 52
    print(f"\n{BLD}{bar}{RST}\n{BLD}  {m}{RST}\n{BLD}{bar}{RST}", flush=True)


# ─── usbmon text-format line parser ──────────────────────────────────────────
# Example: "ffff88020b6b5380 3575914555 S Bo:7:009:4 -115 31 = 47455420 2f646174"
_LINE_RE = re.compile(
    r"^[0-9a-f]+ (\d+) [SCE] "
    r"([BCISi])([io]):"
    r"(\d+):(\d+):(\d+)"
    r" -?\d+ (\d+)"
    r"(?: = ([\da-f ]+))?"
)

def parse_line(line: str) -> dict | None:
    """Parse one usbmon text line. Returns None if not matching our filter."""
    m = _LINE_RE.match(line.strip())
    if not m:
        return None
    ts_us, xfer_type, direction, bus, dev, ep, length, hex_data = m.groups()
    if xfer_type != "B":
        return None
    ep = int(ep)
    if ep not in (EP_BULK_IN, EP_BULK_OUT):
        return None
    data = bytes.fromhex(hex_data.replace(" ", "")) if hex_data else b""
    return {
        "ts":        int(ts_us) / 1_000_000.0,  # usbmon timestamp in seconds
        "direction": "IN" if direction == "i" else "OUT",
        "bus": int(bus),
        "dev": int(dev),
        "ep": ep,
        "length": int(length),
        "data": data,
        "data_hex": data.hex(),
        "data_text": data.decode("utf-8", errors="replace"),
    }


def find_motu_devices() -> list[dict]:
    """Return list of {name, bus, dev} for all MOTU devices found in sysfs."""
    vid_str = f"{MOTU_VID:04x}"
    pid_str = f"{MOTU_PID:04x}"
    devices = []
    for sysdev in sorted(Path("/sys/bus/usb/devices").iterdir()):
        vf, pf = sysdev / "idVendor", sysdev / "idProduct"
        if not vf.is_file() or vf.read_text().strip() != vid_str:
            continue
        if not pf.is_file() or pf.read_text().strip() != pid_str:
            continue
        bf  = sysdev / "busnum"
        df  = sysdev / "devnum"
        nf  = sysdev / "product"
        bus = int(bf.read_text().strip()) if bf.is_file() else -1
        dev = int(df.read_text().strip()) if df.is_file() else -1
        name = nf.read_text().strip() if nf.is_file() else "MOTU"
        devices.append({"name": name, "bus": bus, "dev": dev})
        info(f"Found {name}  bus={bus} dev={dev}")
    return devices


# ─── usbmon availability ──────────────────────────────────────────────────────
def find_usbmon_file(bus: int) -> Path | None:
    """
    Locate the usbmon text-mode file for `bus`.
    Tries bus-specific file first, then the all-buses file.
    """
    for p in [Path(f"/sys/kernel/debug/usb/usbmon/{bus}u"),
              Path("/sys/kernel/debug/usb/usbmon/0u")]:
        if p.exists():
            return p
    return None


def find_or_create_usbmon_dev(bus: int) -> Path | None:
    """
    Try to locate or create /dev/usbmon<bus>.
    Returns the Path if available (binary mode = full payloads), else None.
    """
    dev_path = Path(f"/dev/usbmon{bus}")
    if dev_path.exists():
        return dev_path

    # Try to read the major number from /proc/devices
    try:
        proc = Path("/proc/devices").read_text()
        for line in proc.splitlines():
            if "usbmon" in line.lower():
                major = int(line.split()[0])
                os.system(f"mknod {dev_path} c {major} {bus} 2>/dev/null")
                if dev_path.exists():
                    ok(f"Created {dev_path} (major={major})")
                    return dev_path
    except Exception:
        pass
    return None


def ensure_usbmon(bus: int) -> tuple[Path, str]:
    """Returns (path, mode) where mode is 'binary' or 'text'."""
    debug = Path("/sys/kernel/debug")
    if not debug.exists() or not any(debug.iterdir()):
        err("debugfs not mounted. Run: sudo mount -t debugfs none /sys/kernel/debug")
        sys.exit(1)

    usbmon_dir = Path("/sys/kernel/debug/usb/usbmon")
    if not usbmon_dir.exists():
        info("Loading usbmon kernel module...")
        os.system("modprobe usbmon 2>/dev/null")
        time.sleep(0.8)

    # Prefer binary mode (/dev/usbmon*) for full packet capture
    dev = find_or_create_usbmon_dev(bus)
    if dev:
        ok(f"Binary usbmon: {dev}  (full packet payloads ✓)")
        return dev, "binary"

    # Fall back to text mode (32-byte payload cap)
    p = find_usbmon_file(bus)
    if p is None:
        available = list(usbmon_dir.iterdir()) if usbmon_dir.exists() else []
        err(
            f"Cannot find usbmon interface for bus {bus}.\n"
            f"  Tried: /dev/usbmon{bus} and /sys/kernel/debug/usb/usbmon/{bus}u\n"
            f"  Available debugfs files: {available}\n"
            f"  Try: sudo modprobe usbmon"
        )
        sys.exit(1)

    warn(f"Text-mode usbmon: {p}  (payload capped at 32 bytes — PTTH content will be truncated)")
    warn(f"For full payloads: sudo mknod /dev/usbmon{bus} c "
         f"$(grep usbmon /proc/devices | awk '{{print $1}}') {bus}")
    return p, "text"


# ─── Binary usbmon capture (full payloads via ioctl) ─────────────────────────
# Kernel usbmon binary API: MON_IOCX_GETX ioctl on /dev/usbmon<N>
# Source: drivers/usb/mon/mon_bin.c
#
# struct usbmon_packet (64 bytes, packed):
#   u64 id; u8 type; u8 xfer_type; u8 epnum; u8 devnum; u16 busnum;
#   s8 flag_setup; s8 flag_data; s64 ts_sec; s32 ts_usec; s32 status;
#   u32 length; u32 len_cap; u8 setup[8]; s32 interval; s32 start_frame;
#   u32 xfer_flags; u32 ndesc;
#
# struct mon_bin_get { usbmon_packet *hdr; void *data; size_t alloc; }
#   = 24 bytes on 64-bit
#
# MON_IOCX_GETX = _IOW(0x92, 10, struct mon_bin_get)
#               = (1<<30) | (24<<16) | (0x92<<8) | 10  = 0x4018920a

try:
    import ctypes, fcntl as _fcntl

    _SNAPSHOT = 65536  # bytes to capture per packet

    # usbmon_packet: exactly 64 bytes, packed
    _PKT_FMT = "=QBBBBHbbqiiIIQ iii II"  # not used directly, kept for reference

    class _UsbmonPkt(ctypes.Structure):
        _pack_ = 1
        _fields_ = [
            ("id",          ctypes.c_uint64),   # 0
            ("type",        ctypes.c_uint8),    # 8
            ("xfer_type",   ctypes.c_uint8),    # 9
            ("epnum",       ctypes.c_uint8),    # 10
            ("devnum",      ctypes.c_uint8),    # 11
            ("busnum",      ctypes.c_uint16),   # 12
            ("flag_setup",  ctypes.c_int8),     # 14
            ("flag_data",   ctypes.c_int8),     # 15
            ("ts_sec",      ctypes.c_int64),    # 16
            ("ts_usec",     ctypes.c_int32),    # 24
            ("status",      ctypes.c_int32),    # 28
            ("length",      ctypes.c_uint32),   # 32
            ("len_cap",     ctypes.c_uint32),   # 36
            ("setup",       ctypes.c_uint8 * 8), # 40  (union with iso; just use setup)
            ("interval",    ctypes.c_int32),    # 48
            ("start_frame", ctypes.c_int32),    # 52
            ("xfer_flags",  ctypes.c_uint32),   # 56
            ("ndesc",       ctypes.c_uint32),   # 60
        ]  # total = 64 bytes

    assert ctypes.sizeof(_UsbmonPkt) == 64, ctypes.sizeof(_UsbmonPkt)

    # MON_IOCX_GETX = _IOW(magic=0x92, nr=10, type=mon_bin_get{ptr,ptr,size_t}=24B)
    # _IOW  → direction bits = 1 (write-to-kernel)
    # _IOWR → direction bits = 3 (read+write) — previously wrong
    _MON_IOCX_GETX = (1 << 30) | (24 << 16) | (0x92 << 8) | 10  # 0x4018920a

    def _read_binary(mon_dev: Path, motu_devnums: set[int],
                     stop_flag: list) -> list[dict] | None:
        """Full-payload capture via MON_IOCX_GETX ioctl on /dev/usbmon<N>."""
        pkts: list[dict] = []
        pkt_hdr  = _UsbmonPkt()
        databuf  = ctypes.create_string_buffer(_SNAPSHOT)
        pkt_addr = ctypes.addressof(pkt_hdr)
        dat_addr = ctypes.addressof(databuf)

        try:
            fd = os.open(str(mon_dev), os.O_RDONLY | os.O_NONBLOCK)
        except PermissionError:
            err(f"Cannot open {mon_dev}: run as root.")
            return None

        try:
            while not stop_flag[0]:
                # struct mon_bin_get: { usbmon_packet *hdr; void *data; size_t alloc; }
                # Pass as a mutable bytearray so fcntl.ioctl can write the result back.
                arg = bytearray(struct.pack("QQQ", pkt_addr, dat_addr, _SNAPSHOT))
                try:
                    _fcntl.ioctl(fd, _MON_IOCX_GETX, arg, True)
                except BlockingIOError:        # EAGAIN: no event ready yet
                    time.sleep(0.002)
                    continue
                except OSError as exc:
                    warn(f"ioctl MON_IOCX_GETX failed: {exc} — falling back to text mode")
                    return None

                # Filter: bulk only, our endpoints, our devices
                if pkt_hdr.xfer_type != 3:
                    continue
                ep = pkt_hdr.epnum & 0x7F
                if ep not in (EP_BULK_IN, EP_BULK_OUT):
                    continue
                if pkt_hdr.devnum not in motu_devnums:
                    continue
                # Skip URB-submit events for IN eps (no payload yet, comes on callback)
                if pkt_hdr.type == ord('S') and (pkt_hdr.epnum & 0x80):
                    continue

                data = bytes(databuf[:pkt_hdr.len_cap])
                direction = "IN" if (pkt_hdr.epnum & 0x80) else "OUT"
                ts = pkt_hdr.ts_sec + pkt_hdr.ts_usec / 1_000_000.0
                p = {
                    "ts":        ts,
                    "direction": direction,
                    "bus":       pkt_hdr.busnum,
                    "dev":       pkt_hdr.devnum,
                    "ep":        ep,
                    "length":    pkt_hdr.length,
                    "data":      data,
                    "data_hex":  data.hex(),
                    "data_text": data.decode("utf-8", errors="replace"),
                }
                pkts.append(p)
                _print_packet(p)
        except KeyboardInterrupt:
            pass
        finally:
            os.close(fd)
        return pkts

    _BINARY_SUPPORT = True

except ImportError:
    _BINARY_SUPPORT = False
    def _read_binary(*_a, **_kw):  # type: ignore[misc]
        return None


# ─── Text usbmon capture (32-byte snapshot limit) ────────────────────────────
def _read_text(mon_file: Path, motu_devnums: set[int], stop_flag: list) -> list[dict]:
    pkts: list[dict] = []
    try:
        with open(mon_file, "r", errors="replace") as f:
            while not stop_flag[0]:
                line = f.readline()
                if not line:
                    time.sleep(0.005)
                    continue
                pkt = parse_line(line)
                if pkt is None:
                    continue
                if pkt["dev"] not in motu_devnums:
                    continue
                pkts.append(pkt)
                _print_packet(pkt)
    except KeyboardInterrupt:
        pass
    return pkts


# ─── Main capture dispatcher ──────────────────────────────────────────────────
def capture(mon_path: Path, mode: str, motu_devnums: set[int],
            stop_flag: list, bus: int = 0) -> dict[int, list[dict]]:
    info(f"Watching EPs {EP_BULK_IN} (IN) and {EP_BULK_OUT} (OUT) "
         f"on dev(s) {sorted(motu_devnums)}")
    info("Access the MOTU web UI from your Windows VM now. Press Ctrl+C to stop.\n")

    flat: list[dict] | None = None
    if mode == "binary":
        flat = _read_binary(mon_path, motu_devnums, stop_flag)
        if flat is None:
            warn("Binary ioctl failed — retrying in text mode (32-byte cap).")
            text_file = find_usbmon_file(bus)
            if text_file:
                flat = _read_text(text_file, motu_devnums, stop_flag)
    if flat is None:
        flat = _read_text(mon_path, motu_devnums, stop_flag)

    packets: dict[int, list[dict]] = {devnum: [] for devnum in motu_devnums}
    for pkt in flat:
        packets[pkt["dev"]].append(pkt)
    return packets


def _print_packet(pkt: dict) -> None:
    direction = pkt["direction"]
    colour = GRN if direction == "IN" else CYN
    prefix = (f"{colour}[{direction}]{RST} "
              f"bus={pkt['bus']} dev={pkt['dev']} ep={pkt['ep']} "
              f"len={pkt['length']}")
    data = pkt["data"]
    if not data:
        print(prefix, flush=True)
        return
    if any(sig in data for sig in (b"GET ", b"POST ", b"PUT ", b"HTTP/")):
        preview = data[:300].decode("utf-8", errors="replace")
        preview = preview.replace("\r\n", "↵\n    ").replace("\n", "↵\n    ")
        print(f"{prefix}\n    {GRN}[HTTP]{RST} {preview}", flush=True)
    else:
        print(f"{prefix}  hex={data[:32].hex()}", flush=True)


# ─── Analysis ─────────────────────────────────────────────────────────────────
def analyse(packets: list[dict]) -> None:
    hdr("Capture Analysis")
    out_pkts = [p for p in packets if p["direction"] == "OUT"]
    in_pkts  = [p for p in packets if p["direction"] == "IN"]
    info(f"Total: {len(packets)} packets  │  OUT: {len(out_pkts)}  │  IN: {len(in_pkts)}")

    if not packets:
        warn("No bulk packets captured on our endpoints.")
        warn("Confirm the Windows VM is actually using the device (not a network path).")
        return

    found_http = False
    for p in packets:
        for sig in (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HTTP/"):
            if sig in p["data"]:
                idx = p["data"].index(sig)
                ok(f"HTTP signature {sig!r} in {p['direction']} packet (ep={p['ep']})")
                print(f"   {p['data'][idx:idx+256].decode(errors='replace')!r}")
                found_http = True
                break

    if found_http:
        ok("Raw HTTP over bulk confirmed! bulk-probe.py should work.")
        return

    if out_pkts:
        sample = out_pkts[0]["data"]
        if len(sample) >= 4:
            le32 = struct.unpack_from("<I", sample)[0]
            be32 = struct.unpack_from(">I", sample)[0]
            info(f"First OUT packet — first 4 bytes raw={sample[:4].hex()}  LE={le32}  BE={be32}")
            expected = len(sample) - 4
            if le32 == expected:
                warn(f"Little-endian length prefix detected ({le32} == payload {expected})")
                warn("The device uses length-prefixed framing. HTTP must be wrapped in it.")
            elif be32 == expected:
                warn(f"Big-endian length prefix detected ({be32} == payload {expected})")
                warn("The device uses length-prefixed framing. HTTP must be wrapped in it.")
            else:
                info("No obvious length prefix. First 64 bytes:")
                print(f"   {sample[:64].hex()}")


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Capture USB bulk traffic on MOTU vendor interfaces via usbmon.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  sudo python3 usbmon-capture.py                           # auto-detect\n"
            "  sudo python3 usbmon-capture.py --device 7:9             # bus 7 dev 9\n"
            "  sudo python3 usbmon-capture.py --save captures/run.jsonl # custom path\n"
            "  python3 usbmon-capture.py --wireshark --device 7:9      # Wireshark cmd"
        ),
    )
    parser.add_argument(
        "--device", "-d",
        metavar="BUS:DEV",
        help=(
            "Manually specify the USB bus and device numbers to capture, e.g. '7:9'. "
            "Skips auto-detection via sysfs. Use 'lsusb' to find your device."
        ),
    )
    parser.add_argument(
        "--save", "-s",
        metavar="FILE",
        help=(
            "Path to write the JSONL capture file. "
            "Defaults to captures/usbmon-<timestamp>.jsonl"
        ),
    )
    parser.add_argument(
        "--wireshark", "-w",
        action="store_true",
        help=(
            "Print the Wireshark command to capture traffic for the selected bus/device "
            "and exit without starting a capture."
        ),
    )
    return parser.parse_args()


def _wireshark_command(bus: int, dev: int) -> str:
    return (
        f"sudo wireshark -k -i usbmon{bus} "
        f"-Y \"usb.device_address == {dev}\""
    )


# ─── Main ─────────────────────────────────────────────────────────────────────
def main() -> None:
    args = _parse_args()
    hdr("MOTU usbmon Bulk Traffic Capture")

    # ── Resolve bus / device ──────────────────────────────────────────────────
    if args.device:
        # Manual override: parse BUS:DEV
        try:
            bus_str, dev_str = args.device.split(":")
            bus = int(bus_str)
            forced_dev = int(dev_str)
        except ValueError:
            err(f"Invalid --device value '{args.device}'. Expected format: BUS:DEV (e.g. 7:9).")
            sys.exit(1)
        devices = [{"name": f"USB device {bus}:{forced_dev}", "bus": bus, "dev": forced_dev}]
        motu_devnums = {forced_dev}
        info(f"Using manually specified device  bus={bus} dev={forced_dev}")
    else:
        devices = find_motu_devices()
        if not devices:
            err("No MOTU devices found in sysfs.")
            sys.exit(1)
        bus = devices[0]["bus"]
        motu_devnums = {d["dev"] for d in devices}

    # ── Print Wireshark command hint ──────────────────────────────────────────
    for d in devices:
        cmd = _wireshark_command(d["bus"], d["dev"])
        info(f"Wireshark command for {d['name']} (bus={d['bus']} dev={d['dev']}):")
        print(f"  {BLD}{cmd}{RST}", flush=True)

    if args.wireshark:
        sys.exit(0)

    mon_path, mode = ensure_usbmon(bus)

    stop_flag = [False]
    signal.signal(signal.SIGINT, lambda *_: operator.setitem(stop_flag, 0, True))

    packets_by_dev = capture(mon_path, mode, motu_devnums, stop_flag, bus=bus)

    # Build devnum → device info lookup
    dev_info = {d["dev"]: d for d in devices}

    total = sum(len(pkts) for pkts in packets_by_dev.values())
    print()
    ok(f"Captured {total} bulk packets total across {len(devices)} device(s)")

    ts_tag = time.strftime("%Y%m%d-%H%M%S")

    for devnum, pkts in packets_by_dev.items():
        name = dev_info.get(devnum, {}).get("name", f"dev{devnum}")
        safe_name = name.replace(" ", "_")
        ok(f"{name} (dev {devnum}): {len(pkts)} packets")

        if pkts:
            # Resolve output path: --save > default timestamped name
            if args.save:
                out_path = Path(args.save)
            else:
                out_path = Path(
                    f"captures/usbmon-{ts_tag}"
                    f"-bus{bus}-dev{devnum}-{safe_name}.jsonl"
                )
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(
                "\n".join(
                    json.dumps({k: v for k, v in p.items() if k != "data"})
                    for p in pkts
                ) + "\n"
            )
            ok(f"  Saved to {out_path}")

        hdr(f"Analysis: {name} (dev {devnum})")
        analyse(pkts)


if __name__ == "__main__":
    main()
