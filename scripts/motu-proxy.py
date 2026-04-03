#!/usr/bin/env python3
"""
motu-proxy.py — Native Linux HTTP proxy for MOTU USB audio device API.

Implements the reverse-engineered binary protocol over MOTU USB bulk endpoints
(Vendor-Specific class 0xFF/04/01, EP3-IN + EP4-OUT) and exposes the device's
HTTP datastore API locally, matching the Windows driver's localhost:1280 interface.

Protocol summary (from usbmon capture + HAR reverse engineering):
  ┌──────────────────────────────────────────────────────────────────┐
  │ Outer frame (4 bytes, every packet)                              │
  │  [0]    seq       u8    — counter; OUT: 0x20+, IN: 0x54+        │
  │  [1]    flags     u8    — 0x80=data OUT, 0x81=PING, 0x00=resp   │
  │  [2-3]  total_len u16LE — full packet length                     │
  ├──────────────────────────────────────────────────────────────────┤
  │ PING  (OUT, 4 bytes):  [seq] 0x81 0x04 0x00                     │
  │ ACK   (IN,  8 bytes):  [seq] 0x00 0x08 0x00  × 2  (echoes seq) │
  ├──────────────────────────────────────────────────────────────────┤
  │ Data frame header (bytes 4-31, both msg types):                  │
  │  [4-7]   msg_type    4cc  — b"NREK" or b"PTTH"                  │
  │  [8-11]  session_id  u32  — random nonce per channel             │
  │  [12-15] msg_seq     u32  — per-channel counter                  │
  │  [16-19] constant    u32  — always 1                             │
  │  [20-21] pad         u16  — always 0                             │
  │  [22-23] payload_len u16  — len(payload); total_len = 24+paylen  │
  │  [24-27] motu_magic  4cc  — b"UTOM" (MOTU little-endian)        │
  │  [28-31] inner_hdr   u32  — always 8                             │
  │  [32…]   payload          — binary-serialized HTTP (see codec)   │
  └──────────────────────────────────────────────────────────────────┘

Payload format (NOT raw HTTP; both PTTH and NREK share this encoding):
  REQUEST  (OUT, bytes 32…):
    u32 1 | u32 0 | u32 N | u32 method_len+method | u32 path_len+path
    u32 num_headers  [u32 name_len+name + u32 val_len+val] × n
    u32 num_params   [u32 name_len+name + u32 val_len+val] × n  | body
  RESPONSE (IN, bytes 32…total_len-4):
    u32 1 | u32 0 | u32 N (headers section) | u32 status | u32 num_headers
    [u32 name_len+name + u32 val_len+val] × n  | body
  IN frames append a 4-byte footer (outer header copy) at total_len-4.

Usage:
    sudo python3 scripts/motu-proxy.py [--port 1280] [--no-nrek] [--verbose]

Then access (matching Windows driver behaviour):
    http://localhost:1280/<serial>/datastore
    http://localhost:1280/<serial>/datastore?client=<id>   ← long-poll

Requirements:
    pip install pyusb
    Either: run as root, OR set usbfs permissions:
      sudo chmod a+rw /dev/bus/usb/<bus>/<dev>
"""

import argparse
import logging
import queue
import random
import struct
import sys
import threading
import time
import usb.core
import usb.util
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

# ─── Constants ────────────────────────────────────────────────────────────────
MOTU_VID = 0x07FD
MOTU_PID = 0x0005

VENDOR_IFACE_CLASS    = 0xFF
VENDOR_IFACE_SUBCLASS = 0x04
VENDOR_IFACE_PROTO    = 0x01

EP_BULK_IN  = 0x83   # EP3 IN
EP_BULK_OUT = 0x04   # EP4 OUT

MOTU_MAGIC    = b"UTOM"   # b"MOTU" stored LE
INNER_HDR_VAL = 8
CONSTANT_1    = 1

PING_INTERVAL_S  = 1.0    # seconds between keepalive PINGs
NREK_TIMEOUT_S   = 30.0   # seconds to wait for a NREK long-poll response
USB_TIMEOUT_MS   = 5000   # USB bulk timeout in ms
HTTP_LONG_POLL_S = 15.0   # max seconds to wait for a PTTH response

logger = logging.getLogger("motu-proxy")


# ─── Frame builders ────────────────────────────────────────────────────────────
def make_ping(seq: int) -> bytes:
    """4-byte PING keepalive."""
    return bytes([seq & 0xFF, 0x81, 0x04, 0x00])


def make_data_frame(seq: int, msg_type: bytes, session_id: int,
                    msg_seq: int, payload: bytes) -> bytes:
    """Build a NREK or PTTH data frame."""
    assert len(msg_type) == 4
    payload_len = len(payload)
    total_len   = 24 + payload_len
    outer  = struct.pack("<BBH", seq & 0xFF, 0x80, total_len)
    inner  = (msg_type
              + struct.pack("<II", session_id, msg_seq)
              + struct.pack("<IHH", CONSTANT_1, 0, payload_len)
              + MOTU_MAGIC
              + struct.pack("<I", INNER_HDR_VAL))
    return outer + inner + payload

# ─── Binary request/response codec ────────────────────────────────────────────────────
def _u32le(n: int) -> bytes:
    return struct.pack("<I", n)


def _lv(s: "str | bytes") -> bytes:
    """u32 LE length prefix + value bytes."""
    b = s.encode() if isinstance(s, str) else s
    return _u32le(len(b)) + b


def encode_request(method: str, path: str,
                   headers: "list[tuple[str,str]]",
                   query_params: "list[tuple[str,str]]",
                   body: bytes = b"") -> bytes:
    """Encode a PTTH/NREK request payload (placed at byte 32 of the outer frame)."""
    structured = (
        _lv(method) + _lv(path)
        + _u32le(len(headers))
        + b"".join(_lv(k) + _lv(v) for k, v in headers)
        + _u32le(len(query_params))
        + b"".join(_lv(k) + _lv(v) for k, v in query_params)
        + body
    )
    return _u32le(1) + _u32le(0) + _u32le(len(structured)) + structured


def decode_response(data: bytes) -> "tuple[int, list[tuple[str,str]], bytes]":
    """
    Decode binary response payload → (status_code, headers, body).
    `data` = raw[32 : total_len-4] of the outer IN frame (footer already stripped).
    """
    if len(data) < 20:
        raise ValueError(f"Response payload too short: {len(data)} bytes")
    N      = struct.unpack_from("<I", data,  8)[0]  # size of status+headers section
    status = struct.unpack_from("<I", data, 12)[0]
    n_hdrs = struct.unpack_from("<I", data, 16)[0]
    off    = 20
    headers: list[tuple[str, str]] = []
    for _ in range(n_hdrs):
        nl   = struct.unpack_from("<I", data, off)[0]; off += 4
        name = data[off:off+nl].decode("utf-8", errors="replace"); off += nl
        vl   = struct.unpack_from("<I", data, off)[0]; off += 4
        val  = data[off:off+vl].decode("utf-8", errors="replace"); off += vl
        headers.append((name, val))
    body = data[12 + N:]  # body follows immediately after the headers section
    return status, headers, body

# ─── Frame parser ─────────────────────────────────────────────────────────────
class ParsedFrame:
    __slots__ = ("seq", "flags", "total_len", "is_ack",
                 "msg_type", "session_id", "msg_seq", "payload_len", "payload")

    def __init__(self, raw: bytes, usb_len: int):
        if len(raw) < 4:
            raise ValueError(f"Frame too short: {len(raw)} bytes")
        self.seq       = raw[0]
        self.flags     = raw[1]
        self.total_len = struct.unpack_from("<H", raw, 2)[0]

        # 8-byte ACK echoes the OUT seq
        if usb_len == 8 and self.flags == 0x00:
            self.is_ack = True
            self.msg_type = self.session_id = self.msg_seq = None
            self.payload_len = self.payload = None
            return

        self.is_ack = False
        if len(raw) < 32:
            raise ValueError(f"Data frame too short for inner header: {len(raw)}")
        self.msg_type    = raw[4:8]
        self.session_id  = struct.unpack_from("<I", raw, 8)[0]
        self.msg_seq     = struct.unpack_from("<I", raw, 12)[0]
        self.payload_len = struct.unpack_from("<H", raw, 22)[0]
        # Device IN responses carry a 4-byte footer (outer header copy) at total_len-4.
        # Payload is raw[32 … total_len-4]; OUT frames have no footer.
        if raw[1] == 0x00 and self.total_len >= 36:
            end = min(self.total_len - 4, len(raw))
            self.payload = raw[32:end] if end > 32 else b""
        else:
            self.payload = raw[32:] if len(raw) > 32 else b""

    def __repr__(self) -> str:
        if self.is_ack:
            return f"<ACK seq=0x{self.seq:02x}>"
        t = self.msg_type.decode("ascii", errors="?") if self.msg_type else "?"
        return (f"<{t} seq=0x{self.seq:02x} msg_seq={self.msg_seq} "
                f"payload_len={self.payload_len}>")


# ─── USB device abstraction ────────────────────────────────────────────────────
class MotuDevice:
    """
    Low-level USB comms layer for one MOTU device.

    Runs a reader thread that feeds incoming frames into per-channel queues.
    Callers should use `send_http()` to perform a full PTTH request/response.
    """

    def __init__(self, dev: usb.core.Device, serial: str,
                 enable_nrek: bool = True, verbose: bool = False):
        self._dev         = dev
        self.serial       = serial
        self._verbose     = verbose
        self._enable_nrek = enable_nrek

        # Sequence counters
        self._out_seq   = 0x20
        self._seq_lock  = threading.Lock()

        # Per-channel state
        self._nrek_session   = random.randint(0, 0xFFFFFFFF)
        self._nrek_msg_seq   = 0
        self._nrek_msg_lock  = threading.Lock()
        self._nrek_etag      = "0"   # start at 0 to fetch initial state
        self._nrek_pending: dict[int, queue.Queue] = {}
        self._nrek_lock      = threading.Lock()
        self._ptth_session   = random.randint(0, 0xFFFFFFFF)
        self._ptth_msg_seq   = 0
        self._ptth_msg_lock  = threading.Lock()

        # Pending PTTH responses: msg_seq → queue
        self._ptth_pending: dict[int, queue.Queue] = {}
        self._ptth_lock    = threading.Lock()

        # ACK tracking
        self._ack_queues: dict[int, queue.Queue] = {}
        self._ack_lock   = threading.Lock()

        # Threads
        self._stop    = threading.Event()
        self._reader  = threading.Thread(target=self._read_loop,
                                         name=f"motu-reader-{serial}", daemon=True)
        self._pinger  = threading.Thread(target=self._ping_loop,
                                         name=f"motu-pinger-{serial}", daemon=True)
        self._nreker  = threading.Thread(target=self._nrek_loop,
                                         name=f"motu-nrek-{serial}",  daemon=True)

    # ── Public API ─────────────────────────────────────────────────────────────

    def start(self) -> None:
        """Claim the USB interface and start background threads."""
        self._claim_interface()
        self._reader.start()
        self._pinger.start()
        if self._enable_nrek:
            self._nreker.start()
        logger.info("[%s] Started (nrek=%s)", self.serial, self._enable_nrek)

    def stop(self) -> None:
        self._stop.set()
        try:
            usb.util.release_interface(self._dev, self._iface)
        except Exception:
            pass

    def send_ptth(self, method: str, path: str,
                  headers: "list[tuple[str,str]]",
                  query_params: "list[tuple[str,str]]",
                  body: bytes = b"",
                  timeout: float = HTTP_LONG_POLL_S
                  ) -> "tuple[int, list[tuple[str,str]], bytes]":
        """
        Send a PTTH request and return (status_code, response_headers, body).
        Encodes the request in MOTU binary format and decodes the response.
        """
        payload = encode_request(method, path, headers, query_params, body)

        with self._ptth_msg_lock:
            msg_seq = self._ptth_msg_seq
            self._ptth_msg_seq += 1

        resp_q: queue.Queue = queue.Queue()
        with self._ptth_lock:
            self._ptth_pending[msg_seq] = resp_q

        seq = self._next_seq()
        frame = make_data_frame(seq, b"PTTH", self._ptth_session, msg_seq, payload)
        try:
            self._write(seq, frame)
            logger.debug("[%s] PTTH OUT seq=0x%02x msg_seq=%d payload=%d bytes",
                         self.serial, seq, msg_seq, len(payload))
            resp_payload = resp_q.get(timeout=timeout)
            return decode_response(resp_payload)
        except queue.Empty as exc:
            raise TimeoutError(
                f"No PTTH response for msg_seq={msg_seq} within {timeout}s"
            ) from exc
        finally:
            with self._ptth_lock:
                self._ptth_pending.pop(msg_seq, None)

    # ── Internal helpers ───────────────────────────────────────────────────────

    def _claim_interface(self) -> None:
        cfg = self._dev.get_active_configuration()
        for iface in cfg:
            if (iface.bInterfaceClass    == VENDOR_IFACE_CLASS
                    and iface.bInterfaceSubClass == VENDOR_IFACE_SUBCLASS
                    and iface.bInterfaceProtocol == VENDOR_IFACE_PROTO):
                self._iface = iface.bInterfaceNumber
                break
        else:
            raise RuntimeError("Vendor bulk interface (FF/04/01) not found")

        # Detach any kernel driver
        if self._dev.is_kernel_driver_active(self._iface):
            self._dev.detach_kernel_driver(self._iface)
        usb.util.claim_interface(self._dev, self._iface)
        logger.info("[%s] Claimed interface %d", self.serial, self._iface)

    def _next_seq(self) -> int:
        with self._seq_lock:
            s = self._out_seq
            self._out_seq = (self._out_seq + 1) & 0xFF
            return s

    def _write(self, seq: int, data: bytes) -> None:
        ack_q: queue.Queue = queue.Queue()
        # Register the ACK queue BEFORE writing, so the reader can't miss it
        with self._ack_lock:
            self._ack_queues[seq] = ack_q
        try:
            self._dev.write(EP_BULK_OUT, data, USB_TIMEOUT_MS)
            try:
                ack_q.get(timeout=2.0)
            except queue.Empty:
                logger.debug("[%s] No ACK for seq=0x%02x", self.serial, seq)
        finally:
            with self._ack_lock:
                self._ack_queues.pop(seq, None)

    def _read_loop(self) -> None:
        logger.debug("[%s] Reader thread started", self.serial)
        while not self._stop.is_set():
            try:
                raw = bytes(self._dev.read(EP_BULK_IN, 65536, USB_TIMEOUT_MS))
            except usb.core.USBTimeoutError:
                continue
            except Exception as exc:
                if not self._stop.is_set():
                    logger.warning("[%s] Read error: %s", self.serial, exc)
                break

            if len(raw) < 4:
                continue

            try:
                frame = ParsedFrame(raw, len(raw))
            except ValueError as exc:
                logger.debug("[%s] Parse error: %s", self.serial, exc)
                continue

            if self._verbose:
                logger.debug("[%s] IN  %s", self.serial, frame)

            if frame.is_ack:
                # Deliver ACK to the waiting OUT operation
                with self._ack_lock:
                    q = self._ack_queues.get(frame.seq)
                if q:
                    q.put(frame.seq)

            elif frame.msg_type == b"PTTH":
                with self._ptth_lock:
                    q = self._ptth_pending.get(frame.msg_seq)
                if q:
                    q.put(frame.payload)
                else:
                    logger.warning("[%s] Unexpected PTTH IN msg_seq=%d",
                                   self.serial, frame.msg_seq)

            elif frame.msg_type == b"NREK":
                with self._nrek_lock:
                    q = self._nrek_pending.get(frame.msg_seq)
                if q:
                    q.put(frame.payload)
                else:
                    logger.debug("[%s] NREK IN msg_seq=%d (unmatched)",
                                 self.serial, frame.msg_seq)

            else:
                logger.debug("[%s] Unknown msg_type=%r", self.serial, frame.msg_type)

    def _ping_loop(self) -> None:
        logger.debug("[%s] Pinger thread started", self.serial)
        while not self._stop.wait(PING_INTERVAL_S):
            seq = self._next_seq()
            ping = make_ping(seq)
            try:
                self._write(seq, ping)
                logger.debug("[%s] PING seq=0x%02x", self.serial, seq)
            except Exception as exc:
                logger.warning("[%s] PING failed: %s", self.serial, exc)

    def _nrek_loop(self) -> None:
        """
        Background long-poll on the NREK channel.
        Sends GET /datastore with the current ETag; the device returns 304
        (unchanged) or 200 (new data) — identical behaviour to PTTH but on
        a dedicated lightweight channel so PTTH stays free for browser reqs.
        """
        logger.debug("[%s] NREK thread started", self.serial)
        msg_seq = -1  # keep in scope for finally block
        while not self._stop.is_set():
            try:
                headers = [("If-None-Match", self._nrek_etag)]
                payload = encode_request("GET", "/datastore", headers, [])

                with self._nrek_msg_lock:
                    msg_seq = self._nrek_msg_seq
                    self._nrek_msg_seq += 1

                resp_q: queue.Queue = queue.Queue()
                with self._nrek_lock:
                    self._nrek_pending[msg_seq] = resp_q

                seq = self._next_seq()
                frame = make_data_frame(seq, b"NREK", self._nrek_session,
                                        msg_seq, payload)
                self._write(seq, frame)
                logger.debug("[%s] NREK OUT seq=0x%02x msg_seq=%d etag=%s",
                             self.serial, seq, msg_seq, self._nrek_etag)

                resp_payload = resp_q.get(timeout=NREK_TIMEOUT_S)
                status, resp_headers, body = decode_response(resp_payload)

                if status == 200:
                    for k, v in resp_headers:
                        if k.lower() == "etag":
                            self._nrek_etag = v
                            logger.info("[%s] NREK: datastore changed, new ETag=%s",
                                        self.serial, v)
                            break
                else:
                    logger.debug("[%s] NREK: %d (no change)", self.serial, status)

            except queue.Empty:
                logger.debug("[%s] NREK: no response within %gs",
                             self.serial, NREK_TIMEOUT_S)
            except Exception as exc:
                if not self._stop.is_set():
                    logger.warning("[%s] NREK error: %s", self.serial, exc)
                    self._stop.wait(2.0)
            finally:
                if msg_seq >= 0:
                    with self._nrek_lock:
                        self._nrek_pending.pop(msg_seq, None)


# ─── HTTP proxy handler ────────────────────────────────────────────────────────
class MotuProxyHandler(BaseHTTPRequestHandler):
    """
    Minimal HTTP/1.1 proxy handler.

    Accepts the browser/app request, reconstructs the raw HTTP bytes,
    sends them through the USB PTTH channel, and returns the device response.
    """

    server: "MotuProxyServer"

    def log_message(self, fmt: str, *args) -> None:  # suppress default access log
        logger.debug("HTTP %s - " + fmt, self.client_address[0], *args)

    def _proxy(self, body: bytes = b"") -> None:
        from urllib.parse import urlparse, parse_qsl

        # Split /<serial>/<device-path>?<query> from the browser URL
        parsed    = urlparse(self.path)
        path_parts = parsed.path.lstrip("/").split("/", 1)
        serial    = path_parts[0] if len(path_parts) > 1 else None
        dev_path  = "/" + (path_parts[1] if len(path_parts) > 1 else "")
        params    = parse_qsl(parsed.query)

        dev = (self.server.device_by_serial.get(serial)
               if serial else self.server.default_device)
        if dev is None:
            self.send_error(503,
                f"No MOTU device for serial {serial!r}. "
                f"Available: {list(self.server.device_by_serial)}")
            return

        # Filter out hop-by-hop and proxy-injected headers
        _SKIP = {"host", "connection", "proxy-connection",
                 "keep-alive", "transfer-encoding", "te", "trailer", "upgrade"}
        headers = [(k, v) for k, v in self.headers.items()
                   if k.lower() not in _SKIP]

        qs_str = "?" + "&".join(f"{k}={v}" for k, v in params) if params else ""
        logger.info("[%s] → %s %s%s", dev.serial, self.command, dev_path, qs_str)

        try:
            status, resp_headers, resp_body = dev.send_ptth(
                self.command, dev_path, headers, params, body)
        except TimeoutError as exc:
            logger.warning("[%s] Timeout: %s", dev.serial, exc)
            self.send_error(504, "Device timeout")
            return
        except Exception as exc:
            logger.error("[%s] USB error: %s", dev.serial, exc)
            self.send_error(502, f"USB error: {exc}")
            return

        self._forward_response(status, resp_headers, resp_body)

    def _forward_response(self, status: int,
                          headers: "list[tuple[str,str]]",
                          body: bytes) -> None:
        """Write a decoded device response back to the HTTP client."""
        _STATUS_TEXT = {
            200: "OK", 201: "Created", 204: "No Content",
            304: "Not Modified", 400: "Bad Request",
            404: "Not Found", 500: "Internal Server Error",
        }
        self.send_response(status, _STATUS_TEXT.get(status, "Unknown"))
        _SKIP = {"server", "transfer-encoding", "connection",
                 "content-length", "content-encoding"}
        for k, v in headers:
            if k.lower() not in _SKIP:
                self.send_header(k, v)
        self.send_header("Server", "motu-proxy/0.1")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):
        self._proxy()

    def do_DELETE(self):
        self._proxy()

    def do_OPTIONS(self):
        self._proxy()

    def _read_body(self) -> bytes:
        return self.rfile.read(int(self.headers.get("Content-Length", 0)))

    def do_POST(self):
        self._proxy(self._read_body())

    def do_PATCH(self):
        self._proxy(self._read_body())

    def do_PUT(self):
        self._proxy(self._read_body())


class MotuProxyServer(HTTPServer):
    def __init__(self, addr, devices: list[MotuDevice]):
        super().__init__(addr, MotuProxyHandler)
        self.device_by_serial: dict[str, MotuDevice] = {d.serial: d for d in devices}
        self.default_device = devices[0] if devices else None


# ─── Device discovery ─────────────────────────────────────────────────────────
def find_motu_devices() -> list[tuple[usb.core.Device, str]]:
    """Return [(usb_dev, serial_str)] for all MOTU VID/PID devices."""
    found = []
    for dev in usb.core.find(idVendor=MOTU_VID, idProduct=MOTU_PID, find_all=True) or []:
        try:
            serial = usb.util.get_string(dev, dev.iSerialNumber)
        except Exception:
            serial = f"{dev.bus:03d}-{dev.address:03d}"
        found.append((dev, serial))
    return found


# ─── Main ─────────────────────────────────────────────────────────────────────
def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1].strip())
    ap.add_argument("--port",    type=int, default=1280,
                    help="TCP port to listen on (default: 1280)")
    ap.add_argument("--host",    default="127.0.0.1",
                    help="Bind address (default: 127.0.0.1)")
    ap.add_argument("--no-nrek", action="store_true",
                    help="Disable NREK keepalives (use if device misbehaves)")
    ap.add_argument("--verbose", "-v", action="store_true",
                    help="Enable debug logging")
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s",
    )

    devs = find_motu_devices()
    if not devs:
        logger.error("No MOTU devices found (VID=%04x PID=%04x). "
                     "Is the device plugged in?", MOTU_VID, MOTU_PID)
        sys.exit(1)

    motu_devs = []
    for usb_dev, serial in devs:
        logger.info("Found MOTU device  serial=%s  bus=%d addr=%d",
                    serial, usb_dev.bus, usb_dev.address)
        md = MotuDevice(usb_dev, serial,
                        enable_nrek=not args.no_nrek,
                        verbose=args.verbose)
        try:
            md.start()
        except Exception as exc:
            logger.error("Failed to start device %s: %s", serial, exc)
            continue
        motu_devs.append(md)

    if not motu_devs:
        logger.error("Could not start any MOTU device. Run as root?")
        sys.exit(1)

    server = MotuProxyServer((args.host, args.port), motu_devs)
    logger.info("Proxy listening on http://%s:%d/", args.host, args.port)
    for md in motu_devs:
        logger.info("  http://%s:%d/%s/datastore", args.host, args.port, md.serial)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down…")
    finally:
        server.server_close()
        for md in motu_devs:
            md.stop()


if __name__ == "__main__":
    main()
