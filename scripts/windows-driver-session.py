#!/usr/bin/env python3
"""
windows-driver-session.py — Emulate the MOTU Windows driver over USB bulk.

Implements the exact session lifecycle captured from usbmon when the official
Windows driver connects:

  1.  CONNECT  (4 bytes: seq 0x82 0x04 0x00)
  2.  PING / PONG verify device is alive
  3.  PTTH POST /datastore/host/os  {"value":"win"}  — announce Windows OS
  4.  NREK GET /datastore  If-None-Match: 0          — initial long-poll
  5.  Background PING thread (every ~2 s)
  6.  NREK long-poll loop — reassemble multi-chunk 4 KB responses, track ETag
  7.  PTTH PATCH /datastore/<key>  {"value":...}      — change any setting

Protocol facts confirmed from usbmon capture of Windows driver:
  - CONNECT and PING are BOTH 4-byte frames (NOT 8 bytes)
  - seq counter is 8-bit wrapping, shared across all frame types
  - session_id bytes [8:12] is a CRC32 checksum over frame[12:] — NOT a random
    nonce. MOTUAVBController (HTTPProxyIO.cpp:120) rejects frames with wrong CRC.
  - payload_len bytes [22:24] = len(payload)+8, counting UTOM+inner_hdr+payload
  - PTTH and NREK maintain separate msg_seq counters (start at 1, increment)
  - Device PONGs copy the host's seq byte in bytes 0 and 4
  - Large datastore responses arrive as multiple 4096-byte NREK IN frames,
    each with its own random session_id, incrementing chunk_idx, same msg_seq
  - 304 Not Modified responses are short single frames (< 512 bytes)
  - Auth header: "Unsecure-Auth-MOTU: unicorn666"
  - NREK does NOT include the auth header (only If-None-Match)

Usage:
    sudo python3 scripts/windows-driver-session.py
    sudo python3 scripts/windows-driver-session.py --save captures/my-session.jsonl
    sudo python3 scripts/windows-driver-session.py --patch ext/ibank/2/ch/0/trim 5
    sudo python3 scripts/windows-driver-session.py --patch mix/chan/0/matrix/mute 1
    sudo python3 scripts/windows-driver-session.py --no-long-poll  # connect only
"""

import argparse
import json
import os
import queue
import struct
import sys
import threading
import time
import zlib
from pathlib import Path

try:
    import usb.core
    import usb.util
except ImportError:
    print("ERROR: pip install pyusb")
    sys.exit(1)


# ─── Constants ────────────────────────────────────────────────────────────────

MOTU_VID        = 0x07fd
MOTU_PID        = 0x0005   # 828ES (also try without PID filter for other MOTU)
VENDOR_IF       = 5        # Interface 5, class=FF/04/01
EP_OUT          = 0x04     # EP4 OUT
EP_IN           = 0x83     # EP3 IN  (0x80 | 3)
TIMEOUT_MS      = 5000
PING_INTERVAL_S = 2.0      # how often to ping (seconds)
# ControllerHostCommandHost::Send asserts cmd->fLength <= 4072 (0xfe8).
# Device sends full continuation chunks at exactly payload_len=4072; last chunk
# is smaller.  is_last_chunk() detects the last chunk with `payload_len < this`.
NREK_CHUNK_MAX  = 0xfe8     # 4072 — max device→host fLength (Ghidra: assert 0xfe8 < fLength)

AUTH_HEADER     = "Unsecure-Auth-MOTU"
AUTH_TOKEN      = "unicorn666"

FOURCC_PTTH     = b"PTTH"
FOURCC_NREK     = b"NREK"

# ─── Colour helpers ───────────────────────────────────────────────────────────
RED = "\033[0;31m"; GRN = "\033[0;32m"; YLW = "\033[1;33m"
CYN = "\033[0;36m"; MAG = "\033[0;35m"; BLD = "\033[1m"; RST = "\033[0m"

def _info(m):  print(f"{CYN}[INFO]{RST}  {m}", flush=True)
def _ok(m):    print(f"{GRN}[OK]{RST}    {m}", flush=True)
def _warn(m):  print(f"{YLW}[WARN]{RST}  {m}", flush=True)
def _err(m):   print(f"{RED}[ERR]{RST}   {m}", flush=True)


# ─── Binary request/response codec ───────────────────────────────────────────

def _u32(data: bytes, offset: int = 0) -> int:
    return struct.unpack_from("<I", data, offset)[0]

def _field(s: str | bytes) -> bytes:
    """Encode a length-prefixed field: u32(len) + bytes."""
    b = s.encode() if isinstance(s, str) else s
    return struct.pack("<I", len(b)) + b


def encode_request(
    method: str,
    path: str,
    headers: list[tuple[str, str]] | None = None,
    params:  list[tuple[str, str]] | None = None,
    body:    str | bytes | None           = None,
    content_type: str                     = "json",
) -> bytes:
    """
    Encode an HTTP-style request into the MOTU binary format.

    Wire layout (all u32 little-endian):
      u32 version=1 | u32 flags=0 | u32 N          ← preamble
      u32 method_len + method                        ─┐
      u32 path_len   + path                           │ N bytes
      u32 num_headers; (name + val) × n               │
      u32 num_params;  (name + val) × n              ─┘
      u32 body_struct_len; u32 ct_len + ct; u32 body_len + body  ← body section
    """
    if headers is None:
        headers = [(AUTH_HEADER, AUTH_TOKEN)]
    if params is None:
        params = []

    inner = (_field(method) + _field(path)
             + struct.pack("<I", len(headers))
             + b"".join(_field(k) + _field(v) for k, v in headers)
             + struct.pack("<I", len(params))
             + b"".join(_field(k) + _field(v) for k, v in params))

    preamble = struct.pack("<III", 1, 0, len(inner))

    if body is not None:
        body_b   = body.encode() if isinstance(body, str) else body
        ct_b     = content_type.encode()
        struct_b = _field(ct_b) + _field(body_b)
        body_sec = struct.pack("<I", len(struct_b)) + struct_b
    else:
        body_sec = b""

    return preamble + inner + body_sec


def decode_response(payload: bytes) -> dict | None:
    """
    Decode a MOTU binary response payload (everything after the 32-byte frame header).

    Wire layout:
      u32 version=1 | u32 flags=0 | u32 N   ← preamble (N = status+headers size only)
      u32 status_code | u32 num_headers
      (name + val) × num_headers
      [body bytes start at offset 12+N]
    """
    if len(payload) < 20:
        return None
    try:
        N      = _u32(payload, 8)
        status = _u32(payload, 12)
        n_hdrs = _u32(payload, 16)
        off    = 20
        headers: list[tuple[str, str]] = []
        for _ in range(n_hdrs):
            nl   = _u32(payload, off); off += 4
            name = payload[off:off+nl].decode(errors="replace"); off += nl
            vl   = _u32(payload, off); off += 4
            val  = payload[off:off+vl].decode(errors="replace"); off += vl
            headers.append((name, val))
        body = payload[12 + N:]
        etag = next((v for k, v in headers if k.lower() == "etag"), None)
        return {"status": status, "headers": headers, "body": body, "etag": etag}
    except Exception as e:
        return {"error": str(e), "raw_hex": payload.hex()[:128]}


# ─── Frame builders ───────────────────────────────────────────────────────────

def build_connect(seq: int) -> bytes:
    """4-byte CONNECT frame.  Windows driver sends [seq, 0x82, 0x04, 0x00]."""
    return struct.pack("<BBH", seq & 0xFF, 0x82, 4)


def build_ping(seq: int) -> bytes:
    """4-byte PING frame.  Windows driver sends [seq, 0x81, 0x04, 0x00]."""
    return struct.pack("<BBH", seq & 0xFF, 0x81, 4)


def build_data_frame(
    seq:     int,
    fourcc:  bytes,
    msg_seq: int,
    payload: bytes,
) -> bytes:
    """
    Build a PTTH or NREK request frame.

    Outer + inner header (32 bytes total):
      [0]     seq         u8
      [1]     flags       u8   = 0x80 (host→device data)
      [2:4]   total_len   u16  = 32 + len(payload)
      [4:8]   fourcc      4B   = b"PTTH" or b"NREK" (literal ASCII)
      [8:12]  checksum    u32  = CRC32(frame[24:])  — NOT a random nonce!
                                 Verified by MOTUAVBController HTTPProxyIO.cpp.
                                 Algorithm: standard CRC-32b (zlib), init=0xFFFFFFFF,
                                 computed over frame[24:total_len] (UTOM→end of payload).
      [12:16] msg_seq     u32
      [16:20] direction   u32  = 1 (OUT / request)
      [20:22] chunk_idx   u16  = 0
      [22:24] payload_len u16  = len(payload) + 8  (UTOM + inner_hdr + payload)
      [24:28] motu_magic  4B   = b"UTOM"
      [28:32] inner_hdr   u32  = 8

    The session_id / checksum field is verified by MOTUAVBController
    (HTTPProxyIO.cpp HandleCommand).  It is CRC32 of every byte from
    msg_seq [12] to the end of the frame.  Frames with a wrong checksum
    are logged as 'Wrong checksum!' and silently dropped.

    payload_len counts UTOM(4) + inner_hdr(4) + actual payload bytes,
    i.e. len(payload)+8.  Confirmed from Windows driver usbmon captures.
    """
    assert len(fourcc) == 4, "fourcc must be exactly 4 bytes"
    total    = 32 + len(payload)
    pl_field = len(payload) + 8   # UTOM(4) + inner_hdr(4) + payload

    # Build full frame with session_id=0 as placeholder
    frame = bytearray(
        struct.pack("<BB",  seq & 0xFF, 0x80) +
        struct.pack("<H",   total) +
        fourcc +
        struct.pack("<I",   0) +           # [8:12] placeholder
        struct.pack("<I",   msg_seq) +
        struct.pack("<I",   1) +           # direction = OUT
        struct.pack("<H",   0) +           # chunk_idx = 0
        struct.pack("<H",   pl_field) +    # payload_len = len(payload)+8
        b"UTOM" +
        struct.pack("<I",   8) +           # inner_hdr constant
        payload
    )
    assert len(frame) == total

    # CRC-32b (IEEE 802.3 / zlib) over frame[24:] — bytes from UTOM to end of payload.
    #
    # Confirmed from Ghidra decompilation of FUN_0003970c (HTTPProxyIO.cpp):
    #   pbVar2 = param_1 + 0x14;   // param_1 points to wire[4], so this is wire[24]
    #   pbVar7 = pbVar2 + *(ushort*)(param_1 + 0x12);  // + payload_len_field
    # Loop: standard reflected CRC-32, polynomial 0x04C11DB7, init=0xFFFFFFFF,
    #       finalXOR=0xFFFFFFFF (the ~uVar12 at the end) — identical to zlib.crc32().
    #
    # payload_len_field = len(payload)+8, so the range is frame[24 : 24+len(payload)+8]
    # = frame[24 : total_len] = frame[24:].  NOT frame[12:].
    checksum = zlib.crc32(bytes(frame[24:])) & 0xFFFFFFFF
    struct.pack_into("<I", frame, 8, checksum)
    return bytes(frame)


# ─── USB write wrapper ───────────────────────────────────────────────────────

class UsbWriter:
    """Thread-safe EP_OUT writer.  All reads are owned by FrameReader."""

    def __init__(self, dev: "usb.core.Device"):
        self._dev  = dev
        self._lock = threading.Lock()

    def write(self, data: bytes) -> int:
        with self._lock:
            return self._dev.write(EP_OUT, data, timeout=TIMEOUT_MS)


# ─── Frame reassembler / dispatcher ──────────────────────────────────────────

class FrameReader(threading.Thread):
    """
    Background thread that exclusively owns EP_IN.

    Reads raw 512-byte USB bulk packets, accumulates them into complete logical
    frames by inspecting the outer total_len field, then dispatches each complete
    frame to the appropriate queue:

      pong_queue  — 8-byte PONG frames
      nrek_queue  — complete NREK IN frames  (frame_len may be 4096, ~8 packets)
      ptth_queue  — complete PTTH IN frames
      misc_queue  — anything else

    This eliminates all races between the PING keepalive thread and NREK readers:
    nobody except FrameReader ever calls dev.read().
    """

    USB_PACKET = 512   # wMaxPacketSize for HS bulk

    def __init__(self, dev: "usb.core.Device"):
        super().__init__(daemon=True, name="frame-reader")
        self._dev        = dev
        self._stop       = threading.Event()
        self._buf        = bytearray()
        self.pong_queue  = queue.Queue()
        self.nrek_queue  = queue.Queue()
        self.ptth_queue  = queue.Queue()
        self.misc_queue  = queue.Queue()

    def run(self) -> None:
        while not self._stop.is_set():
            try:
                raw = bytes(self._dev.read(EP_IN, self.USB_PACKET, timeout=3000))
                print(f"  {CYN}[FR]{RST} read {len(raw)}B  "
                      f"buf_before={len(self._buf)}  "
                      f"prefix={raw[:8].hex()}", flush=True)
                self._buf += raw
                self._dispatch()
            except usb.core.USBTimeoutError:
                continue
            except usb.core.USBError as e:
                if not self._stop.is_set():
                    _warn(f"FrameReader USB error: {e}")
                break

    def _dispatch(self) -> None:
        """Parse and dispatch all complete frames sitting in self._buf."""
        while True:
            if len(self._buf) < 4:
                return
            total_len = struct.unpack_from("<H", self._buf, 2)[0]
            if total_len < 4:
                # Corrupt or unknown — drop one byte and retry
                _warn(f"FrameReader: bogus total_len={total_len}, "
                      f"buf_prefix={bytes(self._buf[:8]).hex()}, dropping 1 byte")
                del self._buf[0]
                continue
            if len(self._buf) < total_len:
                print(f"  {CYN}[FR]{RST} accumulating: need {total_len}B "
                      f"have {len(self._buf)}B", flush=True)
                return   # not enough bytes yet — wait for more USB packets
            frame = bytes(self._buf[:total_len])
            del self._buf[:total_len]
            self._route(frame)

    def _route(self, frame: bytes) -> None:
        if len(frame) < 4:
            return
        flags     = frame[1]
        total_len = struct.unpack_from("<H", frame, 2)[0]
        fourcc    = frame[4:8] if len(frame) >= 8 else b""
        print(f"  {CYN}[FR]{RST} route: len={len(frame)}  "
              f"flags=0x{flags:02x}  total_len={total_len}  "
              f"fourcc={fourcc!r}  "
              f"→ ", end="", flush=True)
        # PONG: 8-byte device→host frame
        if total_len == 8 and flags == 0x00:
            print("pong_queue", flush=True)
            self.pong_queue.put(frame)
            return
        # Data frame: route by fourcc at [4:8]
        if len(frame) >= 8 and flags == 0x00:
            if fourcc == FOURCC_NREK:
                print("nrek_queue", flush=True)
                self.nrek_queue.put(frame)
            elif fourcc == FOURCC_PTTH:
                print("ptth_queue", flush=True)
                self.ptth_queue.put(frame)
            else:
                print(f"misc_queue (unknown fourcc)", flush=True)
                self.misc_queue.put(frame)
            return
        print(f"misc_queue (flags=0x{flags:02x})", flush=True)
        self.misc_queue.put(frame)

    def stop(self) -> None:
        self._stop.set()


# ─── Incoming frame parser ────────────────────────────────────────────────────

class IncomingFrame:
    """
    Parse a complete logical frame delivered by FrameReader.

    Device→host wire layout (confirmed from ControllerHostCommandHost::Send Ghidra):
      [0]       seq         u8   — device's own 6-bit counter | 0x40 for data frames;
                                   always 0x00 for PONG.  NOT an echo of host seq.
      [1]       flags       u8   — 0x00 for all device→host frames
      [2:4]     total_len   u16  — includes the 4-byte footer
      [4:32]    inner hdr   —     fourcc, checksum, msg_seq, direction, chunk_idx, payload_len,
                                   UTOM, inner_hdr_const (same layout as host→device)
      [32:TL-4] payload     —     actual HTTP response bytes
      [TL-4:TL] footer      4B   — repeat of frame[0:4]; appended by Send: memcpy(buf+4+n, buf, 4)
    """
    __slots__ = ("raw", "seq", "flags", "frame_len", "fourcc",
                 "session_id", "msg_seq", "chunk_idx", "payload_len",
                 "payload")

    def __init__(self, raw: bytes):
        self.raw = raw
        if len(raw) < 4:
            self.flags = 0xFF; return
        self.seq       = raw[0]
        self.flags     = raw[1]
        self.frame_len = struct.unpack_from("<H", raw, 2)[0]
        if len(raw) >= 32 and self.flags == 0x00 and self.frame_len > 8:
            self.fourcc      = raw[4:8]
            self.session_id  = struct.unpack_from("<I", raw,  8)[0]
            self.msg_seq     = struct.unpack_from("<I", raw, 12)[0]
            self.chunk_idx   = struct.unpack_from("<H", raw, 20)[0]
            self.payload_len = struct.unpack_from("<H", raw, 22)[0]
            # IN frames have a 4-byte footer (outer header copy) at total_len-4
            end          = self.frame_len - 4
            self.payload = raw[32:end] if end > 32 else b""
        else:
            self.fourcc = b""; self.session_id = 0; self.msg_seq = 0
            self.chunk_idx = 0; self.payload_len = 0; self.payload = b""

    def is_pong(self) -> bool:
        return self.frame_len == 8 and self.flags == 0x00

    def is_nrek(self) -> bool:
        return self.fourcc == FOURCC_NREK

    def is_ptth(self) -> bool:
        return self.fourcc == FOURCC_PTTH

    def is_last_chunk(self) -> bool:
        """True when this is the final NREK chunk in a multi-chunk response.

        The device sends intermediate chunks with payload_len == NREK_CHUNK_MAX (4072).
        The last chunk (or a single-chunk 304) has payload_len < NREK_CHUNK_MAX.
        """
        return self.payload_len < NREK_CHUNK_MAX


# ─── MotuSession ─────────────────────────────────────────────────────────────

class MotuSession:
    """
    Full lifecycle management for a MOTU Windows-driver-compatible USB session.

    Thread model:
      - FrameReader daemon thread — owns ALL EP_IN reads, routes frames to queues
      - _ping_loop() daemon thread — sends PING every PING_INTERVAL_S seconds
      - Main thread — sends NREK, reads from nrek_queue; sends PTTH, reads ptth_queue

    No two threads ever call dev.read() simultaneously; FrameReader is the sole owner.
    """

    def __init__(self, dev: "usb.core.Device", save_path: str | None = None):
        self._writer    = UsbWriter(dev)
        self._reader    = FrameReader(dev)
        self._seq       = 0x22        # Windows driver starts at 0x22
        self._seq_lock  = threading.Lock()
        self._ptth_seq  = 1
        self._nrek_seq  = 1
        self._etag      = "0"
        self._stop      = threading.Event()
        self._pkts: list[dict] = []
        self._save_path = save_path
        self._reader.start()

    # ── Seq counter ───────────────────────────────────────────────────────────

    def _next_seq(self) -> int:
        with self._seq_lock:
            s = self._seq & 0xFF
            self._seq = (self._seq + 1) & 0xFF
            return s

    # ── Packet logging ────────────────────────────────────────────────────────

    def _log(self, direction: str, data: bytes, label: str = ""):
        self._pkts.append({
            "direction": direction,
            "data_hex":  data.hex(),
            "length":    len(data),
            "label":     label,
            "ts":        time.time(),
        })

    # ── Write helpers ─────────────────────────────────────────────────────────

    def _send(self, data: bytes, label: str = ""):
        col = CYN if label.startswith("PING") else MAG
        print(f"  {col}→ OUT{RST} {label:30s} {len(data):4d}B  "
              f"{data.hex()[:32]}", flush=True)
        self._log("OUT", data, label)
        self._writer.write(data)

    # ── Queue helpers ─────────────────────────────────────────────────────────

    def _get_pong(self, timeout: float = 5.0) -> bytes | None:
        """Block until a PONG arrives in the queue or timeout elapses."""
        try:
            raw = self._reader.pong_queue.get(timeout=timeout)
            self._log("IN", raw, "PONG")
            return raw
        except queue.Empty:
            return None

    def _get_nrek(self, timeout: float = 30.0) -> bytes | None:
        """Block until a complete NREK frame arrives or timeout elapses."""
        try:
            raw = self._reader.nrek_queue.get(timeout=timeout)
            self._log("IN", raw, "NREK")
            return raw
        except queue.Empty:
            return None

    def _get_ptth(self, timeout: float = 5.0) -> bytes | None:
        """Block until a PTTH response frame arrives or timeout elapses."""
        try:
            raw = self._reader.ptth_queue.get(timeout=timeout)
            self._log("IN", raw, "PTTH-resp")
            return raw
        except queue.Empty:
            return None

    def _expect_pong(self, label: str = "") -> bool:
        """Wait for a PONG after sending a frame.  Also accepts a PTTH response."""
        raw = self._get_pong(timeout=5.0)
        if raw:
            f = IncomingFrame(raw)
            print(f"  {GRN}← PONG{RST}  seq=0x{f.seq:02x}  [{label}]", flush=True)
            return True
        # PONG queue empty — check if a PTTH response arrived instead (e.g. POST 200)
        try:
            raw = self._reader.ptth_queue.get_nowait()
            self._log("IN", raw, "PTTH-resp")
            f = IncomingFrame(raw)
            decoded = decode_response(f.payload)
            status = decoded.get("status", "?") if decoded else "?"
            print(f"  {GRN}← PTTH response{RST}  status={status}  [{label}]", flush=True)
            return True
        except queue.Empty:
            pass
        _warn(f"No PONG received ({label})")
        return False

    # ── Session lifecycle ─────────────────────────────────────────────────────

    def connect(self):
        """Send CONNECT (4 bytes) and wait for PONG."""
        seq = self._next_seq()
        self._send(build_connect(seq), "CONNECT")
        self._expect_pong("CONNECT")

    def ping(self) -> bool:
        """Send PING (4 bytes) and wait for PONG via queue."""
        seq = self._next_seq()
        frame = build_ping(seq)
        print(f"  {CYN}→ PING{RST}  seq=0x{seq:02x}", flush=True)
        self._log("OUT", frame, "PING")
        self._writer.write(frame)
        raw = self._get_pong(timeout=3.0)
        if raw is None:
            _warn("PING timeout")
            return False
        f = IncomingFrame(raw)
        print(f"  {CYN}← PONG{RST}  seq=0x{f.seq:02x}", flush=True)
        return True

    def announce_windows(self):
        """PTTH POST /datastore/host/os {"value":"win"} — unlocks tamio context."""
        payload = encode_request(
            "POST", "/datastore/host/os",
            headers=[(AUTH_HEADER, AUTH_TOKEN)],
            body='{"value": "win"}',
            content_type="json",
        )
        seq = self._next_seq()
        frame = build_data_frame(seq, FOURCC_PTTH, self._ptth_seq, payload)
        self._ptth_seq += 1
        self._send(frame, "PTTH POST /datastore/host/os")
        self._expect_pong("POST /host/os")

    # ── NREK (long-poll) ──────────────────────────────────────────────────────

    def _build_nrek(self, etag: str) -> bytes:
        # Windows driver sends NREK with ONLY If-None-Match — no auth header.
        payload = encode_request(
            "GET", "/datastore",
            headers=[("If-None-Match", etag)],
        )
        seq = self._next_seq()
        frame = build_data_frame(seq, FOURCC_NREK, self._nrek_seq, payload)
        self._nrek_seq += 1
        return frame

    def send_nrek(self, etag: str | None = None) -> None:
        tag = etag if etag is not None else self._etag
        frame = self._build_nrek(tag)
        self._send(frame, f"NREK GET /datastore (etag={tag!r})")

    def read_nrek_response(self) -> dict | None:
        """
        Read one complete NREK response from nrek_queue.

        FrameReader delivers each logical NREK frame as a complete reassembled
        bytes object (accumulating multiple 512-byte USB packets before queuing).
        Large datastore responses arrive as multiple NREK frames with incrementing
        chunk_idx; we accumulate them until is_last_chunk() is True.
        """
        chunks: dict[int, bytes] = {}
        deadline = time.monotonic() + 30.0

        while time.monotonic() < deadline and not self._stop.is_set():
            remaining_s = deadline - time.monotonic()
            raw = self._get_nrek(timeout=max(remaining_s, 0))
            if raw is None:
                _warn("NREK read timeout")
                break

            f = IncomingFrame(raw)
            idx = f.chunk_idx
            print(f"  {GRN}← NREK{RST}  chunk={idx}  "
                  f"payload_len={f.payload_len}  frame_len={f.frame_len}",
                  flush=True)
            chunks[idx] = f.payload

            if f.is_last_chunk():
                full_payload = b"".join(chunks[i] for i in sorted(chunks))
                decoded = decode_response(full_payload)
                if decoded is None:
                    _warn(f"Failed to decode NREK response ({len(full_payload)} bytes)")
                    return None
                status = decoded.get("status", 0)
                body   = decoded.get("body", b"")
                etag   = decoded.get("etag")
                col    = GRN if status < 300 else YLW
                print(f"  {col}← {status}{RST}  body={len(body)}B  etag={etag!r}",
                      flush=True)
                if etag and etag != self._etag:
                    _info(f"ETag updated: {self._etag!r} → {etag!r}")
                    self._etag = etag
                if body:
                    print(f"    {body[:200].decode('utf-8', errors='replace')!r}",
                          flush=True)
                return decoded

        _warn("read_nrek_response: no complete response received")
        return None

    # ── PTTH (one-shot requests: PATCH, POST, GET) ────────────────────────────

    def ptth_request(
        self,
        method: str,
        path: str,
        body: str | None = None,
        content_type: str = "json",
        params: list[tuple[str, str]] | None = None,
    ) -> dict | None:
        """Send a PTTH request and read the PTTH response from ptth_queue."""
        payload = encode_request(
            method, path,
            headers=[(AUTH_HEADER, AUTH_TOKEN)],
            params=params or [],
            body=body,
            content_type=content_type,
        )
        seq = self._next_seq()
        frame = build_data_frame(seq, FOURCC_PTTH, self._ptth_seq, payload)
        self._ptth_seq += 1
        self._send(frame, f"PTTH {method} {path}")

        # Drain one PONG if it arrives before the response
        try:
            pong = self._reader.pong_queue.get(timeout=0.5)
            self._log("IN", pong, "PTTH-ack")
            f_pong = IncomingFrame(pong)
            print(f"  {GRN}← PTTH ACK{RST}  seq=0x{f_pong.seq:02x}", flush=True)
        except queue.Empty:
            pass

        raw = self._get_ptth(timeout=5.0)
        if raw is None:
            _warn(f"No PTTH response for {method} {path}")
            return None
        f = IncomingFrame(raw)
        decoded = decode_response(f.payload)
        if decoded:
            col = GRN if decoded.get("status", 0) < 300 else YLW
            print(f"  {col}← {decoded.get('status')}{RST}  "
                  f"{decoded.get('headers', [])}", flush=True)
        return decoded

    def patch(self, key: str, value) -> dict | None:
        """PATCH /datastore/<key>  {"value": <value>}"""
        body = json.dumps({"value": value})
        return self.ptth_request("PATCH", f"/datastore/{key}",
                                 body=body, content_type="json")

    def post(self, path: str, body: str) -> dict | None:
        return self.ptth_request("POST", path, body=body, content_type="json")

    def get(self, path: str) -> dict | None:
        return self.ptth_request("GET", path)

    # ── Background PING thread ────────────────────────────────────────────────

    def _ping_loop(self):
        while not self._stop.is_set():
            self._stop.wait(PING_INTERVAL_S)
            if self._stop.is_set():
                break
            try:
                self.ping()
            except Exception as e:
                _warn(f"PING error: {e}")

    def start_ping_thread(self) -> threading.Thread:
        t = threading.Thread(target=self._ping_loop, daemon=True, name="ping")
        t.start()
        return t

    # ── High-level long-poll loop ─────────────────────────────────────────────

    def nrek_loop(self):
        print(f"\n{BLD}NREK long-poll running (Ctrl+C to stop)…{RST}", flush=True)
        while not self._stop.is_set():
            try:
                self.send_nrek()
                self.read_nrek_response()
            except usb.core.USBError as e:
                _err(f"USB error in NREK loop: {e}")
                time.sleep(1.0)

    # ── Full Windows driver init sequence ─────────────────────────────────────

    def init(self, do_nrek: bool = True):
        """
        CONNECT → POST /datastore/host/os → [initial NREK]

        CONNECT + POST alone unlocks tamio's command context.
        Pass do_nrek=False to stop there (--no-long-poll mode).
        """
        print(f"\n{BLD}══ MOTU Windows driver session ══{RST}", flush=True)

        print(f"\n{BLD}[1/2] CONNECT{RST}")
        self.connect()
        time.sleep(0.05)

        print(f"\n{BLD}[2/2] Announce OS = win{RST}")
        self.announce_windows()
        time.sleep(0.05)

        if not do_nrek:
            _ok("Context established (CONNECT + POST done, NREK skipped)")
            return

        print(f"\n{BLD}[+] Initial NREK (ETag=0){RST}")
        self.send_nrek("0")
        resp = self.read_nrek_response()
        if resp and resp.get("status") == 200:
            _ok(f"Initial datastore received — "
                f"{len(resp.get('body', b''))} bytes, ETag={self._etag!r}")
        elif resp:
            _warn(f"Unexpected NREK status: {resp.get('status')}")
        else:
            _warn("No NREK response received")

    # ── Save ─────────────────────────────────────────────────────────────────

    def save(self):
        if not self._save_path:
            return
        p = Path(self._save_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(
            "\n".join(json.dumps({k: v for k, v in pkt.items()})
                       for pkt in self._pkts) + "\n"
        )
        _ok(f"Saved {len(self._pkts)} packets → {p}")

    def stop(self):
        self._stop.set()
        self._reader.stop()


# ─── USB setup ────────────────────────────────────────────────────────────────

def find_and_claim(interface: int) -> "usb.core.Device":
    dev = usb.core.find(idVendor=MOTU_VID)
    if dev is None:
        _err("No MOTU device found (is it plugged in?)")
        sys.exit(1)
    _ok(f"Found: {dev.manufacturer} {dev.product}  "
        f"(bus {dev.bus} dev {dev.address})")

    # Detach every interface that has a kernel driver (snd_usb_audio etc.)
    try:
        cfg = dev.get_active_configuration()
    except usb.core.USBError:
        dev.set_configuration()
        cfg = dev.get_active_configuration()

    for intf in cfg:
        n = intf.bInterfaceNumber
        try:
            if dev.is_kernel_driver_active(n):
                dev.detach_kernel_driver(n)
                _info(f"Detached kernel driver from interface {n}")
        except Exception:
            pass

    usb.util.claim_interface(dev, interface)
    _ok(f"Claimed interface {interface}  EP_OUT=0x{EP_OUT:02x}  EP_IN=0x{EP_IN:02x}")
    return dev


def release(dev: "usb.core.Device", interface: int):
    try:
        usb.util.release_interface(dev, interface)
        dev.attach_kernel_driver(interface)
    except Exception:
        pass


# ─── CLI ─────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="Emulate the MOTU Windows USB driver.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  sudo python3 scripts/windows-driver-session.py --save captures/run1.jsonl\n"
            "  sudo python3 scripts/windows-driver-session.py --patch ext/ibank/2/ch/0/trim 5\n"
            "  sudo python3 scripts/windows-driver-session.py --patch mix/chan/0/matrix/mute 1\n"
            "  sudo python3 scripts/windows-driver-session.py --no-long-poll\n"
        ),
    )
    ap.add_argument("--save",       metavar="FILE",
                    help="Save captured packets to a JSONL file")
    ap.add_argument("--patch",      nargs=2, metavar=("KEY", "VALUE"),
                    help="PATCH one datastore key then run long-poll")
    ap.add_argument("--post",       nargs=2, metavar=("PATH", "JSON_BODY"),
                    help="POST to a path then run long-poll")
    ap.add_argument("--get",        metavar="PATH",
                    help="One-shot PTTH GET then exit")
    ap.add_argument("--no-ping",    action="store_true",
                    help="Disable background PING keepalive")
    ap.add_argument("--no-long-poll", action="store_true",
                    help="Do init sequence then exit without entering NREK loop")
    ap.add_argument("--interface",  type=int, default=VENDOR_IF,
                    help=f"USB interface number (default: {VENDOR_IF})")
    args = ap.parse_args()

    dev = find_and_claim(args.interface)
    session = MotuSession(dev, save_path=args.save)

    try:
        # ── Full Windows driver init ──────────────────────────────────────────
        # For --no-long-poll, skip the initial NREK \u2014 CONNECT + POST alone
        # is enough to establish tamio's command context.
        session.init(do_nrek=not args.no_long_poll)

        if not args.no_ping:
            session.start_ping_thread()
            _info("PING keepalive thread started")

        # ── Optional one-shot actions ─────────────────────────────────────────
        if args.get:
            print(f"\n{BLD}── GET {args.get} ──{RST}")
            resp = session.get(args.get)
            if resp:
                print(json.dumps({
                    "status":  resp.get("status"),
                    "headers": resp.get("headers"),
                    "body":    resp.get("body", b"").decode(errors="replace")[:500],
                }, indent=2))

        if args.patch:
            key, raw_val = args.patch
            try:
                value = json.loads(raw_val)
            except json.JSONDecodeError:
                value = raw_val   # treat as plain string
            print(f"\n{BLD}── PATCH /datastore/{key} = {value!r} ──{RST}")
            session.patch(key, value)

        if args.post:
            path, body = args.post
            print(f"\n{BLD}── POST {path} ──{RST}")
            session.post(path, body)

        # ── Long-poll loop ────────────────────────────────────────────────────
        if not args.no_long_poll and not args.get:
            session.nrek_loop()

    except KeyboardInterrupt:
        print("\nInterrupted.")
    finally:
        session.stop()
        session.save()
        release(dev, args.interface)
        print("Session ended.")


if __name__ == "__main__":
    main()
