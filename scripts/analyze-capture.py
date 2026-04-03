#!/usr/bin/env python3
"""
analyze-capture.py — Decode MOTU USB bulk protocol from a usbmon JSONL capture.

Usage:
    python3 scripts/analyze-capture.py scripts/usbmon-bus7-dev11-828ES-packets.jsonl

Protocol (reverse-engineered from usbmon capture + HAR):

  Outer frame (4 bytes):
    [0]    seq       u8   - sequence counter (OUT: 0x20+, IN: 0x54+)
    [1]    flags     u8   - 0x80 = host→dev data, 0x81 = host→dev ping, 0x00 = dev→host
    [2-3]  total_len u16  - total packet length (little-endian)

  Special short messages:
    CONNECT (OUT, 4 bytes): [seq] 0x82 0x04 0x00  — session open (first packet)
    PING    (OUT, 4 bytes): [seq] 0x81 0x04 0x00
    PONG    (IN,  8 bytes): [seq] 0x00 0x08 0x00  repeated twice

  Data messages (total_len > 8):
    Inner frame (bytes 4–31):
      [4-7]   msg_type    4cc  - b"NREK" (keepalive) or b"PTTH" (HTTP)
      [8-11]  session_id  u32  - random nonce per packet (OUT: stable per session;
                                  IN NREK: unique per 512-byte chunk)
      [12-15] msg_seq     u32  - per-type sequence counter (LE)
      [16-19] direction   u32  - 0x00000001 = OUT (request), 0x00000000 = IN (response)
      [20-21] chunk_idx   u16  - always 0x0000 (OUT and single-URB IN frames)
      [22-23] payload_len u16  - bytes of payload in the FULL logical frame at [32:]
                                  = total_len − 32  (4 outer + 28 inner)
      [24-27] motu_magic  4cc  - b"MOTU" (stored as "UTOM" LE = 0x4D4F5455)
      [28-31] inner_hdr   u32  - always 0x00000008
    Large IN frames (e.g. initial /datastore dump ≥ 4 KiB) are delivered by
    the kernel across multiple 512-byte USB URBs.  Only the FIRST URB of a
    logical frame contains the outer+inner headers.  Subsequent URBs are raw
    body continuation with NO headers — they are NOT independent frames.
    The analyze script reassembles them before decoding.
    Payload format (NOT raw HTTP — compact binary serialization):
      REQUEST (OUT frames, bytes 32…end):
        u32 version=1 | u32 flags=0 | u32 N (size of everything after this preamble)
        u32 method_len + <method>   u32 path_len + <path>
        u32 num_headers  [u32 name_len + <name> + u32 val_len + <val>] × n
        u32 num_params   [u32 name_len + <name> + u32 val_len + <val>] × n
        [body bytes for POST/PATCH]
      RESPONSE (IN frames, bytes 32 … total_len-4):
        u32 version=1 | u32 flags=0 | u32 N (size of status+headers ONLY, NOT body)
        u32 status_code  u32 num_headers
        [u32 name_len + <name> + u32 val_len + <val>] × num_headers
        [body bytes] ← starts at offset 12+N
      IN frames append a 4-byte outer-header copy at total_len-4 as footer;
      payload ends at total_len-4 (not total_len).
      NREK = lightweight long-poll (GET /datastore + If-None-Match only, 0 params)
      PTTH = full browser request (all headers + query params + optional body)
"""

import json
import struct
import sys
from pathlib import Path

# ─── Colours ─────────────────────────────────────────────────────────────────
RED = "\033[0;31m"; GRN = "\033[0;32m"; YLW = "\033[1;33m"
CYN = "\033[0;36m"; MAG = "\033[0;35m"; BLD = "\033[1m"; RST = "\033[0m"

MOTU_MAGIC = b"UTOM"   # "MOTU" stored little-endian as bytes


# ─── Binary payload codec ─────────────────────────────────────────────────────
def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def decode_binary_request(payload: bytes) -> dict | None:
    """Decode binary-encoded PTTH/NREK request payload (bytes 32+ of frame)."""
    if len(payload) < 16:
        return None
    try:
        N = _u32(payload, 8)
        off = 12
        method_len = _u32(payload, off); off += 4
        method = payload[off:off+method_len].decode(); off += method_len
        path_len = _u32(payload, off); off += 4
        path = payload[off:off+path_len].decode(); off += path_len
        num_hdrs = _u32(payload, off); off += 4
        headers = []
        for _ in range(num_hdrs):
            nl = _u32(payload, off); off += 4
            name = payload[off:off+nl].decode(); off += nl
            vl = _u32(payload, off); off += 4
            val = payload[off:off+vl].decode(); off += vl
            headers.append((name, val))
        num_params = _u32(payload, off); off += 4
        params = []
        for _ in range(num_params):
            nl = _u32(payload, off); off += 4
            name = payload[off:off+nl].decode(); off += nl
            vl = _u32(payload, off); off += 4
            val = payload[off:off+vl].decode(); off += vl
            params.append((name, val))
        body = payload[12 + N:] if len(payload) > 12 + N else b""
        return {"method": method, "path": path, "headers": headers,
                "params": params, "body": body}
    except Exception:
        return None


def decode_binary_response(payload: bytes) -> dict | None:
    """Decode binary-encoded PTTH/NREK response payload (bytes 32…total_len-4)."""
    if len(payload) < 20:
        return None
    try:
        N      = _u32(payload,  8)
        status = _u32(payload, 12)
        n_hdrs = _u32(payload, 16)
        off    = 20
        headers = []
        for _ in range(n_hdrs):
            nl   = _u32(payload, off); off += 4
            name = payload[off:off+nl].decode(); off += nl
            vl   = _u32(payload, off); off += 4
            val  = payload[off:off+vl].decode(); off += vl
            headers.append((name, val))
        body = payload[12 + N:]
        return {"status": status, "headers": headers, "body": body}
    except Exception:
        return None


# ─── Packet decoder ───────────────────────────────────────────────────────────
def decode_packet(pkt: dict) -> dict:
    raw = bytes.fromhex(pkt["data_hex"]) if pkt["data_hex"] else b""
    total_len = pkt["length"]
    direction = pkt["direction"]
    result = {
        "direction": direction,
        "total_len": total_len,
        "data_captured": len(raw),
        "truncated": len(raw) < total_len,
        "raw_prefix": raw,
    }

    if len(raw) < 4:
        result["type"] = "UNKNOWN (too short)"
        return result

    seq        = raw[0]
    flags      = raw[1]
    frame_len  = struct.unpack_from("<H", raw, 2)[0]

    result["seq"]       = seq
    result["flags"]     = flags
    result["frame_len"] = frame_len

    # ── CONNECT (session open, flags=0x82) ──
    if total_len == 4 and flags == 0x82:
        result["type"] = "CONNECT"
        return result

    # ── PING ──
    if total_len == 4 and flags == 0x81:
        result["type"] = "PING"
        return result

    # ── PONG ──
    if total_len == 8 and flags == 0x00 and len(raw) >= 8:
        result["type"] = "PONG"
        result["echoed_seq"] = raw[4]
        return result

    # ── Data message ──
    if len(raw) < 32:
        result["type"] = "DATA (inner frame truncated)"
        return result

    msg_type    = raw[4:8]
    session_id  = struct.unpack_from("<I", raw, 8)[0]
    msg_seq     = struct.unpack_from("<I", raw, 12)[0]
    direction_f = struct.unpack_from("<I", raw, 16)[0]  # 1=OUT request, 0=IN response
    chunk_idx   = struct.unpack_from("<H", raw, 20)[0]  # 0 for OUT; increments per 512-byte chunk for IN
    payload_len = struct.unpack_from("<H", raw, 22)[0]
    motu_magic  = raw[24:28]
    inner_hdr   = struct.unpack_from("<I", raw, 28)[0]

    # Device IN frames carry a 4-byte footer (outer header copy) at total_len-4.
    # Payload is raw[32 … total_len-4] for IN frames; raw[32…] for OUT frames.
    is_device_in = (raw[1] == 0x00 and frame_len > 8)
    if is_device_in and frame_len >= 36:
        payload_end = min(frame_len - 4, len(raw))
        payload = raw[32:payload_end] if payload_end > 32 else b""
    else:
        payload = raw[32:]

    result.update({
        "type":        msg_type.decode("ascii", errors="replace"),
        "session_id":  f"0x{session_id:08x}",
        "msg_seq":     msg_seq,
        "chunk_idx":   chunk_idx,
        "payload_len": payload_len,
        "motu_ok":     motu_magic == MOTU_MAGIC,
        "payload":     payload,
    })

    # direction_f: 1 = OUT (request), 0 = IN (response) — not an error if 0
    expected_dir = 0 if direction == "IN" else 1
    if direction_f != expected_dir:
        result["warn_direction"] = f"direction_flag={direction_f:#010x} (expected {expected_dir:#010x} for {direction})"
    if inner_hdr != 8:
        result["warn_inner_hdr"] = f"inner_hdr={inner_hdr:#010x} (expected 0x00000008)"

    # Decode binary payload
    if payload:
        if direction == "OUT":
            req = decode_binary_request(payload)
            if req:
                result["decoded_request"] = req
        else:
            resp = decode_binary_response(payload)
            if resp:
                result["decoded_response"] = resp

    return result


# ─── Formatter ────────────────────────────────────────────────────────────────
def fmt_packet(p: dict, idx: int) -> str:
    dir_col = CYN if p["direction"] == "OUT" else GRN
    dir_str = f"{dir_col}{p['direction']}{RST}"
    trunc = f" {YLW}[TRUNC: have {p['data_captured']}/{p['total_len']} bytes]{RST}" \
            if p.get("truncated") else ""
    ptype = p.get("type", "?")

    lines = [f"  #{idx:>3}  {dir_str}  len={p['total_len']:>4}  {BLD}{ptype}{RST}{trunc}"]

    if "seq" in p:
        lines.append(f"         seq=0x{p['seq']:02x}  flags=0x{p['flags']:02x}"
                     f"  frame_len={p.get('frame_len', '?')}")
    if "session_id" in p:
        motu = f"  {GRN}MOTU✓{RST}" if p.get("motu_ok") else f"  {RED}MOTU✗{RST}"
        chunk = f"  chunk={p['chunk_idx']}" if p.get("chunk_idx", 0) else ""
        lines.append(f"         session={p['session_id']}  msg_seq={p['msg_seq']}{chunk}"
                     f"  payload_len={p['payload_len']}{motu}")
    if "warn_direction" in p:
        lines.append(f"         {YLW}⚠ {p['warn_direction']}{RST}")
    if "decoded_request" in p:
        req = p["decoded_request"]
        qs  = ("?" + "&".join(f"{k}={v}" for k, v in req["params"])
               if req["params"] else "")
        lines.append(f"         {MAG}→ {req['method']} {req['path']}{qs}{RST}")
        for k, v in req["headers"]:
            lines.append(f"             {k}: {v}")
        if req.get("body"):
            lines.append(f"             [body {len(req['body'])} bytes]")
    if "decoded_response" in p:
        resp = p["decoded_response"]
        sc   = resp["status"]
        col  = GRN if sc < 300 else (YLW if sc < 400 else RED)
        lines.append(f"         {col}← {sc}{RST}")
        for k, v in resp["headers"]:
            lines.append(f"             {k}: {v}")
        if resp.get("body"):
            preview = resp["body"][:120].decode("utf-8", errors="replace")
            lines.append(f"             [body {len(resp['body'])} bytes]  {preview!r}")
    if p.get("type") == "PONG":
        lines.append(f"         echoed_seq=0x{p.get('echoed_seq', 0):02x}")

    return "\n".join(lines)


# ─── Session analysis ─────────────────────────────────────────────────────────
def analyse_sessions(decoded: list[dict]) -> None:
    print(f"\n{BLD}══ Session Analysis ══{RST}")

    data_pkts = [p for p in decoded if "session_id" in p]

    # Group by msg_type
    by_type: dict[str, list] = {}
    for p in data_pkts:
        t = p.get("type", "?")
        by_type.setdefault(t, []).append(p)

    for mtype, pkts in sorted(by_type.items()):
        out_p = [p for p in pkts if p["direction"] == "OUT"]
        in_p  = [p for p in pkts if p["direction"] == "IN"]
        sessions = {p["session_id"] for p in pkts}
        seqs_out = sorted({p["msg_seq"] for p in out_p})
        seqs_in  = sorted({p["msg_seq"] for p in in_p})

        print(f"\n  {BLD}{mtype}{RST}:")
        print(f"    OUT packets: {len(out_p)}  IN packets: {len(in_p)}")
        print(f"    Session IDs: {', '.join(sorted(sessions))}")
        print(f"    OUT msg_seq range: {seqs_out[0] if seqs_out else '-'}"
              f" … {seqs_out[-1] if seqs_out else '-'}")
        print(f"    IN  msg_seq range: {seqs_in[0] if seqs_in else '-'}"
              f" … {seqs_in[-1] if seqs_in else '-'}")

        # Check payload_len consistency
        if out_p:
            out_lens = {p["payload_len"] for p in out_p}
            print(f"    OUT payload_len values: {sorted(out_lens)}")
        if in_p:
            in_lens = {p["payload_len"] for p in in_p}
            print(f"    IN  payload_len values: {sorted(in_lens)}")

        # Show decoded HTTP data
        for p in pkts:
            if "decoded_request" in p:
                req = p["decoded_request"]
                qs  = ("?" + "&".join(f"{k}={v}" for k, v in req["params"])
                       if req["params"] else "")
                print(f"\n    OUT {req['method']} {req['path']}{qs}")
                for k, v in req["headers"]:
                    print(f"      {k}: {v}")
            if "decoded_response" in p:
                resp = p["decoded_response"]
                print(f"\n    IN  {resp['status']}")
                for k, v in resp["headers"]:
                    print(f"      {k}: {v}")
                if resp.get("body"):
                    print(f"      Body ({len(resp['body'])} bytes): "
                          f"{resp['body'][:200].decode('utf-8', errors='replace')!r}")

    # Ping/pong/connect stats
    connects = [p for p in decoded if p.get("type") == "CONNECT"]
    pings    = [p for p in decoded if p.get("type") == "PING"]
    pongs    = [p for p in decoded if p.get("type") == "PONG"]
    print(f"\n  CONNECTs: {len(connects)}  PINGs: {len(pings)}  PONGs: {len(pongs)}")


# ─── Multi-URB reassembly ────────────────────────────────────────────────────────────
def reassemble_urbs(pkts: list[dict]) -> list[dict]:
    """
    usbmon captures each 512-byte USB bulk packet as a separate JSONL line.
    Large IN logical frames (total_len > 512) span multiple consecutive lines:
    the first line carries the outer+inner header, subsequent lines carry raw
    body continuation with NO header of their own.

    This function merges those continuation lines into the first-line packet so
    that every returned packet dict represents one complete logical frame.
    """
    result: list[dict] = []
    buf_raw   = b""
    buf_total = 0
    buf_meta: dict | None = None

    for p in pkts:
        raw = bytes.fromhex(p["data_hex"]) if p["data_hex"] else b""

        if not raw:
            # Empty stub — flush any open accumulation (shouldn't happen mid-transfer)
            if buf_meta is not None:
                merged = dict(buf_meta)
                merged["data_hex"] = buf_raw.hex()
                merged["length"]   = len(buf_raw)
                result.append(merged)
                buf_raw = b""; buf_total = 0; buf_meta = None
            result.append(p)
            continue

        if buf_meta is not None:
            # We are accumulating continuation bytes
            buf_raw += raw
            if len(buf_raw) >= buf_total:
                # Complete — emit as a single synthesised packet
                merged = dict(buf_meta)
                merged["data_hex"] = buf_raw[:buf_total].hex()
                merged["length"]   = buf_total
                result.append(merged)
                buf_raw = b""; buf_total = 0; buf_meta = None
            # Continuation bytes consumed; do NOT append p to result
        else:
            # Try to detect the start of a multi-URB IN frame
            if p["direction"] == "IN" and len(raw) >= 4:
                total_len = struct.unpack_from("<H", raw, 2)[0]
                if total_len > len(raw) and total_len < 131072:
                    # Frame declared larger than this URB — start accumulating
                    buf_raw   = raw
                    buf_total = total_len
                    buf_meta  = p
                    continue   # don't append yet
            result.append(p)

    # Flush any incomplete frame at end of capture
    if buf_meta is not None:
        merged = dict(buf_meta)
        merged["data_hex"] = buf_raw.hex()
        merged["length"]   = len(buf_raw)
        merged["truncated"] = True
        result.append(merged)

    return result


# ─── Frame-length discrepancy report ────────────────────────────────────────────────────────────
def report_length_discrepancy(decoded: list[dict]) -> None:
    print(f"\n{BLD}══ Frame-length vs USB-length discrepancy ══{RST}")
    found = False
    for p in decoded:
        if "frame_len" not in p:
            continue
        fl = p.get("frame_len", 0)
        tl = p.get("total_len", 0)
        diff = tl - fl
        if diff == 0:
            continue
        found = True
        note = ""
        if 0 < diff <= 4:
            note = f"  {YLW}(likely USB trailing pad){RST}"
        print(f"  {p['direction']} {p.get('type','?'):4}  "
              f"USB_len={tl}  frame_len_field={fl}  diff={diff}{note}")
    if not found:
        print(f"  {GRN}None — all frames fully reassembled.{RST}")


# ─── Main ─────────────────────────────────────────────────────────────────────
def main() -> None:
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <capture.jsonl> [<capture2.jsonl> ...]")
        sys.exit(1)

    all_pkts: list[dict] = []
    for path in sys.argv[1:]:
        lines = Path(path).read_text().splitlines()
        pkts = [json.loads(l) for l in lines if l.strip()]
        # Drop S-event stubs (empty data, not the completion we care about)
        # Keep: packets that have data_hex OR are the unique-length C events
        # Strategy: drop duplicates where data_hex == "" AND a same-length
        # packet with data already exists
        seen: dict[tuple, bool] = {}
        filtered = []
        for p in pkts:
            key = (p["direction"], p["length"])
            if p["data_hex"]:
                seen[key] = True
                filtered.append(p)
            elif key not in seen:
                filtered.append(p)   # keep lone stubs (pre-allocated URBs)
        all_pkts.extend(filtered)
        print(f"Loaded {len(filtered)} packets from {path}")

    # Reassemble multi-URB logical frames before decoding.
    # usbmon delivers each 512-byte USB packet as a separate JSONL line, but
    # large IN frames span many lines.  Merge them so each entry is one frame.
    before = len([p for p in all_pkts if p["data_hex"]])
    all_pkts = reassemble_urbs(all_pkts)
    after = len([p for p in all_pkts if p["data_hex"]])
    print(f"Reassembled {before} URBs → {after} logical frames "
          f"({before - after} continuation URBs merged)")

    # Decode
    decoded = []
    print(f"\n{BLD}══ Packet-by-packet decode ══{RST}")
    idx = 0
    for raw_pkt in all_pkts:
        if not raw_pkt["data_hex"]:
            continue   # skip stubs with no data
        p = decode_packet(raw_pkt)
        decoded.append(p)
        print(fmt_packet(p, idx))
        idx += 1

    analyse_sessions(decoded)
    report_length_discrepancy(decoded)

    print(f"\n{BLD}══ Capture Limitations ══{RST}")
    truncated = [p for p in decoded if p.get("truncated")]
    print(f"  {len(truncated)}/{len(decoded)} packets truncated (usbmon text cap = 32 bytes)")

if __name__ == "__main__":
    main()
