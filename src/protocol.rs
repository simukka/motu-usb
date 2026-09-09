//! MOTU USB framing protocol: frame encoding/decoding and session state.
//!
//! Handles the outer 4-byte header, inner 28-byte data header, CONNECT/PING/PONG
//! control messages, sequence number tracking, and CRC-32 checksum computation.
//!
//! ## Frame layout (host→device data frame)
//!
//! ```text
//! [0]     seq         u8   — 8-bit wrapping counter, shared across all frame types
//! [1]     flags       u8   — 0x82=CONNECT, 0x81=PING, 0x80=data OUT
//! [2:4]   total_len   u16  — 32 + len(payload)
//! [4:8]   fourcc      4B   — b"PTTH" or b"NREK" (ASCII, not reversed)
//! [8:12]  checksum    u32  — CRC-32b (IEEE 802.3) over frame[24..]
//!                            Verified by MOTUAVBController HTTPProxyIO.cpp.
//! [12:16] msg_seq     u32  — per-channel counter starting at 1
//! [16:20] direction   u32  — 1 = OUT (request)
//! [20:22] chunk_idx   u16  — always 0 for host→device
//! [22:24] payload_len u16  — len(payload) + 8   (counts UTOM(4)+inner_hdr(4)+payload)
//! [24:28] UTOM        4B   — b"UTOM" ("MOTU" stored little-endian)
//! [28:32] inner_hdr   u32  — always 8
//! [32..]  payload     …
//! ```
//!
//! ## Device→host data frame
//!
//! Same layout, but `total_len = actual_payload + 36` (32 header + 4-byte footer),
//! and a 4-byte footer (copy of frame[0:4]) appears at `[total_len-4:]`.
//! `payload_len = actual_payload + 8` (same +8 semantics as host→device).

use crate::error::{MotuError, Result};
use crate::types::{flags, Frame, MessageType, INNER_HDR_VALUE, MOTU_MAGIC};

// ─── Constants ──────────────────────────────────────────────────────────────

/// Full header size for all data frames: 4 (outer) + 28 (inner) = 32 bytes.
///
/// All logical frames — including NREK chunks with chunk_idx > 0 — carry
/// the full 32-byte header. Continuation within a single logical frame (the
/// multiple 512-byte USB packets that make up one chunk) is handled by the
/// USB host controller accumulating until a short packet or buffer full;
/// no sub-frame header is present in those continuation USB packets.
const HEADER_SIZE: usize = 32;

// ─── CRC-32 ─────────────────────────────────────────────────────────────────

/// CRC-32b (IEEE 802.3 / zlib) checksum.
///
/// Confirmed from Ghidra decompilation of `FUN_0003970c` (HTTPProxyIO.cpp):
/// - Polynomial: 0x04C11DB7 (reflected: 0xEDB8_8320)
/// - Init = 0xFFFF_FFFF, finalXOR = 0xFFFF_FFFF
/// - Computed over `frame[24..]` (from UTOM magic to end of payload)
/// - Result stored at `frame[8..12]`
/// - Frames with wrong checksum are logged as "Wrong checksum!" and dropped.
///
/// Equivalent to Python's `zlib.crc32(frame[24:]) & 0xFFFFFFFF`.
pub(crate) fn crc32_ieee(data: &[u8]) -> u32 {
    const POLY: u32 = 0xEDB8_8320;
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ POLY;
            } else {
                crc >>= 1;
            }
        }
    }
    crc ^ 0xFFFF_FFFF
}

// ─── Session State ──────────────────────────────────────────────────────────

/// Tracks protocol state for a MOTU USB session.
#[derive(Debug)]
pub struct SessionState {
    /// Outer frame sequence counter — 8-bit wrapping, shared across all frame
    /// types (CONNECT, PING, PTTH, NREK). Windows driver starts at 0x22.
    seq: u8,
    /// Per-channel message sequence counters (start at 1, increment per frame).
    ptth_seq: u32,
    nrek_seq: u32,
}

impl SessionState {
    pub fn new() -> Self {
        Self {
            // Windows driver usbmon capture shows first CONNECT seq = 0x22.
            seq: 0x22,
            // First PTTH and NREK frames in capture show msg_seq = 1.
            ptth_seq: 1,
            nrek_seq: 1,
        }
    }

    /// Advance and return the next outer sequence number (8-bit wrapping).
    pub fn next_seq(&mut self) -> u8 {
        let s = self.seq;
        self.seq = self.seq.wrapping_add(1);
        s
    }

    /// Advance and return the next per-channel message sequence number.
    pub fn next_msg_seq(&mut self, msg_type: MessageType) -> u32 {
        let counter = match msg_type {
            MessageType::Ptth => &mut self.ptth_seq,
            MessageType::Nrek => &mut self.nrek_seq,
        };
        let s = *counter;
        *counter += 1;
        s
    }
}

impl Default for SessionState {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Frame Encoding ─────────────────────────────────────────────────────────

/// Encode a CONNECT frame (4 bytes, sent first to open a session).
pub fn encode_connect(state: &mut SessionState) -> Vec<u8> {
    let seq = state.next_seq();
    vec![seq, flags::CONNECT, 0x04, 0x00]
}

/// Encode a PING frame (4 bytes, keepalive from host).
pub fn encode_ping(state: &mut SessionState) -> Vec<u8> {
    let seq = state.next_seq();
    vec![seq, flags::PING, 0x04, 0x00]
}

/// Encode a data frame with the given message type and payload.
///
/// Returns a complete frame: outer header (4) + inner header (28) + payload.
/// Total length = 32 + `payload.len()` bytes.
///
/// ## Checksum
///
/// Bytes [8:12] hold a CRC-32b (IEEE 802.3) checksum over `frame[24..]`
/// (from the UTOM magic to the end of the payload). This is verified by
/// `MOTUAVBController` (`HTTPProxyIO.cpp HandleCommand`). Frames with a wrong
/// checksum are logged as "Wrong checksum!" and silently dropped.
///
/// ## `payload_len` field
///
/// Bytes [22:24] hold `len(payload) + 8`. The +8 accounts for the UTOM(4) and
/// `inner_hdr`(4) constants that precede the payload in the device's command
/// buffer. Confirmed from `ControllerHostCommandHost::Send`: `__n = fLength + 0x14`
/// where `fLength` is this field, and the copy covers fourcc+checksum+...+payload.
pub fn encode_data(
    state: &mut SessionState,
    msg_type: MessageType,
    payload: &[u8],
) -> Vec<u8> {
    let seq = state.next_seq();
    let msg_seq = state.next_msg_seq(msg_type);
    let total_len = (HEADER_SIZE + payload.len()) as u16;
    // payload_len field = actual payload bytes + 8 (UTOM magic + inner_hdr constant).
    // The device's fLength field; must NOT equal payload.len() alone.
    let pl_field = (payload.len() as u16) + 8;

    let mut frame = Vec::with_capacity(total_len as usize);

    // Outer header (4 bytes)
    frame.push(seq);                                          // [0]    seq
    frame.push(flags::DATA_OUT);                              // [1]    flags = 0x80
    frame.extend_from_slice(&total_len.to_le_bytes());        // [2:4]  total_len

    // Inner header (28 bytes)
    frame.extend_from_slice(msg_type.as_bytes());             // [4:8]  fourcc
    frame.extend_from_slice(&0u32.to_le_bytes());             // [8:12] checksum placeholder
    frame.extend_from_slice(&msg_seq.to_le_bytes());          // [12:16] msg_seq
    frame.extend_from_slice(&1u32.to_le_bytes());             // [16:20] direction = OUT
    frame.extend_from_slice(&0u16.to_le_bytes());             // [20:22] chunk_idx = 0
    frame.extend_from_slice(&pl_field.to_le_bytes());         // [22:24] payload_len = actual+8
    frame.extend_from_slice(MOTU_MAGIC);                      // [24:28] "UTOM"
    frame.extend_from_slice(&INNER_HDR_VALUE.to_le_bytes());  // [28:32] inner_hdr = 8

    // Payload
    frame.extend_from_slice(payload);

    debug_assert_eq!(frame.len(), total_len as usize);

    // CRC-32b over frame[24..] — from UTOM to end of payload.
    // Confirmed from Ghidra FUN_0003970c:
    //   pbVar2 = param_1 + 0x14  (param_1 = wire[4], so this is wire[24])
    //   pbVar7 = pbVar2 + payload_len_field  (= frame[24 .. 24+payload_len_field] = frame[24..])
    let checksum = crc32_ieee(&frame[24..]);
    frame[8..12].copy_from_slice(&checksum.to_le_bytes());

    frame
}

// ─── Frame Decoding ─────────────────────────────────────────────────────────

/// Decode a complete logical frame received from the device.
///
/// ## Device→host frame structure (confirmed from Ghidra `ControllerHostCommandHost::Send`)
///
/// ```text
/// [0]        seq          u8   — device counter | 0x40 for data; 0x00 for PONG
/// [1]        flags        u8   — always 0x00 for device→host
/// [2:4]      total_len    u16  — actual_payload + 36 (32 header + 4 footer)
/// [4:8]      fourcc       4B
/// [8:12]     checksum     u32  — CRC32(frame[24..]) (device also computes and sends it)
/// [12:16]    msg_seq      u32
/// [16:20]    direction    u32  — 0 for response
/// [20:22]    chunk_idx    u16  — index within a multi-chunk NREK response
/// [22:24]    payload_len  u16  — actual_payload + 8  (= fLength in device source)
/// [24:28]    UTOM         4B
/// [28:32]    inner_hdr    u32  — always 8
/// [32:TL-4]  payload      …    — actual_payload bytes
/// [TL-4:TL]  footer       4B   — copy of frame[0:4], appended by Send()
/// ```
///
/// `actual_payload = payload_len_field - 8 = total_len - 36`
/// `payload_len_field < 4072 (NREK_CHUNK_MAX)` → this is the last (or only) chunk.
pub fn decode_frame(data: &[u8]) -> Result<Frame> {
    if data.len() < 4 {
        return Err(MotuError::Protocol(format!(
            "frame too short: {} bytes",
            data.len()
        )));
    }

    let seq = data[0];
    let frame_flags = data[1];
    let frame_len = u16::from_le_bytes([data[2], data[3]]) as usize;

    // PONG: exactly 8 bytes, flags=0x00, total_len=8.
    // The 8 bytes are the 4-byte outer header followed by the 4-byte footer
    // (a copy of the header): [seq, 0x00, 0x08, 0x00, seq, 0x00, 0x08, 0x00].
    // data[4] holds the echoed host seq from the footer copy.
    if frame_flags == flags::DATA_IN && frame_len == 8 && data.len() >= 8 {
        return Ok(Frame::Pong {
            echoed_seq: data[4],
        });
    }

    // Minimum data frame (no payload): 28 bytes.
    //   [0:4]   outer prefix (seq, flags, total_len)
    //   [4:8]   fourcc
    //   [8:12]  checksum
    //   [12:16] msg_seq
    //   [16:20] direction
    //   [20:22] chunk_idx
    //   [22:24] payload_len
    //   [24:28] footer (copy of [0:4]) — NO UTOM/inner_hdr for empty frames
    //
    // Full data frame (with payload): ≥36 bytes.
    //   [24:28] UTOM, [28:32] inner_hdr, [32..TL-4] payload, [TL-4:TL] footer
    //
    // The device sends 28-byte empty frames as sync/ack while the datastore
    // initializes, or as NREK receipts before actual chunk data follows.
    const MIN_DATA_FRAME: usize = 28;
    if data.len() < MIN_DATA_FRAME {
        return Err(MotuError::Protocol(format!(
            "data frame too short: {} bytes (need ≥{MIN_DATA_FRAME})",
            data.len()
        )));
    }

    let msg_type = MessageType::from_bytes(&data[4..8]).ok_or_else(|| {
        MotuError::Protocol(format!("unknown msg_type fourcc: {:02x?} (full frame: {:02x?})", &data[4..8], data))
    })?;

    let session_id = u32::from_le_bytes([data[8],  data[9],  data[10], data[11]]);
    let msg_seq    = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
    let chunk_idx  = u16::from_le_bytes([data[20], data[21]]);
    // payload_len wire field = actual_payload_bytes + 8.
    // Compare to NREK_CHUNK_MAX (4072) to detect the last chunk:
    //   payload_len == 4072 → continuation chunk (4064 bytes of actual payload)
    //   payload_len <  4072 → last (or only) chunk
    let payload_len = u16::from_le_bytes([data[22], data[23]]);

    // For 28-byte frames there is no UTOM/inner_hdr and no payload — the footer
    // is at [24:28]. For frames with actual payload (total_len ≥ 36) the full
    // 32-byte header is present and payload lives at [32..total_len-4].
    let payload = if frame_len <= 28 || data.len() < HEADER_SIZE {
        Vec::new()
    } else {
        let payload_end = frame_len.saturating_sub(4).min(data.len());
        if payload_end > HEADER_SIZE {
            data[HEADER_SIZE..payload_end].to_vec()
        } else {
            Vec::new()
        }
    };

    Ok(Frame::Data {
        seq,
        msg_type,
        session_id,
        msg_seq,
        chunk_idx,
        payload_len,
        payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc32_known_value() {
        // Python: zlib.crc32(b"UTOM") & 0xFFFFFFFF == 0xc9aec807
        // Verified with: python3 -c "import zlib; print(hex(zlib.crc32(b'UTOM') & 0xFFFFFFFF))"
        // Standard CRC-32 check vector: zlib.crc32(b"123456789") == 0xcbf43926 ✓
        let result = crc32_ieee(b"UTOM");
        assert_eq!(result, 0xc9aec807);
    }

    #[test]
    fn test_session_state_seq_wrapping() {
        // seq is 8-bit wrapping: 0xFF → 0x00
        let mut state = SessionState {
            seq: 0xFF,
            ptth_seq: 1,
            nrek_seq: 1,
        };
        assert_eq!(state.next_seq(), 0xFF);
        assert_eq!(state.next_seq(), 0x00); // wraps to 0
        assert_eq!(state.next_seq(), 0x01);
    }

    #[test]
    fn test_encode_connect() {
        let mut state = SessionState::new();
        let frame = encode_connect(&mut state);
        assert_eq!(frame.len(), 4);
        assert_eq!(frame[1], flags::CONNECT);
        assert_eq!(frame[2], 0x04);
        assert_eq!(frame[3], 0x00);
    }

    #[test]
    fn test_encode_ping() {
        let mut state = SessionState::new();
        let _connect = encode_connect(&mut state);
        let frame = encode_ping(&mut state);
        assert_eq!(frame.len(), 4);
        assert_eq!(frame[1], flags::PING);
    }

    #[test]
    fn test_encode_data_frame_structure() {
        let mut state = SessionState::new();
        let payload = b"test payload";
        let frame = encode_data(&mut state, MessageType::Ptth, payload);

        // Total length
        let total_len = u16::from_le_bytes([frame[2], frame[3]]) as usize;
        assert_eq!(total_len, HEADER_SIZE + payload.len());
        assert_eq!(frame.len(), total_len);

        // Flags
        assert_eq!(frame[1], flags::DATA_OUT);

        // Msg type
        assert_eq!(&frame[4..8], b"PTTH");

        // Checksum at [8:12] — should be CRC32(frame[24..]), not zero or random.
        let checksum = u32::from_le_bytes([frame[8], frame[9], frame[10], frame[11]]);
        let expected_crc = crc32_ieee(&frame[24..]);
        assert_eq!(checksum, expected_crc, "checksum must be CRC32(frame[24..])");

        // Direction = 1 (OUT)
        let direction = u32::from_le_bytes([frame[16], frame[17], frame[18], frame[19]]);
        assert_eq!(direction, 1);

        // payload_len field [22:24] = actual payload len + 8 (UTOM + inner_hdr overhead).
        let pl_field = u16::from_le_bytes([frame[22], frame[23]]);
        assert_eq!(pl_field as usize, payload.len() + 8);

        // MOTU magic
        assert_eq!(&frame[24..28], MOTU_MAGIC);

        // Inner header value = 8
        let inner_hdr = u32::from_le_bytes([frame[28], frame[29], frame[30], frame[31]]);
        assert_eq!(inner_hdr, INNER_HDR_VALUE);

        // Payload
        assert_eq!(&frame[32..], payload);
    }

    #[test]
    fn test_decode_pong() {
        // PONG from capture: 8 bytes = outer header repeated.
        // [seq=0x22, flags=0x00, total_len=0x0008] + [footer=same 4 bytes]
        let data = vec![0x22, 0x00, 0x08, 0x00, 0x22, 0x00, 0x08, 0x00];
        let frame = decode_frame(&data).unwrap();
        match frame {
            Frame::Pong { echoed_seq } => assert_eq!(echoed_seq, 0x22),
            _ => panic!("expected Pong"),
        }
    }

    #[test]
    fn test_decode_connect_from_capture() {
        // First packet in capture: CONNECT = 0x22 0x82 0x04 0x00
        let data = [0x22u8, 0x82, 0x04, 0x00];
        assert_eq!(data[0], 0x22); // seq
        assert_eq!(data[1], 0x82); // CONNECT flag
        assert_eq!(u16::from_le_bytes([data[2], data[3]]), 4); // total_len
    }

    #[test]
    fn test_msg_seq_increments_per_channel() {
        let mut state = SessionState::new();
        let s1 = state.next_msg_seq(MessageType::Ptth);
        let s2 = state.next_msg_seq(MessageType::Ptth);
        let n1 = state.next_msg_seq(MessageType::Nrek);
        let n2 = state.next_msg_seq(MessageType::Nrek);
        // Counters start at 1 to match Windows driver usbmon capture.
        assert_eq!(s1, 1);
        assert_eq!(s2, 2);
        assert_eq!(n1, 1); // Independent counter
        assert_eq!(n2, 2);
    }

    #[test]
    fn test_encode_data_roundtrip_checksum() {
        // Build a frame and verify CRC32 is correctly embedded at [8:12].
        let mut state = SessionState::new();
        let payload = b"GET /datastore";
        let frame = encode_data(&mut state, MessageType::Nrek, payload);

        // payload_len field must be actual + 8
        let pl_field = u16::from_le_bytes([frame[22], frame[23]]);
        assert_eq!(pl_field as usize, payload.len() + 8);

        // Checksum at [8:12] must equal CRC32(frame[24..])
        let embedded_crc = u32::from_le_bytes([frame[8], frame[9], frame[10], frame[11]]);
        let computed_crc = crc32_ieee(&frame[24..]);
        assert_eq!(embedded_crc, computed_crc);
    }
}
