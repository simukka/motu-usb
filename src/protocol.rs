//! MOTU USB framing protocol: frame encoding/decoding and session state.
//!
//! Handles the outer 4-byte header, inner 28-byte data header, CONNECT/PING/PONG
//! control messages, sequence number tracking, and session nonce generation.

use crate::error::{MotuError, Result};
use crate::types::{flags, Frame, MessageType, INNER_HDR_VALUE, MOTU_MAGIC};
use rand::Rng;

// ─── Constants ──────────────────────────────────────────────────────────────

/// OUT sequence counter range: 0x20..=0x3F (wraps).
const SEQ_OUT_MIN: u8 = 0x20;
const SEQ_OUT_MAX: u8 = 0x3F;

/// Total header size for data frames: 4 (outer) + 28 (inner) = 32 bytes.
const HEADER_SIZE: usize = 32;

// ─── Session State ──────────────────────────────────────────────────────────

/// Tracks protocol state for a MOTU USB session.
#[derive(Debug)]
pub struct SessionState {
    /// Outer frame sequence counter (wraps 0x20..0x3F).
    seq: u8,
    /// Per-channel message sequence counters.
    ptth_seq: u32,
    nrek_seq: u32,
}

impl SessionState {
    pub fn new() -> Self {
        Self {
            // Capture shows first CONNECT at 0x22, but starting at base is fine.
            // The device doesn't seem to care about the initial value.
            seq: SEQ_OUT_MIN + 2, // Start at 0x22 to match observed captures
            ptth_seq: 2,          // Capture shows first msg_seq = 2
            nrek_seq: 2,
        }
    }

    /// Advance and return the next outer sequence number.
    pub fn next_seq(&mut self) -> u8 {
        let s = self.seq;
        self.seq = if self.seq >= SEQ_OUT_MAX {
            SEQ_OUT_MIN
        } else {
            self.seq + 1
        };
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

    /// Generate a random session ID nonce.
    pub fn random_session_id() -> u32 {
        rand::rng().random()
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
pub fn encode_data(
    state: &mut SessionState,
    msg_type: MessageType,
    payload: &[u8],
) -> Vec<u8> {
    let seq = state.next_seq();
    let session_id = SessionState::random_session_id();
    let msg_seq = state.next_msg_seq(msg_type);
    let total_len = (HEADER_SIZE + payload.len()) as u16;

    let mut frame = Vec::with_capacity(total_len as usize);

    // Outer header (4 bytes)
    frame.push(seq);
    frame.push(flags::DATA_OUT);
    frame.extend_from_slice(&total_len.to_le_bytes());

    // Inner header (28 bytes)
    frame.extend_from_slice(msg_type.as_bytes()); // [4-7] msg_type
    frame.extend_from_slice(&session_id.to_le_bytes()); // [8-11] session_id
    frame.extend_from_slice(&msg_seq.to_le_bytes()); // [12-15] msg_seq
    frame.extend_from_slice(&1u32.to_le_bytes()); // [16-19] direction=1 (OUT/request)
    frame.extend_from_slice(&0u16.to_le_bytes()); // [20-21] chunk_idx=0
    frame.extend_from_slice(&(payload.len() as u16).to_le_bytes()); // [22-23] payload_len
    frame.extend_from_slice(MOTU_MAGIC); // [24-27] "UTOM"
    frame.extend_from_slice(&INNER_HDR_VALUE.to_le_bytes()); // [28-31] always 8

    // Payload
    frame.extend_from_slice(payload);

    frame
}

// ─── Frame Decoding ─────────────────────────────────────────────────────────

/// Decode a frame received from the device.
///
/// Handles PONG (8 bytes) and data frames (32+ bytes).
/// Returns `None` for unrecognized frames.
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

    // PONG: 8 bytes, flags=0x00, contains echoed seq
    if frame_flags == flags::DATA_IN && frame_len == 8 && data.len() >= 8 {
        return Ok(Frame::Pong {
            echoed_seq: data[4],
        });
    }

    // Data frame: must have at least 32 bytes for headers
    if data.len() < HEADER_SIZE {
        return Err(MotuError::Protocol(format!(
            "data frame too short: {} bytes (need ≥{HEADER_SIZE})",
            data.len()
        )));
    }

    let msg_type = MessageType::from_bytes(&data[4..8]).ok_or_else(|| {
        MotuError::Protocol(format!(
            "unknown msg_type: {:?}",
            &data[4..8]
        ))
    })?;

    let session_id = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
    let msg_seq = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
    let chunk_idx = u16::from_le_bytes([data[20], data[21]]);

    // Device IN frames carry a 4-byte footer (outer header copy) at frame_len-4.
    // Payload is data[32 .. frame_len-4] for IN frames.
    let payload_end = if frame_len >= 36 {
        // Footer present
        std::cmp::min(frame_len - 4, data.len())
    } else {
        std::cmp::min(frame_len, data.len())
    };

    let payload = if payload_end > HEADER_SIZE {
        data[HEADER_SIZE..payload_end].to_vec()
    } else {
        Vec::new()
    };

    Ok(Frame::Data {
        seq,
        msg_type,
        session_id,
        msg_seq,
        chunk_idx,
        payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_state_seq_wrapping() {
        let mut state = SessionState {
            seq: SEQ_OUT_MAX,
            ptth_seq: 0,
            nrek_seq: 0,
        };
        assert_eq!(state.next_seq(), SEQ_OUT_MAX); // 0x3F
        assert_eq!(state.next_seq(), SEQ_OUT_MIN); // wraps to 0x20
        assert_eq!(state.next_seq(), SEQ_OUT_MIN + 1); // 0x21
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

        // Direction = 1 (OUT)
        let direction = u32::from_le_bytes([frame[16], frame[17], frame[18], frame[19]]);
        assert_eq!(direction, 1);

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
        // From capture: PONG is 8 bytes: [seq] 0x00 0x08 0x00 [echoed_seq] 0x00 0x08 0x00
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
        assert_eq!(s1, 2);
        assert_eq!(s2, 3);
        assert_eq!(n1, 2); // Independent counter
        assert_eq!(n2, 3);
    }
}
