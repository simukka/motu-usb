//! MOTU device simulator — Rust reimplementation of the tamio firmware.
//!
//! `DeviceSimulator` runs in a background Tokio task and speaks the same
//! binary framing protocol as the real MOTU 828ES (FX3 USB firmware + tamio
//! daemon), making it possible to test the full host-side client stack
//! without a physical device.
//!
//! ## What is tamio?
//!
//! tamio is an ARM Linux ELF binary that runs on the MOTU 828ES device.
//! It owns:
//! 1. **L3Proxy** — a CONNECT-over-TCP tunnel between the FX3 ETunnel kernel
//!    module (USB facing) and the embedded HTTP server on port 80.
//! 2. **DataStoreIPC** — an IPC shim that bridges the HTTP server's REST API
//!    to the `MOTUAVBController` process that owns the actual mixer state.
//!
//! The simulator collapses those layers into a single async loop:
//!
//! ```text
//! tamio (on-device)                  DeviceSimulator (in-process)
//! ─────────────────────────────────  ──────────────────────────────────────
//! FX3 USB firmware                   protocol::decode_frame / encode_frame
//!   ↕ NREK/PTTH binary frames          ↕ ChannelHalf (mpsc channel pair)
//! ETunnel / ssmac_avb                (no L3Proxy — channels are direct)
//!   ↕ 12-byte Ethernet frames
//! L3Proxy (CONNECT tunnel)
//!   ↕ HTTP/1.x
//! tamio HTTP server :80              sim::http::handle()
//!   ↕ DataStoreIPC RPC
//! MOTUAVBController                  sim::datastore::Datastore
//! ```
//!
//! ## Key tamio.c functions mirrored here
//!
//! | tamio.c address | Function                  | Simulator equivalent          |
//! |-----------------|---------------------------|-------------------------------|
//! | `FUN_000aa670`  | `sendNopToApc` (NOP/PONG) | `make_pong()`                 |
//! | `FUN_000aa958`  | Keepalive timer (10 s)    | Handled by PING/PONG echo     |
//! | `L3Proxy`       | State machine (line 97231)| `DeviceSimulator::run()`      |
//! | `FUN_000aa5e4`  | AVDECC response wrapper   | `encode_response_frames()`    |
//! | `DataStoreIPC`  | Key/value IPC (line 1360) | `sim::datastore::Datastore`   |
//!
//! ## Frame format (device → host)
//!
//! ```text
//! [0]      seq | 0x40     u8    — device counter OR-ed with 0x40
//! [1]      0x00           u8    — flags (always 0 for device→host)
//! [2:4]    total_len      u16LE — 36 + payload_bytes (32 hdr + 4 footer)
//! [4:8]    fourcc         4B    — b"PTTH" or b"NREK"
//! [8:12]   checksum       u32LE — CRC-32b(frame[24..TL-4])
//! [12:16]  msg_seq        u32LE
//! [16:20]  direction      u32LE — 0 for responses
//! [20:22]  chunk_idx      u16LE — 0-based chunk counter
//! [22:24]  payload_len    u16LE — payload_bytes + 8
//! [24:28]  UTOM           4B    — b"UTOM"
//! [28:32]  inner_hdr      u32LE — always 8
//! [32..]   payload
//! [TL-4:]  footer         4B    — copy of frame[0:4]
//! ```

pub mod datastore;
pub mod http;

use crate::{
    codec,
    protocol::crc32_ieee,
    transport::ChannelHalf,
    types::{flags, MessageType, INNER_HDR_VALUE, MOTU_MAGIC, NREK_CHUNK_MAX},
};
use datastore::Datastore;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, info, trace, warn};

/// Maximum payload bytes per NREK data chunk (NREK_CHUNK_MAX − 8 = 4064).
///
/// Continuation chunks carry exactly this many bytes; the last chunk carries
/// fewer. This mirrors `ControllerHostCommandHost::Send` which asserts
/// `fLength <= 4072`.
const CHUNK_PAYLOAD: usize = (NREK_CHUNK_MAX - 8) as usize;

// ─── Device-side sequencing state ─────────────────────────────────────────

/// Per-session frame counters for device→host frames.
///
/// Mirrors the two fields inside tamio's `L3Proxy` object that track the
/// device's outbound sequence numbers.
struct DeviceState {
    /// Outer frame sequence byte — OR-ed with 0x40 before being sent.
    seq: u8,
    /// Per-channel message sequence (starts at 1, one per logical response).
    ptth_seq: u32,
    nrek_seq: u32,
}

impl DeviceState {
    fn new() -> Self {
        Self { seq: 0x00, ptth_seq: 1, nrek_seq: 1 }
    }

    fn next_seq(&mut self) -> u8 {
        let s = self.seq;
        self.seq = self.seq.wrapping_add(1);
        s
    }

    fn next_msg_seq(&mut self, msg_type: MessageType) -> u32 {
        match msg_type {
            MessageType::Ptth => { let s = self.ptth_seq; self.ptth_seq += 1; s }
            MessageType::Nrek => { let s = self.nrek_seq; self.nrek_seq += 1; s }
        }
    }
}

// ─── DeviceSimulator ─────────────────────────────────────────────────────────

/// Simulated MOTU 828ES device.
///
/// Runs in a background Tokio task. Feed it the device-half of a
/// [`crate::transport::MotuTransport::channel`] pair, spawn it with
/// [`DeviceSimulator::spawn`], and pass the host-half to
/// [`crate::MotuDevice::connect_via`].
///
/// # Example
///
/// ```no_run
/// use motu_usb::{MotuDevice, MotuTransport, sim::DeviceSimulator};
///
/// # async fn run() {
/// let (transport, channel) = MotuTransport::channel();
/// let _datastore = DeviceSimulator::new(channel).spawn();
/// let mut device = MotuDevice::connect_via(transport).await.unwrap();
/// let resp = device.request(motu_usb::Request::get("/datastore")).await.unwrap();
/// assert_eq!(resp.status, 200);
/// # }
/// ```
pub struct DeviceSimulator {
    channel: ChannelHalf,
    /// Shared datastore handle — tests can mutate this to simulate device-side
    /// changes and exercise the ETag long-poll path.
    pub datastore: Arc<Mutex<Datastore>>,
}

impl DeviceSimulator {
    /// Create a simulator backed by the given channel half and a default datastore.
    pub fn new(channel: ChannelHalf) -> Self {
        Self {
            channel,
            datastore: Arc::new(Mutex::new(Datastore::with_defaults())),
        }
    }

    /// Create a simulator with a custom pre-populated datastore.
    pub fn with_datastore(channel: ChannelHalf, datastore: Arc<Mutex<Datastore>>) -> Self {
        Self { channel, datastore }
    }

    /// Spawn the simulator as a Tokio background task.
    ///
    /// Returns the shared [`Datastore`] handle so tests can inspect or mutate
    /// the store independently.  The simulator exits when the host-side channel
    /// is dropped.
    pub fn spawn(self) -> Arc<Mutex<Datastore>> {
        let ds = Arc::clone(&self.datastore);
        tokio::spawn(self.run());
        ds
    }

    /// Run the device simulator event loop.
    ///
    /// Processes host→device frames and sends device→host responses.  Runs
    /// until the host side of the channel is closed (returns `None` from
    /// `rx.recv()`).
    pub async fn run(mut self) {
        info!("DeviceSimulator: started");
        let mut dev_state = DeviceState::new();

        loop {
            let data = match self.channel.rx.recv().await {
                Some(d) => d,
                None => {
                    info!("DeviceSimulator: channel closed — exiting");
                    break;
                }
            };

            if data.len() < 2 {
                warn!("DeviceSimulator: runt frame ({} bytes) — ignored", data.len());
                continue;
            }

            let host_seq = data[0];
            let frame_flags = data[1];

            match frame_flags {
                // ── CONNECT (0x82) ─────────────────────────────────────────
                // tamio L3Proxy line 97269: send "HTTP/1.1 200 OK\r\n\r\n"
                // then call FUN_000aa670 (sendNopToApc = 12 zero bytes).
                // From the host's perspective this arrives as an 8-byte PONG.
                flags::CONNECT => {
                    info!("DeviceSimulator: CONNECT (seq=0x{host_seq:02x}) → PONG");
                    if !self.send_pong(host_seq).await { break; }
                }

                // ── PING (0x81) ────────────────────────────────────────────
                // tamio FUN_000aa958: keepalive timer replies with NOP
                // (sendNopToApc). At the USB layer this is the 8-byte PONG.
                flags::PING => {
                    trace!("DeviceSimulator: PING (seq=0x{host_seq:02x}) → PONG");
                    if !self.send_pong(host_seq).await { break; }
                }

                // ── DATA OUT (0x80) ────────────────────────────────────────
                // tamio L3Proxy line 97300+: recv() the 12-byte ETunnel frame
                // header, extract payload_len, recv() the payload, pass to
                // the HTTP server.
                flags::DATA_OUT => {
                    if data.len() < 32 {
                        warn!(
                            "DeviceSimulator: DATA frame too short ({} bytes)",
                            data.len()
                        );
                        continue;
                    }

                    let msg_type = match MessageType::from_bytes(&data[4..8]) {
                        Some(t) => t,
                        None => {
                            warn!(
                                "DeviceSimulator: unknown channel fourcc {:02x?}",
                                &data[4..8]
                            );
                            continue;
                        }
                    };

                    // Payload starts at byte 32 (4 outer + 28 inner header).
                    let payload = &data[32..];
                    debug!(
                        "DeviceSimulator: {:?} DATA ({} bytes payload, seq=0x{host_seq:02x})",
                        msg_type, payload.len()
                    );

                    // Decode the binary HTTP request.
                    let req = match codec::decode_request(payload) {
                        Ok(r) => r,
                        Err(e) => {
                            warn!("DeviceSimulator: cannot decode request: {e}");
                            // Still send a PONG so the host doesn't stall.
                            if !self.send_pong(host_seq).await { break; }
                            continue;
                        }
                    };

                    // Acknowledge the frame with PONG before processing.
                    // This matches the real FX3 behaviour: the USB ACK arrives
                    // before the HTTP response.
                    if !self.send_pong(host_seq).await { break; }

                    // Route the HTTP request.
                    let resp = http::handle(&req, &self.datastore).await;
                    let resp_payload = codec::encode_response(&resp);

                    // Encode and send response frame(s).
                    let frames = encode_response_frames(
                        &mut dev_state,
                        msg_type,
                        &resp_payload,
                    );
                    for frame in frames {
                        if self.channel.tx.send(frame).await.is_err() {
                            info!("DeviceSimulator: host channel closed — exiting");
                            return;
                        }
                    }
                }

                other => {
                    warn!("DeviceSimulator: unrecognised frame flags 0x{other:02x}");
                }
            }
        }

        info!("DeviceSimulator: stopped");
    }

    /// Send an 8-byte PONG echoing `host_seq`.  Returns `false` if the channel
    /// is closed (caller should exit the loop).
    async fn send_pong(&self, host_seq: u8) -> bool {
        self.channel.tx.send(make_pong(host_seq)).await.is_ok()
    }
}

// ─── Frame helpers ────────────────────────────────────────────────────────────

/// Build the 8-byte PONG frame that the FX3 firmware sends in response to a
/// CONNECT or PING from the host.
///
/// From Ghidra analysis of `FUN_000aa670` (`sendNopToApc`) in tamio.c:
/// tamio sends 12 zero bytes over the ETunnel socket; the FX3 firmware
/// re-encodes this as the 8-byte PONG at the USB layer:
/// `[seq, 0x00, 0x08, 0x00, seq, 0x00, 0x08, 0x00]`
/// where the second group is a 4-byte footer copy of the first group.
fn make_pong(host_seq: u8) -> Vec<u8> {
    vec![host_seq, 0x00, 0x08, 0x00, host_seq, 0x00, 0x08, 0x00]
}

/// Encode an HTTP response payload into one or more device→host DATA frames.
///
/// Large payloads are split into 4064-byte chunks (NREK_CHUNK_MAX − 8).
/// All chunks except the last have `payload_len == NREK_CHUNK_MAX`; the final
/// chunk has `payload_len < NREK_CHUNK_MAX`.  The host detects the end of a
/// multi-chunk response by this sentinel — see `MotuDevice::read_response`.
fn encode_response_frames(
    state: &mut DeviceState,
    msg_type: MessageType,
    payload: &[u8],
) -> Vec<Vec<u8>> {
    // All chunks within a single logical response share the same msg_seq.
    let msg_seq = state.next_msg_seq(msg_type);

    if payload.is_empty() {
        // Empty response — send one zero-payload frame so the host's
        // read_response() loop has something to terminate on.
        return vec![build_data_frame(state, msg_type, &[], msg_seq, 0)];
    }

    let mut frames = Vec::new();
    for (chunk_idx, chunk) in payload.chunks(CHUNK_PAYLOAD).enumerate() {
        frames.push(build_data_frame(
            state,
            msg_type,
            chunk,
            msg_seq,
            chunk_idx as u16,
        ));
    }
    frames
}

/// Build a single device→host DATA frame.
///
/// See the module-level doc-comment for the exact wire layout.
fn build_data_frame(
    state: &mut DeviceState,
    msg_type: MessageType,
    payload: &[u8],
    msg_seq: u32,
    chunk_idx: u16,
) -> Vec<u8> {
    let seq = state.next_seq();
    // total_len = 32 (header) + payload_bytes + 4 (footer)
    let total_len = (32 + payload.len() + 4) as u16;
    // payload_len wire field = actual bytes + 8 (UTOM + inner_hdr overhead).
    // Exactly mirrors the host→device encoding in protocol::encode_data.
    let pl_field = (payload.len() as u16) + 8;

    let mut frame: Vec<u8> = Vec::with_capacity(total_len as usize);

    // ── Outer header (4 bytes) ──────────────────────────────────────────────
    frame.push(seq | 0x40);                                   // [0]  seq | 0x40
    frame.push(0x00);                                         // [1]  flags = 0
    frame.extend_from_slice(&total_len.to_le_bytes());        // [2:4] total_len

    // ── Inner header (28 bytes) ─────────────────────────────────────────────
    frame.extend_from_slice(msg_type.as_bytes());             // [4:8]   fourcc
    frame.extend_from_slice(&0u32.to_le_bytes());             // [8:12]  checksum (placeholder)
    frame.extend_from_slice(&msg_seq.to_le_bytes());          // [12:16] msg_seq
    frame.extend_from_slice(&0u32.to_le_bytes());             // [16:20] direction = 0 (IN)
    frame.extend_from_slice(&chunk_idx.to_le_bytes());        // [20:22] chunk_idx
    frame.extend_from_slice(&pl_field.to_le_bytes());         // [22:24] payload_len
    frame.extend_from_slice(MOTU_MAGIC);                      // [24:28] "UTOM"
    frame.extend_from_slice(&INNER_HDR_VALUE.to_le_bytes());  // [28:32] inner_hdr = 8

    // ── Payload ─────────────────────────────────────────────────────────────
    frame.extend_from_slice(payload);                         // [32..]

    // ── CRC-32b ─────────────────────────────────────────────────────────────
    // Computed over frame[24..total_len-4] = from UTOM to end of payload.
    // Same polynomial and initialisation as host→device (IEEE 802.3).
    let crc_end = frame.len(); // footer not appended yet, so crc covers [24..current_end]
    let checksum = crc32_ieee(&frame[24..crc_end]);
    frame[8..12].copy_from_slice(&checksum.to_le_bytes());

    // ── Footer (4 bytes) — copy of outer header ──────────────────────────────
    // `ControllerHostCommandHost::Send` appends frame[0:4] as a footer.
    let footer = [frame[0], frame[1], frame[2], frame[3]];
    frame.extend_from_slice(&footer);

    debug_assert_eq!(frame.len(), total_len as usize, "frame length mismatch");

    frame
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MotuDevice, MotuTransport, Request};

    /// Spin up a `DeviceSimulator` and a `MotuDevice` connected via channels,
    /// verify the full connect + GET /datastore round-trip in-process.
    #[tokio::test]
    async fn test_connect_and_get_datastore() {
        let (transport, channel) = MotuTransport::channel();
        DeviceSimulator::new(channel).spawn();

        let mut device = MotuDevice::connect_via(transport)
            .await
            .expect("connect_via failed");

        let resp = device
            .request(Request::get("/datastore"))
            .await
            .expect("request failed");

        assert_eq!(resp.status, 200, "expected 200 OK, got {}", resp.status);
        assert!(!resp.body.is_empty(), "response body must not be empty");

        let body = std::str::from_utf8(&resp.body).expect("body must be UTF-8");
        assert!(body.starts_with('{'), "body must be JSON: {body}");
        assert!(body.contains("828ES"), "body must contain model name");
    }

    #[tokio::test]
    async fn test_post_datastore() {
        let (transport, channel) = MotuTransport::channel();
        let ds = DeviceSimulator::new(channel).spawn();

        let mut device = MotuDevice::connect_via(transport)
            .await
            .expect("connect_via failed");

        let resp = device
            .request(Request::post(
                "/datastore/mix/main/volume",
                crate::codec::encode_motu_post_body(b"json", br#"{"value": 75}"#),
            ))
            .await
            .expect("POST failed");

        assert_eq!(resp.status, 200, "POST /datastore/mix/main/volume → {}", resp.status);

        // Verify the datastore was updated.
        let stored = ds.lock().await.get("mix/main/volume").cloned();
        assert_eq!(
            stored,
            Some(datastore::DataValue::Int(75)),
            "stored value should be 75"
        );
    }

    #[test]
    fn test_make_pong_format() {
        let pong = make_pong(0x22);
        assert_eq!(pong, vec![0x22, 0x00, 0x08, 0x00, 0x22, 0x00, 0x08, 0x00]);
    }

    #[test]
    fn test_build_data_frame_structure() {
        let mut state = DeviceState::new();
        let payload = b"HTTP/1.1 200 OK\r\n\r\nhello";
        let frame = build_data_frame(&mut state, MessageType::Ptth, payload, 1, 0);

        // total_len = 32 + payload.len() + 4
        let total_len = u16::from_le_bytes([frame[2], frame[3]]) as usize;
        assert_eq!(total_len, 32 + payload.len() + 4);
        assert_eq!(frame.len(), total_len);

        // flags = 0 (device→host)
        assert_eq!(frame[1], 0x00);

        // fourcc = "PTTH"
        assert_eq!(&frame[4..8], b"PTTH");

        // direction = 0 (IN)
        let dir = u32::from_le_bytes([frame[16], frame[17], frame[18], frame[19]]);
        assert_eq!(dir, 0);

        // UTOM magic
        assert_eq!(&frame[24..28], b"UTOM");

        // inner_hdr = 8
        let inner_hdr = u32::from_le_bytes([frame[28], frame[29], frame[30], frame[31]]);
        assert_eq!(inner_hdr, 8);

        // payload_len = actual + 8
        let pl_field = u16::from_le_bytes([frame[22], frame[23]]);
        assert_eq!(pl_field as usize, payload.len() + 8);

        // payload at [32..total_len-4]
        assert_eq!(&frame[32..total_len - 4], payload);

        // footer = copy of frame[0:4]
        assert_eq!(&frame[total_len - 4..], &frame[0..4]);

        // CRC-32b at [8:12] over frame[24..total_len-4]
        let embedded_crc = u32::from_le_bytes([frame[8], frame[9], frame[10], frame[11]]);
        let expected_crc = crc32_ieee(&frame[24..total_len - 4]);
        assert_eq!(embedded_crc, expected_crc);
    }

    #[test]
    fn test_chunked_response_sentinel() {
        // A payload larger than CHUNK_PAYLOAD must produce ≥2 frames.
        // All but the last must have payload_len == NREK_CHUNK_MAX.
        let mut state = DeviceState::new();
        let big_payload = vec![0u8; CHUNK_PAYLOAD + 100];
        let frames =
            encode_response_frames(&mut state, MessageType::Nrek, &big_payload);

        assert_eq!(frames.len(), 2, "two chunks expected");

        // First frame: continuation sentinel
        let pl0 = u16::from_le_bytes([frames[0][22], frames[0][23]]);
        assert_eq!(pl0, NREK_CHUNK_MAX, "continuation chunk payload_len must == NREK_CHUNK_MAX");

        // Second frame: last chunk (<NREK_CHUNK_MAX)
        let pl1 = u16::from_le_bytes([frames[1][22], frames[1][23]]);
        assert!(
            pl1 < NREK_CHUNK_MAX,
            "last chunk payload_len must be < NREK_CHUNK_MAX, got {pl1}"
        );
    }
}
