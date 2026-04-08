//! Async Rust library for communicating with MOTU audio devices over USB.
//!
//! MOTU devices (828ES) expose an HTTP API over a USB vendor bulk interface
//! using a custom binary framing protocol. This library implements that
//! protocol, providing a simple async API to send HTTP requests and receive
//! responses.
//!
//! # Example
//!
//! ```no_run
//! use motu_usb::{MotuDevice, Request};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let mut device = MotuDevice::connect().await?;
//!
//!     let response = device.request(Request::get("/datastore")).await?;
//!     println!("Status: {}", response.status);
//!     println!("Body: {}", response.body_text()?);
//!
//!     Ok(())
//! }
//! ```

pub mod codec;
pub mod error;
pub mod protocol;
pub mod sim;
pub mod transport;
pub mod types;
pub mod usb;

pub use error::{MotuError, Result};
pub use transport::MotuTransport;
pub use types::{DeviceInfo, Frame, MessageType, Method, Request, Response, AUTH_HEADER, AUTH_TOKEN, NREK_CHUNK_MAX};

use protocol::{SessionState, decode_frame, encode_connect, encode_data, encode_ping};
use std::time::Duration;
use tracing::{debug, info, trace, warn};

/// Timeout for PONG responses to CONNECT/PING.
const PONG_TIMEOUT: Duration = Duration::from_secs(2);

/// How often to send a keepalive PING while waiting for a response chunk.
///
/// Must be shorter than the device's 5-second watchdog timer
/// (`ControllerHostCommandHost` timer period 0x50 ≈ 5s), otherwise
/// `ResetHTTPProxy()` fires and the pending NREK response is discarded.
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(3);

/// How long to wait for the first chunk before resending the NREK GET.
///
/// After a CONNECT, the device tears down and re-establishes the IPC
/// connection between tamio and MOTUAVBController (takes ~1-2 seconds).
/// A NREK GET sent during this window is forwarded by tamio (which sends
/// the 28-byte sync ack) but silently dropped by MOTUAVBController because
/// the IPC FIFO isn't open yet. We detect this by noticing that we receive
/// only PONGs/sync frames for longer than the IPC reconnection window, then
/// resend the NREK GET.
const NREK_RETRY_INTERVAL: Duration = Duration::from_secs(12);

/// Maximum total time to wait for a complete response (all chunks).
///
/// The initial `GET /datastore` response can be delayed up to ~30 seconds
/// while the device runs `InitExtendedData`, restores 4485 DB entries, and
/// completes `Mixer::Init`. Windows driver effectively waits indefinitely;
/// 60s is a conservative upper bound.
const MAX_RESPONSE_WAIT: Duration = Duration::from_secs(60);

/// Maximum number of logical NREK chunks to receive for a single response.
const MAX_CHUNKS: usize = 256;

// ── Phase 2 registration constants (from Windows 10 driver 4.0.9.2009 capture) ─

/// Driver version string posted to the device during connection setup.
///
/// From usbmon capture: `POST /datastore/host/driver_version {"value":"4.0.9.2009"}`.
const HOST_DRIVER_VERSION: &str = "4.0.9.2009";

/// USB buffer sizes for 1x sample rates (44.1 / 48 kHz), colon-delimited.
///
/// From usbmon capture: `POST /datastore/host/win/buffer_sizes_1x
/// {"value":"16:32:64:128:256:512:1024"}`.
const HOST_WIN_BUFFER_SIZES_1X: &str = "16:32:64:128:256:512:1024";

/// Safety offsets for 1x sample rates, colon-delimited.
///
/// From usbmon capture: `POST /datastore/host/win/safety_offsets_1x
/// {"value":"16:24:32:48:64:128:256"}`.
const HOST_WIN_SAFETY_OFFSETS_1X: &str = "16:24:32:48:64:128:256";

/// High-level interface to a MOTU device over USB.
///
/// Handles the CONNECT handshake, PING/PONG keepalive, protocol framing,
/// and binary HTTP codec transparently.
#[derive(Debug)]
pub struct MotuDevice {
    transport: MotuTransport,
    state: SessionState,
    /// Identity information collected during the connection handshake.
    ///
    /// Use this to identify which physical device you are talking to when
    /// multiple MOTU devices are connected to the same computer.
    pub info: DeviceInfo,
}

impl MotuDevice {
    /// Connect to a MOTU 828ES device and establish an active session.
    ///
    /// Executes the mandatory two-step Windows driver startup sequence:
    ///
    /// 1. **CONNECT** (4 bytes) → device responds with PONG.
    /// 2. **POST `/datastore/host/os` `{"value": "win"}`** → device PONG.
    ///
    /// Step 2 is **required before any other commands**. Without it, the device
    /// never establishes its command context and silently ignores all subsequent
    /// frames, logging `ControllerProcessCommand ERROR` and firing
    /// `CHCHost::ResetHTTPProxy()` every ~5 seconds.
    ///
    /// The device initialises `host/os` to `"mac"` at startup
    /// (`FUN_000777c8` / `InitExtendedData`). Sending `"win"` enables
    /// Windows-specific datastore paths (`host/win/buffer_sizes_1x`,
    /// `host/win/enable_interrupts`, etc.).
    /// Connect to a real MOTU 828ES USB device.
    ///
    /// Equivalent to `connect_via(MotuTransport::usb(MotuUsb::open()?))`.  See
    /// [`MotuDevice::connect_via`] for the full handshake description.
    pub async fn connect() -> Result<Self> {
        let usb = usb::MotuUsb::open()?;
        Self::connect_via(MotuTransport::usb(usb)).await
    }

    /// Connect over any transport (USB or in-process channel) and establish a session.
    ///
    /// Executes the full Windows driver startup sequence captured from usbmon:
    ///
    /// **Phase 1 — CONNECT**
    /// 1. `CONNECT` (4 bytes) → device drains any stale frames, waits for PONG.
    ///
    /// **Phase 2 — Registration POSTs** (all over PTTH with auth header)
    /// 2. `POST /datastore/host/os {"value":"win"}` — unlocks tamio's command context.
    /// 3. `POST /datastore/host/driver_version {"value":"4.0.9.2009"}` — driver identity.
    /// 4. `POST /datastore/host/mode {"value":"USB2"}` — connection mode.
    /// 5. `POST /datastore/host/win/buffer_sizes_1x {"value":"16:32:…"}` — buffer options.
    /// 6. `POST /datastore/host/win/safety_offsets_1x {"value":"16:24:…"}` — safety offsets.
    ///
    /// **Phase 3 — Device identity** (PTTH GETs, stored in [`DeviceInfo`])
    /// 7. `GET /datastore/avb/devs` — AVB EUI (unique hardware identifier).
    /// 8–11. entity name, model name, firmware version, host type.
    ///
    /// Pass a [`transport::ChannelHalf`] from [`MotuTransport::channel`] to
    /// the [`sim::DeviceSimulator`] for fully in-process testing.
    pub async fn connect_via(transport: MotuTransport) -> Result<Self> {
        let mut state = SessionState::new();

        // ── Phase 1: CONNECT ──────────────────────────────────────────────────
        // 4-byte frame [seq, 0x82, 0x04, 0x00]. Device responds with PONG.
        //
        // Drain any stale data frames buffered from a previous session before
        // waiting for the CONNECT PONG (they arrive before it on reconnect).
        let connect_frame = encode_connect(&mut state);
        info!("Sending CONNECT");
        transport.write(&connect_frame).await?;

        loop {
            let data = transport
                .read_timeout(PONG_TIMEOUT)
                .await?
                .ok_or(MotuError::Timeout)?;
            match decode_frame(&data)? {
                Frame::Pong { echoed_seq } => {
                    info!("CONNECT acknowledged (echoed seq=0x{echoed_seq:02x})");
                    break;
                }
                Frame::Data { .. } => {
                    debug!("Discarding stale data frame from previous session");
                }
            }
        }

        // ── Phase 2: Registration POSTs ───────────────────────────────────────
        // Confirmed from Windows 10 usbmon capture (driver 4.0.9.2009).
        // All sent over PTTH; each is a full send→PONG→HTTP-response→ACK cycle.
        //
        // POST body format: MOTU binary KV envelope wrapping JSON:
        //   [u32 remaining][u32 4]["json"][u32 val_len][json_bytes]
        // Sending raw JSON crashes MOTUAVBController (reads '{' as a 1.6 GB alloc).
        let driver_ver_json = format!("{{\"value\": \"{HOST_DRIVER_VERSION}\"}}");
        let buf_sizes_json  = format!("{{\"value\": \"{HOST_WIN_BUFFER_SIZES_1X}\"}}");
        let safety_ofs_json = format!("{{\"value\": \"{HOST_WIN_SAFETY_OFFSETS_1X}\"}}");
        let reg_posts: &[(&str, &[u8])] = &[
            ("/datastore/host/os",                    br#"{"value": "win"}"#),
            ("/datastore/host/driver_version",        driver_ver_json.as_bytes()),
            ("/datastore/host/mode",                  br#"{"value": "USB2"}"#),
            ("/datastore/host/win/buffer_sizes_1x",   buf_sizes_json.as_bytes()),
            ("/datastore/host/win/safety_offsets_1x", safety_ofs_json.as_bytes()),
        ];
        for (path, json_val) in reg_posts {
            let body = codec::encode_motu_post_body(b"json", json_val);
            let resp = ptth_roundtrip(&transport, &mut state, Request::post(*path, body)).await?;
            info!("POST {path}  → {}", resp.status);
        }

        // ── Phase 3: Device identity ──────────────────────────────────────────
        // Fetch the AVB EUI first, then use it to build the per-device paths.
        // All are one-shot PTTH GETs; responses are `{"value":"<string>"}` JSON.
        let devs_resp = ptth_roundtrip(
            &transport,
            &mut state,
            Request::get("/datastore/avb/devs"),
        )
        .await?;
        let avb_eui = extract_string_value(&devs_resp.body);

        let (entity_name, model_name, firmware_version, host_type) = if avb_eui.is_empty() {
            warn!("avb/devs returned empty EUI — device identity unavailable");
            Default::default()
        } else {
            let eid = format!("/datastore/avb/{avb_eui}");
            let entity = ptth_roundtrip(
                &transport,
                &mut state,
                Request::get(format!("{eid}/entity_name")),
            )
            .await?;
            let model = ptth_roundtrip(
                &transport,
                &mut state,
                Request::get(format!("{eid}/model_name")),
            )
            .await?;
            let fw = ptth_roundtrip(
                &transport,
                &mut state,
                Request::get(format!("{eid}/firmware_version")),
            )
            .await?;
            let ht = ptth_roundtrip(
                &transport,
                &mut state,
                Request::get("/datastore/host_type"),
            )
            .await?;
            (
                extract_string_value(&entity.body),
                extract_string_value(&model.body),
                extract_string_value(&fw.body),
                extract_string_value(&ht.body),
            )
        };

        let info = DeviceInfo { avb_eui, entity_name, model_name, firmware_version, host_type };
        info!("Connected: {info}");

        Ok(Self { transport, state, info })
    }

    /// Send a PING and wait for the PONG response.
    pub async fn ping(&mut self) -> Result<()> {
        let ping_frame = encode_ping(&mut self.state);
        self.transport.write(&ping_frame).await?;

        let data = self
            .transport
            .read_timeout(PONG_TIMEOUT)
            .await?
            .ok_or_else(|| MotuError::Timeout)?;

        match decode_frame(&data)? {
            Frame::Pong { echoed_seq } => {
                trace!("PONG (seq=0x{echoed_seq:02x})");
                Ok(())
            }
            other => Err(MotuError::Protocol(format!(
                "expected PONG, got: {other:?}"
            ))),
        }
    }

    /// Send an HTTP request to the device and return the response.
    ///
    /// Automatically selects the appropriate channel (PTTH or NREK) based on
    /// the request, and adds the `Unsecure-Auth-MOTU` header to PTTH requests
    /// if not already present. NREK (long-poll GET /datastore) must NOT include
    /// the auth header — confirmed from usbmon capture of the Windows driver.
    ///
    /// For NREK requests, implements a retry loop: after CONNECT, the IPC
    /// connection between tamio and MOTUAVBController takes ~1-2 seconds to
    /// re-establish. A NREK GET sent during this window is acknowledged by
    /// tamio (28-byte sync frame) but silently dropped on the IPC path.
    /// We detect this by waiting `NREK_RETRY_INTERVAL` for the first chunk;
    /// if only PONGs arrive, the GET is resent.
    pub async fn request(&mut self, req: Request) -> Result<Response> {
        let msg_type = select_channel(&req);
        debug!("{} {} via {:?}", req.method, req.path, msg_type);

        // Add auth header to PTTH one-shot requests.
        // Add If-None-Match: 0 to NREK GETs that don't already carry an ETag.
        // Confirmed from usbmon capture: Windows driver always sends this header;
        // without it the device's ETag extraction fails and the request falls
        // through to the static file server, returning 404 Not Found.
        let req = if msg_type == MessageType::Ptth
            && !req.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case(AUTH_HEADER))
        {
            req.header(AUTH_HEADER, AUTH_TOKEN)
        } else if msg_type == MessageType::Nrek
            && !req.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("If-None-Match"))
        {
            req.header("If-None-Match", "0")
        } else {
            req
        };

        // Encode the HTTP request as binary payload once (same bytes on retry).
        let payload = codec::encode_request(&req);
        let deadline = tokio::time::Instant::now() + MAX_RESPONSE_WAIT;

        loop {
            // (Re-)encode with a fresh seq number each attempt.
            let frame = encode_data(&mut self.state, msg_type, &payload);
            self.transport.write(&frame).await?;

            // Read the PONG acknowledgment for our data frame.
            self.read_pong().await?;

            // Read the actual response.  Returns None if no chunk arrived
            // within NREK_RETRY_INTERVAL (IPC-drop detected → resend).
            let retry_at = tokio::time::Instant::now() + NREK_RETRY_INTERVAL;
            match self.read_response(msg_type, retry_at, deadline).await? {
                Some(response) => return Ok(response),
                None => {
                    if tokio::time::Instant::now() >= deadline {
                        return Err(MotuError::Timeout);
                    }
                    info!("No NREK data received (IPC drop likely) — resending GET");
                }
            }
        }
    }

    /// Read a PONG, handling any interleaved data frames.
    async fn read_pong(&mut self) -> Result<()> {
        let data = self
            .transport
            .read_timeout(PONG_TIMEOUT)
            .await?
            .ok_or_else(|| MotuError::Timeout)?;

        match decode_frame(&data)? {
            Frame::Pong { echoed_seq } => {
                trace!("PONG ack (seq=0x{echoed_seq:02x})");
                Ok(())
            }
            Frame::Data { .. } => {
                // Sometimes the device sends data before the PONG.
                // We'll handle this in the response reading.
                debug!("Received data frame while expecting PONG — will process in response loop");
                Ok(())
            }
        }
    }

    /// Read the response, handling chunked multi-frame responses.
    ///
    /// Returns `Ok(Some(response))` on success, `Ok(None)` if no chunk data
    /// arrived before `retry_at` (indicating the NREK GET was IPC-dropped and
    /// should be resent), or an error on hard failure.
    ///
    /// While waiting, a keepalive PING is sent every `KEEPALIVE_INTERVAL`
    /// seconds to prevent the device's 5-second watchdog from firing
    /// `ResetHTTPProxy()`. The `deadline` caps the total wait across all
    /// retries.
    async fn read_response(
        &mut self,
        _expected_type: MessageType,
        retry_at: tokio::time::Instant,
        deadline: tokio::time::Instant,
    ) -> Result<Option<Response>> {
        let mut response_payload = Vec::new();
        let mut chunks_received = 0;

        loop {
            if chunks_received >= MAX_CHUNKS {
                return Err(MotuError::Protocol(format!(
                    "exceeded maximum chunk count ({MAX_CHUNKS})"
                )));
            }

            // Use a short read timeout so we can send keepalive PINGs.
            // If nothing arrives within KEEPALIVE_INTERVAL, ping the device
            // to prevent the 5-second watchdog from firing ResetHTTPProxy().
            let data = match self.transport.read_timeout(KEEPALIVE_INTERVAL).await? {
                Some(d) => d,
                None => {
                    let now = tokio::time::Instant::now();

                    // Signal retry if no real data has arrived yet and the
                    // per-attempt retry window has elapsed.
                    if response_payload.is_empty() && now >= retry_at {
                        return Ok(None);
                    }

                    if now >= deadline {
                        return Err(if response_payload.is_empty() {
                            MotuError::Timeout
                        } else {
                            MotuError::Protocol(format!(
                                "timeout after receiving {} chunks ({} bytes)",
                                chunks_received,
                                response_payload.len()
                            ))
                        });
                    }

                    // Send keepalive PING — resets the 5-second watchdog.
                    debug!("Sending keepalive PING (waiting for response chunk {chunks_received})");
                    let ping_frame = encode_ping(&mut self.state);
                    self.transport.write(&ping_frame).await?;
                    continue;
                }
            };

            trace!("RX {} bytes: {:02x?}", data.len(), &data[..data.len().min(32)]);

            match decode_frame(&data)? {
                Frame::Pong { .. } => {
                    // PONG during response — keepalive reply or inter-chunk ack.
                    trace!("PONG during response read");
                    continue;
                }
                Frame::Data {
                    chunk_idx,
                    payload,
                    payload_len,
                    msg_seq,
                    ..
                } => {
                    if payload.is_empty() && response_payload.is_empty() {
                        // 28-byte sync/ack frame — tamio acknowledged the request
                        // but MOTUAVBController may not have received it via IPC yet.
                        // Keep waiting; the retry_at deadline handles the IPC-drop case.
                        debug!(
                            "Empty sync frame (chunk_idx={chunk_idx}, payload_len={payload_len}) — waiting for data"
                        );
                        continue;
                    }

                    debug!(
                        "Received chunk {} ({} bytes, msg_seq={}, payload_len={})",
                        chunk_idx,
                        payload.len(),
                        msg_seq,
                        payload_len,
                    );

                    response_payload.extend_from_slice(&payload);
                    chunks_received += 1;

                    // Detect the last chunk using the `payload_len` wire field.
                    //
                    // `payload_len = actual_payload + 8` (fLength in device source).
                    // Continuation chunks have `payload_len == NREK_CHUNK_MAX (4072 = 0xfe8)`.
                    // The last chunk (or a single-chunk response such as 304) has
                    // `payload_len < NREK_CHUNK_MAX`.
                    //
                    // Confirmed from Ghidra `ControllerHostCommandHost::Send`:
                    //   assert("cmd->fLength <= 4072", ...)  (fLength == payload_len wire field)
                    //
                    // After EVERY data frame — including the last — the device sets
                    // fSendCmdInFlight = 1 and starts a 4-second ACK timer.  We PING
                    // to ACK each chunk so the device can clear fSendCmdInFlight.
                    // Without the final PING, UpdateSendState(NULL) fires on timeout
                    // with fSendCmdInFlight already 0 → ASSERT(fSendCmdInFlight).
                    let ping_frame = encode_ping(&mut self.state);
                    self.transport.write(&ping_frame).await?;

                    if payload_len < NREK_CHUNK_MAX {
                        // Last chunk ACKed — response is complete.  Also drain the
                        // PONG reply for our ACK PING so the buffer is clean for the
                        // next request().  If we skip this, the stale PONG would be
                        // consumed by the next read_pong() call instead of the PONG
                        // for the next request's data frame — misaligning subsequent
                        // responses by one frame.
                        match self.transport.read_timeout(PONG_TIMEOUT).await? {
                            Some(d) => match decode_frame(&d)? {
                                Frame::Pong { .. } => trace!("last-chunk ACK PONG received"),
                                Frame::Data { .. } => debug!("Unexpected data frame after last-chunk ACK PING"),
                            },
                            None => debug!("last-chunk ACK PONG timed out"),
                        }
                        break;
                    }
                    // More chunks follow; the loop continues and naturally consumes
                    // the PONG for this PING before processing the next DATA frame.
                }
            }
        }

        // Decode the assembled binary payload
        codec::decode_response(&response_payload).map(Some)
    }
}

// ── Module-level helpers ──────────────────────────────────────────────────────

/// Execute a single PTTH request→PONG→HTTP-response→ACK-PING→PONG cycle.
///
/// Used during [`MotuDevice::connect_via`] for all registration POSTs and
/// identity GETs where we need the auth header, direct framing, and the
/// full ACK sequence without going through the public `request()` dispatcher.
///
/// The `Unsecure-Auth-MOTU` header is added automatically if absent.
///
/// The ACK PING and its PONG reply are consumed here so the USB buffer is
/// empty when the next call starts — avoiding the frame-pipeline misalignment
/// bug that causes `fSendCmdInFlight` assertions.
async fn ptth_roundtrip(
    transport: &MotuTransport,
    state: &mut SessionState,
    req: impl Into<Request>,
) -> Result<Response> {
    let req = {
        let r = req.into();
        if r.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case(AUTH_HEADER)) {
            r
        } else {
            r.header(AUTH_HEADER, AUTH_TOKEN)
        }
    };

    let payload = codec::encode_request(&req);
    let frame = encode_data(state, MessageType::Ptth, &payload);
    transport.write(&frame).await?;

    // (a) Transport PONG — device acks receipt of our data frame.
    loop {
        let d = transport
            .read_timeout(PONG_TIMEOUT)
            .await?
            .ok_or(MotuError::Timeout)?;
        match decode_frame(&d)? {
            Frame::Pong { .. } => break,
            Frame::Data { .. } => debug!("Data frame while awaiting PTTH transport PONG — discarding"),
        }
    }

    // (b) HTTP response frame.
    let response = loop {
        let d = transport
            .read_timeout(PONG_TIMEOUT)
            .await?
            .ok_or(MotuError::Timeout)?;
        match decode_frame(&d)? {
            Frame::Data { payload, .. } => break codec::decode_response(&payload)?,
            Frame::Pong { .. } => debug!("Unexpected PONG while awaiting PTTH HTTP response — discarding"),
        }
    };

    // (c) ACK PING + drain its PONG.
    //
    // Not ACKing leaves fSendCmdInFlight = 1 on the device; the 4-second
    // timer fires UpdateSendState(NULL) → ASSERT(fSendCmdInFlight).
    // Not consuming the PONG reply shifts the next call's frame pipeline
    // forward by one, causing Status: 204 responses from NREK GETs.
    let ping = encode_ping(state);
    transport.write(&ping).await?;
    match transport.read_timeout(PONG_TIMEOUT).await? {
        Some(d) => match decode_frame(&d)? {
            Frame::Pong { .. } => trace!("PTTH ACK PONG — buffer clean"),
            Frame::Data { .. } => debug!("Unexpected data frame after PTTH ACK PING"),
        },
        None => debug!("PTTH ACK PONG timed out"),
    }

    Ok(response)
}

/// Extract the `"value"` string field from a `{"value": "..."}` JSON body.
///
/// Returns an empty string on any parse failure so callers don't have to
/// handle errors for optional identity fields.
fn extract_string_value(body: &[u8]) -> String {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("value").and_then(|v| v.as_str()).map(str::to_string))
        .unwrap_or_default()
}

/// Select the protocol channel based on the request.
///
/// NREK is the long-poll channel; it is used **only** for `GET /datastore`
/// (the root, with `If-None-Match`).  All subtree GETs (`/datastore/avb/…`)
/// and all writes (POST, PATCH, DELETE) use one-shot PTTH.
///
/// Confirmed from usbmon capture: the Windows driver sends
/// `GET /datastore/avb/…` and `GET /datastore/host/…` over PTTH, never NREK.
fn select_channel(req: &Request) -> MessageType {
    if req.method == Method::Get && req.path == "/datastore" {
        MessageType::Nrek
    } else {
        MessageType::Ptth
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_select_channel_nrek_for_datastore_poll() {
        let req = Request::get("/datastore").header("If-None-Match", "6126");
        assert_eq!(select_channel(&req), MessageType::Nrek);
    }

    #[test]
    fn test_select_channel_nrek_for_initial_datastore() {
        let req = Request::get("/datastore");
        assert_eq!(select_channel(&req), MessageType::Nrek);
    }

    #[test]
    fn test_select_channel_ptth_for_post() {
        let req = Request::post("/datastore/host/os", br#"{"value":"win"}"#.to_vec());
        assert_eq!(select_channel(&req), MessageType::Ptth);
    }

    #[test]
    fn test_select_channel_ptth_for_non_datastore() {
        let req = Request::get("/other/path");
        assert_eq!(select_channel(&req), MessageType::Ptth);
    }

    #[test]
    fn test_select_channel_ptth_for_datastore_subtree() {
        // Subtree GETs are one-shot PTTH, not long-poll NREK.
        // Confirmed from Windows 10 usbmon capture:
        //   GET /datastore/avb/…  and  GET /datastore/host/…  both use PTTH.
        assert_eq!(select_channel(&Request::get("/datastore/avb/devs")), MessageType::Ptth);
        assert_eq!(select_channel(&Request::get("/datastore/host_type")), MessageType::Ptth);
        assert_eq!(select_channel(&Request::get("/datastore/avb/0001f2fffe00a4df/entity_name")), MessageType::Ptth);
    }
}
