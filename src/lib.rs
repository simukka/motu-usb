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
pub mod types;
pub mod usb;

pub use error::{MotuError, Result};
pub use types::{Frame, MessageType, Method, Request, Response};

use protocol::{SessionState, decode_frame, encode_connect, encode_data, encode_ping};
use std::time::Duration;
use tracing::{debug, info, trace, warn};
use usb::MotuUsb;

/// Default timeout for waiting for a response from the device.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// Timeout for PONG responses to CONNECT/PING.
const PONG_TIMEOUT: Duration = Duration::from_secs(2);

/// Maximum number of chunks to receive for a single response.
const MAX_CHUNKS: usize = 256;

/// High-level interface to a MOTU device over USB.
///
/// Handles the CONNECT handshake, PING/PONG keepalive, protocol framing,
/// and binary HTTP codec transparently.
#[derive(Debug)]
pub struct MotuDevice {
    usb: MotuUsb,
    state: SessionState,
}

impl MotuDevice {
    /// Connect to a MOTU 828ES device.
    ///
    /// Opens the USB device, claims the vendor bulk interface, sends a
    /// CONNECT frame, and waits for the PONG acknowledgment.
    pub async fn connect() -> Result<Self> {
        let usb = MotuUsb::open()?;
        let mut state = SessionState::new();

        // Send CONNECT
        let connect_frame = encode_connect(&mut state);
        info!("Sending CONNECT");
        usb.write(&connect_frame).await?;

        // Wait for PONG
        let data = usb
            .read_timeout(PONG_TIMEOUT)
            .await?
            .ok_or_else(|| MotuError::Timeout)?;

        match decode_frame(&data)? {
            Frame::Pong { echoed_seq } => {
                info!("Connected (PONG echoed seq=0x{echoed_seq:02x})");
            }
            other => {
                warn!("Expected PONG after CONNECT, got: {other:?}");
            }
        }

        Ok(Self { usb, state })
    }

    /// Send a PING and wait for the PONG response.
    pub async fn ping(&mut self) -> Result<()> {
        let ping_frame = encode_ping(&mut self.state);
        self.usb.write(&ping_frame).await?;

        let data = self
            .usb
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
    /// the request. Handles PING/PONG interleaving and chunked response
    /// reassembly for large responses.
    pub async fn request(&mut self, req: Request) -> Result<Response> {
        let msg_type = select_channel(&req);
        debug!(
            "{} {} via {:?}",
            req.method, req.path, msg_type
        );

        // Encode the HTTP request as binary payload
        let payload = codec::encode_request(&req);

        // Wrap in protocol frame and send
        let frame = encode_data(&mut self.state, msg_type, &payload);
        self.usb.write(&frame).await?;

        // Read the PONG acknowledgment for our data frame
        self.read_pong().await?;

        // Now read the actual response.
        // Large responses come as multiple chunked data frames interleaved
        // with PING/PONG exchanges.
        self.read_response(msg_type).await
    }

    /// Read a PONG, handling any interleaved data frames.
    async fn read_pong(&mut self) -> Result<()> {
        let data = self
            .usb
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
    /// For large responses (e.g., full /datastore dump), the device sends
    /// multiple 4096-byte NREK frames with incrementing `chunk_idx`. The host
    /// must PING between chunks to keep the transfer going.
    async fn read_response(&mut self, _expected_type: MessageType) -> Result<Response> {
        let mut response_payload = Vec::new();
        let mut chunks_received = 0;

        loop {
            if chunks_received >= MAX_CHUNKS {
                return Err(MotuError::Protocol(format!(
                    "exceeded maximum chunk count ({MAX_CHUNKS})"
                )));
            }

            let data = self
                .usb
                .read_timeout(DEFAULT_TIMEOUT)
                .await?
                .ok_or_else(|| {
                    if response_payload.is_empty() {
                        MotuError::Timeout
                    } else {
                        MotuError::Protocol(format!(
                            "timeout after receiving {} chunks ({} bytes)",
                            chunks_received,
                            response_payload.len()
                        ))
                    }
                })?;

            match decode_frame(&data)? {
                Frame::Pong { .. } => {
                    // PONG during response — this happens when we PING between chunks.
                    trace!("PONG during response read");
                    continue;
                }
                Frame::Data {
                    chunk_idx,
                    payload,
                    msg_seq,
                    ..
                } => {
                    debug!(
                        "Received chunk {} ({} bytes, msg_seq={})",
                        chunk_idx,
                        payload.len(),
                        msg_seq
                    );

                    if chunk_idx == 0 && chunks_received == 0 {
                        // First chunk — this contains the response headers.
                        response_payload.extend_from_slice(&payload);
                    } else {
                        // Continuation chunk — raw body bytes, no headers.
                        response_payload.extend_from_slice(&payload);
                    }
                    chunks_received += 1;

                    // If this chunk is smaller than 4068 bytes (4096 - 28 header),
                    // it's the last one. Also check for small single-chunk responses.
                    if payload.len() < 4068 || chunk_idx == 0 {
                        // For single-chunk responses (chunk_idx == 0), we're done
                        // unless the response payload length suggests more chunks.
                        if chunk_idx == 0 {
                            // Single chunk response — done.
                            break;
                        }
                        if payload.len() < 4068 {
                            // Short chunk = last chunk.
                            break;
                        }
                    }

                    // Send PING to request the next chunk.
                    let ping_frame = encode_ping(&mut self.state);
                    self.usb.write(&ping_frame).await?;
                }
            }
        }

        // Decode the assembled binary payload
        codec::decode_response(&response_payload)
    }
}

/// Select the protocol channel based on the request.
///
/// NREK is used for GET /datastore with ETag (long-poll) — the lightweight channel.
/// PTTH is used for everything else (POST, other paths, etc.).
fn select_channel(req: &Request) -> MessageType {
    if req.method == Method::Get
        && req.path == "/datastore"
        && req.headers.iter().any(|(k, _)| k == "If-None-Match")
    {
        MessageType::Nrek
    } else if req.method == Method::Get && req.path.starts_with("/datastore") {
        // From capture: initial GET /datastore (no ETag) also uses NREK
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
}
