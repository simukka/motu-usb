//! Transport abstraction for MOTU USB communication.
//!
//! Provides a unified write/read interface over either real USB hardware
//! (`nusb`) or an in-process channel pair used for tests and the device
//! simulator.
//!
//! ## Design rationale (from tamio.c architecture)
//!
//! On the device, the FX3 USB firmware communicates with tamio's `L3Proxy`
//! via the ETunnel kernel module over a local TCP socket on port 17221.
//! `MotuTransport::Channel` mirrors that concept: the two `mpsc` channels act
//! as the "wire", letting the host-side `MotuDevice` and the in-process
//! `DeviceSimulator` exchange frames without real USB hardware.

use crate::error::{MotuError, Result};
use std::time::Duration;
use tokio::sync::{mpsc, Mutex};

/// Unified USB bulk I/O transport for host-side MOTU communication.
///
/// Two variants are provided:
///
/// * **`Usb`** — wraps a real `MotuUsb` device; use [`MotuTransport::usb`].
/// * **`Channel`** — in-process `mpsc` channel pair; use
///   [`MotuTransport::channel`] to obtain both sides.
pub enum MotuTransport {
    /// Real MOTU USB device accessed via nusb.
    Usb(crate::usb::MotuUsb),
    /// In-process channel pair (host side).
    Channel {
        /// Sends frames to the device.
        tx: mpsc::Sender<Vec<u8>>,
        /// Receives frames from the device.  Wrapped in a `Mutex` so that
        /// `MotuTransport` is `Sync` (required by Tokio async tasks), even
        /// though `mpsc::Receiver<T>` alone is not.
        rx: Mutex<mpsc::Receiver<Vec<u8>>>,
    },
}

impl MotuTransport {
    /// Wrap an open [`crate::usb::MotuUsb`] device.
    pub fn usb(usb: crate::usb::MotuUsb) -> Self {
        Self::Usb(usb)
    }

    /// Create an in-process channel transport pair.
    ///
    /// Returns `(host_transport, device_half)`.
    ///
    /// * Pass `host_transport` to [`crate::MotuDevice::connect_via`].
    /// * Pass `device_half` to [`crate::sim::DeviceSimulator::new`].
    ///
    /// The channel buffer is 256 frames deep — enough to hold a full chunked
    /// NREK response without back-pressure.
    pub fn channel() -> (Self, ChannelHalf) {
        // host → device direction
        let (host_tx, device_rx) = mpsc::channel::<Vec<u8>>(256);
        // device → host direction
        let (device_tx, host_rx) = mpsc::channel::<Vec<u8>>(256);

        let host = Self::Channel {
            tx: host_tx,
            rx: Mutex::new(host_rx),
        };
        let device = ChannelHalf {
            tx: device_tx,
            rx: device_rx,
        };
        (host, device)
    }

    /// Write a frame to the device (bulk OUT equivalent).
    pub async fn write(&self, data: &[u8]) -> Result<()> {
        match self {
            Self::Usb(usb) => usb.write(data).await,
            Self::Channel { tx, .. } => tx
                .send(data.to_vec())
                .await
                .map_err(|_| MotuError::Protocol("host→device channel closed".into())),
        }
    }

    /// Receive the next frame from the device (bulk IN equivalent).
    pub async fn read(&self) -> Result<Vec<u8>> {
        match self {
            Self::Usb(usb) => usb.read().await,
            Self::Channel { rx, .. } => {
                let mut rx = rx.lock().await;
                rx.recv()
                    .await
                    .ok_or_else(|| MotuError::Protocol("device→host channel closed".into()))
            }
        }
    }

    /// Receive the next frame with a deadline, returning `None` on timeout.
    pub async fn read_timeout(&self, timeout: Duration) -> Result<Option<Vec<u8>>> {
        match self {
            Self::Usb(usb) => usb.read_timeout(timeout).await,
            Self::Channel { rx, .. } => {
                // Lock then apply timeout only to the recv() — locking is
                // always instantaneous in single-task tests.
                let mut rx = rx.lock().await;
                match tokio::time::timeout(timeout, rx.recv()).await {
                    Ok(Some(data)) => Ok(Some(data)),
                    Ok(None) => Err(MotuError::Protocol("device→host channel closed".into())),
                    Err(_elapsed) => Ok(None),
                }
            }
        }
    }
}

impl std::fmt::Debug for MotuTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Usb(_) => f.write_str("MotuTransport::Usb"),
            Self::Channel { .. } => f.write_str("MotuTransport::Channel"),
        }
    }
}

// ─── Device side ────────────────────────────────────────────────────────────

/// The device side of a [`MotuTransport::channel`] pair.
///
/// Pass this to [`crate::sim::DeviceSimulator::new`].
pub struct ChannelHalf {
    /// Sends frames to the host.
    pub tx: mpsc::Sender<Vec<u8>>,
    /// Receives frames from the host.
    pub rx: mpsc::Receiver<Vec<u8>>,
}
