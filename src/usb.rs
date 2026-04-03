//! USB device discovery and async bulk I/O for MOTU devices.

use crate::error::{MotuError, Result};
use nusb::transfer::RequestBuffer;
use tracing::{debug, info, warn};

/// MOTU USB vendor ID.
pub const MOTU_VID: u16 = 0x07FD;
/// MOTU USB product ID (shared across AVB devices).
pub const MOTU_PID: u16 = 0x0005;

/// 828ES vendor bulk interface number.
const INTERFACE_NUM: u8 = 5;
/// Bulk IN endpoint address.
const EP_BULK_IN: u8 = 0x83;
/// Bulk OUT endpoint address.
const EP_BULK_OUT: u8 = 0x04;

/// Maximum read size for bulk IN transfers (128 KB, enough for full datastore).
const MAX_READ_SIZE: usize = 131_072;

/// Wrapper around the nusb USB device for MOTU bulk communication.
pub struct MotuUsb {
    interface: nusb::Interface,
}

impl MotuUsb {
    /// Open the MOTU 828ES USB device and claim the vendor bulk interface.
    ///
    /// Searches for the device by VID/PID and claims interface 5 (FF/04/01).
    pub fn open() -> Result<Self> {
        let device_info = nusb::list_devices()?
            .find(|d| d.vendor_id() == MOTU_VID && d.product_id() == MOTU_PID)
            .ok_or(MotuError::DeviceNotFound)?;

        info!(
            "Found MOTU device: bus={} addr={}",
            device_info.bus_number(),
            device_info.device_address()
        );

        let device = device_info.open()?;

        // Detach kernel driver if active, then claim interface
        let interface = device.claim_interface(INTERFACE_NUM)?;

        info!("Claimed interface {INTERFACE_NUM}");

        Ok(Self { interface })
    }

    /// Write data to the bulk OUT endpoint.
    pub async fn write(&self, data: &[u8]) -> Result<()> {
        debug!("USB write: {} bytes", data.len());
        let completion = self.interface.bulk_out(EP_BULK_OUT, data.to_vec()).await;
        completion.status?;
        Ok(())
    }

    /// Read data from the bulk IN endpoint.
    ///
    /// Returns the complete transfer data. nusb handles USB-level reassembly
    /// of multi-packet bulk transfers automatically.
    pub async fn read(&self) -> Result<Vec<u8>> {
        let completion = self
            .interface
            .bulk_in(EP_BULK_IN, RequestBuffer::new(MAX_READ_SIZE))
            .await;
        completion.status?;
        let data = completion.data;
        debug!("USB read: {} bytes", data.len());
        Ok(data.to_vec())
    }

    /// Try to read data with a timeout.
    ///
    /// Returns `Ok(Some(data))` if data was received, `Ok(None)` on timeout.
    pub async fn read_timeout(&self, timeout: std::time::Duration) -> Result<Option<Vec<u8>>> {
        match tokio::time::timeout(timeout, self.read()).await {
            Ok(result) => result.map(Some),
            Err(_) => {
                warn!("USB read timed out after {:?}", timeout);
                Ok(None)
            }
        }
    }
}

impl std::fmt::Debug for MotuUsb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MotuUsb")
            .field("interface", &INTERFACE_NUM)
            .finish()
    }
}
