use thiserror::Error;

/// Errors that can occur when communicating with a MOTU device.
#[derive(Debug, Error)]
pub enum MotuError {
    #[error("USB error: {0}")]
    Usb(#[from] nusb::Error),

    #[error("USB transfer error: {0}")]
    Transfer(#[from] nusb::transfer::TransferError),

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("Codec error: {0}")]
    Codec(String),

    #[error("MOTU device not found")]
    DeviceNotFound,

    #[error("Operation timed out")]
    Timeout,
}

pub type Result<T> = std::result::Result<T, MotuError>;
