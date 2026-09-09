//! Example: Connect to a MOTU 828ES.
//! 
use motu_usb::{MotuDevice};

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    println!("Connecting to MOTU 828ES...");
    let device = MotuDevice::connect().await?;
    println!("Connected!");
    println!("MOTU {} ({}) Firmware {}", device.info.model_name, device.info.host_type, device.info.firmware_version);
    Ok(())
}
