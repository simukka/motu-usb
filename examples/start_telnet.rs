//! Example: Start telnetd on the MOTU 828ES via its hidden HTTP route.
//!
//! The device firmware exposes a `GET /start_telnet` route that calls
//! `system("/etc/init.d/telnetd start")`. This is a one-shot trigger —
//! the device sets an internal flag after the first call so subsequent
//! requests are no-ops. Confirmed from Ghidra analysis of `FUN_00071f50`
//! in MOTUAVBController.
//!
//! After running this example, connect with:
//!
//! ```sh
//! telnet 10.0.1.205
//! ```
//!
//! Usage:
//! ```sh
//! sudo cargo run --example start_telnet
//! ```

use motu_usb::{MotuDevice, Request};

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    println!("Connecting to MOTU 828ES...");
    let mut device = MotuDevice::connect().await?;
    println!("Connected!");

    // GET /start_telnet — device calls system("/etc/init.d/telnetd start").
    // No auth header required; registered as a public route alongside /apiversion.
    // One-shot: device sets an internal flag after first call, subsequent
    // requests return a response but do not re-execute the system() call.
    println!("\nSending GET /start_telnet...");
    let response = device.request(Request::get("/start_telnet")).await?;

    println!("Status: {}", response.status);

    if response.status == 200 || response.status == 204 {
        println!("telnetd started successfully.");
    } else {
        println!(
            "Unexpected status {}. telnetd may already be running, \
             or the one-shot flag was already set.",
            response.status
        );
    }

    Ok(())
}
