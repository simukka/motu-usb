//! Example: Connect to a MOTU 828ES and fetch the datastore.

use motu_usb::{MotuDevice, Request};

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    println!("Connecting to MOTU 828ES...");
    let mut device = MotuDevice::connect().await?;
    println!("Connected!");

    // Send initial GET /datastore request
    println!("\nFetching /datastore...");
    let response = device
        .request(Request::get("/datastore"))
        .await?;

    println!("Status: {}", response.status);
    for (name, value) in &response.headers {
        println!("  {name}: {value}");
    }

    if let Ok(body) = response.body_text() {
        if body.len() > 500 {
            println!("\nBody ({} bytes, first 500 chars):", body.len());
            println!("{}", &body[..500]);
            println!("...");
        } else {
            println!("\nBody:\n{body}");
        }
    } else {
        println!("\nBody: ({} bytes, non-UTF8)", response.body.len());
    }

    Ok(())
}
