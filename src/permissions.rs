/*
 * This includes all permission checks.
 * It may be a bit extra but I like having all checks in one place.
 */
use anyhow::Result;
use log::{debug, error};
use std::net::UdpSocket;

pub fn permissions_check_server() -> Result<()> {
    // to check if we are allowed to start a dhcp server we just try to bind the port
    let socket = UdpSocket::bind("0.0.0.0:67");
    match socket {
        Ok(_) => {
            debug!("Successfully bound to port 67");
            Ok(())
        }
        Err(e) => {
            error!("Permission denied to bind to port 67: {}", e);
            Err(anyhow::anyhow!(
                "Permission denied to bind to port 67: {}",
                e
            ))
        }
    }
}
