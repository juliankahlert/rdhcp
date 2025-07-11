//! Check that the program can start a DHCP server.
//!
//! This tries to open a UDP socket on port 67 (the standard DHCP server port).
//! If it can bind to that port, it means the program has permission to run a DHCP server.
//! If not, it returns an error with a message explaining the problem.
use anyhow::Result;
use log::{debug, error};
use std::net::UdpSocket;

/// Check if the program has permission to bind to UDP port 67, the standard DHCP server port.
///
/// # Returns
///
/// - `Ok(())` if the program can bind to port 67, indicating permission to run a DHCP server.
/// - `Err` with a descriptive error message if binding to the port fails.
///
/// # Errors
///
/// This function returns an error if it cannot bind to UDP port 67, which usually indicates
/// a permission issue (e.g., not running as root or the port is already in use).
pub fn permissions_check_server() -> Result<()> {
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
