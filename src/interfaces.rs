//! This module provides tools for managing and finding info about
//! network interfaces.
//! It retrieves details like interface index, name, main IPv4 address,
//! and MAC address.
//! The Interface struct holds properties of a network interface.
//!
//! Included functions:
//! - from_name: Create Interface from its name.
//! - from_index: Create Interface from its index.
//! - get_interface_index: Find index by interface name.
//! - get_interface_name: Find name by interface index.
//! - get_primary_ipv4: Find primary IPv4 address of an interface.
//! - get_mac_address: Find MAC address of an interface.
//!
//! Uses nix crate for system network data and anyhow for errors.

use anyhow::{Result, anyhow};
use nix::ifaddrs::getifaddrs;
use nix::libc::{c_char, if_indextoname, if_nametoindex};
use std::ffi::{CStr, CString};

/// Represents a network interface with key properties.
///
/// Holds the interface name, index, primary IPv4 address, and MAC address.
#[derive(Debug)]
pub struct Interface {
    /// Name of the network interface (e.g. "eth0").
    pub name: String,
    /// Index of the interface assigned by the system.
    pub index: i32,
    /// Primary IPv4 address assigned to the interface.
    pub paddr: std::net::Ipv4Addr,
    /// MAC address of the interface (6 bytes).
    pub mac: [u8; 6],
}

impl Interface {
    /// Creates an Interface instance from its name.
    ///
    /// # Arguments
    ///
    /// * `name` - The string name of the interface (e.g. "eth0").
    ///
    /// # Errors
    ///
    /// Returns an error if the interface index, primary IPv4 address,
    /// or MAC address cannot be determined.
    ///
    /// # Examples
    ///
    /// ```
    /// use rdhcp::interfaces::Interface;
    ///
    /// let iface = Interface::from_name("lo")?;
    /// println!("{:?}", iface);
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn from_name(name: &str) -> Result<Self> {
        let index = get_interface_index(name)?;
        let paddr = get_primary_ipv4(name)?;
        let mac = get_mac_address(name)?;

        Ok(Self {
            name: name.to_string(),
            index: index as i32,
            paddr,
            mac,
        })
    }

    /// Creates an Interface instance from its index.
    ///
    /// # Arguments
    ///
    /// * `index` - The system-assigned index of the interface.
    ///
    /// # Errors
    ///
    /// Returns an error if the interface name, primary IPv4 address,
    /// or MAC address cannot be determined.
    ///
    /// # Examples
    ///
    /// ```
    /// use rdhcp::interfaces::Interface;
    ///
    /// let iface = Interface::from_index(2)?;
    /// println!("{:?}", iface);
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn from_index(index: u32) -> Result<Self> {
        let name = get_interface_name(index)?;
        let paddr = get_primary_ipv4(&name)?;
        let mac = get_mac_address(&name)?;

        Ok(Self {
            name,
            index: index as i32,
            paddr,
            mac,
        })
    }
}

/// Gets the interface index corresponding to a given interface name.
///
/// # Safety
/// This function safely wraps the unsafe libc call `if_nametoindex`.
/// It converts the Rust string to a CString to ensure null-termination,
/// then passes a pointer to that C string to the C function.
///
/// # Errors
/// Returns an error if:
/// - The input string contains interior null bytes (CString::new fails).
/// - The system call returns 0, indicating the interface was not found.
fn get_interface_index(name: &str) -> Result<u32> {
    // Convert Rust &str to CString to ensure null-terminated string for C API
    let c_name =
        CString::new(name).map_err(|e| anyhow!("Invalid interface name '{}': {}", name, e))?;

    // Unsafe block for calling the C function
    let index = unsafe {
        // if_nametoindex returns 0 if the interface is not found
        if_nametoindex(c_name.as_ptr())
    };

    // Check result and convert to Result type
    if index == 0 {
        Err(anyhow!("Unable to get index for interface '{}'", name))
    } else {
        Ok(index)
    }
}

/// Gets the interface name corresponding to a given index.
///
/// # Safety
/// This function wraps the unsafe libc call `if_indextoname`.
/// It provides a buffer to store the interface name, and uses the returned pointer.
/// The pointer returned is either NULL or points to the buffer.
/// We convert it to a Rust &CStr safely.
///
/// # Errors
/// Returns an error if the system call returns NULL, meaning no interface for that index.
fn get_interface_name(index: u32) -> Result<String> {
    // Buffer must be IF_NAMESIZE bytes to hold interface name plus NUL.
    // This size is defined by libc and guarantees sufficient space.
    let mut buf = [0 as u8; nix::libc::IF_NAMESIZE];

    // Unsafe block for C FFI call.
    let c_name = unsafe {
        let p = if_indextoname(index, buf.as_mut_ptr() as *mut c_char);
        // if_indextoname returns null pointer on failure.
        if p.is_null() {
            None
        } else {
            // It's safe to create a CStr from pointer since it's either NULL or buf.
            Some(CStr::from_ptr(p))
        }
    };

    // If no interface name found, return error.
    let Some(c_str) = c_name else {
        return Err(anyhow!("Unable to get name for interface index {}", index));
    };

    // Convert CStr to Rust String (UTF-8), propagating error if invalid.
    Ok(c_str.to_str()?.to_string())
}

/// Retrieves the primary IPv4 address assigned to the given network interface.
///
/// Iterates over all network interfaces found via `getifaddrs` and returns the first
/// IPv4 address matching the specified interface name.
///
/// # Arguments
///
/// * `interface_name` - The name of the network interface (e.g. "eth0").
///
/// # Errors
///
/// Returns an error if no IPv4 address is found for the given interface.
fn get_primary_ipv4(interface_name: &str) -> Result<std::net::Ipv4Addr> {
    for ifaddr in getifaddrs()? {
        if ifaddr.interface_name != interface_name {
            continue;
        }

        let Some(socket_addr) = ifaddr.address else {
            continue;
        };

        let Some(std_inet) = socket_addr.as_sockaddr_in() else {
            continue;
        };

        let ipv4_bytes = std_inet.ip().octets();
        let ipv4_addr =
            std::net::Ipv4Addr::new(ipv4_bytes[0], ipv4_bytes[1], ipv4_bytes[2], ipv4_bytes[3]);

        return Ok(ipv4_addr);
    }

    Err(anyhow!(
        "No IPv4 address found for interface '{}'",
        interface_name
    ))
}

/// Retrieves the MAC address of the specified network interface.
///
/// Iterates over the system's network interfaces using `getifaddrs`.
/// For the given interface name, it attempts to find a link-layer (MAC) address.
/// Returns the MAC address as a 6-byte array if found.
///
/// # Arguments
///
/// * `interface_name` - The name of the network interface to query (e.g., "eth0").
///
/// # Errors
///
/// Returns an error if no MAC address is found for the interface.
fn get_mac_address(interface_name: &str) -> Result<[u8; 6]> {
    for ifaddr in getifaddrs()? {
        if ifaddr.interface_name != interface_name {
            continue;
        }

        let Some(socket_addr) = &ifaddr.address else {
            continue;
        };

        let Some(link_addr) = socket_addr.as_link_addr() else {
            continue;
        };

        let Some(addr) = link_addr.addr() else {
            continue;
        };

        if addr.len() == 6 {
            let mut mac = [0u8; 6];
            mac.copy_from_slice(&addr);
            return Ok(mac);
        }
    }

    Err(anyhow!(
        "No MAC address found for interface '{}'",
        interface_name
    ))
}
