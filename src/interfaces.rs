use anyhow::{Result, anyhow};
use nix::ifaddrs::getifaddrs;
use nix::libc::{if_indextoname, if_nametoindex};
use std::ffi::{CStr, CString};

#[derive(Debug)]
pub struct Interface {
    pub name: String,
    pub index: i32,
    pub paddr: std::net::Ipv4Addr,
    pub mac: [u8; 6],
}

impl Interface {
    pub fn from_name(name: &str) -> Result<Self> {
        let index = get_interface_index(name)?;
        let paddr = get_primary_ipv4(name)?
            .ok_or_else(|| anyhow!("No IPv4 address found for interface '{}'", name))?;
        let mac = get_mac_address(name)?;
        Ok(Self {
            name: name.to_string(),
            index: index as i32,
            paddr,
            mac,
        })
    }

    pub fn from_index(index: u32) -> Result<Self> {
        let name = get_interface_name(index)?;
        let paddr = get_primary_ipv4(&name)?
            .ok_or_else(|| anyhow!("No IPv4 address found for interface '{}'", name))?;
        let mac = get_mac_address(&name)?;
        Ok(Self {
            name,
            index: index as i32,
            paddr,
            mac,
        })
    }
}

fn get_interface_index(name: &str) -> Result<u32> {
    let c_name = CString::new(name)?;
    let index = unsafe { if_nametoindex(c_name.as_ptr()) };
    if index == 0 {
        Err(anyhow!("Unable to get index for interface '{}'", name))
    } else {
        Ok(index)
    }
}

fn get_interface_name(index: u32) -> Result<String> {
    let mut buf = [0 as u8; nix::libc::IF_NAMESIZE];
    let ptr = unsafe { if_indextoname(index, buf.as_mut_ptr()) };
    if ptr.is_null() {
        Err(anyhow!("Unable to get name for interface index {}", index))
    } else {
        let c_str = unsafe { CStr::from_ptr(ptr) };
        Ok(c_str.to_str()?.to_string())
    }
}

fn get_primary_ipv4(interface_name: &str) -> Result<Option<std::net::Ipv4Addr>> {
    for ifaddr in getifaddrs()? {
        if ifaddr.interface_name == interface_name {
            match ifaddr.address {
                Some(socket_addr) => {
                    if let Some(std_inet) = socket_addr.as_sockaddr_in() {
                        let ipv4_bytes = std_inet.ip().octets();
                        let ipv4_addr = std::net::Ipv4Addr::new(
                            ipv4_bytes[0],
                            ipv4_bytes[1],
                            ipv4_bytes[2],
                            ipv4_bytes[3],
                        );
                        return Ok(Some(ipv4_addr));
                    }
                }
                None => {}
            }
        }
    }
    Ok(None)
}

fn get_mac_address(interface_name: &str) -> Result<[u8; 6]> {
    for ifaddr in getifaddrs()? {
        if ifaddr.interface_name == interface_name {
            if let Some(socket_addr) = &ifaddr.address {
                if let Some(link_addr) = socket_addr.as_link_addr() {
                    let Some(addr) = link_addr.addr() else {
                        continue;
                    };

                    if addr.len() == 6 {
                        let mut mac = [0u8; 6];
                        mac.copy_from_slice(&addr);
                        return Ok(mac);
                    }
                }
            }
        }
    }
    Err(anyhow!(
        "No MAC address found for interface '{}'",
        interface_name
    ))
}
