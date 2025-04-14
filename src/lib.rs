use std::fmt;
use std::net::Ipv4Addr;

use std::convert::From;

pub mod server;

#[repr(C)]
#[derive(Debug)]
pub enum DhcpOpCode {
    Request,
    Response,
    Invalid,
}

impl From<DhcpOpCode> for u8 {
    fn from(op: DhcpOpCode) -> Self {
        match op {
            DhcpOpCode::Request => 1u8,
            DhcpOpCode::Response => 2u8,
            DhcpOpCode::Invalid => 0u8,
        }
    }
}

impl From<u8> for DhcpOpCode {
    fn from(op: u8) -> Self {
        match op {
            1u8 => Self::Request,
            2u8 => Self::Response,
            _ => Self::Invalid,
        }
    }
}

impl fmt::Display for DhcpOpCode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let str = match self {
            DhcpOpCode::Request => "Request",
            DhcpOpCode::Response => "Response",
            DhcpOpCode::Invalid => "Invalid",
        };

        write!(f, "{str}")
    }
}

#[repr(C)]
#[derive(Debug)]
pub enum DhcpHType {
    Ethernet,
    IEEE802,
    ARCNET,
    Unknown,
}

impl From<DhcpHType> for u8 {
    fn from(value: DhcpHType) -> Self {
        match value {
            DhcpHType::Ethernet => 1u8,
            DhcpHType::IEEE802 => 6u8,
            DhcpHType::ARCNET => 7u8,
            DhcpHType::Unknown => 0u8,
        }
    }
}

impl From<u8> for DhcpHType {
    fn from(value: u8) -> Self {
        match value {
            1 => Self::Ethernet,
            6 => Self::IEEE802,
            7 => Self::ARCNET,
            _ => Self::Unknown,
        }
    }
}

impl fmt::Display for DhcpHType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let str = match self {
            DhcpHType::Ethernet => "Ethernet",
            DhcpHType::IEEE802 => "IEEE802",
            DhcpHType::ARCNET => "ARCNET",
            DhcpHType::Unknown => "Unknown",
        };

        write!(f, "{str}")
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub enum DhcpFlag {
    None = 0,
    Broadcast = 1 << 0,
    Unknown,
}

impl From<u16> for DhcpFlag {
    fn from(value: u16) -> Self {
        match value {
            1 => Self::Broadcast,
            _ => Self::Unknown,
        }
    }
}

impl fmt::Display for DhcpFlag {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let str = match self {
            DhcpFlag::None => "None",
            DhcpFlag::Broadcast => "Broadcast",
            DhcpFlag::Unknown => "Unknown",
        };

        write!(f, "{str}")
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct DhcpFlags {
    value: u16,
}

impl From<DhcpFlags> for u16 {
    fn from(value: DhcpFlags) -> Self {
        value.value
    }
}

impl From<u16> for DhcpFlags {
    fn from(value: u16) -> Self {
        Self { value }
    }
}

impl DhcpFlags {
    pub fn have(&self, flag: DhcpFlag) -> bool {
        (self.value & (flag as u16)) == (flag as u16)
    }

    pub fn add(&mut self, flag: DhcpFlag) {
        self.value = self.value | flag as u16;
    }
}

impl fmt::Display for DhcpFlags {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut s = "".to_string();

        if self.value == 0 {
            return write!(f, "<None>");
        }

        for i in 0u16..16u16 {
            let is_set = (self.value >> i) & 1 == 1;
            if !is_set {
                continue;
            }

            let flag = DhcpFlag::from(i);
            if s != "" {
                s += " | ";
            }
            s += &flag.to_string();
        }

        write!(f, "<{s}>")
    }
}

#[derive(Debug)]
pub struct DhcpHeader {
    op: DhcpOpCode,   // Message op code (1 byte)
    htype: DhcpHType, // Hardware address type (1 byte)
    hlen: u8,         // Hardware address length (1 byte)
    hops: u8,         // Number of hops (1 byte)
    xid: u32,         // Transaction ID (4 bytes)
    secs: u16,        // Seconds elapsed (2 bytes)
    flags: DhcpFlags, // Flags (2 bytes)
    ciaddr: u32,      // Client IP address (4 bytes)
    yiaddr: u32,      // Your IP address (4 bytes)
    siaddr: u32,      // Server IP address (4 bytes)
    giaddr: u32,      // Gateway IP address (4 bytes)
    chaddr: [u8; 16], // Client hardware address (16 bytes)
    sname: [u8; 64],  // Server name (64 bytes)
    file: [u8; 128],  // Boot file name (128 bytes)
}

// Struct to represent a DHCP packet, including options
#[derive(Debug)]
pub struct DhcpPacket {
    header: DhcpHeader,
    options: Vec<DhcpOption>,
}

#[derive(Debug)]
struct DhcpOption {
    code: u8,
    length: u8,
    value: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum DhcpMessageType {
    Discover = 1,
    Offer = 2,
    Request = 3,
    Decline = 4,
    Ack = 5,
    Nak = 6,
    Release = 7,
    Inform = 8,
    Unknown(u8),
}

impl DhcpPacket {
    pub fn message_type(&self) -> Option<DhcpMessageType> {
        for opt in &self.options {
            if opt.code == 53 && opt.length == 1 {
                return Some(match opt.value[0] {
                    1 => DhcpMessageType::Discover,
                    2 => DhcpMessageType::Offer,
                    3 => DhcpMessageType::Request,
                    4 => DhcpMessageType::Decline,
                    5 => DhcpMessageType::Ack,
                    6 => DhcpMessageType::Nak,
                    7 => DhcpMessageType::Release,
                    8 => DhcpMessageType::Inform,
                    other => DhcpMessageType::Unknown(other),
                });
            }
        }

        None
    }

    // Helper function to convert an IP address from a u32 to an Ipv4Addr
    fn ip_to_string(ip: u32) -> String {
        let ip_bytes = ip.to_be_bytes();
        Ipv4Addr::new(ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]).to_string()
    }

    // Method to decode and display the DHCP header information in a readable format
    pub fn decode_header(&self) {
        let op = &self.header.op;
        let htype = &self.header.htype;
        let flags = &self.header.flags;

        println!("DHCP Header Information:");
        println!("  Operation: {}", op);
        println!("  Hardware Type: {}", htype);
        println!("  Hardware Length: {}", self.header.hlen);
        println!("  Hops: {}", self.header.hops);
        println!("  Transaction ID (XID): {:#010x}", self.header.xid);
        println!("  Seconds: {}", self.header.secs);
        println!("  Flags: {}", flags);
        println!(
            "  Client IP: {}",
            DhcpPacket::ip_to_string(self.header.ciaddr)
        );
        println!(
            "  Your IP: {}",
            DhcpPacket::ip_to_string(self.header.yiaddr)
        );
        println!(
            "  Server IP: {}",
            DhcpPacket::ip_to_string(self.header.siaddr)
        );
        println!(
            "  Gateway IP: {}",
            DhcpPacket::ip_to_string(self.header.giaddr)
        );

        // Client MAC address
        let mac_addr = self
            .header
            .chaddr
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<String>>()
            .join(":");
        println!("  Client MAC Address: {}", mac_addr);

        // Print the server name and file
        let binding = String::from_utf8_lossy(&self.header.sname);
        let sname = binding.trim_matches(char::from(0));

        let binding = String::from_utf8_lossy(&self.header.file);
        let file = binding.trim_matches(char::from(0));

        /* This is bad, do not use println! in production code */
        println!("  Server Name: <{}>", sname);
        println!("  Boot File Name: <{}>", file);
    }
}

fn parse_dhcp_packet_priv(data: &[u8]) -> Option<DhcpPacket> {
    const HEADER_LEN: usize = 236;

    if data.len() < HEADER_LEN {
        return None;
    }

    let header = DhcpHeader {
        op: DhcpOpCode::from(data[0]),
        htype: DhcpHType::from(data[1]),
        hlen: data[2],
        hops: data[3],
        xid: u32::from_be_bytes(data[4..8].try_into().ok()?),
        secs: u16::from_be_bytes(data[8..10].try_into().ok()?),
        flags: DhcpFlags::from(u16::from_be_bytes(data[10..12].try_into().ok()?)),
        ciaddr: u32::from_be_bytes(data[12..16].try_into().ok()?),
        yiaddr: u32::from_be_bytes(data[16..20].try_into().ok()?),
        siaddr: u32::from_be_bytes(data[20..24].try_into().ok()?),
        giaddr: u32::from_be_bytes(data[24..28].try_into().ok()?),
        chaddr: data[28..44].try_into().ok()?,
        sname: data[44..108].try_into().ok()?,
        file: data[108..236].try_into().ok()?,
    };

    let options = data[236..].to_vec();

    Some(DhcpPacket {
        header,
        options: parse_dhcp_options(&options),
    })
}

fn parse_dhcp_options(data: &[u8]) -> Vec<DhcpOption> {
    let mut options = Vec::new();

    // Check for the DHCP magic cookie
    const DHCP_MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];
    if data.len() < 4 || data[0..4] != DHCP_MAGIC_COOKIE {
        eprintln!("Invalid DHCP magic cookie");
        return options;
    }

    let mut i = 4; // Start parsing after the magic cookie

    while i < data.len() {
        let code = data[i];

        match code {
            0 => {
                // Pad option (just move on)
                i += 1;
            }
            255 => {
                // End option
                break;
            }
            _ => {
                if i + 1 >= data.len() {
                    eprintln!("Malformed option at index {}", i);
                    break;
                }

                let length = data[i + 1] as usize;
                if i + 2 + length > data.len() {
                    eprintln!("Option (code {}) at index {} exceeds data length", code, i);
                    break;
                }

                let value = data[i + 2..i + 2 + length].to_vec();
                options.push(DhcpOption {
                    code,
                    length: length as u8,
                    value,
                });

                i += 2 + length;
            }
        }
    }

    options
}

pub fn parse_dhcp_packet(data: &[u8]) -> Result<DhcpPacket, String> {
    if let Some(packet) = parse_dhcp_packet_priv(data) {
        // Decode and display the header information
        packet.decode_header();

        return Ok(packet);
    }

    Err("Failed to parse DHCP packet".to_string())
}

#[cfg(test)]
mod tests {
    use crate::parse_dhcp_packet;
    use std::mem::MaybeUninit;

    #[test]
    fn test() {
        use socket2::{Domain, Socket, Type};
        use std::net::SocketAddr;

        let socket = Socket::new(Domain::IPV4, Type::DGRAM, None).unwrap();

        let address: SocketAddr = "0.0.0.0:67".parse().unwrap();
        // Set SO_REUSEADDR option on the socket
        socket.set_reuse_address(true).unwrap();
        // Allow receiving broadcast messages
        socket.set_broadcast(true).unwrap();

        // Set the socket to non-blocking mode
        socket.set_nonblocking(false).unwrap();

        // Bind the socket to port 68 (DHCP client port);
        socket.bind(&address.into()).unwrap();

        println!("Listening for DHCP packets on port 67...");

        loop {
            // Buffer to store the received data (using MaybeUninit for safety)
            let mut buf: [MaybeUninit<u8>; 1024] = unsafe { MaybeUninit::uninit().assume_init() };

            match socket.recv_from(&mut buf) {
                Ok((size, _)) => {
                    // Convert the buffer into a slice of u8
                    let data: Vec<u8> = buf[..size]
                        .iter()
                        .map(|b| unsafe { b.assume_init() })
                        .collect();

                    // Process the received DHCP packet
                    parse_dhcp_packet(&data);
                }
                Err(e) => {
                    println!("Error reading from socket: {}", e);
                }
            }
        }
    }
}
