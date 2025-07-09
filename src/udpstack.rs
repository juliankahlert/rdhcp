use log::{debug, error};
use std::net::Ipv4Addr;

/// Ethernet frame structure for Layer 2 networking
/// Holds destination/source MAC addresses, EtherType and payload bytes
/// Typical use is to encapsulate IPv4 or ARP packets
pub struct EthernetFrame {
    pub destination: [u8; 6], // Destination MAC address
    pub source: [u8; 6],      // Source MAC address
    pub ethertype: u16,       // EtherType field (e.g. 0x0800 for IPv4)
    pub payload: Vec<u8>,     // Frame payload (Layer 3 packet)
}

impl EthernetFrame {
    /// Creates a new EthernetFrame from given components
    ///
    /// # Arguments
    ///
    /// * `destination` - Destination MAC address as a 6-byte array
    /// * `source` - Source MAC address as a 6-byte array
    /// * `ethertype` - EtherType field indicating the protocol encapsulated in the payload (e.g., 0x0800 for IPv4)
    /// * `payload` - Payload bytes contained in the Ethernet frame
    pub fn new(destination: [u8; 6], source: [u8; 6], ethertype: u16, payload: Vec<u8>) -> Self {
        EthernetFrame {
            destination,
            source,
            ethertype,
            payload,
        }
    }

    /// Create an EthernetFrame encapsulating an IPv4 packet
    ///
    /// # Arguments
    ///
    /// * `destination` - Destination MAC address as a 6-byte array
    /// * `source` - Source MAC address as a 6-byte array
    /// * `payload` - The IPv4 packet to encapsulate inside the Ethernet frame
    pub fn form_ipv4(destination: [u8; 6], source: [u8; 6], mut payload: IpFrame) -> Self {
        EthernetFrame {
            destination,
            source,
            ethertype: 0x0800, // IPv4 EtherType
            payload: payload.to_bytes(),
        }
    }

    /// Construct an EthernetFrame from a UDP frame by wrapping it in an IPv4 packet
    ///
    /// # Arguments
    ///
    /// * `destination` - Destination MAC address as a 6-byte array
    /// * `source` - Source MAC address as a 6-byte array
    /// * `udp_frame` - The UDP frame to encapsulate inside the IPv4 packet
    /// * `identification` - IPv4 packet identification field
    /// * `ttl` - Optional time-to-live value for the IPv4 packet (defaults to 128 if None)
    /// * `ipv4_options` - Optional vector of IPv4 header options bytes
    pub fn from_udp(
        destination: [u8; 6],
        source: [u8; 6],
        udp_frame: UdpFrame,
        identification: u16,
        ttl: Option<u8>,
        ipv4_options: Option<Vec<u8>>,
    ) -> Self {
        let ttl = ttl.unwrap_or(128);
        let mut ip_frame = IpFrame::udp(udp_frame, identification, ttl, ipv4_options);
        EthernetFrame {
            destination,
            source,
            ethertype: 0x0800,
            payload: ip_frame.to_bytes(),
        }
    }

    /// Construct an EthernetFrame from raw datagram payload with UDP encapsulation
    /// Includes IP addresses, ports, identification, TTL and optional IPv4 header options
    ///
    /// # Arguments
    ///
    /// * `destination` - Destination MAC address as a 6-byte array
    /// * `source` - Source MAC address as a 6-byte array
    /// * `payload` - UDP payload data as a vector of bytes
    /// * `source_ip` - Source IPv4 address
    /// * `destination_ip` - Destination IPv4 address
    /// * `source_port` - Source UDP port number
    /// * `destination_port` - Destination UDP port number
    /// * `identification` - IPv4 packet identification field for fragmentation
    /// * `ttl` - Optional Time-To-Live value for the IP header, defaults to 128 if None
    /// * `ipv4_options` - Optional IPv4 header options as a vector of bytes
    pub fn from_datagram(
        destination: [u8; 6],
        source: [u8; 6],
        payload: Vec<u8>,
        source_ip: Ipv4Addr,
        destination_ip: Ipv4Addr,
        source_port: u16,
        destination_port: u16,
        identification: u16,
        ttl: Option<u8>,
        ipv4_options: Option<Vec<u8>>,
    ) -> Self {
        let ttl = ttl.unwrap_or(128);
        let udp_frame = UdpFrame::new(
            source_port,
            destination_port,
            payload,
            source_ip,
            destination_ip,
        );
        let mut ip_frame = IpFrame::udp(udp_frame, identification, ttl, ipv4_options);
        EthernetFrame {
            destination,
            source,
            ethertype: 0x0800,
            payload: ip_frame.to_bytes(),
        }
    }

    /// Convenience constructor for DHCP packets
    ///
    /// # Arguments
    ///
    /// * `destination` - Destination MAC address as a 6-byte array
    /// * `payload` - The DHCP payload as a vector of bytes
    /// * `source_ip` - Source IPv4 address from which the DHCP packet originates
    /// * `destination_ip` - Destination IPv4 address to which the DHCP packet is sent
    /// * `source_port` - Source UDP port number (usually DHCP client port 68)
    /// * `destination_port` - Destination UDP port number (usually DHCP server port 67)
    /// * `identification` - IPv4 packet identification field for fragmentation
    pub fn from_dhcp(
        destination: [u8; 6],
        payload: Vec<u8>,
        source_ip: Ipv4Addr,
        destination_ip: Ipv4Addr,
        source_port: u16,
        destination_port: u16,
        identification: u16,
    ) -> Self {
        Self::from_datagram(
            destination,
            [0; 6], // source MAC set to zero
            payload,
            source_ip,
            destination_ip,
            source_port,
            destination_port,
            identification,
            None,
            None,
        )
    }

    /// Convenience method for building DHCP server responses
    ///
    /// # Arguments
    ///
    /// * `destination` - Destination MAC address as a 6-byte array
    /// * `payload` - The DHCP payload as a vector of bytes
    /// * `source_ip` - Source IPv4 address from which the DHCP packet originates
    /// * `destination_ip` - Destination IPv4 address to which the DHCP packet is sent
    /// * `identification` - IPv4 packet identification field for fragmentation
    pub fn from_dhcp_response(
        destination: [u8; 6],
        payload: Vec<u8>,
        source_ip: Ipv4Addr,
        destination_ip: Ipv4Addr,
        identification: u16,
    ) -> Self {
        Self::from_dhcp(
            destination,
            payload,
            source_ip,
            destination_ip,
            67, // DHCP server port
            68, // DHCP client port
            identification,
        )
    }

    /// Serialize the Ethernet frame into a byte vector suitable for sending
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut frame = Vec::with_capacity(14 + self.payload.len());
        frame.extend_from_slice(&self.destination);
        frame.extend_from_slice(&self.source);
        frame.extend_from_slice(&self.ethertype.to_be_bytes());
        frame.extend_from_slice(&self.payload);
        frame
    }

    /// Send the Ethernet frame on the specified interface using a raw socket
    ///
    /// # Arguments
    ///
    /// * `iface_name` - Name of the network interface to send the Ethernet frame on (e.g. "eth0")
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on successful transmission, or an `io::Error` if socket creation,
    /// interface lookup, frame sending, or other system calls fail.
    ///
    /// This method opens a raw AF_PACKET socket, retrieves the interface index and MAC address,
    /// builds a sockaddr_ll for sending, and sends the Ethernet frame bytes directly.
    pub fn send_on(mut self, iface_name: &str) -> std::io::Result<()> {
        use nix::libc;
        use std::ffi::CString;
        use std::io::{Error, ErrorKind};

        debug!(
            "Preparing to send Ethernet frame on interface '{}'",
            iface_name
        );

        // Open raw socket to send Ethernet frames
        let socket_fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW,
                libc::htons(libc::ETH_P_ALL as u16) as i32,
            )
        };
        if socket_fd < 0 {
            let err = Error::last_os_error();
            error!("Failed to open raw socket: {}", err);
            return Err(err);
        }
        debug!("Raw socket opened with fd {}", socket_fd);

        // Convert interface name to CString
        let ifname_c = match CString::new(iface_name) {
            Ok(name) => {
                debug!("Interface name converted to CString successfully");
                name
            }
            Err(_) => {
                error!("Invalid interface name provided: '{}'", iface_name);
                unsafe {
                    libc::close(socket_fd);
                }
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "Invalid interface name",
                ));
            }
        };

        // Retrieve interface index using ioctl
        let if_index = unsafe {
            let mut ifr: libc::ifreq = std::mem::zeroed();
            // Copy interface name (up to IFNAMSIZ)
            for (dst, src) in ifr.ifr_name.iter_mut().zip(ifname_c.as_bytes_with_nul()) {
                *dst = *src as libc::c_char;
            }
            debug!("Calling ioctl to get interface index for '{}'", iface_name);
            if libc::ioctl(socket_fd, libc::SIOCGIFINDEX, &mut ifr) < 0 {
                let err = Error::last_os_error();
                error!("ioctl SIOCGIFINDEX failed: {}", err);
                libc::close(socket_fd);
                return Err(err);
            }
            ifr.ifr_ifru.ifru_ifindex
        };

        // Get MAC address (hardware address)
        let if_mac = unsafe {
            let mut ifr: libc::ifreq = std::mem::zeroed();
            for (dst, src) in ifr.ifr_name.iter_mut().zip(ifname_c.as_bytes_with_nul()) {
                *dst = *src as libc::c_char;
            }
            debug!("Calling ioctl to get MAC address for '{}'", iface_name);
            if libc::ioctl(socket_fd, libc::SIOCGIFHWADDR, &mut ifr) < 0 {
                let err = Error::last_os_error();
                error!("ioctl SIOCGIFHWADDR failed: {}", err);
                libc::close(socket_fd);
                return Err(err);
            }
            let sa_data = ifr.ifr_ifru.ifru_hwaddr.sa_data;
            [
                sa_data[0] as u8,
                sa_data[1] as u8,
                sa_data[2] as u8,
                sa_data[3] as u8,
                sa_data[4] as u8,
                sa_data[5] as u8,
            ]
        };

        self.source = if_mac;

        if if_index <= 0 {
            unsafe {
                libc::close(socket_fd);
            }
            error!("Invalid interface index obtained: {}", if_index);
            return Err(Error::new(ErrorKind::Other, "Invalid interface index"));
        }
        debug!("Interface '{}' has index {}", iface_name, if_index);

        // Prepare sockaddr_ll struct for sendto
        let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        sll.sll_family = libc::AF_PACKET as libc::c_ushort;
        sll.sll_ifindex = if_index;
        sll.sll_halen = 6;
        sll.sll_addr[..6].copy_from_slice(&self.destination);

        debug!(
            "Sending to MAC address {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.destination[0],
            self.destination[1],
            self.destination[2],
            self.destination[3],
            self.destination[4],
            self.destination[5]
        );

        // Convert EthernetFrame to bytes
        let frame_bytes = self.to_bytes();
        debug!("Frame length: {} bytes", frame_bytes.len());

        // Send frame
        let send_result = unsafe {
            libc::sendto(
                socket_fd,
                frame_bytes.as_ptr() as *const libc::c_void,
                frame_bytes.len(),
                0,
                &sll as *const libc::sockaddr_ll as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };

        // Close socket
        unsafe {
            libc::close(socket_fd);
        }
        debug!("Raw socket with fd {} closed", socket_fd);

        if send_result < 0 {
            let err = Error::last_os_error();
            error!("Failed to send Ethernet frame: {}", err);
            return Err(err);
        }

        debug!(
            "Ethernet frame sent successfully, bytes sent: {}",
            send_result
        );

        Ok(())
    }
}

/// IPv4 packet structure with header and payload
/// Supports optional IP header options, computes checksums as needed
pub struct IpFrame {
    pub version_ihl: u8,          // Combined version and header length (IHL)
    pub dscp_ecn: u8, // Differentiated Services Code Point and Explicit Congestion Notification
    pub total_length: u16, // Total length of IP packet (header + payload)
    pub identification: u16, // Identification field
    pub flags_fragment: u16, // Flags and fragment offset
    pub ttl: u8,      // Time To Live
    pub protocol: u8, // Encapsulated protocol number (e.g. 17 for UDP)
    pub header_checksum: u16, // Header checksum (auto-computed)
    pub source: Ipv4Addr, // Source IP address
    pub destination: Ipv4Addr, // Destination IP address
    pub options: Option<Vec<u8>>, // Optional header options
    pub payload: Vec<u8>, // Encapsulated payload bytes
}

impl IpFrame {
    /// Constructs a new IP frame from given parameters
    /// Automatically calculates IHL, total length, and zeroes checksum for later calculation
    pub fn new(
        source: Ipv4Addr,
        destination: Ipv4Addr,
        protocol: u8,
        payload: Vec<u8>,
        options: Option<Vec<u8>>, // default None
        identification: u16,
        ttl: u8,
    ) -> Self {
        let ihl = 5 + if let Some(ref opts) = options {
            (opts.len() as u8 + 3) / 4 // header length in 32-bit words
        } else {
            0
        };
        let version_ihl = (4 << 4) | (ihl & 0x0f);
        let total_length = (ihl as usize * 4 + payload.len()) as u16;

        IpFrame {
            version_ihl,
            dscp_ecn: 0,
            total_length,
            identification,
            flags_fragment: 0,
            ttl,
            protocol,
            header_checksum: 0, // to be computed later
            source,
            destination,
            options,
            payload,
        }
    }

    /// Convenience method to build an IP frame carrying a UDP frame
    /// Handles encapsulation of UDP into IP packet with specified identification, ttl, and optional options
    pub fn udp(
        mut udp_frame: UdpFrame,
        identification: u16,
        ttl: u8,
        options: Option<Vec<u8>>,
    ) -> Self {
        let payload = udp_frame.to_bytes();
        let ihl = 5 + if let Some(ref opts) = options {
            (opts.len() as u8 + 3) / 4
        } else {
            0
        };
        let version_ihl = (4 << 4) | (ihl & 0x0f);
        let total_length = (ihl as usize * 4 + payload.len()) as u16;

        IpFrame {
            version_ihl,
            dscp_ecn: 0,
            total_length,
            identification,
            flags_fragment: 0,
            ttl,
            protocol: 17, // UDP protocol number
            header_checksum: 0,
            source: udp_frame.source_ip,
            destination: udp_frame.destination_ip,
            options,
            payload,
        }
    }

    /// Compute IP header checksum over given header bytes
    /// Implements standard checksum algorithm for IP headers
    fn compute_checksum(header: &[u8]) -> u16 {
        let mut sum = 0u32;
        let mut i = 0;
        while i < header.len() {
            let word = if i + 1 < header.len() {
                ((header[i] as u16) << 8) | (header[i + 1] as u16)
            } else {
                (header[i] as u16) << 8
            };
            sum = sum.wrapping_add(word as u32);
            i += 2;
        }

        while (sum >> 16) != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }

        !(sum as u16)
    }

    /// Build IPv4 header bytes, compute and fill the checksum
    pub fn build_header(&mut self) -> Vec<u8> {
        let ihl_bytes = (self.version_ihl & 0x0f) * 4;
        let mut header = Vec::with_capacity(ihl_bytes as usize);
        header.push(self.version_ihl);
        header.push(self.dscp_ecn);
        header.extend_from_slice(&self.total_length.to_be_bytes());
        header.extend_from_slice(&self.identification.to_be_bytes());
        header.extend_from_slice(&self.flags_fragment.to_be_bytes());
        header.push(self.ttl);
        header.push(self.protocol);
        header.extend_from_slice(&[0, 0]); // checksum placeholder
        header.extend_from_slice(&self.source.octets());
        header.extend_from_slice(&self.destination.octets());

        if let Some(ref opts) = self.options {
            header.extend_from_slice(opts);
        }

        let checksum = IpFrame::compute_checksum(&header);
        header[10] = (checksum >> 8) as u8;
        header[11] = (checksum & 0xff) as u8;

        header
    }

    /// Serialize the full IP frame including header and payload
    pub fn to_bytes(&mut self) -> Vec<u8> {
        let header = self.build_header();
        let mut frame = Vec::with_capacity(header.len() + self.payload.len());
        frame.extend_from_slice(&header);
        frame.extend_from_slice(&self.payload);
        frame
    }
}

/// UDP frame structure
/// Contains source/destination ports, length, checksum and payload data
/// Also includes source and destination IP addresses for checksum calculation
pub struct UdpFrame {
    pub source_port: u16,
    pub destination_port: u16,
    pub length: u16,
    pub checksum: u16,
    pub payload: Vec<u8>,
    pub source_ip: Ipv4Addr,
    pub destination_ip: Ipv4Addr,
}

impl UdpFrame {
    /// Create a new UDP frame with given ports and payload
    /// Length is computed from payload + UDP header size
    pub fn new(
        source_port: u16,
        destination_port: u16,
        payload: Vec<u8>,
        source_ip: Ipv4Addr,
        destination_ip: Ipv4Addr,
    ) -> Self {
        let length = (8 + payload.len()) as u16;

        UdpFrame {
            source_port,
            destination_port,
            length,
            checksum: 0, // checksum will be computed later
            payload,
            source_ip,
            destination_ip,
        }
    }

    /// Compute UDP checksum including pseudo-header
    /// This function sums the UDP header, payload, and pseudo-header fields (source/destination IPs, protocol, UDP length)
    fn compute_checksum(&self, buf: &[u8]) -> u16 {
        let mut sum = 0u32;

        // Pseudo-header fields: source IP
        let src = self.source_ip.octets();
        let dst = self.destination_ip.octets();
        let protocol = 17u8;
        let udp_length = self.length;

        for i in (0..src.len()).step_by(2) {
            let word = ((src[i] as u16) << 8) | (src[i + 1] as u16);
            sum = sum.wrapping_add(word as u32);
        }
        for i in (0..dst.len()).step_by(2) {
            let word = ((dst[i] as u16) << 8) | (dst[i + 1] as u16);
            sum = sum.wrapping_add(word as u32);
        }

        sum = sum.wrapping_add(protocol as u32);
        sum = sum.wrapping_add(udp_length as u32);

        // Add UDP header and payload
        let mut i = 0;
        while i < buf.len() {
            let word = if i + 1 < buf.len() {
                ((buf[i] as u16) << 8) | (buf[i + 1] as u16)
            } else {
                (buf[i] as u16) << 8
            };
            sum = sum.wrapping_add(word as u32);
            i += 2;
        }

        // Fold 32-bit sum to 16 bits and complement
        while (sum >> 16) != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }

        !(sum as u16)
    }

    /// Serializes UDP header and payload, computes checksum and inserts it into header
    pub fn to_bytes(&mut self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.length as usize);
        buf.push((self.source_port >> 8) as u8);
        buf.push((self.source_port & 0xff) as u8);
        buf.push((self.destination_port >> 8) as u8);
        buf.push((self.destination_port & 0xff) as u8);
        buf.push((self.length >> 8) as u8);
        buf.push((self.length & 0xff) as u8);
        buf.push(0);
        buf.push(0); // checksum placeholder
        buf.extend_from_slice(&self.payload);

        self.checksum = self.compute_checksum(&buf);
        buf[6] = (self.checksum >> 8) as u8;
        buf[7] = (self.checksum & 0xff) as u8;

        buf
    }
}

// Module unit tests for UDPStack primitives
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_ethernet_frame_from_datagram_to_bytes() {
        let destination_mac = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let source_mac = [0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
        let payload_data = b"Hello UDP Payload".to_vec();
        let source_ip = Ipv4Addr::new(192, 168, 1, 10);
        let destination_ip = Ipv4Addr::new(192, 168, 1, 20);
        let source_port = 12345;
        let destination_port = 80;
        let identification = 0x1234;
        let ttl = Some(128);
        let ipv4_options = None;

        let eth_frame = EthernetFrame::from_datagram(
            destination_mac,
            source_mac,
            payload_data.clone(),
            source_ip,
            destination_ip,
            source_port,
            destination_port,
            identification,
            ttl,
            ipv4_options,
        );

        let bytes = eth_frame.to_bytes();

        // Check Ethernet header
        assert_eq!(&bytes[0..6], &destination_mac);
        assert_eq!(&bytes[6..12], &source_mac);
        assert_eq!(&bytes[12..14], &0x0800u16.to_be_bytes()); // IPv4 EtherType

        // Check that payload contains UDP packet with our payload_data inside
        // Extract IP header length from the first byte of IP header (should be 5 default)
        let ip_hdr_len = (bytes[14] & 0x0f) as usize * 4;
        let ip_total_len = u16::from_be_bytes([bytes[16], bytes[17]]) as usize;

        // Validate IP header length and total length consistency
        assert!(ip_hdr_len >= 20);
        assert!(ip_total_len >= ip_hdr_len);

        // Extract UDP header offset
        let udp_start = 14 + ip_hdr_len;
        // UDP length from UDP header
        let udp_length = u16::from_be_bytes([bytes[udp_start + 4], bytes[udp_start + 5]]) as usize;

        // UDP data payload start
        let udp_payload_start = udp_start + 8;
        let udp_payload_end = udp_start + udp_length;
        assert_eq!(
            &bytes[udp_payload_start..udp_payload_end],
            &payload_data[..]
        );

        // The frame length should equal ethernet header + IP total length
        assert_eq!(bytes.len(), 14 + ip_total_len);
    }

    #[test]
    fn test_ethernet_frame_from_udp_to_bytes_and_back() {
        let destination_mac = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let source_mac = [0x66, 0x55, 0x44, 0x33, 0x22, 0x11];
        let payload_data = b"Another UDP Test".to_vec();
        let source_ip = Ipv4Addr::new(172, 16, 0, 1);
        let destination_ip = Ipv4Addr::new(172, 16, 0, 2);
        let source_port = 65000;
        let destination_port = 65001;
        let identification = 0x4321;
        let ttl = None; // use default TTL
        let ipv4_options = Some(vec![1, 2, 3, 4]); // dummy IP options

        let udp_frame = UdpFrame::new(
            source_port,
            destination_port,
            payload_data.clone(),
            source_ip,
            destination_ip,
        );

        let eth_frame = EthernetFrame::from_udp(
            destination_mac,
            source_mac,
            udp_frame,
            identification,
            ttl,
            ipv4_options.clone(),
        );

        let bytes = eth_frame.to_bytes();

        // Ethernet header checks
        assert_eq!(&bytes[0..6], &destination_mac);
        assert_eq!(&bytes[6..12], &source_mac);
        assert_eq!(&bytes[12..14], &0x0800u16.to_be_bytes());

        // IP header with options length
        let ip_hdr_len = (bytes[14] & 0x0f) as usize * 4;
        assert_eq!(ip_hdr_len, 24); // 20 base + 4 option bytes rounded to 4x = 24 bytes

        // Payload length check
        let ip_total_len = u16::from_be_bytes([bytes[16], bytes[17]]) as usize;
        assert_eq!(bytes.len(), 14 + ip_total_len);

        // UDP offset and payload check
        let udp_start = 14 + ip_hdr_len;
        let udp_length = u16::from_be_bytes([bytes[udp_start + 4], bytes[udp_start + 5]]) as usize;
        assert_eq!(udp_length, 8 + payload_data.len());

        let udp_payload_start = udp_start + 8;
        let udp_payload_end = udp_start + udp_length;
        assert_eq!(
            &bytes[udp_payload_start..udp_payload_end],
            &payload_data[..]
        );
    }
}
