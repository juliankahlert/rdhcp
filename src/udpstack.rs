use std::net::Ipv4Addr;
use log::{debug, error};

/// Ethernet frame (IEEE 802.3)
/// Contains Destination MAC, Source MAC, EtherType and Payload
pub struct EthernetFrame {
    pub destination: [u8; 6],
    pub source: [u8; 6],
    pub ethertype: u16, // usually 0x0800 for IPv4
    pub payload: Vec<u8>,
}

impl EthernetFrame {
    pub fn new(destination: [u8; 6], source: [u8; 6], ethertype: u16, payload: Vec<u8>) -> Self {
        EthernetFrame {
            destination,
            source,
            ethertype,
            payload,
        }
    }

    pub fn form_ipv4(destination: [u8; 6], source: [u8; 6], mut payload: IpFrame) -> Self {
        EthernetFrame {
            destination,
            source,
            ethertype: 0x0800,
            payload: payload.to_bytes(),
        }
    }

    pub fn from_udp(
        destination: [u8; 6],
        source: [u8; 6],
        udp_frame: UdpFrame,
        identification: u16,
        ttl: Option<u8>,
        ipv4_options: Option<Vec<u8>>,
    ) -> Self {
        let ttl = ttl.unwrap_or(64);
        let mut ip_frame = IpFrame::udp(udp_frame, identification, ttl, ipv4_options);
        EthernetFrame {
            destination,
            source,
            ethertype: 0x0800,
            payload: ip_frame.to_bytes(),
        }
    }

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
        let ttl = ttl.unwrap_or(64);
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

    /// Build the complete Ethernet frame as a Vec<u8>
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut frame = Vec::with_capacity(14 + self.payload.len());
        frame.extend_from_slice(&self.destination);
        frame.extend_from_slice(&self.source);
        frame.extend_from_slice(&self.ethertype.to_be_bytes());
        frame.extend_from_slice(&self.payload);
        frame
    }

    /// Send the Ethernet frame on a raw socket on the given interface.
    /// Consumes the EthernetFrame.
    pub fn send_on(mut self, iface_name: &str) -> std::io::Result<()> {
        use nix::libc;
        use std::ffi::CString;
        use std::io::{Error, ErrorKind};

        debug!("Preparing to send Ethernet frame on interface '{}'", iface_name);

        // Open a raw socket for sending Ethernet frames
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

        // Prepare sockaddr_ll address
        let ifname_c = match CString::new(iface_name) {
            Ok(name) => {
                debug!("Interface name converted to CString successfully");
                name
            }
            Err(_) => {
                error!("Invalid interface name provided: '{}'", iface_name);
                unsafe { libc::close(socket_fd); }
                return Err(Error::new(ErrorKind::InvalidInput, "Invalid interface name"));
            }
        };

        // Get interface index
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

        debug!("Ethernet frame sent successfully, bytes sent: {}", send_result);

        Ok(())
    }
}

/// IPv4 frame header
pub struct IpFrame {
    pub version_ihl: u8,          // Version and IHL (header length)
    pub dscp_ecn: u8,             // DSCP and ECN
    pub total_length: u16,        // Total length (header + data)
    pub identification: u16,      // Identification
    pub flags_fragment: u16,      // Flags + Fragment offset
    pub ttl: u8,                  // Time to live
    pub protocol: u8,             // Protocol (e.g. 17 for UDP)
    pub header_checksum: u16,     // Header checksum (computed)
    pub source: Ipv4Addr,         // Source IP
    pub destination: Ipv4Addr,    // Destination IP
    pub options: Option<Vec<u8>>, // Optional IP header options
    pub payload: Vec<u8>,         // Payload data (e.g. UDP frame)
}

impl IpFrame {
    pub fn new(
        source: Ipv4Addr,
        destination: Ipv4Addr,
        protocol: u8,
        payload: Vec<u8>,
        options: Option<Vec<u8>>, // defaults to None
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
            header_checksum: 0, // will compute later
            source,
            destination,
            options,
            payload,
        }
    }

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

    /// Compute IP header checksum
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

    /// Build the complete IPv4 header (without payload) as bytes
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

    /// Build the full IP frame (header + payload)
    pub fn to_bytes(&mut self) -> Vec<u8> {
        let header = self.build_header();
        let mut frame = Vec::with_capacity(header.len() + self.payload.len());
        frame.extend_from_slice(&header);
        frame.extend_from_slice(&self.payload);
        frame
    }
}

/// UDP frame header
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
            checksum: 0, // to be computed
            payload,
            source_ip,
            destination_ip,
        }
    }

    /// Compute UDP checksum with pseudo-header
    fn compute_checksum(&self, buf: &[u8]) -> u16 {
        let mut sum = 0u32;

        // Pseudo-header fields
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

        // UDP header + payload
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

        // Add carries
        while (sum >> 16) != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }

        !(sum as u16)
    }

    /// Build UDP header + payload bytes
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
