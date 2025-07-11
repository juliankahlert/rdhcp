use crate::permissions::permissions_check_server;
use crate::{DhcpMessageType, DhcpPacket, parse_dhcp_packet, udpstack};
use lazy_static::lazy_static;
use log::{debug, error, info, warn};
use nix::libc::{IP_PKTINFO, IPPROTO_IP, c_int, c_void, setsockopt, socklen_t};
use nix::sys::socket::{ControlMessageOwned, MsgFlags, SockaddrStorage, recvmsg};
use socket2::{Domain, Socket, Type};
use std::future::Future;
use std::mem::MaybeUninit;
use std::net::SocketAddr;
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc};
use tokio::task;

pub struct Server {
    tx: mpsc::Sender<ClientPacket>,
    rx: Arc<Mutex<mpsc::Receiver<ClientPacket>>>,
    socket: Option<Arc<Mutex<Socket>>>,
}

#[derive(Debug)]
pub struct Request {
    pub id: usize,
    pub ancillary_data: AncillaryData,
    respond: mpsc::Sender<ServerPacket>,
}

use std::fmt;

pub struct ServerPacketMeta {
    req_if_index: i32, // interface index the request was received on
}

pub enum ServerPacket {
    DhcpOffer {
        xid: u32,                         // Transaction ID
        yiaddr: std::net::Ipv4Addr,       // IP address assigned to the client
        chaddr: [u8; 16],                 // MAC address of the client requesting the lease
        siaddr: std::net::Ipv4Addr,       // IP address of the DHCP server sending this message
        lease_time: u32,                  // Lease duration in seconds (Default 3600 = 1 hour)
        giaddr: std::net::Ipv4Addr, // Default gateway provided to the client (Default 192.168.1.1)
        diaddrs: Vec<std::net::Ipv4Addr>, // DNS server IPs assigned to the client (Default 8.8.8.8, 8.8.4.4)
        subnet: std::net::Ipv4Addr, // Subnet mask assigned to the client (Default 255.255.255.0)
        options: Vec<(u8, Vec<u8>)>, // Additional DHCP options
        meta: ServerPacketMeta,     // metadata for the packet
    },
    DhcpAck {
        xid: u32,                         // Transaction ID
        yiaddr: std::net::Ipv4Addr,       // IP address assigned to the client
        chaddr: [u8; 16],                 // MAC address of the client requesting the lease
        siaddr: std::net::Ipv4Addr,       // IP address of the DHCP server sending this message
        lease_time: u32,                  // Lease duration in seconds (Default 3600 = 1 hour)
        giaddr: std::net::Ipv4Addr, // Default gateway provided to the client (Default 192.168.1.1)
        diaddrs: Vec<std::net::Ipv4Addr>, // DNS server IPs assigned to the client (Default 8.8.8.8, 8.8.4.4)
        subnet: std::net::Ipv4Addr, // Subnet mask assigned to the client (Default 255.255.255.0)
        options: Vec<(u8, Vec<u8>)>, // Additional DHCP options
        meta: ServerPacketMeta,     // metadata for the packet
    },
    DhcpNak {
        xid: u32,                    // Transmission ID
        chaddr: [u8; 16],            // Client hardware address (chaddr)
        siaddr: std::net::Ipv4Addr,  // Server IP address for options later
        options: Vec<(u8, Vec<u8>)>, // Additional DHCP options
        meta: ServerPacketMeta,      // metadata for the packet
    },
}

impl fmt::Debug for ServerPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServerPacket::DhcpOffer {
                xid,
                yiaddr,
                chaddr,
                siaddr,
                lease_time,
                giaddr,
                diaddrs,
                subnet,
                options,
                ..
            } => f
                .debug_struct("DhcpOffer")
                .field("xid", &format_args!("{:#x}", xid))
                .field("yiaddr", yiaddr)
                .field("chaddr", chaddr)
                .field("siaddr", siaddr)
                .field("lease_time", lease_time)
                .field("giaddr", giaddr)
                .field("diaddrs", diaddrs)
                .field("subnet", subnet)
                .field("options", options)
                .finish(),
            ServerPacket::DhcpAck {
                xid,
                yiaddr,
                chaddr,
                siaddr,
                lease_time,
                giaddr,
                diaddrs,
                subnet,
                options,
                ..
            } => f
                .debug_struct("DhcpAck")
                .field("xid", &format_args!("{:#x}", xid))
                .field("yiaddr", yiaddr)
                .field("chaddr", chaddr)
                .field("siaddr", siaddr)
                .field("lease_time", lease_time)
                .field("giaddr", giaddr)
                .field("diaddrs", diaddrs)
                .field("subnet", subnet)
                .field("options", options)
                .finish(),
            ServerPacket::DhcpNak {
                xid,
                chaddr,
                siaddr,
                options,
                ..
            } => f
                .debug_struct("DhcpNak")
                .field("xid", &format_args!("{:#x}", xid))
                .field("chaddr", chaddr)
                .field("siaddr", siaddr)
                .field("options", options)
                .finish(),
        }
    }
}

impl ServerPacket {
    /// Creates a new DHCP Offer packet with default parameters.
    ///
    /// # Parameters
    ///
    /// - `xid`: Transaction ID to associate requests and replies.
    /// - `yiaddr`: The IP address being offered to the client.
    /// - `chaddr`: Client hardware address (MAC address).
    /// - `siaddr`: Server IP address sending this offer.
    /// - `subnet`: Subnet mask assigned to the client.
    ///
    /// # Returns
    ///
    /// A `ServerPacket::DhcpOffer` instance populated with the provided parameters,
    /// along with default lease time (3600 seconds), default gateway (192.168.1.1),
    /// default DNS servers (8.8.8.8 and 8.8.4.4), and an empty options vector.
    pub fn offer(
        xid: u32,
        yiaddr: std::net::Ipv4Addr,
        chaddr: [u8; 16],
        siaddr: std::net::Ipv4Addr,
        subnet: Option<std::net::Ipv4Addr>,
        if_index: i32,
    ) -> Self {
        let snaddr = if let Some(addr) = subnet {
            addr
        } else {
            std::net::Ipv4Addr::new(255, 255, 255, 0)
        };

        ServerPacket::DhcpOffer {
            xid,
            yiaddr,
            chaddr,
            siaddr,
            lease_time: 3600,
            giaddr: std::net::Ipv4Addr::new(192, 168, 1, 1),
            diaddrs: vec![
                std::net::Ipv4Addr::new(8, 8, 8, 8),
                std::net::Ipv4Addr::new(8, 8, 4, 4),
            ],
            subnet: snaddr,
            options: Vec::new(),
            meta: ServerPacketMeta {
                req_if_index: if_index,
            },
        }
    }

    pub fn ack(
        xid: u32,
        yiaddr: std::net::Ipv4Addr,
        chaddr: [u8; 16],
        siaddr: std::net::Ipv4Addr,
        subnet: Option<std::net::Ipv4Addr>,
        if_index: i32,
    ) -> Self {
        let snaddr = if let Some(addr) = subnet {
            addr
        } else {
            std::net::Ipv4Addr::new(255, 255, 255, 0)
        };

        ServerPacket::DhcpAck {
            xid,
            yiaddr,
            chaddr,
            siaddr,
            lease_time: 3600,
            giaddr: std::net::Ipv4Addr::new(192, 168, 1, 1),
            diaddrs: vec![
                std::net::Ipv4Addr::new(8, 8, 8, 8),
                std::net::Ipv4Addr::new(8, 8, 4, 4),
            ],
            subnet: snaddr,
            options: Vec::new(),
            meta: ServerPacketMeta {
                req_if_index: if_index,
            },
        }
    }

    pub fn nak(xid: u32, chaddr: [u8; 16], siaddr: std::net::Ipv4Addr, if_index: i32) -> Self {
        ServerPacket::DhcpNak {
            xid,
            chaddr,
            siaddr,
            options: Vec::new(),
            meta: ServerPacketMeta {
                req_if_index: if_index,
            },
        }
    }

    pub fn client_hardware_address(&self) -> [u8; 16] {
        match &self {
            ServerPacket::DhcpOffer { chaddr, .. } => *chaddr,
            ServerPacket::DhcpAck { chaddr, .. } => *chaddr,
            ServerPacket::DhcpNak { chaddr, .. } => *chaddr,
        }
    }

    pub fn with_option(mut self, option: (u8, Vec<u8>)) -> Self {
        match &mut self {
            ServerPacket::DhcpOffer { options, .. } => options.push(option),
            ServerPacket::DhcpAck { options, .. } => options.push(option),
            ServerPacket::DhcpNak { options, .. } => options.push(option),
        }
        self
    }

    pub fn with_lease_time(mut self, lease_time: u32) -> Self {
        match &mut self {
            ServerPacket::DhcpOffer { lease_time: lt, .. } => *lt = lease_time,
            ServerPacket::DhcpAck { lease_time: lt, .. } => *lt = lease_time,
            ServerPacket::DhcpNak { .. } => {
                warn!("DhcpNak has no lease_time field")
            }
        }
        self
    }

    pub fn with_giaddr(mut self, giaddr: std::net::Ipv4Addr) -> Self {
        match &mut self {
            ServerPacket::DhcpOffer { giaddr: gaddr, .. } => *gaddr = giaddr,
            ServerPacket::DhcpAck { giaddr: gaddr, .. } => *gaddr = giaddr,
            ServerPacket::DhcpNak { .. } => {
                warn!("DhcpNak has no giaddr field")
            }
        }
        self
    }

    pub fn with_diaddrs(mut self, diaddrs: Vec<std::net::Ipv4Addr>) -> Self {
        match &mut self {
            ServerPacket::DhcpOffer {
                diaddrs: daddrs, ..
            } => *daddrs = diaddrs,
            ServerPacket::DhcpAck {
                diaddrs: daddrs, ..
            } => *daddrs = diaddrs,
            ServerPacket::DhcpNak { .. } => {
                warn!("DhcpNak has no diaddrs field")
            }
        }
        self
    }

    pub fn req_if_index(&self) -> i32 {
        match &self {
            ServerPacket::DhcpOffer { meta, .. } => meta.req_if_index,
            ServerPacket::DhcpAck { meta, .. } => meta.req_if_index,
            ServerPacket::DhcpNak { meta, .. } => meta.req_if_index,
        }
    }
}

#[derive(Debug)]
pub enum ClientPacket {
    DhcpDiscover {
        request: Request,
        packet: DhcpPacket,
    },
    DhcpRequest {
        request: Request,
        packet: DhcpPacket,
    },
    DhcpDecline {
        request: Request,
        packet: DhcpPacket,
    },
    DhcpRelease {
        request: Request,
        packet: DhcpPacket,
    },
}

impl Request {
    pub async fn respond(&self, response: ServerPacket) {
        if let Err(_) = self.respond.send(response).await {
            error!("Failed to respond to request ID: {}", self.id);
        }
    }
}

lazy_static! {
    static ref EVENT_LOOP: Mutex<Server> = Mutex::new(Server::new());
}

fn set_pktinfo(s: &Socket) -> Result<(), String> {
    let fd = s.as_raw_fd();
    let optval: c_int = 1;
    let ret = unsafe {
        setsockopt(
            fd,
            IPPROTO_IP,
            IP_PKTINFO,
            &optval as *const _ as *const c_void,
            std::mem::size_of_val(&optval) as socklen_t,
        )
    };
    if ret == 0 {
        Ok(())
    } else {
        let err = std::io::Error::last_os_error();
        Err(format!("setsockopt IP_PKTINFO failed: {}", err))
    }
}

/// Helper to bind a socket2 async
async fn bind(_siaddr: std::net::Ipv4Addr) -> Result<Socket, String> {
    let task = task::spawn_blocking(move || {
        debug!("Creating and binding socket on 0.0.0.0:67");
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, None)
            .map_err(|e| format!("Socket creation failed: {}", e))?;

        let address: SocketAddr = "0.0.0.0:67"
            .parse()
            .map_err(|e| format!("Invalid address: {}", e))?;

        socket
            .set_reuse_address(true)
            .map_err(|e| format!("set_reuse_address failed: {}", e))?;

        socket
            .set_broadcast(true)
            .map_err(|e| format!("set_broadcast failed: {}", e))?;

        if let Err(_) = set_pktinfo(&socket) {
            warn!(
                "Failed to set IP_PKTINFO on socket; not needed yet as we do not process ancillary data currently"
            );
        }

        socket
            .set_nonblocking(false)
            .map_err(|e| format!("set_nonblocking failed: {}", e))?;

        socket
            .bind(&address.into())
            .map_err(|e| format!("Bind failed: {}", e))?;

        debug!("Socket successfully created and bound");

        Ok(socket)
    });

    task.await.map_err(|e| format!("Join error: {}", e))?
}

impl Server {
    pub fn have_permission() -> bool {
        if let Err(_) = permissions_check_server() {
            false
        } else {
            true
        }
    }

    pub fn new() -> Self {
        debug!("Initializing new Server instance");
        let (tx, rx) = mpsc::channel(32);
        let rx = Arc::new(Mutex::new(rx));
        Server {
            tx,
            rx,
            socket: None,
        }
    }

    pub async fn spawn(siaddr: std::net::Ipv4Addr) -> Result<task::JoinHandle<()>, String> {
        debug!("Spawning server tasks and binding socket");
        let mut rdhcp = EVENT_LOOP.lock().await;
        let tx = rdhcp.tx.clone();
        let socket = bind(siaddr).await?;

        rdhcp.socket = Some(Arc::new(Mutex::new(socket)));
        debug!("Socket bound and tasks starting");
        Ok(start_tasks(tx))
    }

    pub async fn accept<F, Fut>(mut f: F) -> tokio::task::JoinHandle<()>
    where
        F: FnMut(ClientPacket) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let rx = {
            let rdhcp = EVENT_LOOP.lock().await;
            rdhcp.rx.clone()
        };

        tokio::spawn(async move {
            loop {
                let mut rx = rx.lock().await;
                if let Some(req) = rx.recv().await {
                    debug!("Handling client packet: {:?}", req);
                    f(req).await;
                }
            }
        })
    }
}

pub fn start_tasks(tx: mpsc::Sender<ClientPacket>) -> task::JoinHandle<()> {
    let (return_tx, return_rx) = mpsc::channel(32);
    task::spawn(async move {
        let task1 = task::spawn_blocking(|| blocking_read_loop(tx, return_tx));

        let task2 = task::spawn_blocking(|| blocking_write_loop(return_rx));

        let (res1, res2) = tokio::join!(task1, task2);

        match res1 {
            Ok(_) => debug!("Blocking read loop task terminated successfully"),
            Err(e) => error!("Blocking read loop task terminated with error: {:?}", e),
        }

        match res2 {
            Ok(_) => debug!("Blocking write loop task terminated successfully"),
            Err(e) => error!("Blocking write loop task terminated with error: {:?}", e),
        }
    })
}

#[derive(Debug)]
pub struct AncillaryData {
    pub recv_ifindex: Option<i32>,
    pub dst_ip: Option<std::net::Ipv4Addr>,
}

fn extract_ancillary_data<T>(msg: &nix::sys::socket::RecvMsg<T>) -> Result<AncillaryData, String> {
    let mut recv_ifindex = None;
    let mut dst_ip = None;

    let cmsgs = msg
        .cmsgs()
        .map_err(|e| format!("Failed to get control messages: {}", e))?;
    for cmsg in cmsgs {
        if let ControlMessageOwned::Ipv4PacketInfo(pktinfo) = cmsg {
            recv_ifindex = Some(pktinfo.ipi_ifindex);
            dst_ip = Some(std::net::Ipv4Addr::from(u32::from_be(
                pktinfo.ipi_spec_dst.s_addr,
            )));
            break;
        }
    }
    Ok(AncillaryData {
        recv_ifindex,
        dst_ip,
    })
}

fn blocking_read_loop(tx: mpsc::Sender<ClientPacket>, respond: mpsc::Sender<ServerPacket>) {
    debug!("Starting blocking_read_loop");

    // Grab the shared socket
    let socket = {
        let rdhcp = EVENT_LOOP.blocking_lock();
        if let Some(sock) = &rdhcp.socket {
            sock.clone()
        } else {
            error!("Socket not initialized - exiting read loop");
            return;
        }
    };

    // Prepare buffers
    let mut buf: [MaybeUninit<u8>; 1024] = unsafe { MaybeUninit::uninit().assume_init() };
    // space for one in_pktinfo
    let mut cmsg_space = nix::cmsg_space!(nix::libc::in_pktinfo);

    loop {
        // Build IoSliceMut
        let mut iov = [std::io::IoSliceMut::new(unsafe {
            // SAFETY: We only read into the uninitialized buffer.
            std::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut u8, buf.len())
        })];

        // recvmsg gives us both payload and control messages
        let msg = match {
            let socket = socket.blocking_lock();
            recvmsg::<SockaddrStorage>(
                socket.as_raw_fd(),
                &mut iov,
                Some(&mut cmsg_space),
                MsgFlags::empty(),
            )
        } {
            Ok(msg) => msg,
            Err(e) => {
                error!("recvmsg failed: {}", e);
                continue;
            }
        };

        let size = msg.bytes;

        let ancillary = match extract_ancillary_data(&msg) {
            Ok(data) => data,
            Err(e) => {
                error!("Failed to extract ancillary data: {}", e);
                continue;
            }
        };

        debug!(
            "Received {} bytes on ifindex {:?} dst_ip {:?}",
            size, ancillary.recv_ifindex, ancillary.dst_ip
        );

        // Convert buffer to Vec<u8>
        let data = unsafe {
            // SAFETY: the first `size` bytes are now initialized by recvmsg
            std::slice::from_raw_parts(buf.as_ptr() as *const u8, size).to_vec()
        };

        let pkg = match parse_dhcp_packet(&data) {
            Ok(p) => p,
            Err(e) => {
                warn!("Failed to parse DHCP packet: {}", e);
                continue;
            }
        };

        let msg_type = match pkg.message_type() {
            Some(t) => t,
            None => {
                debug!("DHCP packet missing message type, skipping");
                continue;
            }
        };

        let req = Request {
            id: 0, // you might want to increment a counter here
            ancillary_data: ancillary,
            respond: respond.clone(),
        };

        let pack = match msg_type {
            DhcpMessageType::Discover => ClientPacket::DhcpDiscover {
                request: req,
                packet: pkg,
            },
            DhcpMessageType::Request => ClientPacket::DhcpRequest {
                request: req,
                packet: pkg,
            },
            DhcpMessageType::Decline => ClientPacket::DhcpDecline {
                request: req,
                packet: pkg,
            },
            DhcpMessageType::Release => ClientPacket::DhcpRelease {
                request: req,
                packet: pkg,
            },
            _ => continue,
        };

        if tx.blocking_send(pack).is_err() {
            info!("Receiver closed, exiting read loop");
            break;
        }
    }
}

fn blocking_write_loop(mut rx: mpsc::Receiver<ServerPacket>) {
    debug!("Starting blocking_write_loop");

    let mut id = 1;

    loop {
        if let Some(server_packet) = rx.blocking_recv() {
            info!("SENDING RESPONSE {:?}", &server_packet);
            let chaddr = server_packet.client_hardware_address();
            let if_index = server_packet.req_if_index();
            let dhcp_packet: DhcpPacket = server_packet.into();
            let yiaddr = dhcp_packet.your_address();
            let raw_packet: Vec<u8> = dhcp_packet.into();

            debug!("Raw DHCP packet hex dump:");
            for (i, chunk) in raw_packet.chunks(16).enumerate() {
                let mut line = format!("{:04x}: ", i * 16);
                for byte in chunk {
                    line.push_str(&format!("{:02x} ", byte));
                }
                debug!("{}", line);
            }

            let eth_frame = udpstack::EthernetFrame::from_dhcp_response(
                chaddr[..6].try_into().unwrap_or([0xff; 6]),
                raw_packet,
                std::net::Ipv4Addr::new(172, 20, 0, 10),
                yiaddr,
                id,
            );

            if let Err(e) = eth_frame.send_on(if_index) {
                error!("Failed to send Ethernet frame: {}", e);
            } else {
                debug!("Sent DHCP response to client with chaddr {:?}", chaddr);
                id += 1;
            }
        } else {
            debug!("Write loop channel closed");
            break;
        }
    }
}
