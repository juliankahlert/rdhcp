use crate::permissions::permissions_check_server;
use crate::{DhcpMessageType, DhcpPacket, parse_dhcp_packet};
use lazy_static::lazy_static;
use log::{debug, error, info, warn};
use nix::libc::{IP_PKTINFO, IPPROTO_IP, c_int, c_void, setsockopt, socklen_t};
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
    pub data: String,
    respond: mpsc::Sender<ServerPacket>,
}

use std::fmt;

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
    },
    DhcpNak {
        xid: u32,                    // Transmission ID
        chaddr: [u8; 16],            // Client hardware address (chaddr)
        siaddr: std::net::Ipv4Addr,  // Server IP address for options later
        options: Vec<(u8, Vec<u8>)>, // Additional DHCP options
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
        }
    }

    pub fn ack(
        xid: u32,
        yiaddr: std::net::Ipv4Addr,
        chaddr: [u8; 16],
        siaddr: std::net::Ipv4Addr,
        subnet: Option<std::net::Ipv4Addr>,
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
        }
    }

    pub fn nak(xid: u32, chaddr: [u8; 16], siaddr: std::net::Ipv4Addr) -> Self {
        ServerPacket::DhcpNak {
            xid,
            chaddr,
            siaddr,
            options: Vec::new(),
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
        Ok(start_tasks(tx).await)
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

pub async fn start_tasks(tx: mpsc::Sender<ClientPacket>) -> task::JoinHandle<()> {
    let (return_tx, return_rx) = mpsc::channel(32);
    task::spawn(async move {
        let task1 = task::spawn_blocking(|| blocking_read_loop(tx, return_tx));

        let task2 = task::spawn_blocking(|| blocking_write_loop(return_rx));

        let _ = tokio::join!(task1, task2);
    })
}

// @TODO somehow get acilliary data and get the reciving ip
fn blocking_read_loop(tx: mpsc::Sender<ClientPacket>, respond: mpsc::Sender<ServerPacket>) {
    debug!("Starting blocking_read_loop");
    let counter = 0;
    let mut buf: [MaybeUninit<u8>; 1024] = unsafe { MaybeUninit::uninit().assume_init() };

    let rdhcp = EVENT_LOOP.blocking_lock();
    let socket = if let Some(ref sock) = rdhcp.socket {
        debug!("Socket successfully cloned for read loop");
        sock.clone()
    } else {
        error!("Socket not initialized - exiting read loop");
        return;
    };
    drop(rdhcp);

    loop {
        let res = match socket.blocking_lock().recv_from(&mut buf) {
            Ok((size, src_addr)) => {
                debug!(
                    "Received {} bytes from socket by source {:?}",
                    size, src_addr
                );
                // Convert the buffer into a slice of u8
                let data: Vec<u8> = buf[..size]
                    .iter()
                    .map(|b| unsafe { b.assume_init() })
                    .collect();

                debug!("Parsing DHCP packet");
                parse_dhcp_packet(&data)
            }
            Err(e) => {
                error!("Socket receive error: {}", e);
                Err(e.to_string())
            }
        };

        let Ok(pkg) = res else {
            debug!("Failed to parse DHCP packet, skipping");
            continue;
        };

        let Some(msg_type) = pkg.message_type() else {
            debug!("DHCP packet missing message type, skipping");
            continue;
        };

        debug!("Handling DHCP message type: {:?}", msg_type);

        let req = Request {
            id: counter,
            data: format!("Event"),
            respond: respond.clone(),
        };

        // Only handle client requests
        let pack = match msg_type {
            DhcpMessageType::Discover => {
                debug!("Received Discover message");
                ClientPacket::DhcpDiscover {
                    request: req,
                    packet: pkg,
                }
            }
            DhcpMessageType::Request => {
                debug!("Received Request message");
                ClientPacket::DhcpRequest {
                    request: req,
                    packet: pkg,
                }
            }
            DhcpMessageType::Decline => {
                debug!("Received Decline message");
                ClientPacket::DhcpDecline {
                    request: req,
                    packet: pkg,
                }
            }
            DhcpMessageType::Release => {
                debug!("Received Release message");
                ClientPacket::DhcpRelease {
                    request: req,
                    packet: pkg,
                }
            }
            _ => {
                debug!("Received unsupported DHCP message type, skipping");
                continue;
            }
        };

        if let Err(_) = tx.blocking_send(pack) {
            info!("Exit the loop if the receiver is closed");
            continue;
        }
    }
}

fn blocking_write_loop(mut rx: mpsc::Receiver<ServerPacket>) {
    debug!("Starting blocking_write_loop");

    let rdhcp = EVENT_LOOP.blocking_lock();
    let socket = if let Some(ref sock) = rdhcp.socket {
        debug!("Socket successfully cloned for write loop");
        sock.clone()
    } else {
        error!("Socket not initialized - exiting write loop");
        return;
    };
    drop(rdhcp);

    loop {
        if let Some(server_packet) = rx.blocking_recv() {
            info!("SENDING RESPONSE {:?}", &server_packet);
            let chaddr = server_packet.client_hardware_address();
            let dhcp_packet: DhcpPacket = server_packet.into();
            let _yiaddr = dhcp_packet.your_address();
            let raw_packet: Vec<u8> = dhcp_packet.into();

            debug!("Raw DHCP packet hex dump:");
            for (i, chunk) in raw_packet.chunks(16).enumerate() {
                let mut line = format!("{:04x}: ", i * 16);
                for byte in chunk {
                    line.push_str(&format!("{:02x} ", byte));
                }
                debug!("{}", line);
            }

            // Send to broadcast address on port 68 since DHCP client listens there
            let dest_addr = std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
                std::net::Ipv4Addr::new(255, 255, 255, 255),
                68,
            ));

            // Send the packet using the shared socket
            let send_res = socket
                .blocking_lock()
                .send_to(&raw_packet, &dest_addr.into());

            match send_res {
                Ok(sent) => {
                    if sent != raw_packet.len() {
                        warn!(
                            "Partial packet sent: {} of {} bytes",
                            sent,
                            raw_packet.len()
                        );
                    } else {
                        debug!("Sent DHCP response to client with chaddr {:?}", chaddr);
                    }
                }
                Err(e) => {
                    error!("Failed to send DHCP response: {}", e);
                }
            }
        } else {
            debug!("Write loop channel closed");
            break;
        }
    }
}
