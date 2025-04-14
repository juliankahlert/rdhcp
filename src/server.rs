use crate::{DhcpPacket, parse_dhcp_packet};
use lazy_static::lazy_static;
use socket2::{Domain, Socket, Type};
use std::mem::MaybeUninit;
use std::net::SocketAddr;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
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

#[derive(Debug)]
pub enum ServerPacket {
    DhcpOffer(String),
    DhcpAck(String),
    DhcpNak(String),
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
            eprintln!("Failed to respond to request ID: {}", self.id);
        }
    }
}

lazy_static! {
    static ref EVENT_LOOP: Mutex<Server> = Mutex::new(Server::new());
}

/// Helper to bind a socket2 async
async fn bind() -> Result<Socket, String> {
    let task = task::spawn_blocking(|| {
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

        socket
            .set_nonblocking(false)
            .map_err(|e| format!("set_nonblocking failed: {}", e))?;

        socket
            .bind(&address.into())
            .map_err(|e| format!("Bind failed: {}", e))?;

        Ok(socket)
    });

    task.await.map_err(|e| format!("Join error: {}", e))?
}

impl Server {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::channel(32);
        let rx = Arc::new(Mutex::new(rx));
        Server {
            tx,
            rx,
            socket: None,
        }
    }

    pub async fn spawn() -> Result<task::JoinHandle<()>, String> {
        let mut rdhcp = EVENT_LOOP.lock().await;
        let tx = rdhcp.tx.clone();
        let socket = bind().await?;

        rdhcp.socket = Some(Arc::new(Mutex::new(socket)));
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
                    f(req).await;
                }
            }
        })
    }
}

pub async fn start_tasks(tx: mpsc::Sender<ClientPacket>) -> task::JoinHandle<()> {
    let (return_tx, return_rx) = mpsc::channel(32);
    task::spawn(async move {
        let task1 = task::spawn_blocking({ || blocking_read_loop(tx, return_tx) });

        let task2 = task::spawn_blocking({ || blocking_write_loop(return_rx) });

        let _ = tokio::join!(task1, task2);
    })
}

fn blocking_read_loop(tx: mpsc::Sender<ClientPacket>, respond: mpsc::Sender<ServerPacket>) {
    let mut counter = 0;
    let mut buf: [MaybeUninit<u8>; 1024] = unsafe { MaybeUninit::uninit().assume_init() };

    let rdhcp = EVENT_LOOP.blocking_lock();
    let socket = if let Some(ref sock) = rdhcp.socket {
        sock.clone()
    } else {
        return;
    };
    drop(rdhcp);

    loop {
        let res = match socket.blocking_lock().recv_from(&mut buf) {
            Ok((size, _)) => {
                // Convert the buffer into a slice of u8
                let data: Vec<u8> = buf[..size]
                    .iter()
                    .map(|b| unsafe { b.assume_init() })
                    .collect();

                parse_dhcp_packet(&data)
            }
            Err(e) => Err(e.to_string()),
        };

        let Ok(pkg) = res else {
            continue;
        };

        let req = Request {
            id: counter,
            data: format!("Event"),
            respond: respond.clone(),
        };

        let pack = ClientPacket::DhcpDiscover {
            request: req,
            packet: pkg,
        };
        if let Err(_) = tx.blocking_send(pack) {
            println!("Exit the loop if the receiver is closed");
            continue;
        }
    }
}

fn blocking_write_loop(mut rx: mpsc::Receiver<ServerPacket>) {
    loop {
        if let Some(data) = rx.blocking_recv() {
            println!("RESPONSE {:?}", data)
        }
    }
}
