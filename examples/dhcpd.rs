use log::{error, info};
use rdhcp::server::{self, ClientPacket, Server};
use tokio;

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();

    if !Server::have_permission() {
        error!(
            "Missing permissions: Maybe run `sudo setcap 'cap_net_bind_service=+ep' /path/to/your/binary`"
        );
        return;
    }

    let siaddr = std::net::Ipv4Addr::new(172, 20, 0, 10);
    // Start the EventLoop
    let Ok(server) = Server::spawn(siaddr).await else {
        error!("Failed to spawn server");
        return;
    };

    // Handle requests from the event loop in parallel
    let task = Server::accept(async move |packet: ClientPacket| match packet {
        ClientPacket::DhcpDiscover { request, packet } => {
            info!("DHCP Discover");
            let xid = packet.transmission_id();
            let chaddr = packet.client_hardware_address();
            let siaddr = std::net::Ipv4Addr::new(172, 20, 0, 10);
            let yiaddr = std::net::Ipv4Addr::new(172, 20, 0, 100);
            let mut offer = server::ServerPacket::offer(xid, yiaddr, chaddr, siaddr, None);
            offer = offer.with_giaddr(std::net::Ipv4Addr::new(172, 20, 0, 1));
            request.respond(offer).await;
        }
        ClientPacket::DhcpRequest { request, packet } => {
            info!("DHCP Request");
            let xid = packet.transmission_id();
            let chaddr = packet.client_hardware_address();
            let siaddr = std::net::Ipv4Addr::new(172, 20, 0, 10);
            let yiaddr = std::net::Ipv4Addr::new(172, 20, 0, 100);
            let mut ack = server::ServerPacket::ack(xid, yiaddr, chaddr, siaddr, None);
            ack = ack.with_giaddr(std::net::Ipv4Addr::new(172, 20, 0, 1));
            request.respond(ack).await;
        }
        ClientPacket::DhcpRelease { .. } => {
            info!("DHCP Release");
        }
        ClientPacket::DhcpDecline { .. } => {
            info!("DHCP Decline");
        }
    })
    .await;

    let _ = tokio::join!(task, server);
}
