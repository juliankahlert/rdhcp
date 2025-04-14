use rdhcp::server::{ClientPacket, Server, ServerPacket::DhcpOffer};
use tokio;

#[tokio::main]
async fn main() {
    // Start the EventLoop
    let Ok(server) = Server::spawn().await else {
        eprintln!("Failed to spawn server");
        return;
    };

    // Handle requests from the event loop in parallel
    let task = Server::accept(async move |packet: ClientPacket| match packet {
        ClientPacket::DhcpDiscover { request, packet } => {
            println!("DHCP Discover");
            request
                .respond(DhcpOffer(format!("<{:?}>", request.id)))
                .await;
        }
        ClientPacket::DhcpRequest { request, packet } => {
            println!("DHCP Request");
        }
        ClientPacket::DhcpRelease { request, packet } => {
            println!("DHCP Release");
        }
        ClientPacket::DhcpDecline { request, packet } => {
            println!("DHCP Decline");
        }
    })
    .await;

    let _ = tokio::join!(task, server);
}
