use rdhcp::server::{ClientPacket, Server, ServerPacket};
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
            if let Some(msg_type) = packet.message_type() {
                println!("DHCP Message Type: {:?}", msg_type);
            } else {
                println!("DHCP Message Type not found.");
            }
            request
                .respond(ServerPacket::DhcpOffer(format!("<{:?}>", request.id)))
                .await;
        }
        _ => {}
    })
    .await;

    let _ = tokio::join!(task, server);
}
