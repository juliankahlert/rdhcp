use std::mem::MaybeUninit;
use rdhcp::parse_dhcp_packet2;

fn main() {
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
                parse_dhcp_packet2(&data);
            }
            Err(e) => {
                println!("Error reading from socket: {}", e);
            }
        }
    }
}