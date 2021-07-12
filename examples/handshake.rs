extern crate handshake;

use std::io::Write;
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{env, process};

use handshake::consensus::encode;
use handshake::network::stream_reader::StreamReader;
use handshake::network::{address, constants, message, message_network};
use handshake::secp256k1;
use handshake::secp256k1::rand::Rng;

fn main() {
    let network = constants::Network::Mainnet;
    handshake::network::init(network);

    // This example establishes a connection to a Bitcoin node, sends the intial
    // "version" message, waits for the reply, and finally closes the connection.
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("not enough arguments");
        process::exit(1);
    }

    let str_address = &args[1];

    let address: SocketAddr = str_address.parse().unwrap_or_else(|error| {
        eprintln!("Error parsing address: {:?}", error);
        process::exit(1);
    });

    let version_message = build_version_message(address);

    let first_message = message::RawNetworkMessage {
        magic: network.magic(),
        payload: version_message,
    };

    if let Ok(mut stream) = TcpStream::connect(address) {
        // Send the message
        let _ = stream.write_all(encode::serialize(&first_message).as_slice());
        println!("Sent version message");

        // Setup StreamReader
        let read_stream = stream.try_clone().unwrap();
        let mut stream_reader = StreamReader::new(read_stream, None);
        loop {
            // Loop an retrieve new messages
            let reply: message::RawNetworkMessage = stream_reader.read_next().unwrap();
            match reply.payload {
                message::NetworkMessage::Version(_) => {
                    println!("Received version message: {:?}", reply.payload);

                    let second_message = message::RawNetworkMessage {
                        magic: network.magic(),
                        payload: message::NetworkMessage::Verack,
                    };

                    let _ = stream.write_all(encode::serialize(&second_message).as_slice());
                    println!("Sent verack message");
                }
                message::NetworkMessage::Verack => {
                    println!("Received verack message: {:?}", reply.payload);
                }
                message::NetworkMessage::SendCmpct { version, mode } => {
                    println!(
                        "Received sendcmpct with version: {}, mode: {}",
                        version, mode
                    );
                }
                message::NetworkMessage::Ping(id) => {
                    // println!("-> ping!");
                    let pong_message = message::RawNetworkMessage {
                        magic: network.magic(),
                        payload: message::NetworkMessage::Pong(id),
                    };

                    let _ = stream.write_all(encode::serialize(&pong_message).as_slice());
                    // println!("<- pong!");

                    let ping_message = message::RawNetworkMessage {
                        magic: network.magic(),
                        payload: message::NetworkMessage::Ping(id),
                    };
                    let _ = stream.write_all(encode::serialize(&ping_message).as_slice());
                    // println!("<- ping!");
                }
                message::NetworkMessage::Pong(_) => {
                    // println!("-> pong!");
                }
                message::NetworkMessage::Inv(items) => {
                    for i in items.clone() {
                        println!("+ Inventory {:?}", i);
                    }

                    let getdata_message = message::RawNetworkMessage {
                        magic: network.magic(),
                        payload: message::NetworkMessage::GetData(items.clone()),
                    };
                    let _ = stream.write_all(encode::serialize(&getdata_message).as_slice());
                }
                message::NetworkMessage::Tx(tx) => {
                    println!("tx data: {:?}", tx);
                }
                message::NetworkMessage::Unknown { command, .. } => {
                    println!("Received unknown command: {}", command as u8);
                    // break;
                }
                _ => {
                    println!("Received unknown message: {:?}", reply.payload);
                    // break;
                }
            }
        }
        let _ = stream.shutdown(Shutdown::Both);
    } else {
        eprintln!("Failed to open connection");
    }
}

fn build_version_message(address: SocketAddr) -> message::NetworkMessage {
    // "bitfield of features to be enabled for this connection"
    let services = constants::ServiceFlags::WITNESS;

    // "standard UNIX timestamp in seconds"
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time error")
        .as_secs();

    // "The network address of the node receiving this message"
    let addr_recv = address::Address::new(&address, constants::ServiceFlags::NONE);

    // "Node random nonce, randomly generated every time a version packet is sent. This nonce is used to detect connections to self."
    let nonce: u64 = secp256k1::rand::thread_rng().gen();

    // "User Agent (0x00 if string is 0 bytes long)"
    let user_agent = String::from("rust-example");

    // "The last block received by the emitting node"
    let start_height: i32 = 0;

    // Construct the message
    message::NetworkMessage::Version(message_network::VersionMessage::new(
        services,
        timestamp as i64,
        addr_recv,
        nonce,
        user_agent,
        start_height,
    ))
}
