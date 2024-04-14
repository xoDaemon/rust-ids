use std::io;

use pcap::{Capture, Device};
use pnet::packet::{
    ethernet::{EtherTypes, EthernetPacket},
    ip::IpNextHeaderProtocols,
    ipv4::Ipv4Packet,
    tcp::TcpPacket,
    udp::UdpPacket,
    Packet,
};

fn main() {
    println!("---------------------------------------------------");
    println!("Scanning for network interface devices...");
    let devices = Device::list().unwrap();
    for index in 0..devices.len() {
        let device = devices[index].clone();
        print!(
            "{}. Device {} ({}) has {} addresses stored",
            index + 1,
            device.name,
            device.desc.as_ref().unwrap(),
            device.addresses.len()
        );
        if device.addresses.len() > 0 {
            println!(": ");
            for address in device.addresses.iter() {
                println!("{} ", address.addr);
            }
        } else {
            println!(".");
        }
        println!();
    }

    println!();
    println!("---------------------------------------------------");

    println!("Enter the index of the device you want to start the capture on:");

    let mut input_line = String::new();
    io::stdin()
        .read_line(&mut input_line)
        .expect("Failed to read device index!");

    let index = input_line
        .trim()
        .parse::<usize>()
        .expect("Input not an integer!")
        - 1;

    println!();
    println!("---------------------------------------------------");

    println!(
        "Started capture on device {} ({})!",
        devices[index].name,
        devices[index].desc.as_ref().unwrap()
    );

    let mut cap = Capture::from_device(devices[index].clone())
        .unwrap() // assume the device exists and we are authorized to open it
        .open() // activate the handle
        .unwrap(); // assume activation worked;

    while let Ok(packet) = cap.next_packet() {
        // Parse Ethernet packet
        if let Some(eth_pkg) = EthernetPacket::new(packet.data) {
            match eth_pkg.get_ethertype() {
                EtherTypes::Ipv4 => {
                    // Parse IPv4 packet
                    if let Some(ipv4) = Ipv4Packet::new(eth_pkg.payload()) {
                        let protocol = ipv4.get_next_level_protocol();
                        print!("Ipv4 packet: {} -> {} - ", ipv4.get_source(),
                                    ipv4.get_destination());
                        match protocol {
                            IpNextHeaderProtocols::Tcp => {
                                // Handle TCP packets
                                let tcp_packet = TcpPacket::new(eth_pkg.payload());
                                if let Some(tcp_packet) = tcp_packet {
                                    println!(
                                        "using TCP: {}:{} -> {}:{}; Seq: {}, Ack: {}",
                                        eth_pkg.get_source(),
                                        tcp_packet.get_source(),
                                        eth_pkg.get_destination(),
                                        tcp_packet.get_destination(),
                                        tcp_packet.get_sequence(),
                                        tcp_packet.get_acknowledgement()
                                    );
                                }
                            }
                            IpNextHeaderProtocols::Udp => {
                                // Handle UDP packets
                                let udp_packet = UdpPacket::new(eth_pkg.payload());
                                if let Some(udp_packet) = udp_packet {
                                    println!(
                                        "using UDP: {}:{} -> {}:{}; Len: {}",
                                        eth_pkg.get_source(),
                                        udp_packet.get_source(),
                                        eth_pkg.get_destination(),
                                        udp_packet.get_destination(),
                                        udp_packet.get_length()
                                    );
                                }
                            }
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }
    }
}
