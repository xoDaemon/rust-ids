use std::io;

use pcap::{Capture, Device};

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
        println!("Received packet! {:?}", packet);
    }
}
