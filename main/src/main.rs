use std::{
    collections::HashMap,
    fs::{self, File},
    io::{self, stdout, BufRead, Write},
    process::{exit, Command},
    sync::{Arc, Mutex},
    thread::{self, sleep},
    time::{self, Duration},
};

use chrono::{Datelike, Local, Timelike};
use colored::*;
use crossterm::event::{poll, read, Event, KeyCode, KeyEvent, KeyModifiers};
use crossterm::terminal::ClearType;
use crossterm::{cursor::MoveTo, execute, terminal};
use pcap::{Capture, Device};
use pnet::packet::{
    ethernet::{EtherTypes, EthernetPacket},
    ip::IpNextHeaderProtocols,
    ipv4::Ipv4Packet,
    tcp::TcpPacket,
    udp::UdpPacket,
    Packet,
};
use regex::Regex;
use serde::Deserialize;

struct IpStats {
    sent: u64,
    received: u64,
}

#[derive(Deserialize)]
struct Config {
    general: GeneralConfig,
    alert: AlertConfig,
}

#[derive(Deserialize)]
struct GeneralConfig {
    mode: String,
}

#[allow(dead_code)]
#[derive(Deserialize)]
struct AlertConfig {
    ip: String,
    port: u16,
}

fn main() {
    let waiting_time = time::Duration::from_secs(1);

    let config_content = fs::read_to_string("config.toml").unwrap();
    let config: Config = toml::from_str(&config_content).unwrap();

    let devices = Device::list().unwrap();

    if devices.is_empty() {
        println!("No available network devices found.");
        return;
    }

    let number_of_devices = devices.len();

    print_start_menu(&devices);
    loop {
        let mut input_line = String::new();
        io::stdin()
            .read_line(&mut input_line)
            .expect("Failed to read device index!");

        let index = input_line
            .trim()
            .parse::<usize>()
            .expect("Input not an integer!");

        if index == 0 {
            print_logs();
        } else if index == 101 {
            println!("Enter name of examined log:");

            let mut file_name = String::new();
            io::stdin()
                .read_line(&mut file_name)
                .expect("Failed to read file name!");

            let trimmed_file_name = file_name.trim();
            extract_from_log(&trimmed_file_name.to_string(), &config.alert.ip);
        } else if index == 336 {
            println!("Enter name of deleted log:");

            let mut file_name = String::new();
            io::stdin()
                .read_line(&mut file_name)
                .expect("Failed to read file name!");

            let trimmed_file_name = file_name.trim();

            let mut confirmation = String::new();

            println!("Are you sure you want to delete this log? (y/n)");
            std::io::stdin()
                .read_line(&mut confirmation)
                .expect("Failed to read answer");
            let trimmed_conf = confirmation.trim();

            if trimmed_conf.eq("y") {
                delete_log(&trimmed_file_name.to_string());
            }
        } else if index >= 1 && index < number_of_devices {
            print_capture(&config, &devices, index - 1);
            break;
        } else {
            println!("Invalid index!");
        }
        sleep(waiting_time);
        print_menu_options()
    }
}

fn delete_log(deleted_log: &str) {
    Command::new("cmd")
        .args(["/C", format!("del {}", deleted_log).as_str()])
        .spawn()
        .expect("failed to execute process");

    println!("Log deleted!");
}

fn print_capture(config: &Config, devices: &Vec<Device>, index: usize) {
    println!();
    println!("---------------------------------------------------");

    println!(
        "Started capture on device {} ({})!",
        devices[index].name,
        devices[index].desc.as_ref().unwrap()
    );

    let mut cap = Capture::from_device(devices[index].clone())
        .unwrap()
        .open()
        .unwrap();

    let shared_ip_map = Arc::new(Mutex::new(HashMap::<String, IpStats>::new()));
    let ip_map_for_thread = Arc::clone(&shared_ip_map);

    if config.general.mode == "summary" {
        let mut flag = false;
        thread::spawn(move || loop {
            display_summary(&ip_map_for_thread.lock().unwrap(), &flag);
            thread::sleep(Duration::from_millis(500));
        });

        loop {
            register_keystroke(&mut flag);
            if flag == true {
                return;
            }

            if let Ok(packet) = cap.next_packet() {
                if let Some(ethernet_packet) = EthernetPacket::new(&packet.data) {
                    match ethernet_packet.get_ethertype() {
                        EtherTypes::Ipv4 => {
                            let ipv4_packet = Ipv4Packet::new(ethernet_packet.payload()).unwrap();
                            let src_ip = ipv4_packet.get_source().to_string();
                            let dst_ip = ipv4_packet.get_destination().to_string();
                            update_ip_stats(
                                &mut shared_ip_map.lock().unwrap(),
                                src_ip,
                                true,
                                packet.header.len,
                            );
                            update_ip_stats(
                                &mut shared_ip_map.lock().unwrap(),
                                dst_ip,
                                false,
                                packet.header.len,
                            );

                            if ipv4_packet.get_source().to_string() == config.alert.ip {
                                send_alert(&config.alert.ip);
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    let mut flag = false;
    let mut alert_number = 0;
    loop {
        register_keystroke(&mut flag);
        if flag == true {
            log_alert(&config.alert.ip, &alert_number);
            return;
        }
        // println!("----------------------{}", flag);
        if let Ok(packet) = cap.next_packet() {
            if let Some(eth_pkg) = EthernetPacket::new(packet.data) {
                match eth_pkg.get_ethertype() {
                    EtherTypes::Ipv4 => {
                        if let Some(ipv4) = Ipv4Packet::new(eth_pkg.payload()) {
                            let protocol = ipv4.get_next_level_protocol();
                            print!(
                                "Ipv4 packet: {} -> {} - ",
                                ipv4.get_source(),
                                ipv4.get_destination()
                            );

                            match protocol {
                                IpNextHeaderProtocols::Tcp => {
                                    let tcp_packet = TcpPacket::new(eth_pkg.payload());
                                    if let Some(tcp_packet) = tcp_packet {
                                        if config.general.mode == "detailed" {
                                            println!(
                                                "{}",
                                                format!(
                                                    "using TCP: {}:{} -> {}:{}; Seq: {}, Ack: {}",
                                                    eth_pkg.get_source(),
                                                    tcp_packet.get_source(),
                                                    eth_pkg.get_destination(),
                                                    tcp_packet.get_destination(),
                                                    tcp_packet.get_sequence(),
                                                    tcp_packet.get_acknowledgement()
                                                )
                                                .bright_blue()
                                            );
                                        }
                                        if ipv4.get_source().to_string() == config.alert.ip {
                                            send_alert(&config.alert.ip);
                                            alert_number += 1;
                                        }
                                    }
                                }
                                IpNextHeaderProtocols::Udp => {
                                    let udp_packet = UdpPacket::new(eth_pkg.payload());

                                    if config.general.mode == "detailed" {
                                        if let Some(udp_packet) = udp_packet {
                                            println!(
                                                "{}",
                                                format!(
                                                    "using UDP: {}:{} -> {}:{}; Len: {}",
                                                    eth_pkg.get_source(),
                                                    udp_packet.get_source(),
                                                    eth_pkg.get_destination(),
                                                    udp_packet.get_destination(),
                                                    udp_packet.get_length()
                                                )
                                                .green()
                                            );
                                        }
                                        if ipv4.get_source().to_string() == config.alert.ip {
                                            send_alert(&config.alert.ip);
                                            alert_number += 1;
                                        }
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
}

fn log_alert(alert_ip: &String, alert_number: &i32) {
    let local_time = Local::now();

    let mut f = File::create(format!(
        "./logs/log{}{}{}{}{}{}.txt",
        local_time.year(),
        local_time.month(),
        local_time.day(),
        local_time.hour(),
        local_time.minute(),
        local_time.second()
    ))
    .expect("Unable to create file");
    f.write_all(
        format!(
            "Traffic from ip {} has been registered {} times.",
            alert_ip, alert_number
        )
        .to_string()
        .as_bytes(),
    )
    .expect("Unable to write data");

    println!("---------------------------------------------------");
    println!("Alerts were successfully logged!");
    sleep(time::Duration::from_secs(1));
}

fn print_start_menu(devices: &Vec<Device>) {
    println!("---------------------------------------------------");
    println!("Scanning for network interface devices...");

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

    print_menu_options()
}

fn print_menu_options() {
    println!();
    println!("---------------------------------------------------");

    println!("Enter code 0 to see available logs.");
    println!("Enter code 101 to cross-reference the current alert ip with an existing log.");
    println!("Enter code 336 to delete a log.");
    println!("Enter the index of a device to start the capture.");
    println!("---------------------------------------------------");
}

fn send_alert(ip: &str) {
    println!("{}", format!("ALERT! Traffic from IP {} ", ip).red());

    unsafe {
        let lib = libloading::Library::new("WindowsAlertSystem.dll").unwrap();

        let windows_alert: libloading::Symbol<extern "C" fn(&str)> = match lib.get(b"windows_alert")
        {
            Ok(windows_alert) => windows_alert,
            Err(_) => {
                println!("Failed to load function from DLL");
                std::process::exit(0)
            }
        };

        windows_alert(ip);
    }
}

fn update_ip_stats(
    ip_map: &mut HashMap<String, IpStats>,
    ip: String,
    is_source: bool,
    packet_size: u32,
) {
    let stats = ip_map.entry(ip).or_insert(IpStats {
        sent: 0,
        received: 0,
    });
    if is_source {
        stats.sent += packet_size as u64;
    } else {
        stats.received += packet_size as u64;
    }
}

fn display_summary(ip_map: &HashMap<String, IpStats>, flag: &bool) {
    let mut stdout = stdout();
    execute!(stdout, terminal::Clear(ClearType::All), MoveTo(0, 0)).unwrap();

    println!("IP Address        | Packets Sent | Packets Received");
    println!("------------------+--------------+-----------------");
    for (ip, stats) in ip_map.iter() {
        println!("{:<18} | {:<12} | {}", ip, stats.sent, stats.received);
        if *flag == true {
            exit(0);
        }
    }
}

fn register_keystroke(flag: &mut bool) {
    if poll(Duration::from_secs(0)).unwrap() {
        match read().unwrap() {
            Event::Key(KeyEvent {
                code: KeyCode::Char('d'),
                modifiers: KeyModifiers::CONTROL,
                kind: _,
                state: _,
            }) => {
                *flag = true;
                print_menu_options()
            },
            Event::Key(KeyEvent {
                code: KeyCode::Char('c'),
                modifiers: KeyModifiers::CONTROL,
                kind: _,
                state: _,
            }) => exit(1),
            _ => (),
        }
    }
}

fn print_logs() {
    Command::new("cmd")
        .args(["/C", "dir *log*.txt"])
        .spawn()
        .expect("failed to execute process");
}

fn extract_from_log(file_name: &String, cross_ip: &String) {
    let file = File::open(file_name).expect("file not found");
    let reader = io::BufReader::new(file);

    let re = Regex::new(
        r"Traffic from ip (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) has been registered (\d+) times\.",
    )
    .unwrap();

    for line in reader.lines() {
        let line = line.unwrap();

        if let Some(captures) = re.captures(&line) {
            let ip = captures.get(1).map_or("", |m| m.as_str());
            let count = captures.get(2).map_or("", |m| m.as_str());

            let u_count: u32 = count.parse().unwrap();
            if ip == cross_ip {
                if u_count > 0 {
                    println!(
                        "{}",
                        format!(
                            "Found occurence of ip: traffic from {} has been registered {} times!",
                            ip, count
                        )
                        .red()
                    );
                } else {
                    println!("Found ip {}, but no registered traffic.", ip);
                }
            } else {
                println!("No crossref of ip {} in current log.", ip);
            }
        }
    }
}
