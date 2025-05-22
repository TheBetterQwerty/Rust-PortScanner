/* Syn - Scanner
 * 
 * Scans for specific ports only 
 * Listens 5 seconds after each packet if not then leaves
 * works with only ipv4 and domain names
 * TODO: add support for ipv6 address (use IpAddr then if let the value into ipv4addr)
 * TODO: customizable src ipv4 address
 *
 * */

use std::env::args;
use std::net::{
    Ipv4Addr, IpAddr, ToSocketAddrs
};
use std::thread;
use std::sync::{ Arc, Mutex };
use std::time::{ Duration, Instant };
use pnet::packet::{
    Packet, 
    ipv4::MutableIpv4Packet,
    ip::IpNextHeaderProtocols,
    ipv4::Ipv4Packet,
    tcp::{
        MutableTcpPacket, TcpPacket, TcpFlags, ipv4_checksum
    },

};
use pnet::transport::{
    transport_channel, TransportSender, TransportChannelType::Layer3
};
use pnet::{
    datalink::{self, Channel::Ethernet},
    packet::{
        ethernet::{EthernetPacket, EtherTypes},
    },
    util::checksum,
};


/* CONSTANTS */
const SRC_IP: &str = "172.19.176.159";
const IP_HEADER: usize = 20;
const TCP_HEADER: usize = 20;
const PACKET_LEN: usize = IP_HEADER + TCP_HEADER;
const TIMEOUT: Duration = Duration::from_secs(5);

struct Config {
    src: Ipv4Addr,
    dst: Ipv4Addr,
    ports: Vec<u16>,
    sockfd: TransportSender,
}

impl Config {
    fn new (dst: &String, ports: Vec<u16>) -> Self {
        let (sockfd, _) = transport_channel(1024, Layer3(IpNextHeaderProtocols::Ipv4)).unwrap_or_else(|_| {
            panic!("[!] Please use root privilages for this script!");
        });
        let dst_ip = dst.parse().unwrap_or_else(|_| {
            resolve_ip(dst).expect("[!] Error resolving ip")
        });

        Config {
            src: SRC_IP.parse().expect("[!] Error parsing source ip!"),
            dst: dst_ip,
            ports,
            sockfd
        }
    }

    fn build_packet(&self, packet: &mut [u8; PACKET_LEN], port: u16, pkt_type: bool) {
        // IP HEADERS
        {
            let mut ip = MutableIpv4Packet::new(&mut packet[..IP_HEADER]).expect("Error creating ip packet!");
            ip.set_version(4);
            ip.set_header_length(5);

            ip.set_source(self.src);
            ip.set_destination(self.dst);

            ip.set_total_length(PACKET_LEN as u16);
            ip.set_ttl(64);
            ip.set_next_level_protocol(IpNextHeaderProtocols::Tcp);

            let ip_checksum = checksum(ip.packet(), 0);
            ip.set_checksum(ip_checksum);
        }

        // TCP HEADERS
        {
            let mut tcp = MutableTcpPacket::new(&mut packet[TCP_HEADER..]).expect("Error creating tcp packet!");
            tcp.set_source(12345);
            tcp.set_destination(port);
            tcp.set_sequence(0);
            tcp.set_acknowledgement(0);

            tcp.set_data_offset(5);
            tcp.set_window(5480);

            match pkt_type {
                true => tcp.set_flags(TcpFlags::SYN),
                false => tcp.set_flags(TcpFlags::RST),
            }

            let tcp_checksum = ipv4_checksum(&tcp.to_immutable(), &self.src, &self.dst);
            tcp.set_checksum(tcp_checksum);
        } 
    }

    fn send_packet(&mut self, packet: &[u8; PACKET_LEN]) {
        match self.sockfd.send_to(Ipv4Packet::new(packet).unwrap(), IpAddr::V4(self.dst)) {
            Ok(_) => {},
            Err(e) => println!("[!] Error {} occured while sending packet to {:?}", e, self.dst),       
        }
    }
}

fn listener(packet_config: Arc<Mutex<Config>>) {
    let interface = datalink::interfaces()
        .into_iter()
        .find(|dev| dev.is_up() && !dev.is_loopback() && !dev.ips.is_empty())
        .expect("[!] Error finding devices!");

    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Error in channel!"),
        Err(e) => panic!("[!] Error {} occured!", e),
    };

    let mut response_time = Instant::now();

    while let Ok(packet) = rx.next() {
        /* is it 5 sec or more since the last packet was recived ? if so break */
        if response_time.elapsed() >= TIMEOUT {
            println!("[+] Packet capture complete");
            break;
        }

        let eth_packet = EthernetPacket::new(packet).expect("Failed to parse ethernet packet");
        if eth_packet.get_ethertype() != EtherTypes::Ipv4 {
            continue;
        }

        let ipv4_packet = Ipv4Packet::new(eth_packet.payload()).expect("Error parsing ethernet payload");     
        if ipv4_packet.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
            continue;
        }

        let tcp_packet = TcpPacket::new(&ipv4_packet.payload()).expect("Error parsing ipv4 packet for tcp!");
        
        let flag = tcp_packet.get_flags();
        if (flag & TcpFlags::ACK != 0) && (flag & TcpFlags::SYN != 0) {
            println!("\t[#] Port {} is open", tcp_packet.get_source());
            
            let mut pkt_conf = packet_config.lock().unwrap();
            let mut packet = [0u8; PACKET_LEN];

            /* Send RST packet */
            pkt_conf.build_packet(&mut packet, tcp_packet.get_source(), false);
            pkt_conf.send_packet(&packet);
        }

        response_time = Instant::now();
    }
}

fn sender(packet_config: Arc<Mutex<Config>>) {
    let mut packet = [0u8; PACKET_LEN];
    let mut shared_pkt = packet_config.lock().unwrap();

    for port in shared_pkt.ports.clone() {
        shared_pkt.build_packet(&mut packet, port, true);
        shared_pkt.send_packet(&packet);
        thread::sleep(Duration::from_secs(1));
    }
}

fn resolve_ip(dst: &str) -> Result<Ipv4Addr, &str> {
    if let Ok(mut address) = format!("{}:69", dst).to_socket_addrs() {
        if let Some(IpAddr::V4(ip)) = address.next().map(|x| x.ip()) {
            Ok(ip)
        } else {
            Err("[!] Error resolving ip address")
        }
    } else {
        Err("[!] Error resolving ip")
    }
}

fn main() {
    let argv: Vec<String> = args().collect();
    if argv.len() < 2 {
        println!("[?] Usage: {} <destination-ip>", argv[0]);
        return;
    }
    
    let ports: Vec<u16> = vec![22, 80, 100, 443];
    let packet_config: Arc<Mutex<Config>> = Arc::new(Mutex::new(Config::new(&argv[1], ports))); 
    
    let sender_packet_config = Arc::clone(&packet_config);
    let listener_packet_config = Arc::clone(&packet_config);
    
    println!("[+] Started Scanning Ports of {}", argv[1]);
    let sender = thread::spawn(move || sender(sender_packet_config));
    let reciever = thread::spawn(|| listener(listener_packet_config));
    
    sender.join().unwrap();
    reciever.join().unwrap();
}
