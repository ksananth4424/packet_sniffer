use crate::arguments::parse_packets::{HeaderPacket, PacketParse, ParsedPacket};
use pcap::{Active, Capture, Device};

pub struct CatchPackets {
    err_count: u64,
}

impl CatchPackets {
    pub fn new() -> CatchPackets {
        CatchPackets { err_count: 0 }
    }

    pub fn list_devices() -> Result<(), pcap::Error> {
        let devices: Vec<String> = Device::list()?.iter().map(|val| val.name.clone()).collect();
        println!("All Interfaces : ");
        devices.iter().for_each(|val| println!("* {}", val));
        Ok(())
    }

    fn print_err(&mut self, err: String) {
        self.err_count += 1;
        eprintln!("ERROR {} : {}", self.err_count, err);
    }

    pub fn save_to_file(&mut self, mut cap_handle: Capture<Active>, file_name: &str) {
        match cap_handle.savefile(&file_name) {
            Ok(mut file) => {
                while let Ok(packet) = cap_handle.next_packet() {
                    file.write(&packet);
                }
            }
            Err(err) => {
                self.print_err(err.to_string());
            }
        }
    }

    pub fn print_to_console(&mut self, mut cap_handle: Capture<Active>) {
        self.print_headers();

        while let Ok(packet) = cap_handle.next_packet() {
            let data = packet.data.to_owned();
            let len = packet.header.len;
            let ts: String = format!(
                "{}.{:06}",
                &packet.header.ts.tv_sec, &packet.header.ts.tv_usec
            );

            let packet_parse = PacketParse::new();
            let parsed_packet = packet_parse.parse_packet(data, len, ts);
            match parsed_packet {
                Ok(parsed_packet) => {
                    self.print_packet(&parsed_packet);
                }
                Err(err) => {
                    self.print_err(err.to_string());
                }
            }
        }
    }

    fn print_headers(&self) {
        println!(
            "{0: <25} | {1: <15} | {2: <25} | {3: <15} | {4: <15} | {5: <15} | {6: <35} |",
            "Source IP", "Source Port", "Dest IP", "Dest Port", "Protocol", "Length", "Timestamp"
        );
        println!("{:-^1$}", "-", 165,);
    }

    fn get_packet_meta(&self, parsed_packet: &ParsedPacket) -> (String, String, String, String) {
        let mut src_addr = "".to_string();
        let mut dst_addr = "".to_string();
        let mut src_port = "".to_string();
        let mut dst_port = "".to_string();

        parsed_packet.headers.iter().for_each(|pack| {
            match pack {
                HeaderPacket::Tcp(packet) => {
                    src_port = packet.source_port.to_string();
                    dst_port = packet.dest_port.to_string();
                }
                HeaderPacket::Udp(packet) => {
                    src_port = packet.source_port.to_string();
                    dst_port = packet.dest_port.to_string();
                }
                HeaderPacket::Ipv4(packet) => {
                    src_addr = packet.source_addr.to_string();
                    dst_addr = packet.dest_addr.to_string();
                }
                HeaderPacket::Ipv6(packet) => {
                    src_addr = packet.source_addr.to_string();
                    dst_addr = packet.dest_addr.to_string();
                }
                HeaderPacket::Arp(packet) => {
                    src_addr = packet.src_addr.to_string();
                    dst_addr = packet.dest_addr.to_string();
                }
                _ => {}
            };
        });

        (src_addr, src_port, dst_addr, dst_port)
    }

    fn print_packet(&self, parsed_packet: &ParsedPacket) {
        let (src_addr, src_port, dst_addr, dst_port) = self.get_packet_meta(&parsed_packet);
        let protocol = &parsed_packet.headers[0].to_string();
        let length = &parsed_packet.len;
        let ts = &parsed_packet.timestamp;
        println!(
            "{0: <25} | {1: <15} | {2: <25} | {3: <15} | {4: <15} | {5: <15} | {6: <35}",
            src_addr, src_port, dst_addr, dst_port, protocol, length, ts
        );
    }

}
