mod catch;
mod parse;
mod catch_packets;
mod parse_packet;
use clap::{crate_authors, crate_description, crate_name, crate_version, App};
use pcap::{Capture, Device};

use crate::args::capture::CatchSubcommand;
use crate::args::parse::ParseSubcommand;
use crate::args::catch_packets::PacketCapture;
use std::cell::RefCell;

fn print_default(name: String) {
    println!("{:-^1$}", "-", 20,);
    println!("Sniffing  {}", name);
    println!("{:-^1$} \n\n", "-", 20,);
}

pub fn parse_arguments() {
    let capture_subcommand = CatchSubcommand::new();
    let parse_subcommand = ParseSubcommand::new();

    let matches = App::new(crate_name!())
        .version(crate_version!())
        .author(crate_authors!())
        .about(crate_description!())
        .subcommand(catch_subcommand.get_subcommand())
        .subcommand(parse_subcommand.get_subcommand())
        .get_matches();

    if let Some(sub) = matches.subcommand_matches("catch") {
        if sub.subcommand_matches("list").is_some() {
            if let Err(err) = PacketCapture::list_devices() {
                eprintln!("{}", err.to_string())
            }
        } else if let Some(run_args) = sub.subcommand_matches("run") {
            let device;

            match run_args.value_of("device_handle") {
                Some(handle) => {
                    device = Capture::from_device(handle);
                }
                None => {
                    let capture_device = Device::lookup().unwrap();
                    print_default_device(capture_device.clone().unwrap().name.clone());
                    device = Capture::from_device(capture_device.unwrap().name.as_str());
                }
            }

            match device {
                Ok(device) => {
                    let device = RefCell::new(device);
                    let device = catch_subcommand.run_args(device, run_args);
                    catch_subcommand.start(device, run_args);
                }
                Err(err) => {
                    eprintln!("{}", err.to_string());
                }
            }
        }
    };

    // if let Some(args) = matches.subcommand_matches("parse") {
        // parse_subcommand.start(args);
    // }
}
