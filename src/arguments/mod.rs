mod catch;
mod parse;

use clap::{crate_authors, crate_description, crate_name, crate_version, App};
use pcap::{Capture, Device};

use std::cell::RefCell;
use crate::arguments::catch::CatchSubcommand;
use crate::arguments::parse::ParseSubcommand;
use crate::lib::catch_packets::CatchPackets;

pub fn parse_arguments(){
    let catch_subcommand = CatchSubcommand::new();
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
            if let Err(err) = CatchPackets::list_devices() {
                println!("{}", err);
            }
        }else if let Some(run_args) = sub.subcommand_matches("run"){
            let device;
            match run_args.value_of("device_handler"){
                Some(handle) => {
                    device = Capture::from_device(handle);
                }
                None => {
                    let capture_device = Device::lookup().unwrap();
                    print_default(capture_device.name.clone());
                    device = Capture::from_device(capture_device);
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
    if let Some(args) = matches.subcommand_matches("parse") {
        parse_subcommand.start(args);
    }
}

fn print_default(name: String) {
    println!("{:-^1$}", "-", 20,);
    println!("Sniffing device {}", name);
    println!("{:-^1$} \n\n", "-", 20,);
}