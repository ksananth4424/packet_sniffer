// inlcude all the subcommands
mod catch;
mod parse;
mod catch_packets;
mod parse_packets;

//use clap and pcap
//clap is used for parsing command line arguments
//pcap is used for capturing packets
use clap::{crate_authors, crate_description, crate_name, crate_version, App};
use pcap::{Capture, Device};

//use the subcommands
use crate::arguments::catch::CatchSubcommand;
use crate::arguments::parse::ParseSubcommand;
use crate::arguments::catch_packets::CatchPackets;
use std::cell::RefCell;

//print the default device
fn print_default_device(name: String) {
    println!("{:-^1$}", "-", 20,);
    println!("Sniffing  {}", name);
    println!("{:-^1$} \n\n", "-", 20,);
}

//parse the arguments
pub fn parse_arguments() {
    let catch_subcommand = CatchSubcommand::new();
    let parse_subcommand = ParseSubcommand::new();

    //match the patterns
    let matches = App::new(crate_name!())
        .version(crate_version!())
        .author(crate_authors!())
        .about(crate_description!())
        .subcommand(catch_subcommand.get_subcommand())
        .subcommand(parse_subcommand.get_subcommand())
        .get_matches();

    //match the subcommands
    if let Some(sub) = matches.subcommand_matches("capture") {
        if sub.subcommand_matches("list").is_some() {
            if let Err(err) = CatchPackets::list_devices() {
                eprintln!("{}", err.to_string())
            }
        } else if let Some(run_args) = sub.subcommand_matches("run") {
            let device;

            match run_args.value_of("device_handle") {
                Some(handle) => {
                    device = Capture::from_device(handle);
                }
                None => {
                    let catch_device = Device::lookup().unwrap();
                    print_default_device(catch_device.clone().unwrap().name.clone());
                    device = Capture::from_device(catch_device.unwrap().name.as_str());
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
}
