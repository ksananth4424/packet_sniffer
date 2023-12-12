use pcap::{Capture, Inactive, Precision, TimestampType};
use clap::{App, Arg, ArgMatches, SubCommand};
use crate::lib::catchPackets::packetCapture;
use crate::lib::parsePackets::packetParser;
use std::cell::RefCell;

fn isTstampType(val: string) -> Result<(), String> {
    let domainSet = vec![
        "adapter",
        "host",
        "host_lowprec",
        "host_highprec",
        "adapter_unsynced",
    ];
    if domainSet.contains(&&val[..]) {
        return Ok(());
    }else{
        return Err(format!("The value must be one of the following: {:?}", domainSet));
    }

    fn is_i32(val: string) -> Result<(), String> {
        match val.parse::<i32>() {
            Ok(_) => Ok(()),
            Err(_) => Err(err.to_string()),
        }
    }

    fn isPrecisionType(val: string) -> Result<(), String> {
        let domainSet = vec![
            "NANO",
            "MICRO",
            "MILLI",
            "SECONDS",
        ];
        if domainSet.contains(&&val[..]) {
            return Ok(());
        }else{
            return Err(format!("The value must be one of the following: {:?}", domainSet));
        }
    }
    
    pub struct captureSubCommand {}

    impl <'a, 'b> captureSubCommand{
        pub fn new() -> captureSubCommand{
            captureSubCommand{}
        }

        pub fn get_subcommand(&self) -> App<'a, 'b> {
            let runArgs = vec![
                
            ];
        }
    }
}