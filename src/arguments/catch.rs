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
                Arg::with_name("device_handle")
                    .help("Mention the device interface")
                    .takes_value(true)
                    .long("device_handle"),
                Arg::with_name("timeout")
                    .help("Set the read timeout for the catch. By default it is 0, which means it will block indefinitely")
                    .takes_value(true)
                    .long("timeout")
                    .validator(is_i32)
                    .short("t"),
                Arg::with_name("promisc")
                    .help("Set the promiscuous mode for the catch. By default it is false")
                    .takes_value(true)
                    .long("promisc")
                    .short("p"),
                Arg::with_name("rfmon")
                    .help("Set the rfmon mode for the catch. The default is maintained by the pcap.")
                    .short("r")
                    .long("rfmon"),
                Arg::with_name("snaplen")
                    .help("Set the snaplen size (the maximum length of a packet captured into the buffer). \
                        Useful if you only want certain headers, but not the entire packet.The default is 65535.")
                    .takes_value(true)
                    .validator(is_i32)
                    .short("s")
                    .long("snaplen"),
                Arg::with_name("buffer_size")
                    .help("Set the buffer size for the catch. The default is 1000000.")
                    .takes_value(true)
                    .validator(is_i32)
                    .short("b")
                    .long("buffer_size"),
                Arg::with_name("timestamp_type")
                    .help("Set the timestamp type for the catch. (Host / HostLowPrec / HostHighPrec / Adapter / AdapterUnsynced)")
                    .takes_value(true)
                    .validator(isTstampType)
                    .short("ts")
                    .long("timestamp_type"),
                Arg::with_name("precision")
                    .help("Set the precision for the catch. (NANO / MICRO)")
                    .takes_value(true)
                    .validator(isPrecisionType)
                    .short("p")
                    .long("precision"),
                Arg::with_name("filter")
                    .help("Set the filter for the catch.")
                    .takes_value(true)
                    .short("f")
                    .long("filter"),
                Arg::with_name("saveFile")
                    .help("Save the caught packets in a file.")
                    .takes_value(true)
                    .short("sf")
                    .long("saveFile")
            ];

            SubCommand::with_name("catch")
                .about("Catch the packets from the network interface")
                .subCommand(SubCommand::with_name("list").about("List all the available network interfaces"))
                .subCommand(SubCommand::with_name("run").about("Run the catch command").args(&runArgs))
        }

        pub fn runArgs(
            &self,
            device: RefCell<Capture<Inactive>>,
            args: &ArgMatches,
        ) -> RefCell<Capture<Inactive>> {
            let mut device = device.into_inner();

            if let Some(temp) =  args.value_of("timeout") {
                device = device.timeout(temp.parse().unwrap());
            }
            if let Some(temp) =  args.value_of("promisc") {
                device = device.promisc(temp.parse().unwrap());
            }
            if let Some(temp) =  args.value_of("rfmon") {
                device = device.rfmon(temp.parse().unwrap());
            }
            if let Some(temp) =  args.value_of("snaplen") {
                device = device.snaplen(temp.parse().unwrap());
            }
            if let Some(temp) =  args.value_of("buffer_size") {
                device = device.buffer_size(temp.parse().unwrap());
            }
            if let Some(temp) = args.value_of("timestamp_type") {
                device = device.timestamp_type(self.getTstampType(temp).unwrap());
            }
            RefCell::new(device)
        }

        pub fn start(&self, device: RefCell<Capture<Inactive>>) {
            let device = device.into_inner();
            let mut packet_capture = packetCapture::new();

            match device.open() {
                Ok(mut cap_handle) => {
                    if let Some(temp) = args.value_of("filter") {
                        cap_handle
                            .filter(temp)
                            .expect("Failed to set the filter");
                    }

                    if let Some(temp) = args.value_of("saveFile") {
                        packet_capture.saveFile(cap_handle, temp);
                    }else{
                        packet_capture.printPackets(cap_handle);
                    }
                    Err(e) => {
                        eprintln!("Failed to open the device: {:?}", e);
                    }
                }
            }

            fn getPrecisionType(&self, val: &str) -> Result<Precision, ()> {
                match val {
                    "NANO" => Ok(Precision::NANO),
                    "MICRO" => Ok(Precision::MICRO),
                    _ => Err(()),
                }
            }

            fn getTstampType(&self, val: &str) -> Result<TimestampType, ()> {
                match val {
                    "adapter" => Ok(TimestampType::Adapter),
                    "host" => Ok(TimestampType::Host),
                    "host_lowprec" => Ok(TimestampType::HostLowPrec),
                    "host_highprec" => Ok(TimestampType::HostHighPrec),
                    "adapter_unsynced" => Ok(TimestampType::AdapterUnsynced),
                    _ => Err(()),
                }
            }
        }
    }
}