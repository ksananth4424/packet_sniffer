use clap::{App, Arg, ArgMatches, SubCommand};
use crate::lib::catchPackets::packetCapture;

pub struct parseSubcommand {}

impl<'a, 'b> parseSubcommand {
    pub fn new() -> parseSubcommand {
        parseSubcommand {}
    }

    pub fn getSubCommand(&self) -> App<'a, 'b> {
        let parseArgs = vec![
            Arg::with_name("fileName").required(true),
            Arg::with_name("saveFile")
                .help("Parse the packets into JSON and save them to memory.")
                .takes_value(true)
                .short("s")
                .long("saveFile"),
            Arg::with_name("filter")
                .help("Set filter to the capture using the given BPF program string.")
                .takes_value(true)
                .short("f")
                .long("filter"),
        ];
        SubCommand::with_name("parse")
            .about("Parse a pcap file.")
            .args(&parseArgs)
    }

    pub fn start(&self, args: &ArgMatches){
        let mut filter = None;
        let mut saveFilePath = None;
        let mut packet_capture = packetCapture::new();

        if let Some(temp) = args.value_of("filter") {
            filter = Some(temp.to_string());
        }
        if let Some(temp) = args.value_of("saveFile") {
            saveFilePath = Some(temp.to_string());
        }
        if let Some(temp) = args.value_of("fileName") {
            packet_capture.parseFromFile(temp, saveFilePath, filter);
        }
    }
}
