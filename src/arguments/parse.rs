use clap::{App, Arg, ArgMatches, SubCommand};
use crate::lib::catch_packets::CatchPackets;

pub struct ParseSubcommand {}

impl<'a, 'b> ParseSubcommand {
    pub fn new() -> ParseSubcommand {
        ParseSubcommand {}
    }

    pub fn get_subcommand(&self) -> App<'a, 'b> {
        let parse_args = vec![
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
            .args(&parse_args)
    }

    pub fn start(&self, args: &ArgMatches){
        let mut filter = None;
        let mut save_file_path = None;
        let mut packet_capture = CatchPackets::new();

        if let Some(temp) = args.value_of("filter") {
            filter = Some(temp.to_string());
        }
        if let Some(temp) = args.value_of("saveFile") {
            save_file_path = Some(temp.to_string());
        }
        if let Some(temp) = args.value_of("fileName") {
            packet_capture.parse_from_file(temp, save_file_path, filter);
        }
    }
}
