//here we define the arguments for the parse subcommand
use clap::{App, Arg, SubCommand};

pub struct ParseSubcommand {}

// Implementing the ParseSubcommand
impl<'a, 'b> ParseSubcommand {
    pub fn new() -> ParseSubcommand {
        ParseSubcommand {}
    }

    // this function will get the subcommand
    pub fn get_subcommand(&self) -> App<'a, 'b> {
        let parse_args = vec![
            Arg::with_name("file_name").required(true),
            Arg::with_name("savefile")
                .help("Parse the packets into JSON and save them to memory.")
                .takes_value(true)
                .short("s")
                .long("savefile"),
            Arg::with_name("filter")
                .help("Set filter to the capture using the given BPF program string.")
                .takes_value(true)
                .long("filter")
                .short("f"),
        ];

        SubCommand::with_name("parse")
            .about("Parse pcap files.")
            .args(&parse_args)
    }

}
