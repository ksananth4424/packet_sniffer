## Packet Sniffer
A project to list packets

## Features

* Capturing packets and encoding them to Pcap files, or print them onto console.
* While capturing packets, various configuration parameters can be specified. 
* Multi-threaded parsing of packets.
* Filter packets while parsing and capturing.

## File Structure
.
├── Cargo.lock
├── Cargo.toml
├── README.md
└── src
    ├── arguments
    │   ├── catch_packets.rs
    │   ├── catch.rs
    │   ├── mod.rs
    │   ├── parse_packets.rs
    │   └── parse.rs
    └── main.rs

2 directories, 9 files

## Installation
Ensure that you have `libpcap-dev` (ubuntu) or the corresponding package installed on your system.

Clone the repository by running the following command

    $ git clone https://github.com/ksananth4424/packet_sniffer.git

## Build
Change directory to packet_sniffer and build the project

    $ cargo build

## Quick Start

```zsh
$ sudu cargo run capture run
--------------------
Sniffing  wlo1
-------------------- 


Source IP                 | Source Port     | Dest IP                   | Dest Port       | Protocol        | Length          | Timestamp                           |
---------------------------------------------------------------------------------------------------------------------------------------------------------------------
192.168.1.106             | 54755           | 192.168.1.1               | 53              | Dns             | 85              | 1713540874.094076                  
192.168.1.106             | 41631           | 192.168.1.1               | 53              | Udp             | 85              | 1713540874.094246                  
192.168.1.106             | 50866           | 192.168.1.1               | 53              | Dns             | 91              | 1713540874.094384                  
192.168.1.106             | 55013           | 192.168.1.1               | 53              | Udp             | 91              | 1713540874.094525                  
192.168.1.106             | 48693           | 192.168.1.1               | 53              | Udp             | 100             | 1713540874.096900                  
192.168.1.1               | 53              | 192.168.1.106             | 41631           | Udp             | 150             | 1713540874.103167                  
192.168.1.1               | 53              | 192.168.1.106             | 54755           | Dns             | 452             | 1713540874.103214                  
192.168.1.1               | 53              | 192.168.1.106             | 50866           | Dns             | 491             | 1713540874.208984                  
192.168.1.1               | 53              | 192.168.1.106             | 55013           | Udp             | 189             | 1713540874.208984                  
192.168.1.1               | 53              | 192.168.1.106             | 48693           | Udp             | 165             | 1713540874.209013                  
192.168.1.106             | 45319           | 192.168.1.1               | 53              | Dns             | 81              | 1713540884.769773                  
192.168.1.106             | 33198           | 192.168.1.1               | 53              | Udp             | 81              | 1713540884.770257                  
192.168.1.1               | 53              | 192.168.1.106             | 33198           | Udp             | 146             | 1713540884.778951                  
192.168.1.1               | 53              | 192.168.1.106             | 45319           | Dns             | 448             | 1713540884.778951                  
192.168.1.106             | 36280           | 192.168.1.1               | 53              | Dns             | 100             | 1713540885.321794                  
192.168.1.106             | 57082           | 192.168.1.1               | 53              | Udp             | 100             | 1713540885.321943                  
192.168.1.1               | 53              | 192.168.1.106             | 57082           | Udp             | 165             | 1713540885.388973                  
192.168.1.1               | 53              | 192.168.1.106             | 36280           | Dns             | 515             | 1713540885.394520                  
192.168.1.106             | 57645           | 192.168.1.1               | 53              | Dns             | 102             | 1713540886.850198                  
192.168.1.106             | 59326           | 192.168.1.1               | 53              | Udp             | 102             | 1713540886.850378                  
192.168.1.1               | 53              | 192.168.1.106             | 59326           | Udp             | 159             | 1713540886.858145                  
192.168.1.1               | 53              | 192.168.1.106             | 57645           | Dns             | 501             | 1713540886.858961                  
192.168.1.106             | 48389           | 192.168.1.1               | 53              | Dns             | 90              | 1713540889.079968                  
192.168.1.106             | 58598           | 192.168.1.1               | 53              | Udp             | 90              | 1713540889.080159                  
192.168.1.106             | 51116           | 192.168.1.1               | 53              | Udp             | 91              | 1713540889.083010                  
192.168.1.1               | 53              | 192.168.1.106             | 51116           | Udp             | 141             | 1713540889.088617                  
192.168.1.1               | 53              | 192.168.1.106             | 58598           | Udp             | 164             | 1713540889.088617                  
192.168.1.1               | 53              | 192.168.1.106             | 48389           | Dns             | 266             | 1713540889.088618                  
192.168.1.106             |                 | 192.168.1.1               |                 | Arp             | 42              | 1713540889.856878                  
192.168.1.1               |                 | 192.168.1.106             |                 | Arp             | 42              | 1713540889.861447                  
192.168.1.106             | 42157           | 192.168.1.1               | 53              | Dns             | 106             | 1713540890.393606                  
192.168.1.106             | 38655           | 192.168.1.1               | 53              | Udp             | 106             | 1713540890.393784                  
192.168.1.1               | 53              | 192.168.1.106             | 38655           | Udp             | 163             | 1713540890.400506                  
192.168.1.1               | 53              | 192.168.1.106             | 42157           | Dns             | 505             | 1713540890.401585                  
192.168.1.106             | 48460           | 192.168.1.1               | 53              | Dns             | 100             | 1713540890.412640                  
192.168.1.106             | 45181           | 192.168.1.1               | 53              | Udp             | 100             | 1713540890.412877                  
192.168.1.106             | 33093           | 192.168.1.1               | 53              | Udp             | 99              | 1713540890.415002
```

Capture packets and save them in Pcap files :

```shell
$ sudo cargo run capture run --timeout 10000 --savefile captured.pcap
```
## TO DO
-> Parse Pcap files to JSON files

-> Documentation

Happy Coding!!
