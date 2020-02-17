//! This is currently a simple tool to read base64 encoded ENR's. More features may be added in
//! the future.

use clap::{App, Arg};
use enr::Enr;

fn main() {
    // Parse the CLI parameters.
    let matches = App::new("enr-cli")
        .version("0.1.0")
        .author("Sigma Prime <contact@sigmaprime.io>")
        .about("Simple CLI for reading and modifying ENRs.")
        .arg(
            Arg::with_name("enr")
                .short("e")
                .long("enr")
                .value_name("BASE64-ENR")
                .allow_hyphen_values(true)
                .required(true)
                .help("Reads a base64 ENR and prints common parameters.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("read")
                .short("r")
                .help("Reads a base64 ENR and prints common parameters."),
        )
        /*
        .arg(
            Arg::with_name("set-ip")
                .long("set-ip")
                .value_name("IP-ADDRESS")
                .help("Sets the IP address of an ENR.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("set-tcp")
                .long("set-tcp")
                .value_name("PORT")
                .help("Sets the TCP port of an ENR.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("set-udp")
                .long("set-udp")
                .value_name("PORT")
                .help("Sets the UDP port of an ENR.")
                .takes_value(true),
        )
        */
        .get_matches();

    let enr = matches
        .value_of("enr")
        .map(|enr| enr.parse::<Enr>().expect("Invalid ENR"))
        .expect("Must supply an ENR");

    if matches.is_present("read") {
        print_enr(enr);
    }
}

fn print_enr(enr: Enr) {
    println!("ENR Read");
    println!("Sequence No: {}", enr.seq());
    println!("Node ID: {}", enr.node_id());

    if let Some(ip) = enr.ip() {
        println!("IP: {:?}", ip);
    }
    if let Some(tcp) = enr.tcp() {
        println!("TCP port: {:?}", tcp);
    }
    if let Some(udp) = enr.udp() {
        println!("UDP: {:?}", udp);
    }
}
