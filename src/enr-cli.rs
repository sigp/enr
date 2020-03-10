//! This is currently a simple tool to read base64 encoded ENR's. More features may be added in
//! the future.

use clap::{App, Arg};
#[cfg(feature = "ed25519")]
use enr::CombinedKey;
use enr::{Enr, EnrKey};

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
        .get_matches();

    let enr_base64 = matches.value_of("enr").expect("Must supply an ENR");

    // if the ed25519 key is supported, we can use the combined key to attempt to decode all
    // types
    #[cfg(feature = "ed25519")]
    let enr = enr_base64.parse::<Enr<CombinedKey>>().unwrap();
    #[cfg(not(feature = "ed25519"))]
    let enr = enr_base64.parse::<Enr>().unwrap();
    print_enr(enr);
}

fn print_enr<K: EnrKey>(enr: Enr<K>) {
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
