enr
============

[![Build Status]][Build Link] [![Doc Status]][Doc Link] [![Crates
Status]][Crates Link]

[Build Status]: https://github.com/AgeManning/enr/workflows/build/badge.svg?branch=master
[Build Link]: https://github.com/AgeManning/enr/actions
[Doc Status]: https://docs.rs/mio/badge.svg
[Doc Link]: https://docs.rs/enr
[Crates Status]: https://img.shields.io/crates/v/enr.svg
[Crates Link]: https://crates.io/crates/enr

[Documentation at docs.rs](https://docs.rs/enr)

This crate contains an implementation of an Ethereum Node Record (ENR) as specified by
[EIP-778](https://eips.ethereum.org/EIPS/eip-778) extended to allow for the use of ed25519 keys.

An ENR is a signed, key-value record which has an associated `NodeId` (a 32-byte identifier).
Updating/modifying an ENR requires an `EnrKey` in order to re-sign the record with the
associated key-pair.

User's wishing to implement their own singing algorithms simply need to
implement the `EnrKey` trait and apply it to an `EnrRaw`.

This implementation uses a `DefaultKey` which implements signing for `secp256k1` and
`ed25519` keys. With the `libp2p` feature enabled, this provides conversions from libp2p
`Keypair` for libp2p integration.

ENR's are identified by their sequence number. When updating an ENR, the sequence number is
increased.

Different identity schemes can be used to define the node id and signatures. Currently only the
"v4" identity is supported and is set by default.

## Features

This crate supports two features.

- `serde`: Allows for serde serialization and deserialization for ENRs.
- `libp2p`: Provides libp2p integration. Libp2p `Keypair`'s can be converted to `DefaultKey`
structs which can be used to sign and modify ENRs. This feature also adds the `peer_id()`
and `multiaddr()` functions to an ENR which provides an ENR's associated `PeerId`.

These can be enabled via adding the feature flag in your `Cargo.toml`

```toml
enr = { version = 0.1.0-alpha-1, features = ["serde", "libp2p"] }
```

# Example

To build an ENR, an `EnrBuilder` is provided.

Example (Building an ENR):

```rust
use enr::{EnrBuilder, DefaultKey};
use std::net::Ipv4Addr;
use rand::thread_rng;
use std::convert::TryInto;

// generate a new key
let key = DefaultKey::generate_secp256k1();

// pre-existing keys can also be used
let mut rng = thread_rng();
let key: DefaultKey = secp256k1::SecretKey::random(&mut rng).into();

// with the `libp2p` feature flag, one can also use a libp2p key
// let libp2p_key = libp2p_core::identity::Keypair::generate_secp256k1();
// let key: DefaultKey = libp2p_key.try_into().expect("supports secp256k1");

let ip = Ipv4Addr::new(192,168,0,1);
let enr = EnrBuilder::new("v4").ip(ip.into()).tcp(8000).build(&key).unwrap();

assert_eq!(enr.ip(), Some("192.168.0.1".parse().unwrap()));
assert_eq!(enr.id(), Some("v4".into()));
```

ENR fields can be added and modified using the getters/setters on `EnrRaw`. A custom field
can be added using the `add_key`.

```rust
use enr::{EnrBuilder, DefaultKey, Enr};
use std::net::Ipv4Addr;

let key = DefaultKey::generate_secp256k1();

let ip = Ipv4Addr::new(192,168,0,1);
let mut enr = EnrBuilder::new("v4").ip(ip.into()).tcp(8000).build(&key).unwrap();

enr.set_tcp(8001, &key);
// set a custom key
enr.insert("custom_key", vec![0,0,1], &key);

// encode to base64
let base_64_string = enr.to_base64();

// decode from base64
let decoded_enr: Enr = base_64_string.parse().unwrap();

assert_eq!(decoded_enr.ip(), Some("192.168.0.1".parse().unwrap()));
assert_eq!(decoded_enr.id(), Some("v4".into()));
assert_eq!(decoded_enr.tcp(), Some(8001));
assert_eq!(decoded_enr.get("custom_key"), Some(&vec![0,0,1]));
```
