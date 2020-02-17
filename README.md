enr
============

[![Build Status]][Build Link] [![Doc Status]][Doc Link] [![Crates
Status]][Crates Link]

[Build Status]: https://github.com/AgeManning/enr/workflows/build/badge.svg?branch=master
[Build Link]: https://github.com/AgeManning/enr/actions
[Doc Status]: https://docs.rs/mio/badge.svg
[Doc Link]: https://docs.rs/enr/0.1.0-alpha/enr/
[Crates Status]: https://img.shields.io/crates/v/enr.svg
[Crates Link]: https://crates.io/crates/enr

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

- `serde`: Allows for serde serialization and deserialization for ENRs
- `libp2p`: Provides libp2p integration. Libp2p keypairs can be converted to `DefaultKey`
structs which can be used to sign and modify ENR's. This feature also adds a `peer_id()`
function to an ENR which provides an ENR's associated peer_id.

These can be enabled via adding the feature flag in your `Cargo.toml`

```toml
enr = { version = "0.1.0-alpha", features = ["serde", "libp2p"]
```

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
enr = "0.1.0-alpha"
```

To build an ENR, an `EnrBuilder` is provided.

Example (Building an ENR):

```rust
use enr::{EnrBuilder, DefaultKey};
use std::net::Ipv4Addr;

let key = DefaultKey::generate_secp256k1();
let ip = Ipv4Addr::new(192,168,0,1);
let enr = EnrBuilder::new("v4").ip(ip.into()).tcp(8000).build(&key).unwrap();

assert_eq!(enr.ip(), Some("192.168.0.1".parse().unwrap()));
assert_eq!(enr.id(), Some("v4".into()));
```

Pre-existing keys can also be used to sign/modify an ENR.
```rust
use enr::{EnrBuilder, DefaultKey};
use std::net::Ipv4Addr;
use secp256k1::SecretKey;
use rand::thread_rng;
use std::convert::TryInto;

let mut rng = thread_rng();
let key: DefaultKey = secp256k1::SecretKey::random(&mut rng).into();

// with the `libp2p` feature flag, can also use a libp2p key
// let libp2p_key = libp2p_core::identity::Keypair::generate_secp256k1();
// let key: DefaultKey = libp2p_key.try_into().expect("supports secp256k1");

let ip = Ipv4Addr::new(192,168,0,1);
let enr = EnrBuilder::new("v4").ip(ip.into()).tcp(8000).build(&key).unwrap();

// a multiaddr and peer_id exist with libp2p feature flag
// assert_eq!(enr.multiaddr()[0], "/ip4/192.168.0.1/tcp/8000".parse().unwrap());
assert_eq!(enr.ip(), Some("192.168.0.1".parse().unwrap()));
assert_eq!(enr.id(), Some("v4".into()));
```
