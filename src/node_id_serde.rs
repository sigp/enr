//! The identifier for an ENR record. This is the keccak256 hash of the public key (for secp256k1
//! keys this is the uncompressed encoded form of the public key).

use crate::{digest, keys::EnrPublicKey, Enr, EnrKey};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use stremio_serde_hex::{SerHex, StrictPfx};

type RawNodeIdSerde = [u8; 32];

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
/// The `NodeIdSerde` of an ENR (a 32 byte identifier).
pub struct NodeIdSerde(RawNodeIdSerde);

impl NodeIdSerde {
    /// Creates a new node record from 32 bytes.
    #[must_use]
    pub const fn new(raw_input: &[u8; 32]) -> Self {
        Self(*raw_input)
    }

    /// Parses a byte slice to form a node Id. This fails if the slice isn't of length 32.
    pub fn parse(raw_input: &[u8]) -> Result<Self, &'static str> {
        if raw_input.len() > 32 {
            return Err("Input too large");
        }

        let mut raw: RawNodeIdSerde = [0_u8; 32];
        raw[..std::cmp::min(32, raw_input.len())].copy_from_slice(raw_input);

        Ok(Self(raw))
    }

    /// Generates a random `NodeIdSerde`.
    #[must_use]
    pub fn random() -> Self {
        Self(rand::random())
    }
}

impl<T: EnrPublicKey> From<T> for NodeIdSerde {
    fn from(public_key: T) -> Self {
        Self::parse(&digest(public_key.encode_uncompressed().as_ref()))
            .expect("always of correct length; qed")
    }
}

impl AsRef<[u8]> for NodeIdSerde {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

impl PartialEq<RawNodeIdSerde> for NodeIdSerde {
    fn eq(&self, other: &RawNodeIdSerde) -> bool {
        self.0.eq(other)
    }
}

impl From<RawNodeIdSerde> for NodeIdSerde {
    fn from(raw: RawNodeIdSerde) -> Self {
        Self(raw)
    }
}

impl std::fmt::Display for NodeIdSerde {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let hex_encode = hex::encode(self.0);
        write!(
            f,
            "0x{}..{}",
            &hex_encode[0..4],
            &hex_encode[hex_encode.len() - 4..]
        )
    }
}

impl std::fmt::Debug for NodeIdSerde {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use super::*;

    #[cfg(feature = "serde")]
    use serde_json;
    use serde_json::json;

    #[test]
    fn test_eq_node_raw_node() {
        let node = NodeIdSerde::random();
        let raw = node.0;
        assert_eq!(node, raw);
        assert_eq!(node.as_ref(), &raw[..]);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_serde() {
        let node = NodeIdSerde::random();
        let json_string = serde_json::to_string(&node).unwrap();
        assert_eq!(node, serde_json::from_str::<NodeIdSerde>(&json_string).unwrap());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_serde_will_fail() {
        let mut responses: HashMap<NodeIdSerde, u16> = Default::default();
        responses.insert(NodeIdSerde::random(), 1);
        let hi = json!(responses);
    }
}
