//! The identifier for an ENR record. This is the keccak256 hash of the public key (for secp256k1
//! keys this is the uncompressed encoded form of the public key).

use crate::keys::EnrPublicKey;
use sha3::{Digest, Keccak256};

type RawNodeId = [u8; 32];

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
/// The NodeId of an ENR (a 32 byte identifier).
pub struct NodeId {
    raw: RawNodeId,
}

impl NodeId {
    /// Creates a new node record from 32 bytes.
    pub fn new(raw_input: &[u8; 32]) -> Self {
        NodeId { raw: *raw_input }
    }

    /// Parses a byte slice to form a node Id. This fails if the slice isn't of length 32.
    pub fn parse(raw_input: &[u8]) -> Result<Self, &'static str> {
        if raw_input.len() > 32 {
            return Err("Input too large");
        }

        let mut raw: RawNodeId = [0u8; 32];
        raw[..std::cmp::min(32, raw_input.len())].copy_from_slice(raw_input);

        Ok(NodeId { raw })
    }

    /// Generates a random NodeId.
    pub fn random() -> Self {
        NodeId {
            raw: rand::random(),
        }
    }

    /// Returns a `RawNodeId` which is a 32 byte list.
    pub fn raw(&self) -> RawNodeId {
        self.raw
    }
}

impl<T: EnrPublicKey> From<T> for NodeId {
    fn from(public_key: T) -> Self {
        let pubkey_bytes = public_key.encode_uncompressed();
        NodeId::parse(&Keccak256::digest(&pubkey_bytes)).expect("must be the correct length")
    }
}

impl std::fmt::Display for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let hex_encode = hex::encode(self.raw);
        write!(
            f,
            "0x{}..{}",
            &hex_encode[0..4],
            &hex_encode[hex_encode.len() - 4..]
        )
    }
}
