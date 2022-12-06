//! ### `NodeId`
//!
//! The identifier for an ENR record - a keccak256 hash of the public key.
//! For secp256k1 keys this is the uncompressed encoded form of the public key.
//!
//! #### Usage
//!
//! The `NodeId` can be constructed using the [rand](rand) crate. See an example below.
//! ```rust
//! use enr::NodeId;
//! let node_id = NodeId::random();
//! ```
//!
//! Another option is providing a 32 byte array to the `new` function.
//! ```rust
//! use enr::NodeId;
//! let node_id = NodeId::new([0; 32]);
//! ```
//!
//! Additionally, [`NodeId`](enr::NodeId) conveniently exposes a `parse` function which takes a slice with dynamic length.
//! NOTE: This method only accepts slices with length <= 32, padding underflowing slices with zeros.
//! ```rust
//! use enr::NodeId;
//! let node_id = NodeId::parse(&[0; 32]).unwrap();
//! ```
//!
//! To retrieve the raw bytes of the node id, use the `raw` method as follows.
//! ```rust
//! use enr::NodeId;
//! let node_id = NodeId::new([0; 32]);
//! let raw = node_id.raw();
//! assert_eq!(raw, [0; 32]);
//! ```

use crate::{digest, keys::EnrPublicKey, Enr, EnrKey};

type RawNodeId = [u8; 32];

/// The `NodeId` of an ENR (a 32 byte identifier).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NodeId {
    raw: RawNodeId,
}

impl NodeId {
    /// Creates a new node record from 32 bytes.
    #[must_use]
    pub const fn new(raw_input: &[u8; 32]) -> Self {
        Self { raw: *raw_input }
    }

    /// Parses a byte slice to form a node Id. This fails if the slice isn't of length 32.
    pub fn parse(raw_input: &[u8]) -> Result<Self, &'static str> {
        if raw_input.len() > 32 {
            return Err("Input too large");
        }

        let mut raw: RawNodeId = [0_u8; 32];
        raw[..std::cmp::min(32, raw_input.len())].copy_from_slice(raw_input);

        Ok(Self { raw })
    }

    /// Generates a random `NodeId`.
    #[must_use]
    pub fn random() -> Self {
        Self {
            raw: rand::random(),
        }
    }

    /// Returns a `RawNodeId` which is a 32 byte list.
    #[must_use]
    pub const fn raw(&self) -> RawNodeId {
        self.raw
    }
}

impl<T: EnrPublicKey> From<T> for NodeId {
    fn from(public_key: T) -> Self {
        Self::parse(&digest(public_key.encode_uncompressed().as_ref()))
            .expect("always of correct length; qed")
    }
}

impl<T: EnrKey> From<Enr<T>> for NodeId {
    fn from(enr: Enr<T>) -> Self {
        enr.node_id()
    }
}

impl<T: EnrKey> From<&Enr<T>> for NodeId {
    fn from(enr: &Enr<T>) -> Self {
        enr.node_id()
    }
}

impl AsRef<[u8]> for NodeId {
    fn as_ref(&self) -> &[u8] {
        &self.raw[..]
    }
}

impl PartialEq<RawNodeId> for NodeId {
    fn eq(&self, other: &RawNodeId) -> bool {
        self.raw.eq(other)
    }
}

impl From<RawNodeId> for NodeId {
    fn from(raw: RawNodeId) -> Self {
        Self { raw }
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
