//! Exposes [`Update`] that describe update intents, and [`Op`] a validated update operation.

use bytes::Bytes;
use rlp::Encodable;

use super::Error;
use crate::{Enr, EnrKey, Key};

/// An update operation.
// NOTE: The most user facing type: this simply states an intent and it's not validated.
pub enum Update {
    /// Insert a key and RLP data.
    Insert {
        key: Key,
        content: Bytes,
        trust_valid_rlp: bool,
    },
    /// Remove a key.
    Remove { key: Key },
}

impl Update {
    /// Create an insert operation that adds an [`Encodable`] object to the given key.
    pub fn insert(key: impl AsRef<[u8]>, value: &impl Encodable) -> Self {
        let content = rlp::encode(value).freeze();
        Update::Insert {
            key: key.as_ref().to_vec(),
            content,
            trust_valid_rlp: true,
        }
    }

    /// Create an insert operation where the raw rlp is provided. Due to implementation contrains, this
    /// only accepts rlp strings, but not lists.
    pub fn insert_raw(key: impl AsRef<[u8]>, content: Bytes) -> Self {
        Update::Insert {
            key: key.as_ref().to_vec(),
            content,
            trust_valid_rlp: false,
        }
    }

    /// Create a remove operation.
    pub fn remove(key: impl AsRef<[u8]>) -> Self {
        Update::Remove {
            key: key.as_ref().to_vec(),
        }
    }

    /// Validate the update operation.
    pub(super) fn to_valid_op(self) -> Result<Op, Error> {
        match self {
            Update::Insert {
                key,
                content,
                trust_valid_rlp,
            } => {
                if !trust_valid_rlp {
                    // TODO(@divma): this verification only checks that the rlp header is valid, it's unlikely
                    // we can fully verify in depth the data but at least we could verify the payload size
                    //
                    // also, this only verifies that this has a "valid" payload if a rlp string, but the data
                    // could be a list as well so rejecting this is probably wrong in some cases
                    //
                    // rlp sucks
                    rlp::Rlp::new(content.as_ref())
                        .data()
                        .map_err(Error::InvalidRlpData)?;
                }
                match key.as_slice() {
                    b"tcp" | b"tcp6" | b"udp" | b"udp6" => {
                        if rlp::decode::<u16>(&content).is_err() {
                            return Err(Error::InvalidReservedKeyData(key));
                        }
                    }
                    b"id" => {
                        let id_bytes =
                            rlp::decode::<Vec<u8>>(&content).map_err(Error::InvalidRlpData)?;
                        if id_bytes != b"v4" {
                            return Err(Error::UnsupportedIdentityScheme);
                        }
                    }
                    b"ip" => {
                        let ip4_bytes =
                            rlp::decode::<Vec<u8>>(&content).map_err(Error::InvalidRlpData)?;
                        if ip4_bytes.len() != 4 {
                            return Err(Error::InvalidReservedKeyData(key));
                        }
                    }
                    b"ip6" => {
                        let ip6_bytes =
                            rlp::decode::<Vec<u8>>(&content).map_err(Error::InvalidRlpData)?;
                        if ip6_bytes.len() != 16 {
                            return Err(Error::InvalidReservedKeyData(key));
                        }
                    }
                    _ => {}
                };

                Ok(Op::Insert { key, content })
            }
            Update::Remove { key } => match key.as_slice() {
                b"id" => Err(Error::InvalidReservedKeyData(key)),
                _ => Ok(Op::Remove { key }),
            },
        }
    }
}

/// A valid update operation over the [`Enr`]. This is the result of validating an [`Update`].
pub(super) enum Op {
    /// Insert a key and RLP data.
    Insert { key: Key, content: Bytes },
    /// Remove a key.
    Remove { key: Key },
}

impl Op {
    /// Applies the operation and returns the inverse.
    pub fn apply_and_invert<K: EnrKey>(self, enr: &mut Enr<K>) -> Op {
        match self {
            Op::Insert { key, content } => match enr.content.insert(key.clone(), content) {
                Some(content) => Op::Insert { key, content },
                None => Op::Remove { key },
            },
            Op::Remove { key } => match enr.content.remove(&key) {
                Some(content) => Op::Insert { key, content },
                None => Op::Remove { key },
            },
        }
    }

    /// Applies the operation to the [`Enr`].
    pub fn apply<K: EnrKey>(self, enr: &mut Enr<K>) {
        match self {
            Op::Insert { key, content } => enr.content.insert(key, content),
            Op::Remove { key } => enr.content.remove(&key),
        };
    }
}
