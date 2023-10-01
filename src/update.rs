//! Update operations over the [`Enr`].

use bytes::Bytes;
use rlp::Encodable;

use crate::{Enr, EnrKey, EnrPublicKey, Key, NodeId, MAX_ENR_SIZE};

/// An update operation.
// The most user facing type: this simply states an intent and is not validated.
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
    pub fn insert(key: impl AsRef<[u8]>, value: &impl Encodable) -> Self {
        let content = rlp::encode(value).freeze();
        Update::Insert {
            key: key.as_ref().to_vec(),
            content,
            trust_valid_rlp: true,
        }
    }

    pub fn insert_raw(key: impl AsRef<[u8]>, content: Bytes) -> Self {
        Update::Insert {
            key: key.as_ref().to_vec(),
            content,
            trust_valid_rlp: false,
        }
    }

    pub fn remove(key: impl AsRef<[u8]>) -> Self {
        Update::Remove {
            key: key.as_ref().to_vec(),
        }
    }
}

/// A valid update operation over the [`Enr`]. This is the result of validating an [`Update`].
pub enum Op {
    /// Insert a key and RLP data.
    Insert { key: Key, content: Bytes },
    /// Remove a key.
    Remove { key: Key },
}

impl Op {
    /// Create an insert operation that adds an [`Encodable`] object to the given key.
    pub fn insert(key: impl AsRef<[u8]>, value: &impl Encodable) -> Result<Self, Error> {
        let encoded = rlp::encode(value).freeze();
        // we just encoded the data, we can trust is valid Rlp
        Self::insert_raw_trusted(key, encoded)
    }

    /// Create an insert operation where the raw rlp is provided. Due to implementation contrains, this
    /// only accepts rlp strings, but not lists.
    pub fn insert_raw(key: impl AsRef<[u8]>, value: Bytes) -> Result<Self, Error> {
        // TODO(@divma): this verification only checks that the rlp header is valid, it's unlikely
        // we can fully verify in depth the data but at least we coudl verify the payload size
        //
        // also, this only verifies that this has a  "valid" payload if a rlp string, but the data
        // could be a list as well so rejecting this is probably wrong in some cases
        //
        // rlp sucks
        rlp::Rlp::new(value.as_ref())
            .data()
            .map_err(Error::InvalidRlpData)?;
        Self::insert_raw_trusted(key, value)
    }

    /// Create a remove operation.
    pub fn remove(key: impl AsRef<[u8]>) -> Result<Self, Error> {
        let key = key.as_ref().to_vec();
        match key.as_slice() {
            b"id" => Err(Error::InvalidReservedKeyData(key)),
            _ => Ok(Op::Remove { key }),
        }
    }

    /// Create an insert operation where data is trusted to be valid rlp.
    ///
    /// This verifies that for spec reserved keys, the data can be decoded as the expected type.
    fn insert_raw_trusted(key: impl AsRef<[u8]>, content: Bytes) -> Result<Self, Error> {
        let key = key.as_ref().to_vec();
        match key.as_slice() {
            b"tcp" | b"tcp6" | b"udp" | b"udp6" => {
                if rlp::decode::<u16>(&content).is_err() {
                    return Err(Error::InvalidReservedKeyData(key));
                }
            }
            b"id" => {
                let id_bytes = rlp::decode::<Vec<u8>>(&content).map_err(Error::InvalidRlpData)?;
                if id_bytes != b"v4" {
                    return Err(Error::UnsupportedIdentityScheme);
                }
            }
            b"ip" => {
                let ip4_bytes = rlp::decode::<Vec<u8>>(&content).map_err(Error::InvalidRlpData)?;
                if ip4_bytes.len() != 4 {
                    return Err(Error::InvalidReservedKeyData(key));
                }
            }
            b"ip6" => {
                let ip6_bytes = rlp::decode::<Vec<u8>>(&content).map_err(Error::InvalidRlpData)?;
                if ip6_bytes.len() != 16 {
                    return Err(Error::InvalidReservedKeyData(key));
                }
            }
            _ => {}
        };

        Ok(Op::Insert { key, content })
    }
}

pub enum Error {
    /// The ENR is too large.
    ExceedsMaxSize,
    /// The sequence number is too large.
    SequenceNumberTooHigh,
    /// There was an error with signing an ENR record.
    SigningError,
    /// The identity scheme is not supported.
    UnsupportedIdentityScheme,
    /// Data is valid RLP but the contents do not represent the expected type for the key.
    InvalidReservedKeyData(Key),
    /// The entered RLP data is invalid.
    InvalidRlpData(rlp::DecoderError),
}

pub struct Revert<'a, K: EnrKey, I> {
    enr: &'a mut Enr<K>,
    pending: RevertOps<I>,
    error: Error,
}

pub struct RevertOps<I> {
    content_inverses: I,
    key: Option<Bytes>,
    seq: Option<u64>,
    signature: Option<Vec<u8>>,
}

impl<I> RevertOps<I> {
    fn new(content_inverses: I) -> Self {
        RevertOps {
            content_inverses,
            key: None,
            seq: None,
            signature: None,
        }
    }
}

/// An update guard over the [`Enr`].
pub struct Guard<'a, K: EnrKey, I> {
    /// [`Enr`] with update [`Op`]s already applied.
    enr: &'a mut Enr<K>,
    /// Inverses that would need to be applied to the [`Enr`] to restore [`Enr::content`].
    ///
    /// Inverses must be in the order in which they were obtained, so that applying them in
    /// reserved order produces the original content.
    inverses: I,
}

impl<'a, K: EnrKey, I> Guard<'a, K, I> {
    pub fn noop(enr: &'a mut Enr<K>) -> Self {
        todo!()
    }

    fn mark_update(self) {}

    pub fn finish(self, signing_key: &K) -> Result<I, Revert<'a, K, I>> {
        let Guard { enr, inverses } = self;
        let mut revert = RevertOps::new(inverses);

        // 1. set the public key
        let public_key = signing_key.public();
        revert.key = enr.content.insert(
            public_key.enr_key(),
            rlp::encode(&public_key.encode().as_ref()).freeze(),
        );

        // 2. set the new sequence number
        revert.seq = Some(enr.seq());
        enr.seq = match enr.seq.checked_add(1) {
            Some(seq) => seq,
            None => {
                return Err(Revert {
                    enr,
                    pending: revert,
                    error: Error::SequenceNumberTooHigh,
                })
            }
        };

        // 3. sign the ENR
        revert.signature = Some(enr.signature.clone());
        enr.signature = match enr.compute_signature(signing_key) {
            Ok(signature) => signature,
            Err(_) => {
                return Err(Revert {
                    enr,
                    pending: revert,
                    error: Error::SigningError,
                })
            }
        };

        // the size of the node id is fixed, and its encded size depends exclusively on the data
        // size, so we first check the size and then update the node id. This allows us to not need
        // to track the previous node id in case of failure since this is the last step

        // 4. check the encoded size
        if enr.size() > MAX_ENR_SIZE {
            return Err(Revert {
                enr,
                pending: revert,
                error: Error::ExceedsMaxSize,
            });
        }

        // 5. update the node_id
        enr.node_id = NodeId::from(public_key);

        // nothing to revert, return the content inverses since those identify what was done
        let RevertOps {
            content_inverses, ..
        } = revert;
        Ok(content_inverses)
    }
}
