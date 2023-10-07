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
                    k @ (b"tcp" | b"tcp6" | b"udp" | b"udp6") => {
                        if rlp::decode::<u16>(&content).is_err() {
                            return Err(Error::InvalidReservedKeyData("ugh fixmehh"));
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
                            return Err(Error::InvalidReservedKeyData("ip"));
                        }
                    }
                    b"ip6" => {
                        let ip6_bytes =
                            rlp::decode::<Vec<u8>>(&content).map_err(Error::InvalidRlpData)?;
                        if ip6_bytes.len() != 16 {
                            return Err(Error::InvalidReservedKeyData("ip6"));
                        }
                    }
                    _ => {}
                };

                Ok(Op::Insert { key, content })
            }
            Update::Remove { key } => match key.as_slice() {
                b"id" => Err(Error::InvalidReservedKeyData("id")),
                _ => Ok(Op::Remove { key }),
            },
        }
    }
}

/// A valid update operation over the [`Enr`]. This is the result of validating an [`Update`].
pub(crate) enum Op {
    /// Insert a key and RLP data.
    Insert { key: Key, content: Bytes },
    /// Remove a key.
    Remove { key: Key },
}

impl Op {
    /// Applies the operation and returns the inverse.
    pub fn apply_with_inverse<K: EnrKey>(self, enr: &mut Enr<K>) -> Op {
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
    pub fn irrecoverable_apply<K: EnrKey>(self, enr: &mut Enr<K>) {
        match self {
            Op::Insert { key, content } => enr.content.insert(key, content),
            Op::Remove { key } => enr.content.remove(&key),
        };
    }
}

/*
 * Helper traits to expand the definition of Update to tuples of Updates and vectors
 */

pub(crate) trait UpdatesT {
    type ValidatedUpdates: ValidUpdatesT;
    fn to_valid(self) -> Result<Self::ValidatedUpdates, Error>;
}

pub(crate) trait ValidUpdatesT {
    fn apply_and_invert<K: EnrKey>(self, enr: &mut Enr<K>) -> Self;
    fn apply_as_inverse<K: EnrKey>(self, enr: &mut Enr<K>);
}

/*
 * implementation for a single update
 */

impl UpdatesT for Update {
    type ValidatedUpdates = Op;

    fn to_valid(self) -> Result<Self::ValidatedUpdates, Error> {
        self.to_valid_op()
    }
}
impl ValidUpdatesT for Op {
    fn apply_and_invert<K: EnrKey>(self, enr: &mut Enr<K>) -> Self {
        self.apply_with_inverse(enr)
    }

    fn apply_as_inverse<K: EnrKey>(self, enr: &mut Enr<K>) {
        self.irrecoverable_apply(enr)
    }
}

/*
 * implementation for an arbitrary number of updates
 */
impl UpdatesT for Vec<Update> {
    type ValidatedUpdates = Vec<Op>;

    fn to_valid(self) -> Result<Self::ValidatedUpdates, Error> {
        self.into_iter().map(Update::to_valid_op).collect()
    }
}

impl ValidUpdatesT for Vec<Op> {
    fn apply_and_invert<K: EnrKey>(self, enr: &mut Enr<K>) -> Self {
        self.into_iter()
            .map(|op| op.apply_with_inverse(enr))
            .rev()
            .collect()
    }

    fn apply_as_inverse<K: EnrKey>(self, enr: &mut Enr<K>) {
        self.into_iter().for_each(|op| op.irrecoverable_apply(enr))
    }
}

/*
 * implementation for tuples
 */

/// Map an identifier inside a macro to a type
macro_rules! map_to_type {
    ($in: ident, $out: ident) => {
        $out
    };
}

/// Generates the implementation of PreUpdate::apply to a tuple of 2 or more. The macro arguments
/// are the number of variables needed to map Update intents to valid operations.
///
/// A valid call of this macro looks like
/// `gen_impl!(up0, up1)`
///
/// This generates the implementation for `PreUpdate<'a, K, (Update, Update)>`
/// containing the function
/// `pub fn apply(self) -> Result<Guard<'a, K, (Op, Op)>, Error> { .. }`
macro_rules! gen_impl {
    ($($up: ident,)*) => {

        impl UpdatesT for ($(map_to_type!($up, Update),)*) {
            type ValidatedUpdates = ($(map_to_type!($up, Op),)*);

            fn to_valid(self) -> Result<Self::ValidatedUpdates, Error> {
                // destructure the tuple using the identifiers
                let ($($up,)*) = self;
                // obtain the valid version of each update
                Ok(($($up.to_valid_op()?,)*))
            }


        }

        impl ValidUpdatesT for ($(map_to_type!($up, Op),)*) {

            fn apply_and_invert<K: EnrKey>(self, enr: &mut Enr<K>) -> Self {
                // destructure the tuple using the identifiers
                let ($($up,)*) = self;
                let mut as_array = [$($up.apply_with_inverse(enr),)*];
                // apply and reverse the expresions order to get the correct inverse tuple
                as_array.reverse();
                as_array.into()
            }

            fn apply_as_inverse<K: EnrKey>(self, enr: &mut Enr<K>) {
                // destructure the tuple using the identifiers
                let ($($up,)*) = self;
                $($up.irrecoverable_apply(enr);)*
            }
        }

    };
}

/// Calls `gen_impl` for all tuples of size in the range [2; N], where N is the number
/// of identifies received.
macro_rules! gen_ntuple_impls {
    ($up: ident, $($tokens: tt)+) => {
        gen_impl!($up, $($tokens)*);
        gen_ntuple_impls!($($tokens)*);
    };
    ($up: ident,) => {};
}

gen_ntuple_impls!(up0, up1, up2, up3, up4, up5, up6,);
