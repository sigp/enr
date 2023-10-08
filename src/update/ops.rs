//! Exposes [`Update`] that describe update intents, and [`Op`] a validated update operation.

use bytes::Bytes;
use rlp::Encodable;

use super::EnrError;
use crate::{Enr, EnrKey, Key};

/// An update operation.
// NOTE: The most user facing type: this simply states an intent and it's not validated.
#[derive(Clone)]
pub enum Update {
    /// Insert a key and RLP data.
    Insert { key: Key, content: Bytes },
    /// Remove a key.
    Remove { key: Key },
}

impl Update {
    /// Create an insert operation that adds an [`Encodable`] object to the given key.
    pub fn insert(key: impl AsRef<[u8]>, value: &impl Encodable) -> Self {
        Self::Insert {
            key: key.as_ref().to_vec(),
            content: rlp::encode(value).freeze(),
        }
    }

    /// Create an insert operation where the raw rlp is provided.
    pub fn insert_raw(key: impl AsRef<[u8]>, content: Bytes) -> Self {
        Self::Insert {
            key: key.as_ref().to_vec(),
            content,
        }
    }

    /// Create a remove operation.
    pub fn remove(key: impl AsRef<[u8]>) -> Self {
        Self::Remove {
            key: key.as_ref().to_vec(),
        }
    }

    /// Validate the update operation.
    pub(super) fn to_valid_op(self) -> Result<Op, EnrError> {
        match self {
            Self::Insert { key, content } => {
                match key.as_slice() {
                    b"tcp" | b"tcp6" | b"udp" | b"udp6" => {
                        rlp::decode::<u16>(&content)
                            .map_err(|err| EnrError::InvalidRlpData(err.to_string()))?;
                    }
                    b"id" => {
                        let id_bytes = rlp::decode::<Vec<u8>>(&content)
                            .map_err(|err| EnrError::InvalidRlpData(err.to_string()))?;
                        if id_bytes != b"v4" {
                            return Err(EnrError::UnsupportedIdentityScheme);
                        }
                    }
                    b"ip" => {
                        let ip4_bytes = rlp::decode::<Vec<u8>>(&content)
                            .map_err(|err| EnrError::InvalidRlpData(err.to_string()))?;
                        if ip4_bytes.len() != 4 {
                            return Err(EnrError::InvalidRlpData("Invalid Ipv4 size".to_string()));
                        }
                    }
                    b"ip6" => {
                        let ip6_bytes = rlp::decode::<Vec<u8>>(&content)
                            .map_err(|err| EnrError::InvalidRlpData(err.to_string()))?;
                        if ip6_bytes.len() != 16 {
                            return Err(EnrError::InvalidRlpData("Invalid Ipv6 size".to_string()));
                        }
                    }
                    _ => {
                        // NOTE: we don't verify the keys for the public key, since it's always
                        // calculated in an update
                        rlp::Rlp::new(content.as_ref())
                            .data()
                            .map_err(|err| EnrError::InvalidRlpData(err.to_string()))?;
                    }
                };

                Ok(Op::Insert { key, content })
            }
            Self::Remove { key } => match key.as_slice() {
                b"id" => Err(EnrError::InvalidRlpData(
                    "id key must not be removed".into(),
                )),
                _ => Ok(Op::Remove { key }),
            },
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
    /// Applies the operation and returns the inverse.
    pub fn apply_with_inverse<K: EnrKey>(self, enr: &mut Enr<K>) -> Self {
        match self {
            Self::Insert { key, content } => match enr.content.insert(key.clone(), content) {
                Some(content) => Self::Insert { key, content },
                None => Self::Remove { key },
            },
            Self::Remove { key } => match enr.content.remove(&key) {
                Some(content) => Self::Insert { key, content },
                None => Self::Remove { key },
            },
        }
    }

    /// Applies the operation to the [`Enr`].
    pub fn irrecoverable_apply<K: EnrKey>(self, enr: &mut Enr<K>) {
        match self {
            Self::Insert { key, content } => enr.content.insert(key, content),
            Self::Remove { key } => enr.content.remove(&key),
        };
    }

    /// If this operation is an inverse that succeeded return the output
    pub fn to_output(self) -> Option<Bytes> {
        // key was part of the input, so it's not needed
        match self {
            Self::Insert { content, .. } => Some(content),
            Self::Remove { .. } => None,
        }
    }
}

/*
 * Helper traits to expand the definition of Update to tuples and vectors
 * NOTE: fixed sixed arrays would need `array::try_map` which is not yet stable
 */

mod sealed {
    //! makes the traits Sealed so that it can't be implemented outside this crate
    pub trait Sealed {}
}

pub trait UpdatesT: sealed::Sealed {
    type ValidatedUpdates: ValidUpdatesT;
    /// Validates the updates so that they can be applied.
    fn to_valid(self) -> Result<Self::ValidatedUpdates, EnrError>;
}

pub trait ValidUpdatesT: sealed::Sealed {
    type Output;
    /// Apply the valid update and produce the inverse in case it needs to be reverted.
    fn apply_and_invert<K: EnrKey>(self, enr: &mut Enr<K>) -> Self;
    /// Apply when used as an inverse.
    fn apply_as_inverse<K: EnrKey>(self, enr: &mut Enr<K>);
    /// When successful map the update to its output.
    fn inverse_to_output(self) -> Self::Output;
}

/*
 * implementation for a single update
 */

impl sealed::Sealed for Update {}
impl sealed::Sealed for Op {}

impl UpdatesT for Update {
    type ValidatedUpdates = Op;

    fn to_valid(self) -> Result<Self::ValidatedUpdates, EnrError> {
        self.to_valid_op()
    }
}

impl ValidUpdatesT for Op {
    type Output = Option<Bytes>;
    fn apply_and_invert<K: EnrKey>(self, enr: &mut Enr<K>) -> Self {
        self.apply_with_inverse(enr)
    }

    fn apply_as_inverse<K: EnrKey>(self, enr: &mut Enr<K>) {
        self.irrecoverable_apply(enr);
    }

    fn inverse_to_output(self) -> Self::Output {
        self.to_output()
    }
}

/*
 * implementation for an arbitrary number of updates
 */

impl sealed::Sealed for Vec<Update> {}
impl sealed::Sealed for Vec<Op> {}

impl UpdatesT for Vec<Update> {
    type ValidatedUpdates = Vec<Op>;

    fn to_valid(self) -> Result<Self::ValidatedUpdates, EnrError> {
        self.into_iter().map(Update::to_valid_op).collect()
    }
}

impl ValidUpdatesT for Vec<Op> {
    /// Return the keys back to the user
    type Output = Vec<Option<Bytes>>;
    fn apply_and_invert<K: EnrKey>(self, enr: &mut Enr<K>) -> Self {
        self.into_iter()
            .map(|op| op.apply_with_inverse(enr))
            .collect()
    }

    fn apply_as_inverse<K: EnrKey>(self, enr: &mut Enr<K>) {
        self.into_iter()
            .rev()
            .for_each(|op| op.irrecoverable_apply(enr));
    }

    fn inverse_to_output(self) -> Self::Output {
        self.into_iter().map(Op::to_output).collect()
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

// alias to help the macros
type OptionBytes = Option<Bytes>;

/// Generates the implementation for a tuple of 2 or more values
macro_rules! gen_impl {
    ($($up: ident,)*) => {

        impl sealed::Sealed for ($(map_to_type!($up, Update),)*)  {}
        impl sealed::Sealed for ($(map_to_type!($up, Op),)*)  {}

        impl UpdatesT for ($(map_to_type!($up, Update),)*) {
            type ValidatedUpdates = ($(map_to_type!($up, Op),)*);

            fn to_valid(self) -> Result<Self::ValidatedUpdates, EnrError> {
                // destructure the tuple using the identifiers
                let ($($up,)*) = self;
                // obtain the valid version of each update
                Ok(($($up.to_valid_op()?,)*))
            }
        }

        impl ValidUpdatesT for ($(map_to_type!($up, Op),)*) {
            type Output = ($(map_to_type!($up, OptionBytes),)*);

            fn apply_and_invert<K: EnrKey>(self, enr: &mut Enr<K>) -> Self {
                // destructure the tuple using the identifiers
                let ($($up,)*) = self;
                ($($up.apply_with_inverse(enr),)*)
            }

            fn apply_as_inverse<K: EnrKey>(self, enr: &mut Enr<K>) {
                // destructure the tuple using the identifiers
                let ($($up,)*) = self;
                // need to reverse it to apply it as inverse
                let mut as_array = [$($up,)*];
                // apply and reverse the expresions order to get the correct inverse tuple
                as_array.reverse();
                let [$($up,)*] = as_array;
                $($up.irrecoverable_apply(enr);)*
            }

            fn inverse_to_output(self) -> Self::Output {
                let ($($up,)*) = self;
                ($($up.inverse_to_output(),)*)
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
