//! The error type emitted for various ENR operations.

use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
/// An error type for handling various ENR operations.
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
    InvalidReservedKeyData(&'static str),
    /// The entered RLP data is invalid.
    InvalidRlpData(rlp::DecoderError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExceedsMaxSize => write!(f, "enr exceeds max size"),
            Self::SequenceNumberTooHigh => write!(f, "sequence number too large"),
            Self::SigningError => write!(f, "signing error"),
            Self::UnsupportedIdentityScheme => write!(f, "unsupported identity scheme"),
            Self::InvalidRlpData(_rlp) => write!(f, "invalid rlp data"),
            Self::InvalidReservedKeyData(key) => write!(f, "invalid data for reserved key {}", key),
        }
    }
}

impl std::error::Error for Error {}
