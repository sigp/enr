//! The error type emitted for various ENR operations.

use std::error::Error;
use std::fmt;

#[derive(Clone, Debug)]
/// An error type for handling various ENR operations.
pub enum EnrError {
    /// The ENR is too large.
    ExceedsMaxSize,
    /// The sequence number is too large.
    SequenceNumberTooHigh,
    /// There was an error with signing an ENR record.
    SigningError,
    /// The identity scheme is not supported.
    UnsupportedIdentityScheme,
    /// The entered RLP data is invalid.
    InvalidRlpData(String),
}

impl fmt::Display for EnrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EnrError::ExceedsMaxSize => write!(f, "enr exceeds max size"),
            EnrError::SequenceNumberTooHigh => write!(f, "sequence number too large"),
            EnrError::SigningError => write!(f, "signing error"),
            EnrError::UnsupportedIdentityScheme => write!(f, "unsupported identity scheme"),
            EnrError::InvalidRlpData(_rlp) => write!(f, "invalid rlp data"),
        }
    }
}

impl Error for EnrError {}
