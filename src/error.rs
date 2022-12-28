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
    /// The Nat configuration is incorrect.
    NATConfigurationError,
    /// The entered RLP data is invalid.
    InvalidRlpData(String),
}

impl fmt::Display for EnrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExceedsMaxSize => write!(f, "enr exceeds max size"),
            Self::SequenceNumberTooHigh => write!(f, "sequence number too large"),
            Self::SigningError => write!(f, "signing error"),
            Self::UnsupportedIdentityScheme => write!(f, "unsupported identity scheme"),
            Self::NATConfigurationError => write!(f, "NAT fields cannot be set with IP fields"),
            Self::InvalidRlpData(_rlp) => write!(f, "invalid rlp data"),
        }
    }
}

impl Error for EnrError {}
