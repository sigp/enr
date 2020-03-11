//! This module provides the [`EnrKey`] and [`EnrPublicKey`] traits. User's wishing to implement their
//! own signing schemes can implement these traits and apply them to a [`Enr`].
//!
//! This module contains implementations for the `libsecp256k1` and `ed25519_dalek`
//! secret key libraries, provided the `libsecp256k1` and `ed25519` features are set.
//!
//! [`EnrKey`]: crate::EnrKey
//! [`EnrPublicKey`]: crate::EnrPublicKey
//! [`Enr`]: crate::enr::Enr

// the default implementation
mod libsecp256k1;

#[cfg(any(feature = "ed25519", doc))]
mod combined;
#[cfg(any(feature = "ed25519", doc))]
mod ed25519;
#[cfg(any(feature = "ed25519", doc))]
pub use combined::{CombinedKey, CombinedPublicKey};
#[cfg(feature = "ed25519")]
pub use ed25519_dalek;
#[cfg(feature = "libp2p")]
use libp2p_core::PeerId;

pub use secp256k1;

use rlp::DecoderError;
use std::{
    collections::BTreeMap,
    error::Error,
    fmt::{self, Display},
};

/// The trait required for a key to sign and modify an ENR record.
pub trait EnrKey {
    type PublicKey: EnrPublicKey + Clone;

    /// Performs ENR-specific signing for the `v4` identity scheme.
    fn sign_v4(&self, msg: &[u8]) -> Result<Vec<u8>, SigningError>;

    /// Returns the public key associated with current key pair.
    fn public(&self) -> Self::PublicKey;

    /// Provides a method to decode a raw public key from an ENR `BTreeMap` to a useable public key.
    ///
    /// This method allows a key type to decode the raw bytes in an ENR to a useable
    /// `EnrPublicKey`. It takes the ENR's `BTreeMap` and returns a public key.
    ///
    /// Note: This specifies the supported key schemes for an ENR.
    fn enr_to_public(content: &BTreeMap<String, Vec<u8>>) -> Result<Self::PublicKey, DecoderError>;
}

/// The trait required for a `PublicKey` to verify an ENR record.
pub trait EnrPublicKey {
    /// Verify an ENR signature for the `v4` identity scheme.
    fn verify_v4(&self, msg: &[u8], sig: &[u8]) -> bool;

    /// Encodes the public key to bytes in compressed form, if possible.
    fn encode(&self) -> Vec<u8>;

    /// Encodes the public key in uncompressed form.
    // For compatible keys, encode in uncompressed form. Necessary for generating the node-id
    fn encode_uncompressed(&self) -> Vec<u8>;

    /// Returns the ENR key identifier for the public key type. For `secp256k1` keys this
    /// is `secp256k1`.
    fn enr_key(&self) -> String;

    #[cfg(any(feature = "libp2p", doc))]
    /// Converts an `EnrPublicKey` into a libp2p `PeerId`
    ///
    /// Only required with the `libp2p` feature flag.
    fn into_peer_id(&self) -> PeerId;
}

/// An error during signing of a message.
#[derive(Debug)]
pub struct SigningError {
    msg: String,
    source: Option<Box<dyn Error + Send + Sync>>,
}

/// An error during encoding of key material.
impl SigningError {
    pub(crate) fn new<S: Display>(msg: S) -> Self {
        Self {
            msg: msg.to_string(),
            source: None,
        }
    }
}

impl fmt::Display for SigningError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Key signing error: {}", self.msg)
    }
}

impl Error for SigningError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source.as_ref().map(|s| &**s as &dyn Error)
    }
}
