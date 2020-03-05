//! This file provides the [`EnrKey`] and [`EnrPublicKey`] traits. User's wishing to implement their
//! own signing schemes can implement these traits and apply them to a [`EnrRaw`].
//!
//! A default implementation is provided here with [`DefaultKey`] and [`PublicKey`] which
//! This stores the signing keypair types currently supported by this crate.
//!
//! [`EnrKey`]: crate::EnrKey
//! [`EnrPublicKey`]: crate::EnrPublicKey
//! [`EnrRaw`]: crate::enr::EnrRaw

use ed25519_dalek as ed25519;
use rand::RngCore;
use rlp::DecoderError;
use sha3::{Digest, Keccak256};
use std::{collections::BTreeMap, error::Error, fmt};

#[cfg(feature = "libp2p")]
use libp2p_core::{
    identity::{Keypair as Libp2pKeypair, PublicKey as Libp2pPublicKey},
    PeerId,
};
#[cfg(feature = "libp2p")]
use std::convert::TryFrom;

/// The trait required for a key to sign and modify an ENR record.
pub trait EnrKey {
    type PublicKey: EnrPublicKey + Clone + Into<String>;

    /// Performs ENR-specific signing for the `v4` identity scheme.
    fn sign_v4(&self, msg: &[u8]) -> Result<Vec<u8>, SigningError>;
    /// Returns the public key associated with current key pair.
    fn public(&self) -> Self::PublicKey;
    /// Provides a method to decode a raw public key from an ENR BTreeMap to a useable public key.
    ///
    /// This method allows a key type to decode the raw bytes in an ENR to a useable
    /// `EnrPublicKey`. It takes the ENR's BTreeMap and returns a public key.
    ///
    /// Note: This specifies the supported key schemes for an ENR.
    fn enr_to_public(content: &BTreeMap<String, Vec<u8>>) -> Result<Self::PublicKey, DecoderError>;
}

/// The trait required for a `PublicKey` to verify an ENR record.
pub trait EnrPublicKey {
    /// Verify an ENR signature for the `v4` identity scheme.
    fn verify_v4(&self, msg: &[u8], sig: &[u8]) -> bool;

    fn encode(&self) -> Vec<u8>;
    // For compatible keys, encode in uncompressed form. Necessary for generating the node-id
    fn encode_uncompressed(&self) -> Vec<u8>;

    #[cfg(feature = "libp2p")]
    /// Converts an `EnrPublicKey` into a libp2p `PeerId`
    fn into_peer_id(&self) -> PeerId;
}

/// A standard implementation of the `EnrKey` trait used to sign and modify ENR records. The variants here represent the currently
/// supported in-built signing schemes.
pub enum DefaultKey {
    /// An `secp256k1` keypair.
    Secp256k1(secp256k1::SecretKey),
    /// An `Ed25519` keypair.
    Ed25519(ed25519::Keypair),
}

impl From<secp256k1::SecretKey> for DefaultKey {
    fn from(secret_key: secp256k1::SecretKey) -> DefaultKey {
        DefaultKey::Secp256k1(secret_key)
    }
}

impl From<ed25519_dalek::Keypair> for DefaultKey {
    fn from(keypair: ed25519_dalek::Keypair) -> DefaultKey {
        DefaultKey::Ed25519(keypair)
    }
}

/// Promote an Ed25519 secret key into a keypair.
impl From<ed25519_dalek::SecretKey> for DefaultKey {
    fn from(sk: ed25519_dalek::SecretKey) -> DefaultKey {
        let secret: ed25519::ExpandedSecretKey = (&sk).into();
        let public = ed25519::PublicKey::from(&secret);
        DefaultKey::Ed25519(ed25519::Keypair { secret: sk, public })
    }
}

#[cfg(feature = "libp2p")]
impl TryFrom<Libp2pKeypair> for DefaultKey {
    type Error = &'static str;

    fn try_from(keypair: Libp2pKeypair) -> Result<Self, Self::Error> {
        match keypair {
            Libp2pKeypair::Secp256k1(key) => {
                let secret = secp256k1::SecretKey::parse(&key.secret().to_bytes())
                    .expect("libp2p key must be valid");
                Ok(DefaultKey::Secp256k1(secret))
            }
            Libp2pKeypair::Ed25519(key) => {
                let a = key.encode();
                dbg!(a.len());
                let ed_keypair = ed25519::SecretKey::from_bytes(&key.encode()[..32])
                    .expect("libp2p key must be valid");
                Ok(DefaultKey::from(ed_keypair))
            }
            _ => Err("Unsupported key type"),
        }
    }
}

impl EnrKey for DefaultKey {
    type PublicKey = DefaultPublicKey;

    /// Performs ENR-specific signing.
    ///
    /// Note: that this library supports a number of signing algorithms. The ENR specification
    /// currently lists the `v4` identity scheme which requires the `secp256k1` signing algorithm.
    /// Using `secp256k1` keys follow the `v4` identity scheme, using other types do not, although
    /// they are supported.
    fn sign_v4(&self, msg: &[u8]) -> Result<Vec<u8>, SigningError> {
        match self {
            // Keypair::Rsa(ref pair) => pair.sign(msg).map_err(|e| e.into()),
            DefaultKey::Secp256k1(ref key) => {
                // take a keccak256 hash then sign.
                let hash = Keccak256::digest(msg);
                let m = secp256k1::Message::parse_slice(&hash)
                    .map_err(|_| SigningError::new("failed to parse secp256k1 digest"))?;
                // serialize to an uncompressed 64 byte vector
                Ok(secp256k1::sign(&m, &key).0.serialize().to_vec())
            }
            DefaultKey::Ed25519(ref keypair) => Ok(keypair.sign(msg).to_bytes().to_vec()),
        }
    }

    fn public(&self) -> Self::PublicKey {
        match self {
            DefaultKey::Secp256k1(secret_key) => {
                DefaultPublicKey::Secp256k1(secp256k1::PublicKey::from_secret_key(&secret_key))
            }
            DefaultKey::Ed25519(keypair) => DefaultPublicKey::Ed25519(keypair.public),
        }
    }

    /// Decodes the raw bytes of an ENR's content into a public key if possible.
    fn enr_to_public(content: &BTreeMap<String, Vec<u8>>) -> Result<Self::PublicKey, DecoderError> {
        if let Some(pubkey_bytes) = content.get("secp256k1") {
            // should be encoded in compressed form, i.e 33 byte raw secp256k1 public key
            secp256k1::PublicKey::parse_slice(
                pubkey_bytes,
                Some(secp256k1::PublicKeyFormat::Compressed),
            )
            .map(DefaultPublicKey::Secp256k1)
            .map_err(|_| DecoderError::Custom("Invalid Secp256k1 Signature"))
        } else if let Some(pubkey_bytes) = content.get("ed25519") {
            ed25519::PublicKey::from_bytes(pubkey_bytes)
                .map(DefaultPublicKey::Ed25519)
                .map_err(|_| DecoderError::Custom("Invalid ed25519 Signature"))
        } else {
            Err(DecoderError::Custom("Unknown signature"))
        }
    }
}

impl DefaultKey {
    /// Generates a new secp256k1 key.
    pub fn generate_secp256k1() -> Self {
        let mut r = rand::thread_rng();
        let mut b = [0; secp256k1::util::SECRET_KEY_SIZE];
        // This is how it is done in `secp256k1::SecretKey::random` which
        // we do not use here because it uses `rand::Rng` from rand-0.4.
        loop {
            r.fill_bytes(&mut b);
            if let Ok(k) = secp256k1::SecretKey::parse(&b) {
                return DefaultKey::Secp256k1(k);
            }
        }
    }

    /// Generates a new ed25510 key.
    pub fn generate_ed25519() -> Self {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        DefaultKey::from(
            ed25519::SecretKey::from_bytes(&bytes).expect(
                "this returns `Err` only if the length is wrong; the length is correct; qed",
            ),
        )
    }

    /// Imports a secp256k1 from raw bytes in any format.
    pub fn secp256k1_from_bytes(bytes: &[u8]) -> Result<Self, DecoderError> {
        secp256k1::SecretKey::parse_slice(bytes)
            .map_err(|_| DecoderError::Custom("Invalid secp256k1 secret key"))
            .map(DefaultKey::from)
    }

    /// Imports an ed25519 key from raw 32 bytes.
    pub fn ed25519_from_bytes(bytes: &[u8]) -> Result<Self, DecoderError> {
        ed25519::SecretKey::from_bytes(bytes)
            .map_err(|_| DecoderError::Custom("Invalid ed25519 secret key"))
            .map(DefaultKey::from)
    }

    /// Encodes the `DefaultKey` into bytes.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            DefaultKey::Secp256k1(key) => key.serialize().to_vec(),
            DefaultKey::Ed25519(key) => key.secret.as_bytes().to_vec(),
        }
    }
}

/// A standard implementation of `EnrPublicKey` which has support for `Secp256k1`
/// and `Ed25519` for ENR signature verification.
#[derive(Clone, Debug)]
pub enum DefaultPublicKey {
    /// An `Secp256k1` public key.
    Secp256k1(secp256k1::PublicKey),
    /// An `Ed25519` public key.
    Ed25519(ed25519::PublicKey),
}

impl From<secp256k1::PublicKey> for DefaultPublicKey {
    fn from(public_key: secp256k1::PublicKey) -> DefaultPublicKey {
        DefaultPublicKey::Secp256k1(public_key)
    }
}

impl From<ed25519::PublicKey> for DefaultPublicKey {
    fn from(public_key: ed25519::PublicKey) -> DefaultPublicKey {
        DefaultPublicKey::Ed25519(public_key)
    }
}

/// Generates the ENR public key strings associated with each `DefaultPublicKey` variant.
///
/// These strings are stored as the keys in the ENR record.
impl Into<String> for DefaultPublicKey {
    fn into(self) -> String {
        match self {
            DefaultPublicKey::Secp256k1(_) => String::from("secp256k1"),
            DefaultPublicKey::Ed25519(_) => String::from("ed25519"),
        }
    }
}

impl EnrPublicKey for DefaultPublicKey {
    /// Verify a raw message, given a public key for the v4 identity scheme.
    fn verify_v4(&self, msg: &[u8], sig: &[u8]) -> bool {
        match self {
            DefaultPublicKey::Secp256k1(pk) => {
                let msg = Keccak256::digest(msg);
                secp256k1::Signature::parse_slice(sig)
                    .and_then(|sig| {
                        secp256k1::Message::parse_slice(&msg)
                            .map(|m| secp256k1::verify(&m, &sig, pk))
                    })
                    .is_ok()
            }
            DefaultPublicKey::Ed25519(pk) => ed25519::Signature::from_bytes(sig)
                .and_then(|s| pk.verify(msg, &s))
                .is_ok(), //DefaultPublicKey::Rsa(pk) => pk.verify(&msg, sig),
        }
    }

    fn encode(&self) -> Vec<u8> {
        match self {
            // serialize in compressed form: 33 bytes
            DefaultPublicKey::Secp256k1(pk) => pk.serialize_compressed().to_vec(),
            DefaultPublicKey::Ed25519(pk) => pk.to_bytes().to_vec(),
        }
    }

    // For compatible keys, encode in uncompressed form. Necessary for generating node-id
    fn encode_uncompressed(&self) -> Vec<u8> {
        match self {
            // Note: The current libsecp256k1 library prefixes the uncompressed output with a byte
            // indicating the type of output. We ignore it here
            DefaultPublicKey::Secp256k1(pk) => pk.serialize()[1..].to_vec(),
            DefaultPublicKey::Ed25519(pk) => pk.to_bytes().to_vec(),
        }
    }

    #[cfg(feature = "libp2p")]
    fn into_peer_id(&self) -> PeerId {
        match self {
            DefaultPublicKey::Secp256k1(pk) => {
                let pk_bytes = pk.serialize_compressed();
                let libp2p_pk = Libp2pPublicKey::Secp256k1(
                    libp2p_core::identity::secp256k1::PublicKey::decode(&pk_bytes)
                        .expect("valid public key"),
                );
                PeerId::from_public_key(libp2p_pk)
            }
            DefaultPublicKey::Ed25519(pk) => {
                let pk_bytes = pk.to_bytes();
                let libp2p_pk = Libp2pPublicKey::Ed25519(
                    libp2p_core::identity::ed25519::PublicKey::decode(&pk_bytes)
                        .expect("valid public key"),
                );
                PeerId::from_public_key(libp2p_pk)
            }
        }
    }
}

/// An error during signing of a message.
#[derive(Debug)]
pub struct SigningError {
    msg: String,
    source: Option<Box<dyn Error + Send + Sync>>,
}

/// An error during encoding of key material.
impl SigningError {
    pub(crate) fn new<S: ToString>(msg: S) -> Self {
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

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "libp2p")]
    use std::convert::TryInto;

    #[cfg(feature = "libp2p")]
    #[test]
    fn test_key_conversion() {
        let libp2p_key = libp2p_core::identity::Keypair::generate_secp256k1();
        let _enr_key: DefaultKey = libp2p_key
            .try_into()
            .expect("Should be able to convert a libp2p secp256k1 keypair");

        let libp2p_key = libp2p_core::identity::Keypair::generate_ed25519();
        let _enr_key: DefaultKey = libp2p_key
            .try_into()
            .expect("Should be able to convert a libp2p ed25519 keypair");
    }

    #[test]
    fn test_key_secp256k1_encoding() {
        let key = DefaultKey::generate_secp256k1();

        let key_bytes = key.encode();

        DefaultKey::secp256k1_from_bytes(&key_bytes).expect("Valid encoding");
    }

    #[test]
    fn test_key_ed25519_encoding() {
        let key = DefaultKey::generate_ed25519();

        let key_bytes = key.encode();

        DefaultKey::ed25519_from_bytes(&key_bytes).expect("Valid encoding");
    }
}
