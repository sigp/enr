//! An implementation for `EnrKey` for `libsecp256k1::SecretKey`

use super::{EnrKey, EnrPublicKey, SigningError};
#[cfg(feature = "libp2p")]
use libp2p_core::{PeerId, PublicKey as Libp2pPublicKey};
use rlp::DecoderError;
use sha3::{Digest, Keccak256};
use std::collections::BTreeMap;

/// The ENR key that stores the public key in the ENR record.
pub const ENR_KEY: &str = "secp256k1";

impl EnrKey for secp256k1::SecretKey {
    type PublicKey = secp256k1::PublicKey;

    /// Performs ENR-specific signing.
    ///
    /// currently lists the `v4` identity scheme which requires the `secp256k1` signing algorithm.
    /// Using `secp256k1` keys follow the `v4` identity scheme.
    fn sign_v4(&self, msg: &[u8]) -> Result<Vec<u8>, SigningError> {
        // take a keccak256 hash then sign.
        let hash = Keccak256::digest(msg);
        let m = secp256k1::Message::parse_slice(&hash)
            .map_err(|_| SigningError::new("failed to parse secp256k1 digest"))?;
        // serialize to an uncompressed 64 byte vector
        Ok(secp256k1::sign(&m, self).0.serialize().to_vec())
    }

    /// Returns the public key associated with the private key.
    fn public(&self) -> Self::PublicKey {
        secp256k1::PublicKey::from_secret_key(self)
    }

    /// Decodes the raw bytes of an ENR's content into a public key if possible.
    fn enr_to_public(content: &BTreeMap<String, Vec<u8>>) -> Result<Self::PublicKey, DecoderError> {
        if let Some(pubkey_bytes) = content.get(ENR_KEY) {
            // should be encoded in compressed form, i.e 33 byte raw secp256k1 public key
            secp256k1::PublicKey::parse_slice(
                pubkey_bytes,
                Some(secp256k1::PublicKeyFormat::Compressed),
            )
            .map_err(|_| DecoderError::Custom("Invalid Secp256k1 Signature"))
        } else {
            Err(DecoderError::Custom("Unknown signature"))
        }
    }
}

impl EnrPublicKey for secp256k1::PublicKey {
    /// Verify a raw message, given a public key for the v4 identity scheme.
    fn verify_v4(&self, msg: &[u8], sig: &[u8]) -> bool {
        let msg = Keccak256::digest(msg);
        secp256k1::Signature::parse_slice(sig)
            .and_then(|sig| {
                secp256k1::Message::parse_slice(&msg).map(|m| secp256k1::verify(&m, &sig, self))
            })
            .is_ok()
    }

    /// Encodes the public key into compressed form, if possible.
    fn encode(&self) -> Vec<u8> {
        // serialize in compressed form: 33 bytes
        self.serialize_compressed().to_vec()
    }

    /// Encodes the public key in uncompressed form.
    // For compatible keys, encode in uncompressed form. Necessary for generating node-id
    fn encode_uncompressed(&self) -> Vec<u8> {
        // Note: The current libsecp256k1 library prefixes the uncompressed output with a byte
        // indicating the type of output. We ignore it here
        self.serialize()[1..].to_vec()
    }

    /// Generates the ENR public key string associated with the secp256k1 key type.
    fn enr_key(&self) -> String {
        ENR_KEY.into()
    }

    #[cfg(any(feature = "libp2p", doc))]
    /// Converts the publickey into a peer id, without consuming the key.
    ///
    /// This is only available with the `libp2p` feature flag.
    fn into_peer_id(&self) -> PeerId {
        let pk_bytes = self.serialize_compressed();
        let libp2p_pk = Libp2pPublicKey::Secp256k1(
            libp2p_core::identity::secp256k1::PublicKey::decode(&pk_bytes)
                .expect("valid public key"),
        );
        PeerId::from_public_key(libp2p_pk)
    }
}
