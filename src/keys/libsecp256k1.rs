//! An implementation for `EnrKey` for `libsecp256k1::SecretKey`

use super::{secp256k1, EnrKey, EnrKeyUnambiguous, EnrPublicKey, SigningError};
use crate::{digest, Key};
use rlp::DecoderError;
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
        let hash = digest(msg);
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
    fn enr_to_public(content: &BTreeMap<Key, Vec<u8>>) -> Result<Self::PublicKey, DecoderError> {
        let pubkey_bytes = content
            .get(ENR_KEY.as_bytes())
            .ok_or(DecoderError::Custom("Unknown signature"))?;

        // Decode the RLP
        let pubkey_bytes = rlp::Rlp::new(pubkey_bytes).data()?;

        Self::decode_public(pubkey_bytes)
    }
}

impl EnrKeyUnambiguous for secp256k1::SecretKey {
    fn decode_public(bytes: &[u8]) -> Result<Self::PublicKey, DecoderError> {
        // should be encoded in compressed form, i.e 33 byte raw secp256k1 public key
        secp256k1::PublicKey::parse_slice(bytes, Some(secp256k1::PublicKeyFormat::Compressed))
            .map_err(|_| DecoderError::Custom("Invalid Secp256k1 Signature"))
    }
}

impl EnrPublicKey for secp256k1::PublicKey {
    type Raw = [u8; secp256k1::util::COMPRESSED_PUBLIC_KEY_SIZE];
    type RawUncompressed = Vec<u8>;

    /// Verify a raw message, given a public key for the v4 identity scheme.
    fn verify_v4(&self, msg: &[u8], sig: &[u8]) -> bool {
        let msg = digest(msg);
        if let Ok(sig) = secp256k1::Signature::parse_slice(sig) {
            if let Ok(msg) = secp256k1::Message::parse_slice(&msg) {
                return secp256k1::verify(&msg, &sig, self);
            }
        }
        false
    }

    /// Encodes the public key into compressed form, if possible.
    fn encode(&self) -> Self::Raw {
        // serialize in compressed form: 33 bytes
        self.serialize_compressed()
    }

    /// Encodes the public key in uncompressed form.
    // For compatible keys, encode in uncompressed form. Necessary for generating node-id
    fn encode_uncompressed(&self) -> Self::RawUncompressed {
        // Note: The current libsecp256k1 library prefixes the uncompressed output with a byte
        // indicating the type of output. We ignore it here
        self.serialize()[1..].to_vec()
    }

    /// Generates the ENR public key string associated with the secp256k1 key type.
    fn enr_key(&self) -> Key {
        ENR_KEY.into()
    }
}
