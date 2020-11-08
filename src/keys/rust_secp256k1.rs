use super::{EnrKey, EnrKeyUnambiguous, EnrPublicKey, SigningError};
use crate::{digest, Key};
use rlp::DecoderError;
use std::collections::BTreeMap;

/// The ENR key that stores the public key in the ENR record.
pub const ENR_KEY: &str = "secp256k1";

impl EnrKey for c_secp256k1::SecretKey {
    type PublicKey = c_secp256k1::PublicKey;

    fn sign_v4(&self, msg: &[u8]) -> Result<Vec<u8>, SigningError> {
        // take a keccak256 hash then sign.
        let hash = digest(msg);
        let m = c_secp256k1::Message::from_slice(&hash)
            .map_err(|_| SigningError::new("failed to parse secp256k1 digest"))?;
        // serialize to an uncompressed 64 byte vector
        Ok(c_secp256k1::Secp256k1::new()
            .sign(&m, self)
            .serialize_compact()
            .to_vec())
    }

    fn public(&self) -> Self::PublicKey {
        Self::PublicKey::from_secret_key(&c_secp256k1::Secp256k1::new(), self)
    }

    fn enr_to_public(content: &BTreeMap<Key, Vec<u8>>) -> Result<Self::PublicKey, DecoderError> {
        let pubkey_bytes = content
            .get(ENR_KEY.as_bytes())
            .ok_or_else(|| DecoderError::Custom("Unknown signature"))?;
        // Decode the RLP
        let pubkey_bytes = rlp::Rlp::new(pubkey_bytes).data()?;

        Self::decode_public(pubkey_bytes)
    }
}

impl EnrKeyUnambiguous for c_secp256k1::SecretKey {
    fn decode_public(bytes: &[u8]) -> Result<Self::PublicKey, DecoderError> {
        // should be encoded in compressed form, i.e 33 byte raw secp256k1 public key
        c_secp256k1::PublicKey::from_slice(bytes)
            .map_err(|_| DecoderError::Custom("Invalid Secp256k1 Signature"))
    }
}

impl EnrPublicKey for c_secp256k1::PublicKey {
    fn verify_v4(&self, msg: &[u8], sig: &[u8]) -> bool {
        let msg = digest(msg);
        if let Ok(sig) = c_secp256k1::Signature::from_compact(sig) {
            if let Ok(msg) = c_secp256k1::Message::from_slice(&msg) {
                return c_secp256k1::Secp256k1::new()
                    .verify(&msg, &sig, self)
                    .is_ok();
            }
        }
        false
    }

    fn encode(&self) -> Vec<u8> {
        self.serialize().to_vec()
    }

    fn encode_uncompressed(&self) -> Vec<u8> {
        self.serialize_uncompressed()[1..].to_vec()
    }

    fn enr_key(&self) -> Key {
        ENR_KEY.into()
    }
}
