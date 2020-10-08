//! An implementation for `EnrKey` for `k256::ecdsa::SigningKey`

use super::{EnrKey, EnrPublicKey, SigningError};
use crate::Key;
use k256::{
    ecdsa::{
        signature::{DigestVerifier, RandomizedDigestSigner, Signature as _},
        Signature, SigningKey, VerifyKey,
    },
    EncodedPoint,
};
use rand::rngs::OsRng;
use rlp::DecoderError;
use sha3::{Digest, Keccak256};
use std::{collections::BTreeMap, convert::TryFrom};

/// The ENR key that stores the public key in the ENR record.
pub const ENR_KEY: &str = "secp256k1";

impl EnrKey for SigningKey {
    type PublicKey = VerifyKey;

    fn sign_v4(&self, msg: &[u8]) -> Result<Vec<u8>, SigningError> {
        // take a keccak256 hash then sign.
        let digest = Keccak256::new().chain(msg);
        let signature: Signature = self
            .try_sign_digest_with_rng(&mut OsRng, digest)
            .map_err(|_| SigningError::new("failed to sign"))?;

        Ok(signature.as_bytes().to_vec())
    }

    fn public(&self) -> Self::PublicKey {
        self.verify_key()
    }

    fn enr_to_public(content: &BTreeMap<Key, Vec<u8>>) -> Result<Self::PublicKey, DecoderError> {
        let pubkey_bytes = content
            .get(ENR_KEY.as_bytes())
            .ok_or_else(|| DecoderError::Custom("Unknown signature"))?;

        // Decode the RLP
        let pubkey_bytes = rlp::Rlp::new(pubkey_bytes).data()?;

        // should be encoded in compressed form, i.e 33 byte raw secp256k1 public key
        Ok(VerifyKey::new(pubkey_bytes)
            .map_err(|_| DecoderError::Custom("Invalid Secp256k1 Signature"))?)
    }
}

impl EnrPublicKey for VerifyKey {
    fn verify_v4(&self, msg: &[u8], sig: &[u8]) -> bool {
        if let Ok(sig) = k256::ecdsa::Signature::try_from(sig) {
            return self
                .verify_digest(Keccak256::new().chain(msg), &sig)
                .is_ok();
        }
        false
    }

    fn encode(&self) -> Vec<u8> {
        // serialize in compressed form: 33 bytes
        self.to_bytes().to_vec()
    }

    fn encode_uncompressed(&self) -> Vec<u8> {
        EncodedPoint::from(self)
            .to_untagged_bytes()
            .unwrap()
            .to_vec()
    }

    fn enr_key(&self) -> Key {
        ENR_KEY.into()
    }
}
