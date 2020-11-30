//! An implementation for `EnrKey` for `k256::ecdsa::SigningKey`

use super::{EnrKey, EnrKeyUnambiguous, EnrPublicKey, SigningError};
use crate::Key;
use k256::{
    ecdsa::{
        signature::{DigestVerifier, RandomizedDigestSigner, Signature as _},
        Signature, SigningKey, VerifyKey,
    },
    elliptic_curve::{generic_array::GenericArray, sec1::UntaggedPointSize},
    CompressedPoint, EncodedPoint, Secp256k1,
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
            .ok_or(DecoderError::Custom("Unknown signature"))?;

        // Decode the RLP
        let pubkey_bytes = rlp::Rlp::new(pubkey_bytes).data()?;

        Self::decode_public(pubkey_bytes)
    }
}

impl EnrKeyUnambiguous for SigningKey {
    fn decode_public(bytes: &[u8]) -> Result<Self::PublicKey, DecoderError> {
        // should be encoded in compressed form, i.e 33 byte raw secp256k1 public key
        Ok(VerifyKey::new(bytes)
            .map_err(|_| DecoderError::Custom("Invalid Secp256k1 Signature"))?)
    }
}

impl EnrPublicKey for VerifyKey {
    type Raw = CompressedPoint;
    type RawUncompressed = GenericArray<u8, UntaggedPointSize<Secp256k1>>;

    fn verify_v4(&self, msg: &[u8], sig: &[u8]) -> bool {
        if let Ok(sig) = k256::ecdsa::Signature::try_from(sig) {
            return self
                .verify_digest(Keccak256::new().chain(msg), &sig)
                .is_ok();
        }
        false
    }

    fn encode(&self) -> Self::Raw {
        // serialize in compressed form: 33 bytes
        self.to_bytes()
    }

    fn encode_uncompressed(&self) -> Self::RawUncompressed {
        EncodedPoint::from(self).to_untagged_bytes().unwrap()
    }

    fn enr_key(&self) -> Key {
        ENR_KEY.into()
    }
}
