//! An implementation for `EnrKey` for `k256::SecretKey`

use super::{EnrKey, EnrPublicKey, SigningError};
use crate::Key;
use ecdsa::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256_crate::ecdsa::signature::{DigestVerifier, RandomizedDigestSigner, Signature};
use rand::rngs::OsRng;
use rlp::DecoderError;
use sha3::{Digest, Keccak256};
use std::{collections::BTreeMap, convert::TryFrom};

/// The ENR key that stores the public key in the ENR record.
pub const ENR_KEY: &str = "secp256k1";

type Signer = ecdsa::SigningKey<k256_crate::Secp256k1>;
type Verifier = ecdsa::VerifyKey<k256_crate::Secp256k1>;

impl EnrKey for k256_crate::SecretKey {
    type PublicKey = k256_crate::EncodedPoint;

    fn sign_v4(&self, msg: &[u8]) -> Result<Vec<u8>, SigningError> {
        // take a keccak256 hash then sign.
        let digest = Keccak256::new().chain(msg);
        let signature: k256_crate::ecdsa::Signature = Signer::new(self.to_bytes().as_slice())
            .map_err(|_| SigningError::new("failed to create signer"))?
            .sign_digest_with_rng(&mut OsRng, digest);

        Ok(signature.as_bytes().to_vec())
    }

    fn public(&self) -> Self::PublicKey {
        k256_crate::EncodedPoint::from_secret_key(self, false)
    }

    fn enr_to_public(content: &BTreeMap<Key, Vec<u8>>) -> Result<Self::PublicKey, DecoderError> {
        let pubkey_bytes = content
            .get(ENR_KEY.as_bytes())
            .ok_or_else(|| DecoderError::Custom("Unknown signature"))?;

        // should be encoded in compressed form, i.e 33 byte raw secp256k1 public key
        Ok(k256_crate::EncodedPoint::from_bytes(pubkey_bytes)
            .map_err(|_| DecoderError::Custom("Invalid Secp256k1 Signature"))?)
    }
}

impl EnrPublicKey for k256_crate::EncodedPoint {
    fn verify_v4(&self, msg: &[u8], sig: &[u8]) -> bool {
        let digest = Keccak256::new().chain(msg);
        if let Ok(sig) = k256_crate::ecdsa::Signature::try_from(sig) {
            if let Ok(verifier) = Verifier::new(self.as_bytes()) {
                if verifier.verify_digest(digest, &sig).is_ok() {
                    return true;
                }
            }
        }
        false
    }

    fn encode(&self) -> Vec<u8> {
        // serialize in compressed form: 33 bytes
        self.compress().as_bytes().to_vec()
    }

    fn encode_uncompressed(&self) -> Vec<u8> {
        k256_crate::AffinePoint::from_encoded_point(self)
            .unwrap()
            .to_encoded_point(false)
            .as_bytes()[1..]
            .to_vec()
    }

    fn enr_key(&self) -> Key {
        ENR_KEY.into()
    }
}
