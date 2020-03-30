use super::{EnrKey, EnrPublicKey, SigningError};
use crate::digest;
#[cfg(feature = "libp2p")]
use libp2p_core::{PeerId, PublicKey as Libp2pPublicKey};
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

    fn enr_to_public(content: &BTreeMap<String, Vec<u8>>) -> Result<Self::PublicKey, DecoderError> {
        if let Some(pubkey_bytes) = content.get(ENR_KEY) {
            // should be encoded in compressed form, i.e 33 byte raw secp256k1 public key
            c_secp256k1::PublicKey::from_slice(pubkey_bytes)
                .map_err(|_| DecoderError::Custom("Invalid Secp256k1 Signature"))
        } else {
            Err(DecoderError::Custom("Unknown signature"))
        }
    }
}

impl EnrPublicKey for c_secp256k1::PublicKey {
    fn verify_v4(&self, msg: &[u8], sig: &[u8]) -> bool {
        let msg = digest(msg);
        c_secp256k1::Signature::from_compact(sig)
            .and_then(|sig| {
                c_secp256k1::Message::from_slice(&msg)
                    .map(|m| c_secp256k1::Secp256k1::new().verify(&m, &sig, self))
            })
            .is_ok()
    }

    fn encode(&self) -> Vec<u8> {
        self.serialize().to_vec()
    }

    fn encode_uncompressed(&self) -> Vec<u8> {
        self.serialize_uncompressed()[1..].to_vec()
    }

    fn enr_key(&self) -> String {
        ENR_KEY.into()
    }

    #[cfg(any(feature = "libp2p", doc))]
    fn into_peer_id(&self) -> PeerId {
        let pk_bytes = self.serialize();
        let libp2p_pk = Libp2pPublicKey::Secp256k1(
            libp2p_core::identity::secp256k1::PublicKey::decode(&pk_bytes)
                .expect("valid public key"),
        );
        PeerId::from_public_key(libp2p_pk)
    }
}
