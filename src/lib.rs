#![doc=include_str!("../README.md")]
#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(
    clippy::map_err_ignore,
    clippy::missing_errors_doc,
    clippy::module_name_repetitions
)]
#![deny(rustdoc::broken_intra_doc_links, rustdoc::private_intra_doc_links)]

use std::{
    collections::BTreeMap,
    hash::{Hash, Hasher},
    marker::PhantomData,
    net::{SocketAddrV4, SocketAddrV6},
};

use bytes::{Bytes, BytesMut};
use log::debug;
use rlp::{DecoderError, Rlp, RlpStream};

#[cfg(feature = "serde")]
use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};
use sha3::{Digest, Keccak256};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
};

mod builder;
pub use builder::EnrBuilder;

mod error;
pub use error::EnrError;

mod keys;
#[cfg(feature = "k256")]
pub use keys::k256;
#[cfg(feature = "rust-secp256k1")]
pub use keys::secp256k1;
#[cfg(all(feature = "ed25519", feature = "k256"))]
pub use keys::{ed25519_dalek, CombinedKey, CombinedPublicKey};
pub use keys::{EnrKey, EnrKeyUnambiguous, EnrPublicKey};

mod node_id;
pub use node_id::NodeId;

/// The "key" in an ENR record can be arbitrary bytes.
type Key = Vec<u8>;
type PreviousRlpEncodedValues = Vec<Option<Bytes>>;

const MAX_ENR_SIZE: usize = 300;

/// The ENR, allowing for arbitrary signing algorithms.
///
/// This struct will always have a valid signature, known public key type, sequence number and `NodeId`. All other parameters are variable/optional.
pub struct Enr<K: EnrKey> {
    /// ENR sequence number.
    seq: u64,

    /// The `NodeId` of the ENR record.
    node_id: NodeId,

    /// Key-value contents of the ENR. A BTreeMap is used to get the keys in sorted order, which is
    /// important for verifying the signature of the ENR.
    /// Everything is stored as raw RLP bytes.
    content: BTreeMap<Key, Bytes>,

    /// The signature of the ENR record, stored as bytes.
    signature: Vec<u8>,

    /// Marker to pin the generic.
    phantom: PhantomData<K>,
}

impl<K: EnrKey> Enr<K> {
    // getters //

    /// The `NodeId` for the record.
    #[must_use]
    pub const fn node_id(&self) -> NodeId {
        self.node_id
    }

    /// The current sequence number of the ENR record.
    #[must_use]
    pub const fn seq(&self) -> u64 {
        self.seq
    }

    /// Reads a custom key from the record if it exists.
    pub fn get(&self, key: impl AsRef<[u8]>) -> Option<&[u8]> {
        self.get_raw_rlp(key).map(|rlp_data| {
            rlp::Rlp::new(rlp_data)
                .data()
                .expect("All data is sanitized")
        })
    }

    /// Reads a custom key from the record if it exists as raw RLP bytes.
    pub fn get_raw_rlp(&self, key: impl AsRef<[u8]>) -> Option<&[u8]> {
        self.content.get(key.as_ref()).map(AsRef::as_ref)
    }

    /// Returns an iterator over all key/value pairs in the ENR.
    pub fn iter(&self) -> impl Iterator<Item = (&Key, &[u8])> {
        self.content.iter().map(|(k, v)| (k, v.as_ref()))
    }

    /// Returns the IPv4 address of the ENR record if it is defined.
    #[must_use]
    pub fn ip4(&self) -> Option<Ipv4Addr> {
        if let Some(ip_bytes) = self.get("ip") {
            return match ip_bytes.len() {
                4 => {
                    let mut ip = [0_u8; 4];
                    ip.copy_from_slice(ip_bytes);
                    Some(Ipv4Addr::from(ip))
                }
                _ => None,
            };
        }
        None
    }

    /// Returns the IPv6 address of the ENR record if it is defined.
    #[must_use]
    pub fn ip6(&self) -> Option<Ipv6Addr> {
        if let Some(ip_bytes) = self.get("ip6") {
            return match ip_bytes.len() {
                16 => {
                    let mut ip = [0_u8; 16];
                    ip.copy_from_slice(ip_bytes);
                    Some(Ipv6Addr::from(ip))
                }
                _ => None,
            };
        }
        None
    }

    /// The `id` of ENR record if it is defined.
    #[must_use]
    pub fn id(&self) -> Option<String> {
        if let Some(id_bytes) = self.get("id") {
            return Some(String::from_utf8_lossy(id_bytes).to_string());
        }
        None
    }

    /// The TCP port of ENR record if it is defined.
    #[must_use]
    pub fn tcp4(&self) -> Option<u16> {
        if let Some(tcp_bytes) = self.get("tcp") {
            if tcp_bytes.len() <= 2 {
                let mut tcp = [0_u8; 2];
                tcp[2 - tcp_bytes.len()..].copy_from_slice(tcp_bytes);
                return Some(u16::from_be_bytes(tcp));
            }
        }
        None
    }

    /// The IPv6-specific TCP port of ENR record if it is defined.
    #[must_use]
    pub fn tcp6(&self) -> Option<u16> {
        if let Some(tcp_bytes) = self.get("tcp6") {
            if tcp_bytes.len() <= 2 {
                let mut tcp = [0_u8; 2];
                tcp[2 - tcp_bytes.len()..].copy_from_slice(tcp_bytes);
                return Some(u16::from_be_bytes(tcp));
            }
        }
        None
    }

    /// The UDP port of ENR record if it is defined.
    #[must_use]
    pub fn udp4(&self) -> Option<u16> {
        if let Some(udp_bytes) = self.get("udp") {
            if udp_bytes.len() <= 2 {
                let mut udp = [0_u8; 2];
                udp[2 - udp_bytes.len()..].copy_from_slice(udp_bytes);
                return Some(u16::from_be_bytes(udp));
            }
        }
        None
    }

    /// The IPv6-specific UDP port of ENR record if it is defined.
    #[must_use]
    pub fn udp6(&self) -> Option<u16> {
        if let Some(udp_bytes) = self.get("udp6") {
            if udp_bytes.len() <= 2 {
                let mut udp = [0_u8; 2];
                udp[2 - udp_bytes.len()..].copy_from_slice(udp_bytes);
                return Some(u16::from_be_bytes(udp));
            }
        }
        None
    }

    /// Provides a socket (based on the UDP port), if the IPv4 and UDP fields are specified.
    #[must_use]
    pub fn udp4_socket(&self) -> Option<SocketAddrV4> {
        if let Some(ip) = self.ip4() {
            if let Some(udp) = self.udp4() {
                return Some(SocketAddrV4::new(ip, udp));
            }
        }
        None
    }

    /// Provides a socket (based on the UDP port), if the IPv6 and UDP fields are specified.
    #[must_use]
    pub fn udp6_socket(&self) -> Option<SocketAddrV6> {
        if let Some(ip6) = self.ip6() {
            if let Some(udp6) = self.udp6() {
                return Some(SocketAddrV6::new(ip6, udp6, 0, 0));
            }
        }
        None
    }

    /// Provides a socket (based on the TCP port), if the IP and TCP fields are specified.
    #[must_use]
    pub fn tcp4_socket(&self) -> Option<SocketAddrV4> {
        if let Some(ip) = self.ip4() {
            if let Some(tcp) = self.tcp4() {
                return Some(SocketAddrV4::new(ip, tcp));
            }
        }
        None
    }

    /// Provides a socket (based on the TCP port), if the IPv6 and TCP6 fields are specified.
    #[must_use]
    pub fn tcp6_socket(&self) -> Option<SocketAddrV6> {
        if let Some(ip6) = self.ip6() {
            if let Some(tcp6) = self.tcp6() {
                return Some(SocketAddrV6::new(ip6, tcp6, 0, 0));
            }
        }
        None
    }

    /// The signature of the ENR record.
    #[must_use]
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// Returns the public key of the ENR record.
    #[must_use]
    pub fn public_key(&self) -> K::PublicKey {
        K::enr_to_public(&self.content).expect("ENR's can only be created with supported keys")
    }

    /// Verify the signature of the ENR record.
    #[must_use]
    pub fn verify(&self) -> bool {
        let pubkey = self.public_key();
        self.id().as_ref().map_or(false, |_| {
            pubkey.verify_v4(&self.rlp_content(), &self.signature)
        })
    }

    /// Provides the URL-safe base64 encoded "text" version of the ENR prefixed by "enr:".
    #[must_use]
    pub fn to_base64(&self) -> String {
        let hex = base64::encode_config(&rlp::encode(self), base64::URL_SAFE_NO_PAD);
        format!("enr:{hex}")
    }

    /// Returns the current size of the ENR.
    #[must_use]
    pub fn size(&self) -> usize {
        rlp::encode(self).len()
    }

    // Setters //

    /// Allows setting the sequence number to an arbitrary value.
    pub fn set_seq(&mut self, seq: u64, key: &K) -> Result<(), EnrError> {
        self.seq = seq;

        // sign the record
        self.sign(key)?;

        // update the node id
        self.node_id = NodeId::from(key.public());

        // check the size of the record
        if self.size() > MAX_ENR_SIZE {
            return Err(EnrError::ExceedsMaxSize);
        }

        Ok(())
    }

    /// Adds or modifies a key/value to the ENR record. A `EnrKey` is required to re-sign the record once
    /// modified.
    ///
    /// Returns the previous value as rlp encoded bytes in the record if it exists.
    pub fn insert(
        &mut self,
        key: impl AsRef<[u8]>,
        value: &[u8],
        enr_key: &K,
    ) -> Result<Option<Bytes>, EnrError> {
        self.insert_raw_rlp(key, rlp::encode(&value).freeze(), enr_key)
    }

    /// Adds or modifies a key/value to the ENR record. A `EnrKey` is required to re-sign the record once
    /// modified. The value here is interpreted as raw RLP data.
    ///
    /// Returns the previous value as rlp encoded bytes in the record if it exists.
    pub fn insert_raw_rlp(
        &mut self,
        key: impl AsRef<[u8]>,
        value: Bytes,
        enr_key: &K,
    ) -> Result<Option<Bytes>, EnrError> {
        // currently only support "v4" identity schemes
        if key.as_ref() == b"id" && &*value != b"v4" {
            return Err(EnrError::UnsupportedIdentityScheme);
        }

        let previous_value = self.content.insert(key.as_ref().to_vec(), value);
        // add the new public key
        let public_key = enr_key.public();
        let previous_key = self.content.insert(
            public_key.enr_key(),
            rlp::encode(&public_key.encode().as_ref()).freeze(),
        );

        // check the size of the record
        if self.size() > MAX_ENR_SIZE {
            // if the size of the record is too large, revert and error
            // revert the public key
            if let Some(key) = previous_key {
                self.content.insert(public_key.enr_key(), key);
            } else {
                self.content.remove(&public_key.enr_key());
            }
            // revert the content
            if let Some(prev_value) = previous_value {
                self.content.insert(key.as_ref().to_vec(), prev_value);
            } else {
                self.content.remove(key.as_ref());
            }
            return Err(EnrError::ExceedsMaxSize);
        }
        // increment the sequence number
        self.seq = self
            .seq
            .checked_add(1)
            .ok_or(EnrError::SequenceNumberTooHigh)?;

        // sign the record
        self.sign(enr_key)?;

        // update the node id
        self.node_id = NodeId::from(enr_key.public());

        if self.size() > MAX_ENR_SIZE {
            // in case the signature size changes, inform the user the size has exceeded the maximum
            return Err(EnrError::ExceedsMaxSize);
        }

        Ok(previous_value)
    }

    /// Sets the `ip` field of the ENR. Returns any pre-existing IP address in the record.
    pub fn set_ip(&mut self, ip: IpAddr, key: &K) -> Result<Option<IpAddr>, EnrError> {
        match ip {
            IpAddr::V4(addr) => {
                let prev_value = self.insert("ip", &addr.octets(), key)?;
                if let Some(bytes) = prev_value {
                    if bytes.len() == 4 {
                        let mut v = [0_u8; 4];
                        v.copy_from_slice(&bytes);
                        return Ok(Some(IpAddr::V4(Ipv4Addr::from(v))));
                    }
                }
            }
            IpAddr::V6(addr) => {
                let prev_value = self.insert("ip6", &addr.octets(), key)?;
                if let Some(bytes) = prev_value {
                    if bytes.len() == 16 {
                        let mut v = [0_u8; 16];
                        v.copy_from_slice(&bytes);
                        return Ok(Some(IpAddr::V6(Ipv6Addr::from(v))));
                    }
                }
            }
        }

        Ok(None)
    }

    /// Sets the `udp` field of the ENR. Returns any pre-existing UDP port in the record.
    pub fn set_udp4(&mut self, udp: u16, key: &K) -> Result<Option<u16>, EnrError> {
        if let Some(udp_bytes) = self.insert("udp", &udp.to_be_bytes(), key)? {
            if udp_bytes.len() <= 2 {
                let mut v = [0_u8; 2];
                v[2 - udp_bytes.len()..].copy_from_slice(&udp_bytes);
                return Ok(Some(u16::from_be_bytes(v)));
            }
        }
        Ok(None)
    }

    /// Sets the `udp6` field of the ENR. Returns any pre-existing UDP port in the record.
    pub fn set_udp6(&mut self, udp: u16, key: &K) -> Result<Option<u16>, EnrError> {
        if let Some(udp_bytes) = self.insert("udp6", &udp.to_be_bytes(), key)? {
            if udp_bytes.len() <= 2 {
                let mut v = [0_u8; 2];
                v[2 - udp_bytes.len()..].copy_from_slice(&udp_bytes);
                return Ok(Some(u16::from_be_bytes(v)));
            }
        }
        Ok(None)
    }

    /// Sets the `tcp` field of the ENR. Returns any pre-existing tcp port in the record.
    pub fn set_tcp4(&mut self, tcp: u16, key: &K) -> Result<Option<u16>, EnrError> {
        if let Some(tcp_bytes) = self.insert("tcp", &tcp.to_be_bytes(), key)? {
            if tcp_bytes.len() <= 2 {
                let mut v = [0_u8; 2];
                v[2 - tcp_bytes.len()..].copy_from_slice(&tcp_bytes);
                return Ok(Some(u16::from_be_bytes(v)));
            }
        }
        Ok(None)
    }

    /// Sets the `tcp6` field of the ENR. Returns any pre-existing tcp6 port in the record.
    pub fn set_tcp6(&mut self, tcp: u16, key: &K) -> Result<Option<u16>, EnrError> {
        if let Some(tcp_bytes) = self.insert("tcp6", &tcp.to_be_bytes(), key)? {
            if tcp_bytes.len() <= 2 {
                let mut v = [0_u8; 2];
                v[2 - tcp_bytes.len()..].copy_from_slice(&tcp_bytes);
                return Ok(Some(u16::from_be_bytes(v)));
            }
        }
        Ok(None)
    }

    /// Sets the IP and UDP port in a single update with a single increment in sequence number.
    pub fn set_udp_socket(&mut self, socket: SocketAddr, key: &K) -> Result<(), EnrError> {
        self.set_socket(socket, key, false)
    }

    /// Sets the IP and TCP port in a single update with a single increment in sequence number.
    pub fn set_tcp_socket(&mut self, socket: SocketAddr, key: &K) -> Result<(), EnrError> {
        self.set_socket(socket, key, true)
    }

    /// Helper function for `set_tcp_socket()` and `set_udp_socket`.
    fn set_socket(&mut self, socket: SocketAddr, key: &K, is_tcp: bool) -> Result<(), EnrError> {
        let (port_string, port_v6_string): (Key, Key) = if is_tcp {
            ("tcp".into(), "tcp6".into())
        } else {
            ("udp".into(), "udp6".into())
        };

        let (prev_ip, prev_port) = match socket.ip() {
            IpAddr::V4(addr) => (
                self.content.insert(
                    "ip".into(),
                    rlp::encode(&(&addr.octets() as &[u8])).freeze(),
                ),
                self.content.insert(
                    port_string.clone(),
                    rlp::encode(&(&socket.port().to_be_bytes() as &[u8])).freeze(),
                ),
            ),
            IpAddr::V6(addr) => (
                self.content.insert(
                    "ip6".into(),
                    rlp::encode(&(&addr.octets() as &[u8])).freeze(),
                ),
                self.content.insert(
                    port_v6_string.clone(),
                    rlp::encode(&(&socket.port().to_be_bytes() as &[u8])).freeze(),
                ),
            ),
        };

        let public_key = key.public();
        let previous_key = self.content.insert(
            public_key.enr_key(),
            rlp::encode(&public_key.encode().as_ref()).freeze(),
        );

        // check the size and revert on failure
        if self.size() > MAX_ENR_SIZE {
            // if the size of the record is too large, revert and error
            // revert the public key
            if let Some(key) = previous_key {
                self.content.insert(public_key.enr_key(), key);
            } else {
                self.content.remove(&public_key.enr_key());
            }
            // revert the content
            match socket.ip() {
                IpAddr::V4(_) => {
                    if let Some(ip) = prev_ip {
                        self.content.insert("ip".into(), ip);
                    } else {
                        self.content.remove(b"ip".as_ref());
                    }
                    if let Some(udp) = prev_port {
                        self.content.insert(port_string, udp);
                    } else {
                        self.content.remove(&port_string);
                    }
                }
                IpAddr::V6(_) => {
                    if let Some(ip) = prev_ip {
                        self.content.insert("ip6".into(), ip);
                    } else {
                        self.content.remove(b"ip6".as_ref());
                    }
                    if let Some(udp) = prev_port {
                        self.content.insert(port_v6_string, udp);
                    } else {
                        self.content.remove(&port_v6_string);
                    }
                }
            }
            return Err(EnrError::ExceedsMaxSize);
        }

        // increment the sequence number
        self.seq = self
            .seq
            .checked_add(1)
            .ok_or(EnrError::SequenceNumberTooHigh)?;

        // sign the record
        self.sign(key)?;

        // update the node id
        self.node_id = NodeId::from(key.public());

        Ok(())
    }

    /// Removes key/value mappings and adds or overwrites key/value mappings to the ENR record as
    /// one sequence number update. An `EnrKey` is required to re-sign the record once modified.
    /// Reverts whole ENR record on error.
    ///
    /// Returns the previous values as rlp encoded bytes if they exist for the removed and added/
    /// overwritten keys.
    pub fn remove_insert<'a>(
        &mut self,
        remove_keys: impl Iterator<Item = impl AsRef<[u8]>>,
        insert_key_values: impl Iterator<Item = (impl AsRef<[u8]>, &'a [u8])>,
        enr_key: &K,
    ) -> Result<(PreviousRlpEncodedValues, PreviousRlpEncodedValues), EnrError> {
        let enr_backup = self.clone();

        let mut removed = Vec::new();
        for key in remove_keys {
            removed.push(self.content.remove(key.as_ref()));
        }

        // add the new public key
        let public_key = enr_key.public();
        self.content.insert(
            public_key.enr_key(),
            rlp::encode(&public_key.encode().as_ref()).freeze(),
        );

        let mut inserted = Vec::new();
        for (key, value) in insert_key_values {
            // currently only support "v4" identity schemes
            if key.as_ref() == b"id" && value != b"v4" {
                *self = enr_backup;
                return Err(EnrError::UnsupportedIdentityScheme);
            }
            inserted.push(
                self.content
                    .insert(key.as_ref().to_vec(), rlp::encode(&(value)).freeze()),
            );
        }

        // increment the sequence number
        self.seq = self
            .seq
            .checked_add(1)
            .ok_or(EnrError::SequenceNumberTooHigh)?;

        // sign the record
        self.sign(enr_key)?;

        // update the node id
        self.node_id = NodeId::from(enr_key.public());

        if self.size() > MAX_ENR_SIZE {
            // in case the signature size changes, inform the user the size has exceeded the
            // maximum
            *self = enr_backup;
            return Err(EnrError::ExceedsMaxSize);
        }

        Ok((removed, inserted))
    }

    /// Sets a new public key for the record.
    pub fn set_public_key(&mut self, public_key: &K::PublicKey, key: &K) -> Result<(), EnrError> {
        self.insert(&public_key.enr_key(), public_key.encode().as_ref(), key)
            .map(|_| {})
    }

    // Private Functions //

    /// Evaluates the RLP-encoding of the content of the ENR record.
    fn rlp_content(&self) -> BytesMut {
        let mut stream = RlpStream::new_with_buffer(BytesMut::with_capacity(MAX_ENR_SIZE));
        stream.begin_list(self.content.len() * 2 + 1);
        stream.append(&self.seq);
        for (k, v) in &self.content {
            // Keys are bytes
            stream.append(k);
            // Values are raw RLP encoded data
            stream.append_raw(v, 1);
        }
        stream.out()
    }

    /// Signs the ENR record based on the identity scheme. Currently only "v4" is supported.
    fn sign(&mut self, key: &K) -> Result<(), EnrError> {
        self.signature = {
            match self.id() {
                Some(ref id) if id == "v4" => key
                    .sign_v4(&self.rlp_content())
                    .map_err(|_| EnrError::SigningError)?,
                // other identity schemes are unsupported
                _ => return Err(EnrError::SigningError),
            }
        };
        Ok(())
    }
}

// traits //

impl<K: EnrKey> Clone for Enr<K> {
    fn clone(&self) -> Self {
        Self {
            seq: self.seq,
            node_id: self.node_id,
            content: self.content.clone(),
            signature: self.signature.clone(),
            phantom: self.phantom,
        }
    }
}

impl<K: EnrKey> std::cmp::Eq for Enr<K> {}

impl<K: EnrKey> PartialEq for Enr<K> {
    fn eq(&self, other: &Self) -> bool {
        self.seq == other.seq && self.node_id == other.node_id && self.signature == other.signature
    }
}

impl<K: EnrKey> Hash for Enr<K> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.seq.hash(state);
        self.node_id.hash(state);
        // since the struct should always have a valid signature, we can hash the signature
        // directly, rather than hashing the content.
        self.signature.hash(state);
    }
}

impl<K: EnrKey> std::fmt::Display for Enr<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "ENR: NodeId: {}, IpV4 Socket: {:?} IpV6 Socket: {:?}",
            self.node_id(),
            self.udp4_socket(),
            self.udp6_socket()
        )
    }
}

impl<K: EnrKey> std::fmt::Debug for Enr<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.to_base64())
    }
}

/// Convert a URL-SAFE base64 encoded ENR into an ENR.
impl<K: EnrKey> FromStr for Enr<K> {
    type Err = String;

    fn from_str(base64_string: &str) -> Result<Self, Self::Err> {
        if base64_string.len() < 4 {
            return Err("Invalid ENR string".to_string());
        }
        // support both enr prefix and not
        let mut decode_string = base64_string;
        if base64_string.starts_with("enr:") {
            decode_string = decode_string
                .get(4..)
                .ok_or_else(|| "Invalid ENR string".to_string())?;
        }
        let bytes = base64::decode_config(decode_string, base64::URL_SAFE_NO_PAD)
            .map_err(|e| format!("Invalid base64 encoding: {e:?}"))?;
        rlp::decode(&bytes).map_err(|e| format!("Invalid ENR: {e:?}"))
    }
}

#[cfg(any(feature = "serde"))]
impl<K: EnrKey> Serialize for Enr<K> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_base64())
    }
}

#[cfg(any(feature = "serde"))]
impl<'de, K: EnrKey> Deserialize<'de> for Enr<K> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: String = Deserialize::deserialize(deserializer)?;
        Self::from_str(&s).map_err(D::Error::custom)
    }
}

impl<K: EnrKey> rlp::Encodable for Enr<K> {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(self.content.len() * 2 + 2);
        s.append(&self.signature);
        s.append(&self.seq);
        // must use rlp_content to preserve ordering.
        for (k, v) in &self.content {
            // Keys are byte data
            s.append(k);
            // Values are raw RLP encoded data
            s.append_raw(v, 1);
        }
    }
}

impl<K: EnrKey> rlp::Decodable for Enr<K> {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        if !rlp.is_list() {
            debug!("Failed to decode ENR. Not an RLP list: {}", rlp);
            return Err(DecoderError::RlpExpectedToBeList);
        }

        let mut rlp_iter = rlp.iter();

        if rlp_iter.len() == 0 || rlp_iter.len() % 2 != 0 {
            debug!("Failed to decode ENR. List size is not a multiple of 2.");
            return Err(DecoderError::Custom("List not a multiple of two"));
        }

        let signature = rlp_iter
            .next()
            .ok_or(DecoderError::Custom("List is empty"))?
            .data()?;
        let seq_bytes = rlp_iter
            .next()
            .ok_or(DecoderError::Custom("List has only one item"))?
            .data()?;

        if seq_bytes.len() > 8 {
            debug!("Failed to decode ENR. Sequence number is not a u64.");
            return Err(DecoderError::Custom("Invalid Sequence number"));
        }

        // build u64 from big endian vec<u8>
        let mut seq: [u8; 8] = [0; 8];
        seq[8 - seq_bytes.len()..].copy_from_slice(seq_bytes);
        let seq = u64::from_be_bytes(seq);

        let mut content = BTreeMap::new();
        let mut prev: Option<&[u8]> = None;
        while let Some(key) = rlp_iter.next() {
            let key = key.data()?;
            let item = rlp_iter
                .next()
                .ok_or(DecoderError::Custom("List not a multiple of 2"))?;

            // Sanitize the data
            let _ = item.data()?;
            let value = item.as_raw();

            if prev.is_some() && prev >= Some(key) {
                return Err(DecoderError::Custom("Unsorted keys"));
            }
            prev = Some(key);
            content.insert(key.to_vec(), Bytes::copy_from_slice(value));
        }

        // verify we know the signature type
        let public_key = K::enr_to_public(&content)?;

        // calculate the node id
        let node_id = NodeId::from(public_key);

        let enr = Self {
            seq,
            node_id,
            signature: signature.into(),
            content,
            phantom: PhantomData,
        };

        // verify the signature before returning
        // if the public key is of an unknown type, this will fail.
        // An ENR record will always have a valid public-key and therefore node-id
        if !enr.verify() {
            return Err(DecoderError::Custom("Invalid Signature"));
        }
        Ok(enr)
    }
}

pub(crate) fn digest(b: &[u8]) -> [u8; 32] {
    let mut output = [0_u8; 32];
    output.copy_from_slice(&Keccak256::digest(b));
    output
}
