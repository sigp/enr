use crate::{Enr, EnrError, EnrKey, EnrPublicKey, Key, NodeId, MAX_ENR_SIZE};
#[cfg(feature = "eth2")]
use crate::{ATTESTATION_BITFIELD_ENR_KEY, ETH2_ENR_KEY, SYNC_COMMITTEE_BITFIELD_ENR_KEY};
use crate::{
    ENR_VERSION, ID_ENR_KEY, IP6_ENR_KEY, IP_ENR_KEY, TCP6_ENR_KEY, TCP_ENR_KEY, UDP6_ENR_KEY,
    UDP_ENR_KEY,
};
#[cfg(feature = "quic")]
use crate::{QUIC6_ENR_KEY, QUIC_ENR_KEY};

use bytes::{Bytes, BytesMut};
use rlp::{Encodable, RlpStream};
use std::{
    collections::BTreeMap,
    marker::PhantomData,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

// Generates function setters on the `EnrBuilder`.
macro_rules! generate_setter {
    // Function name, variable type and key
    ($name:ident, $type:ty, $key:ident) => {
        #[doc = concat!(" Adds a `", stringify!($name),"` field to the `ENRBuilder.")]
        pub fn $name(&mut self, var: $type) -> &mut Self {
            self.add_value($key, &var);
            self
        }
    };
}

/// The base builder for generating ENR records with arbitrary signing algorithms.
pub struct Builder<K: EnrKey> {
    /// The identity scheme used to build the ENR record.
    id: Vec<u8>,

    /// The starting sequence number for the ENR record.
    seq: u64,

    /// The key-value pairs for the ENR record.
    /// Values are stored as RLP encoded bytes.
    content: BTreeMap<Key, Bytes>,

    /// Pins the generic key types.
    phantom: PhantomData<K>,
}

impl<K: EnrKey> Default for Builder<K> {
    /// Constructs a minimal [`Builder`] for the v4 identity scheme.
    fn default() -> Self {
        Self {
            id: ENR_VERSION.into(),
            seq: 1,
            content: BTreeMap::new(),
            phantom: PhantomData,
        }
    }
}

impl<K: EnrKey> Builder<K> {
    /// Constructs a minimal `EnrBuilder` providing only a sequence number.
    /// Currently only supports the id v4 scheme and therefore disallows creation of any other
    /// scheme.
    pub fn new() -> Self {
        Self::default()
    }

    /// Modifies the sequence number of the builder.
    pub fn seq(&mut self, seq: u64) -> &mut Self {
        self.seq = seq;
        self
    }

    /// Adds an arbitrary key-value to the `ENRBuilder`.
    pub fn add_value<T: Encodable>(&mut self, key: impl AsRef<[u8]>, value: &T) -> &mut Self {
        self.add_value_rlp(key, rlp::encode(value).freeze())
    }

    /// Adds an arbitrary key-value where the value is raw RLP encoded bytes.
    pub fn add_value_rlp(&mut self, key: impl AsRef<[u8]>, rlp: Bytes) -> &mut Self {
        self.content.insert(key.as_ref().to_vec(), rlp);
        self
    }

    /// Adds an `ip`/`ip6` field to the `ENRBuilder`.
    pub fn ip(&mut self, ip: IpAddr) -> &mut Self {
        match ip {
            IpAddr::V4(addr) => self.ip4(addr),
            IpAddr::V6(addr) => self.ip6(addr),
        }
    }

    /// Adds an `ip` field to the `ENRBuilder`.
    pub fn ip4(&mut self, ip: Ipv4Addr) -> &mut Self {
        self.add_value(IP_ENR_KEY, &ip.octets().as_ref());
        self
    }

    /// Adds an `ip6` field to the `ENRBuilder`.
    pub fn ip6(&mut self, ip: Ipv6Addr) -> &mut Self {
        self.add_value(IP6_ENR_KEY, &ip.octets().as_ref());
        self
    }

    generate_setter!(tcp4, u16, TCP_ENR_KEY);
    generate_setter!(tcp6, u16, TCP6_ENR_KEY);
    generate_setter!(udp4, u16, UDP_ENR_KEY);
    generate_setter!(udp6, u16, UDP6_ENR_KEY);
    #[cfg(feature = "quic")]
    generate_setter!(quic, u16, QUIC_ENR_KEY);
    #[cfg(feature = "quic")]
    generate_setter!(quic6, u16, QUIC6_ENR_KEY);
    #[cfg(feature = "eth2")]
    generate_setter!(eth2, &[u8], ETH2_ENR_KEY);
    #[cfg(feature = "eth2")]
    generate_setter!(attestation_bitfield, &[u8], ATTESTATION_BITFIELD_ENR_KEY);
    #[cfg(feature = "eth2")]
    generate_setter!(
        sync_committee_bitfield,
        &[u8],
        SYNC_COMMITTEE_BITFIELD_ENR_KEY
    );

    /// Generates the rlp-encoded form of the ENR specified by the builder config.
    fn rlp_content(&self) -> BytesMut {
        let mut stream = RlpStream::new_with_buffer(BytesMut::with_capacity(MAX_ENR_SIZE));
        stream.begin_list(self.content.len() * 2 + 1);
        stream.append(&self.seq);
        for (k, v) in &self.content {
            stream.append(k);
            // The values are stored as raw RLP encoded bytes
            stream.append_raw(v, 1);
        }
        stream.out()
    }

    /// Signs record based on the identity scheme. Currently only ENR_VERSION is supported.
    fn signature(&self, key: &K) -> Result<Vec<u8>, EnrError> {
        match self.id.as_slice() {
            ENR_VERSION => key
                .sign_v4(&self.rlp_content())
                .map_err(|_| EnrError::SigningError),
            // unsupported identity schemes
            _ => Err(EnrError::SigningError),
        }
    }

    /// Adds a public key to the ENR builder.
    fn add_public_key(&mut self, key: &K::PublicKey) {
        self.add_value(key.enr_key(), &key.encode().as_ref());
    }

    /// Constructs an ENR from the [`Builder`].
    ///
    /// # Errors
    /// Fails if the identity scheme is not supported, or the record size exceeds `MAX_ENR_SIZE`.
    pub fn build(&mut self, key: &K) -> Result<Enr<K>, EnrError> {
        // Sanitize all data, ensuring all RLP data is correctly formatted.
        for (key, value) in &self.content {
            if rlp::Rlp::new(value).data().is_err() {
                return Err(EnrError::InvalidRlpData(
                    String::from_utf8_lossy(key).into(),
                ));
            }
        }

        self.add_value_rlp(ID_ENR_KEY, rlp::encode(&self.id).freeze());

        self.add_public_key(&key.public());
        let rlp_content = self.rlp_content();

        let signature = self.signature(key)?;

        // check the size of the record
        if rlp_content.len() + signature.len() + 8 > MAX_ENR_SIZE {
            return Err(EnrError::ExceedsMaxSize);
        }

        Ok(Enr {
            seq: self.seq,
            node_id: NodeId::from(key.public()),
            content: self.content.clone(),
            signature,
            phantom: PhantomData,
        })
    }
}
