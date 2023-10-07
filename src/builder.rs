use crate::{
    update::{self, Update},
    Enr, EnrKey, EnrPublicKey, Error, Key, NodeId, MAX_ENR_SIZE,
};
use bytes::{Bytes, BytesMut};
use rlp::{Encodable, RlpStream};
use std::{
    collections::BTreeMap,
    marker::PhantomData,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

/// The base builder for generating ENR records with arbitrary signing algorithms.
#[derive(Clone)]
pub struct EnrBuilder<K: EnrKey> {
    enr: Enr<K>,
    updates: Vec<Update>,
}

impl<K: EnrKey> EnrBuilder<K> {
    /// Constructs a minimal `EnrBuilder` providing only a sequence number.
    // TODO: fix docs
    pub fn new_v4() -> Self {
        let v4_id = rlp::encode(&b"v4".as_ref()).freeze();
        Self {
            enr: Enr {
                seq: 0,
                node_id: NodeId::new(&[0; 32]),
                content: BTreeMap::from([(b"id".to_vec(), v4_id)]),
                signature: Vec::default(),
                phantom: PhantomData::default(),
            },
            updates: Vec::default(),
        }
    }

    /// Modifies the sequence number of the builder.
    pub fn seq(&mut self, seq: u64) -> &mut Self {
        self.enr.seq = seq;
        self
    }

    /// Adds an arbitrary key-value to the `ENRBuilder`.
    pub fn add_value<T: Encodable>(&mut self, key: impl AsRef<[u8]>, value: &T) -> &mut Self {
        self.updates.push(Update::insert(key, value));
        self
    }

    /// Adds an arbitrary key-value where the value is raw RLP encoded bytes.
    pub fn add_value_rlp(&mut self, key: impl AsRef<[u8]>, rlp: Bytes) -> &mut Self {
        self.updates.push(Update::insert_raw(key, rlp));
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
        self.updates
            .push(Update::insert("ip4", &ip.octets().as_ref()));
        self
    }

    /// Adds an `ip6` field to the `ENRBuilder`.
    pub fn ip6(&mut self, ip: Ipv6Addr) -> &mut Self {
        self.updates
            .push(Update::insert("ip6", &ip.octets().as_ref()));
        self
    }

    /// Adds a `tcp` field to the `ENRBuilder`.
    pub fn tcp4(&mut self, tcp: u16) -> &mut Self {
        self.add_value("tcp", &tcp);
        self
    }

    /// Adds a `tcp6` field to the `ENRBuilder`.
    pub fn tcp6(&mut self, tcp: u16) -> &mut Self {
        self.add_value("tcp6", &tcp);
        self
    }

    /// Adds a `udp` field to the `ENRBuilder`.
    pub fn udp4(&mut self, udp: u16) -> &mut Self {
        self.add_value("udp", &udp);
        self
    }

    /// Adds a `udp6` field to the `ENRBuilder`.
    pub fn udp6(&mut self, udp: u16) -> &mut Self {
        self.add_value("udp6", &udp);
        self
    }

    /// Generates the rlp-encoded form of the ENR specified by the builder config.
    fn rlp_content(&self) -> BytesMut {
        let mut stream = RlpStream::new_with_buffer(BytesMut::with_capacity(MAX_ENR_SIZE));
        let include_signature = false;
        self.enr.append_rlp_content(&mut stream, include_signature);
        stream.out()
    }

    /// Signs record based on the identity scheme. Currently only "v4" is supported.
    fn signature(&self, key: &K) -> Result<Vec<u8>, Error> {
        self.enr.compute_signature(key)
    }

    /// Adds a public key to the ENR builder.
    fn add_public_key(&mut self, key: &K::PublicKey) {
        self.add_value(key.enr_key(), &key.encode().as_ref());
    }

    /// Constructs an ENR from the `EnrBuilder`.
    ///
    /// # Errors
    /// Fails if the identity scheme is not supported, or the record size exceeds `MAX_ENR_SIZE`.
    pub fn build(mut self, signing_key: &K) -> Result<Enr<K>, Error> {
        let EnrBuilder { mut enr, updates } = self;
        enr.update(updates, signing_key)?;
        Ok(enr)
    }
}
