use crate::{update::Update, Enr, EnrError, EnrKey, NodeId};
use bytes::Bytes;
use rlp::Encodable;
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
    /// Currently only supports the id v4 scheme and therefore disallows creation of any other
    /// scheme.
    pub fn new(id: impl Into<String>) -> Self {
        let id = rlp::encode(&id.into().as_bytes()).freeze();
        // create a dummy Enr over which work is done
        let enr = Enr {
            seq: 0,
            node_id: NodeId::new(&[0; 32]),
            content: BTreeMap::from([(b"id".to_vec(), id)]),
            signature: Vec::default(),
            phantom: PhantomData,
        };
        let updates = Vec::default();
        Self { enr, updates }
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
            .push(Update::insert("ip", &ip.octets().as_ref()));
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

    /// Constructs an ENR from the `EnrBuilder`.
    ///
    /// # Errors
    /// Fails if the identity scheme is not supported, or the record size exceeds the byte length
    /// limit.
    pub fn build(&self, signing_key: &K) -> Result<Enr<K>, EnrError> {
        let mut enr = self.enr.clone();
        let updates = self.updates.clone();
        enr.update(updates, signing_key)?;
        Ok(enr)
    }
}
