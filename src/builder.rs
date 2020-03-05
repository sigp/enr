use crate::{DefaultKey, EnrError, EnrKey, EnrPublicKey, EnrRaw, NodeId, MAX_ENR_SIZE};
use rlp::RlpStream;
use std::{collections::BTreeMap, marker::PhantomData, net::IpAddr};

/// The default builder of ENR records which uses the standard signing algorithms.
pub type EnrBuilder = EnrBuilderRaw<DefaultKey>;

///! The raw builder for generating ENR records with arbitrary signing algorithms.
pub struct EnrBuilderRaw<K: EnrKey> {
    /// The identity scheme used to build the ENR record.
    id: String,

    /// The starting sequence number for the ENR record.
    seq: u64,

    /// The key-value pairs for the ENR record.
    content: BTreeMap<String, Vec<u8>>,

    /// Pins the generic key types.
    phantom: PhantomData<K>,
}

impl<K: EnrKey> EnrBuilderRaw<K> {
    /// Constructs a minimal `EnrBuilder` providing only a sequence number.
    /// Currently only supports the id v4 scheme and therefore disallows creation of any other
    /// scheme.
    pub fn new(id: impl Into<String>) -> Self {
        EnrBuilderRaw {
            id: id.into(),
            seq: 1,
            content: BTreeMap::new(),
            phantom: PhantomData,
        }
    }

    /// Modifies the sequence number of the builder.
    pub fn seq(&mut self, seq: u64) -> &mut Self {
        self.seq = seq;
        self
    }

    /// Adds an arbitrary key-value to the `ENRBuilder`.
    pub fn add_value(&mut self, key: String, value: Vec<u8>) -> &mut Self {
        self.content.insert(key, value);
        self
    }

    /// Adds an `ip` field to the `ENRBuilder`.
    pub fn ip(&mut self, ip: IpAddr) -> &mut Self {
        match ip {
            IpAddr::V4(addr) => {
                self.content
                    .insert(String::from("ip"), addr.octets().to_vec());
            }
            IpAddr::V6(addr) => {
                self.content
                    .insert(String::from("ip6"), addr.octets().to_vec());
            }
        }
        self
    }

    /*
     * Removed from the builder as only the v4 scheme is currently supported.
     * This is set as default in the builder.

    /// Adds an `Id` field to the `ENRBuilder`.
    pub fn id(&mut self, id: &str) -> &mut Self {
        self.content.insert("id".into(), id.as_bytes().to_vec());
        self
    }
    */

    /// Adds a `tcp` field to the `ENRBuilder`.
    pub fn tcp(&mut self, tcp: u16) -> &mut Self {
        self.content
            .insert("tcp".into(), tcp.to_be_bytes().to_vec());
        self
    }

    /// Adds a `tcp6` field to the `ENRBuilder`.
    pub fn tcp6(&mut self, tcp: u16) -> &mut Self {
        self.content
            .insert("tcp6".into(), tcp.to_be_bytes().to_vec());
        self
    }

    /// Adds a `udp` field to the `ENRBuilder`.
    pub fn udp(&mut self, udp: u16) -> &mut Self {
        self.content
            .insert("udp".into(), udp.to_be_bytes().to_vec());
        self
    }

    /// Adds a `udp6` field to the `ENRBuilder`.
    pub fn udp6(&mut self, udp: u16) -> &mut Self {
        self.content
            .insert("udp6".into(), udp.to_be_bytes().to_vec());
        self
    }

    /// Generates the rlp-encoded form of the ENR specified by the builder config.
    fn rlp_content(&self) -> Vec<u8> {
        let mut stream = RlpStream::new();
        stream.begin_list(self.content.len() * 2 + 1);
        stream.append(&self.seq);
        for (k, v) in self.content.iter() {
            stream.append(k);
            stream.append(v);
        }
        stream.drain()
    }

    /// Signs record based on the identity scheme. Currently only "v4" is supported.
    fn signature(&self, key: &K) -> Result<Vec<u8>, EnrError> {
        match self.id.as_str() {
            "v4" => key
                .sign_v4(&self.rlp_content())
                .map_err(|_| EnrError::SigningError),
            // unsupported identity schemes
            _ => Err(EnrError::SigningError),
        }
    }

    /// Adds a public key to the ENR builder.
    fn add_public_key(&mut self, key: &K::PublicKey) {
        self.add_value(key.clone().into(), key.encode());
    }

    /// Constructs an ENR from the ENRBuilder struct.
    pub fn build(&mut self, key: &K) -> Result<EnrRaw<K>, EnrError> {
        // add the identity scheme to the content
        if self.id != "v4" {
            return Err(EnrError::UnsupportedIdentityScheme);
        }

        self.content
            .insert("id".into(), self.id.as_bytes().to_vec());

        self.add_public_key(&key.public());
        let rlp_content = self.rlp_content();

        let signature = self.signature(key)?;

        // check the size of the record
        if rlp_content.len() + signature.len() + 8 > MAX_ENR_SIZE {
            return Err(EnrError::ExceedsMaxSize);
        }

        Ok(EnrRaw {
            seq: self.seq,
            node_id: NodeId::from(key.public()),
            content: self.content.clone(),
            signature,
            phantom: PhantomData,
        })
    }
}
