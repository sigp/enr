/// For documentation see [`crate::Enr`]
pub trait AsEnr {
    type Key: EnrKey;
    #[must_use]
    fn node_id(&self) -> NodeId;
    #[must_use]
    fn seq(&self) -> u64;
    fn get(&self, key: impl AsRef<[u8]>) -> Option<&[u8]>;
    fn get_decodable<T: Decodable>(&self, key: impl AsRef<[u8]>)
        -> Option<Result<T, DecoderError>>;
    fn get_raw_rlp(&self, key: impl AsRef<[u8]>) -> Option<&[u8]>;
    fn iter<'a>(&self) -> Iterator<Item = (&'a Self::Key, &'a [u8])>;
    #[must_use]
    fn ip4(&self) -> Option<Ipv4Addr>;
    #[must_use]
    fn ip6(&self) -> Option<Ipv6Addr>;
    #[must_use]
    fn id(&self) -> Option<String>;
    #[must_use]
    fn tcp4(&self) -> Option<u16>;
    #[must_use]
    fn tcp6(&self) -> Option<u16>;
    #[must_use]
    fn udp4(&self) -> Option<u16>;
    #[must_use]
    fn udp6(&self) -> Option<u16>;
    #[must_use]
    fn udp4_socket(&self) -> Option<SocketAddrV4>;
    #[must_use]
    fn udp6_socket(&self) -> Option<SocketAddrV6>;
    #[must_use]
    fn tcp4_socket(&self) -> Option<SocketAddrV4>;
    #[must_use]
    fn tcp6_socket(&self) -> Option<SocketAddrV6>;
    #[must_use]
    fn signature(&self) -> &[u8];
    #[must_use]
    fn public_key(&self) -> <Self::Key as EnrKey>::PublicKey;
    #[must_use]
    fn verify(&self) -> bool;
    #[must_use]
    fn to_base64(&self) -> String;
    #[must_use]
    fn size(&self) -> usize;
    fn set_seq(&mut self, seq: u64, key: &Self::Key) -> Result<(), EnrError>;
    fn insert<T: Encodable>(
        &mut self,
        key: impl AsRef<[u8]>,
        value: &T,
        enr_key: &Self::Key,
    ) -> Result<Option<Bytes>, EnrError>;
    fn insert_raw_rlp(
        &mut self,
        key: impl AsRef<[u8]>,
        value: Bytes,
        enr_key: &Self::Key,
    ) -> Result<Option<Bytes>, EnrError>;
    fn set_ip(&mut self, ip: IpAddr, key: &Self::Key) -> Result<Option<IpAddr>, EnrError>;
    fn set_udp4(&mut self, udp: u16, key: &Self::Key) -> Result<Option<u16>, EnrError>;
    fn set_udp6(&mut self, udp: u16, key: &Self::Key) -> Result<Option<u16>, EnrError>;
    fn set_tcp4(&mut self, tcp: u16, key: &Self::Key) -> Result<Option<u16>, EnrError>;
    fn set_tcp6(&mut self, tcp: u16, key: &Self::Key) -> Result<Option<u16>, EnrError>;
    fn set_udp_socket(&mut self, socket: SocketAddr, key: &Self::Key) -> Result<(), EnrError>;
    fn set_tcp_socket(&mut self, socket: SocketAddr, key: &Self::Key) -> Result<(), EnrError>;
    fn set_socket(
        &mut self,
        socket: SocketAddr,
        key: &Self::Key,
        is_tcp: bool,
    ) -> Result<(), EnrError>;
    fn remove_insert<'a>(
        &mut self,
        remove_keys: impl Iterator<Item = impl AsRef<[u8]>>,
        insert_key_values: impl Iterator<Item = (impl AsRef<[u8]>, &'a [u8])>,
        enr_key: &Self::Key,
    ) -> Result<(PreviousRlpEncodedValues, PreviousRlpEncodedValues), EnrError>;
    fn set_public_key(
        &mut self,
        public_key: &<Self::Key as EnrKey>::PublicKey,
        key: &Self::Key,
    ) -> Result<(), EnrError>;
    #[must_use]
    fn is_udp_reachable(&self) -> bool;
    #[must_use]
    fn is_tcp_reachable(&self) -> bool;
}

impl<K: EnrKey> AsEnr for Arc<RwLock<Enr<K>>> {
    type Key = K;
    #[must_use]
    fn node_id(&self) -> NodeId;
    #[must_use]
    fn seq(&self) -> u64;
    fn get(&self, key: impl AsRef<[u8]>) -> Option<&[u8]>;
    fn get_decodable<T: Decodable>(&self, key: impl AsRef<[u8]>)
        -> Option<Result<T, DecoderError>>;
    fn get_raw_rlp(&self, key: impl AsRef<[u8]>) -> Option<&[u8]>;
    fn iter<'a>(&self) -> Iterator<Item = (&'a Self::Key, &'a [u8])>;
    #[must_use]
    fn ip4(&self) -> Option<Ipv4Addr>;
    #[must_use]
    fn ip6(&self) -> Option<Ipv6Addr>;
    #[must_use]
    fn id(&self) -> Option<String>;
    #[must_use]
    fn tcp4(&self) -> Option<u16>;
    #[must_use]
    fn tcp6(&self) -> Option<u16>;
    #[must_use]
    fn udp4(&self) -> Option<u16>;
    #[must_use]
    fn udp6(&self) -> Option<u16>;
    #[must_use]
    fn udp4_socket(&self) -> Option<SocketAddrV4>;
    #[must_use]
    fn udp6_socket(&self) -> Option<SocketAddrV6>;
    #[must_use]
    fn tcp4_socket(&self) -> Option<SocketAddrV4>;
    #[must_use]
    fn tcp6_socket(&self) -> Option<SocketAddrV6>;
    #[must_use]
    fn signature(&self) -> &[u8];
    #[must_use]
    fn public_key(&self) -> <Self::Key as EnrKey>::PublicKey;
    #[must_use]
    fn verify(&self) -> bool;
    #[must_use]
    fn to_base64(&self) -> String;
    #[must_use]
    fn size(&self) -> usize;
    fn set_seq(&mut self, seq: u64, key: &Self::Key) -> Result<(), EnrError>;
    fn insert<T: Encodable>(
        &mut self,
        key: impl AsRef<[u8]>,
        value: &T,
        enr_key: &Self::Key,
    ) -> Result<Option<Bytes>, EnrError>;
    fn insert_raw_rlp(
        &mut self,
        key: impl AsRef<[u8]>,
        value: Bytes,
        enr_key: &Self::Key,
    ) -> Result<Option<Bytes>, EnrError>;
    fn set_ip(&mut self, ip: IpAddr, key: &Self::Key) -> Result<Option<IpAddr>, EnrError>;
    fn set_udp4(&mut self, udp: u16, key: &Self::Key) -> Result<Option<u16>, EnrError>;
    fn set_udp6(&mut self, udp: u16, key: &Self::Key) -> Result<Option<u16>, EnrError>;
    fn set_tcp4(&mut self, tcp: u16, key: &Self::Key) -> Result<Option<u16>, EnrError>;
    fn set_tcp6(&mut self, tcp: u16, key: &Self::Key) -> Result<Option<u16>, EnrError>;
    fn set_udp_socket(&mut self, socket: SocketAddr, key: &Self::Key) -> Result<(), EnrError>;
    fn set_tcp_socket(&mut self, socket: SocketAddr, key: &Self::Key) -> Result<(), EnrError>;
    fn set_socket(
        &mut self,
        socket: SocketAddr,
        key: &Self::Key,
        is_tcp: bool,
    ) -> Result<(), EnrError>;
    fn remove_insert<'a>(
        &mut self,
        remove_keys: impl Iterator<Item = impl AsRef<[u8]>>,
        insert_key_values: impl Iterator<Item = (impl AsRef<[u8]>, &'a [u8])>,
        enr_key: &Self::Key,
    ) -> Result<(PreviousRlpEncodedValues, PreviousRlpEncodedValues), EnrError>;
    fn set_public_key(
        &mut self,
        public_key: &<Self::Key as EnrKey>::PublicKey,
        key: &Self::Key,
    ) -> Result<(), EnrError>;
    #[must_use]
    fn is_udp_reachable(&self) -> bool;
    #[must_use]
    fn is_tcp_reachable(&self) -> bool;
}

macro_rules! impl_trait_for_arc_lock {
    ($fn_name: ident, $signature_ref: tt) => {
        $signature {
            self.0.read().$fn_name()
        }
    };
}