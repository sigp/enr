#[cfg(feature = "thread-safe")]
pub mod thread_safe_enr {
    use crate::*;
    use parking_lot::RwLock;
    use std::sync::Arc;

    /// Treat [`Enr`] wrappers as the underlying type with transparent API. Excludes the `iter`
    /// method, which must be called through wrapper-aware call, e.g. `wrapper.read().iter()` for
    /// a lock wrapper. For documentation of individual methods see [`Enr`].
    pub trait AsEnr
    where
        Self: Sized,
    {
        type Key: EnrKey;
        #[must_use]
        fn node_id(&self) -> NodeId;
        #[must_use]
        fn seq(&self) -> u64;
        /// Returns Vec<u8> instead of &[u8] as original [`Enr`] method does.
        fn get(&self, key: impl AsRef<[u8]>) -> Option<Vec<u8>>;
        fn get_decodable<T: Decodable>(
            &self,
            key: impl AsRef<[u8]>,
        ) -> Option<Result<T, DecoderError>>;
        /// Returns Vec<u8> instead of &[u8] as original [`Enr`] method does.
        fn get_raw_rlp(&self, key: impl AsRef<[u8]>) -> Option<Vec<u8>>;
        //fn iter<'a>(&self) -> impl Iterator<Item = (&Key, &[u8])>; NOT IMPLEMENTED!
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
        /// Returns Vec<u8> instead of &[u8] as original [`Enr`] method does.
        #[must_use]
        fn signature(&self) -> Vec<u8>;
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

    macro_rules! impl_method {
    ($(#[$meta:meta])* $fn_name:ident$(<$generic:ident$(:$trait:path)*>)* (&self $(, $param:ident: $type:ty)*) -> $return_type:ty) => {
        $(#[$meta])*
        fn $fn_name$(<$generic$(:$trait)*>)*(&self, $($param: $type)*) -> $return_type {
            self.0.read().$fn_name($($param,)*)
        }
    };
    ($fn_name:ident$(<$generic:ident$(:$trait:path)*>)* (&mut self $(, $param:ident: $type:ty)*) -> $return_type:ty) => {
        fn $fn_name$(<$generic$(:$trait)*>)*(&mut self $(, $param: $type)*) -> $return_type {
            self.0.write().$fn_name($($param,)*)
        }
    };
    ($fn_name:ident$(<$lifetime:lifetime>)* (&mut self $(, $param:ident: $type:ty)*) -> $return_type:ty) => {
        fn $fn_name$(<$lifetime>)*(&mut self $(, $param: $type)*) -> $return_type {
            self.0.write().$fn_name($($param,)*)
        }
    };
}

    /// An atomic mutable [`Enr`].
    pub struct ArcRwLockEnr<K: EnrKey>(pub Arc<RwLock<Enr<K>>>);

    impl<K: EnrKey> From<Enr<K>> for ArcRwLockEnr<K> {
        fn from(enr: Enr<K>) -> Self {
            ArcRwLockEnr(Arc::new(RwLock::new(enr)))
        }
    }

    impl<K: EnrKey> AsEnr for ArcRwLockEnr<K> {
        type Key = K;

        impl_method!(#[must_use] node_id(&self) -> NodeId);
        impl_method!(#[must_use] seq(&self) -> u64);
        fn get(&self, key: impl AsRef<[u8]>) -> Option<Vec<u8>> {
            self.0.read().get(key).map(|v| v.to_vec())
        }
        impl_method!(get_decodable<T: Decodable>(&self, key: impl AsRef<[u8]>) -> Option<Result<T, DecoderError>>);
        fn get_raw_rlp(&self, key: impl AsRef<[u8]>) -> Option<Vec<u8>> {
            self.0.read().get_raw_rlp(key).map(|v| v.to_vec())
        }
        impl_method!(#[must_use] ip4(&self) -> Option<Ipv4Addr>);
        impl_method!(#[must_use] ip6(&self) -> Option<Ipv6Addr>);
        impl_method!(#[must_use] id(&self) -> Option<String>);
        impl_method!(#[must_use] tcp4(&self) -> Option<u16>);
        impl_method!(#[must_use] tcp6(&self) -> Option<u16>);
        impl_method!(#[must_use] udp4(&self) -> Option<u16>);
        impl_method!(#[must_use] udp6(&self) -> Option<u16>);
        impl_method!(#[must_use] udp4_socket(&self) -> Option<SocketAddrV4>);
        impl_method!(#[must_use] udp6_socket(&self) -> Option<SocketAddrV6>);
        impl_method!(#[must_use] tcp4_socket(&self) -> Option<SocketAddrV4>);
        impl_method!(#[must_use] tcp6_socket(&self) -> Option<SocketAddrV6>);
        fn signature(&self) -> Vec<u8> {
            self.0.read().signature().to_vec()
        }
        impl_method!(#[must_use] public_key(&self) -> <Self::Key as EnrKey>::PublicKey);
        impl_method!(#[must_use] verify(&self) -> bool);
        impl_method!(#[must_use] to_base64(&self) -> String);
        impl_method!(#[must_use] size(&self) -> usize);
        impl_method!(set_seq(&mut self, seq: u64, key: &Self::Key) -> Result<(), EnrError>);
        impl_method!(insert<T: Encodable>(&mut self, key: impl AsRef<[u8]>, value: &T, enr_key: &Self::Key) -> Result<Option<Bytes>, EnrError>);
        impl_method!(insert_raw_rlp(
        &mut self,
        key: impl AsRef<[u8]>,
        value: Bytes,
        enr_key: &Self::Key) -> Result<Option<Bytes>, EnrError>);
        impl_method!(set_ip(&mut self, ip: IpAddr, key: &Self::Key) -> Result<Option<IpAddr>, EnrError>);
        impl_method!(set_udp4(&mut self, udp: u16, key: &Self::Key) -> Result<Option<u16>, EnrError>);
        impl_method!(set_udp6(&mut self, udp: u16, key: &Self::Key) -> Result<Option<u16>, EnrError>);
        impl_method!(set_tcp4(&mut self, tcp: u16, key: &Self::Key) -> Result<Option<u16>, EnrError>);
        impl_method!(set_tcp6(&mut self, tcp: u16, key: &Self::Key) -> Result<Option<u16>, EnrError>);
        impl_method!(set_udp_socket(&mut self, socket: SocketAddr, key: &Self::Key) -> Result<(), EnrError>);
        impl_method!(set_tcp_socket(&mut self, socket: SocketAddr, key: &Self::Key) -> Result<(), EnrError>);
        impl_method!(set_socket(
        &mut self,
        socket: SocketAddr,
        key: &Self::Key,
        is_tcp: bool) -> Result<(), EnrError>);
        impl_method!(remove_insert<'a>(
        &mut self,
        remove_keys: impl Iterator<Item = impl AsRef<[u8]>>,
        insert_key_values: impl Iterator<Item = (impl AsRef<[u8]>, &'a [u8])>,
        enr_key: &Self::Key
    ) -> Result<(PreviousRlpEncodedValues, PreviousRlpEncodedValues), EnrError>);
        impl_method!(set_public_key(
        &mut self,
        public_key: &<Self::Key as EnrKey>::PublicKey,
        key: &Self::Key
    ) -> Result<(), EnrError>);
        impl_method!(#[must_use] is_udp_reachable(&self) -> bool);
        impl_method!(#[must_use] is_tcp_reachable(&self) -> bool);
    }
}

#[cfg(test)]
#[cfg(all(feature = "thread-safe", feature = "k256"))]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[cfg(all(feature = "ed25519", feature = "k256"))]
    #[test]
    fn test_encode_decode_ed25519() {
        let mut rng = rand::thread_rng();
        let key = ed25519_dalek::SigningKey::generate(&mut rng);
        let ip = Ipv4Addr::new(10, 0, 0, 1);
        let tcp = 30303;

        let enr = {
            let mut builder = EnrBuilder::new("v4");
            builder.ip4(ip);
            builder.tcp4(tcp);
            builder.build(&key).unwrap()
        }
        .into();

        assert_eq!(enr.id(), Some("v4".into()));
        assert_eq!(enr.ip4(), Some(ip));
        assert_eq!(enr.tcp4(), Some(tcp));
        assert_eq!(enr.public_key().encode(), key.public().encode());
        assert!(enr.verify());
    }

    #[test]
    fn test_add_key() {
        let mut rng = rand::thread_rng();
        let key = k256::ecdsa::SigningKey::random(&mut rng);
        let ip = Ipv4Addr::new(10, 0, 0, 1);
        let tcp = 30303;

        let enr = {
            let mut builder = EnrBuilder::new("v4");
            builder.ip(ip.into());
            builder.tcp4(tcp);
            builder.build(&key).unwrap()
        };
        let mut enr: ArcRwLockEnr<k256::ecdsa::SigningKey> = enr.into();

        enr.insert("random", &Vec::new(), &key).unwrap();
        assert!(enr.verify());
    }

    #[test]
    fn test_set_ip() {
        let mut rng = rand::thread_rng();
        let key = k256::ecdsa::SigningKey::random(&mut rng);
        let tcp = 30303;
        let ip = Ipv4Addr::new(10, 0, 0, 1);

        let mut enr: ArcRwLockEnr<k256::ecdsa::SigningKey> = {
            let mut builder = EnrBuilder::new("v4");
            builder.tcp4(tcp);
            builder.build(&key).unwrap()
        }
        .into();

        assert!(enr.set_ip(ip.into(), &key).is_ok());
        assert_eq!(enr.id(), Some("v4".into()));
        assert_eq!(enr.ip4(), Some(ip));
        assert_eq!(enr.tcp4(), Some(tcp));
        assert!(enr.verify());

        // Compare the encoding as the key itself can be different
        assert_eq!(enr.public_key().encode(), key.public().encode());
    }

    #[test]
    fn ip_mutation_static_node_id() {
        let mut rng = rand::thread_rng();
        let key = k256::ecdsa::SigningKey::random(&mut rng);
        let tcp = 30303;
        let udp = 30304;
        let ip = Ipv4Addr::new(10, 0, 0, 1);

        let mut enr: ArcRwLockEnr<k256::ecdsa::SigningKey> = {
            let mut builder = EnrBuilder::new("v4");
            builder.ip(ip.into());
            builder.tcp4(tcp);
            builder.udp4(udp);
            builder.build(&key).unwrap()
        }
        .into();

        let node_id = enr.node_id();

        enr.set_udp_socket("192.168.0.1:800".parse::<SocketAddr>().unwrap(), &key)
            .unwrap();
        assert_eq!(node_id, enr.node_id());
        assert_eq!(
            enr.udp4_socket(),
            "192.168.0.1:800".parse::<SocketAddrV4>().unwrap().into()
        );
    }

    #[test]
    fn test_remove_insert() {
        let mut rng = rand::thread_rng();
        let key = k256::ecdsa::SigningKey::random(&mut rng);
        let tcp = 30303;
        let mut topics = Vec::new();
        let mut s = RlpStream::new();
        s.begin_list(2);
        s.append(&"lighthouse");
        s.append(&"eth_syncing");
        topics.extend_from_slice(&s.out().freeze());

        let mut enr: ArcRwLockEnr<k256::ecdsa::SigningKey> = {
            let mut builder = EnrBuilder::new("v4");
            builder.tcp4(tcp);
            builder.build(&key).unwrap()
        }
        .into();

        assert_eq!(enr.tcp4(), Some(tcp));
        assert_eq!(enr.get("topics"), None);

        let topics: &[u8] = &topics;

        let (removed, inserted) = enr
            .remove_insert(
                vec![b"tcp"].iter(),
                vec![(b"topics", topics)].into_iter(),
                &key,
            )
            .unwrap();

        assert_eq!(
            removed[0],
            Some(rlp::encode(&tcp.to_be_bytes().to_vec()).freeze())
        );
        assert_eq!(inserted[0], None);

        assert_eq!(enr.tcp4(), None);
        assert_eq!(enr.get("topics"), Some(topics.to_vec()));

        // Compare the encoding as the key itself can be different
        assert_eq!(enr.public_key().encode(), key.public().encode());
    }
}
