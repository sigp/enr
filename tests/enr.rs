use enr::*;
use rlp::RlpStream;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

type DefaultEnr = Enr<k256::ecdsa::SigningKey>;

#[cfg(feature = "k256")]
#[test]
fn test_vector_k256() {
    let valid_record = hex::decode("f884b8407098ad865b00a582051940cb9cf36836572411a47278783077011599ed5cd16b76f2635f4e234738f30813a89eb9137e3e3df5266e3a1f11df72ecf1145ccb9c01826964827634826970847f00000189736563703235366b31a103ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd31388375647082765f").unwrap();
    let signature = hex::decode("7098ad865b00a582051940cb9cf36836572411a47278783077011599ed5cd16b76f2635f4e234738f30813a89eb9137e3e3df5266e3a1f11df72ecf1145ccb9c").unwrap();
    let expected_pubkey =
        hex::decode("03ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd3138").unwrap();

    let enr = rlp::decode::<DefaultEnr>(&valid_record).unwrap();

    let pubkey = enr.public_key().encode();

    assert_eq!(enr.ip4(), Some(Ipv4Addr::new(127, 0, 0, 1)));
    assert_eq!(enr.id(), Some(String::from("v4")));
    assert_eq!(enr.udp4(), Some(30303));
    assert_eq!(enr.tcp4(), None);
    assert_eq!(enr.signature(), &signature[..]);
    assert_eq!(pubkey.to_vec(), expected_pubkey);
    assert!(enr.verify());
}

#[cfg(feature = "k256")]
#[test]
fn test_vector_2() {
    let text = "enr:-IS4QHCYrYZbAKWCBRlAy5zzaDZXJBGkcnh4MHcBFZntXNFrdvJjX04jRzjzCBOonrkTfj499SZuOh8R33Ls8RRcy5wBgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQPKY0yuDUmstAHYpMa2_oxVtw0RW_QAdpzBQA8yWM0xOIN1ZHCCdl8";
    let signature = hex::decode("7098ad865b00a582051940cb9cf36836572411a47278783077011599ed5cd16b76f2635f4e234738f30813a89eb9137e3e3df5266e3a1f11df72ecf1145ccb9c").unwrap();
    let expected_pubkey =
        hex::decode("03ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd3138").unwrap();
    let expected_node_id =
        hex::decode("a448f24c6d18e575453db13171562b71999873db5b286df957af199ec94617f7").unwrap();

    let enr = text.parse::<DefaultEnr>().unwrap();
    let pubkey = enr.public_key().encode();
    assert_eq!(enr.ip4(), Some(Ipv4Addr::new(127, 0, 0, 1)));
    assert_eq!(enr.ip6(), None);
    assert_eq!(enr.id(), Some(String::from("v4")));
    assert_eq!(enr.udp4(), Some(30303));
    assert_eq!(enr.udp6(), None);
    assert_eq!(enr.tcp4(), None);
    assert_eq!(enr.tcp6(), None);
    assert_eq!(enr.signature(), &signature[..]);
    assert_eq!(pubkey.to_vec(), expected_pubkey);
    assert_eq!(enr.node_id().raw().to_vec(), expected_node_id);

    assert!(enr.verify());
}

#[cfg(feature = "k256")]
#[test]
fn test_vector_2_k256() {
    let text = "enr:-IS4QHCYrYZbAKWCBRlAy5zzaDZXJBGkcnh4MHcBFZntXNFrdvJjX04jRzjzCBOonrkTfj499SZuOh8R33Ls8RRcy5wBgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQPKY0yuDUmstAHYpMa2_oxVtw0RW_QAdpzBQA8yWM0xOIN1ZHCCdl8";
    let signature = hex::decode("7098ad865b00a582051940cb9cf36836572411a47278783077011599ed5cd16b76f2635f4e234738f30813a89eb9137e3e3df5266e3a1f11df72ecf1145ccb9c").unwrap();
    let expected_pubkey =
        hex::decode("03ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd3138").unwrap();
    let expected_node_id =
        hex::decode("a448f24c6d18e575453db13171562b71999873db5b286df957af199ec94617f7").unwrap();

    let enr = text.parse::<Enr<k256::ecdsa::SigningKey>>().unwrap();
    let pubkey = enr.public_key().encode();
    assert_eq!(enr.ip4(), Some(Ipv4Addr::new(127, 0, 0, 1)));
    assert_eq!(enr.ip6(), None);
    assert_eq!(enr.id(), Some(String::from("v4")));
    assert_eq!(enr.udp4(), Some(30303));
    assert_eq!(enr.udp6(), None);
    assert_eq!(enr.tcp4(), None);
    assert_eq!(enr.tcp6(), None);
    assert_eq!(enr.signature(), &signature[..]);
    assert_eq!(pubkey.to_vec(), expected_pubkey);
    assert_eq!(enr.node_id().raw().to_vec(), expected_node_id);

    assert!(enr.verify());
}

// the values in the content are rlp lists
#[test]
fn test_rlp_list_value() {
    let text = "enr:-Je4QH0uN2HkMRmscUp6yvyTOPGtOg9U6lCxBFvCGynyystnDNRJbfz5GhXXY2lcu9tsghMxRiYHoznBwG46GQ7dfm0og2V0aMfGhMvbiDiAgmlkgnY0gmlwhA6hJmuJc2VjcDI1NmsxoQJBP4kg9GNBurV3uVXgR72u1n-XIABibUZLT1WvJLKwvIN0Y3CCdyeDdWRwgncn";
    let signature = hex::decode("7d2e3761e43119ac714a7acafc9338f1ad3a0f54ea50b1045bc21b29f2cacb670cd4496dfcf91a15d763695cbbdb6c821331462607a339c1c06e3a190edd7e6d").unwrap();
    let expected_pubkey =
        hex::decode("02413f8920f46341bab577b955e047bdaed67f972000626d464b4f55af24b2b0bc").unwrap();
    let enr = text.parse::<DefaultEnr>().unwrap();

    assert_eq!(enr.ip4(), Some(Ipv4Addr::new(14, 161, 38, 107)));
    assert_eq!(enr.id(), Some(String::from("v4")));
    assert_eq!(enr.udp4(), Some(30503));
    assert_eq!(enr.tcp4(), Some(30503));
    assert_eq!(enr.seq(), 40);
    assert_eq!(enr.signature(), &signature[..]);
    assert_eq!(enr.public_key().encode().to_vec(), expected_pubkey);

    assert!(enr.verify());
}

#[cfg(feature = "k256")]
#[test]
fn test_read_enr_no_prefix() {
    let text = "-Iu4QM-YJF2RRpMcZkFiWzMf2kRd1A5F1GIekPa4Sfi_v0DCLTDBfOMTMMWJhhawr1YLUPb5008CpnBKrgjY3sstjfgCgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQP8u1uyQFyJYuQUTyA1raXKhSw1HhhxNUQ2VE52LNHWMIN0Y3CCIyiDdWRwgiMo";
    text.parse::<DefaultEnr>().unwrap();
}

#[cfg(feature = "k256")]
#[test]
fn test_read_enr_prefix() {
    let text = "enr:-Iu4QM-YJF2RRpMcZkFiWzMf2kRd1A5F1GIekPa4Sfi_v0DCLTDBfOMTMMWJhhawr1YLUPb5008CpnBKrgjY3sstjfgCgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQP8u1uyQFyJYuQUTyA1raXKhSw1HhhxNUQ2VE52LNHWMIN0Y3CCIyiDdWRwgiMo";
    text.parse::<DefaultEnr>().unwrap();
}

#[cfg(feature = "rust-secp256k1")]
#[test]
fn test_encode_decode_secp256k1() {
    let mut rng = secp256k1::rand::thread_rng();
    let key = secp256k1::SecretKey::new(&mut rng);
    let ip = Ipv4Addr::new(127, 0, 0, 1);
    let tcp = 3000;

    let enr = {
        let mut builder = EnrBuilder::new("v4");
        builder.ip4(ip);
        builder.tcp4(tcp);
        builder.build(&key).unwrap()
    };

    let encoded_enr = rlp::encode(&enr);

    let decoded_enr = rlp::decode::<Enr<secp256k1::SecretKey>>(&encoded_enr).unwrap();

    assert_eq!(decoded_enr.id(), Some("v4".into()));
    assert_eq!(decoded_enr.ip4(), Some(ip));
    assert_eq!(decoded_enr.tcp4(), Some(tcp));
    // Must compare encoding as the public key itself can be different
    assert_eq!(decoded_enr.public_key().encode(), key.public().encode());
    assert!(decoded_enr.verify());
}

#[cfg(feature = "rust-secp256k1")]
#[test]
fn test_secp256k1_sign_ecdsa_with_mock_noncedata() {
    // Uses the example record from the ENR spec.
    //
    // The feature "rust-secp256k1" creates ECDSA signatures with additional random data.
    // Under the unit testing environment, the mock value `MOCK_ECDSA_NONCE_ADDITIONAL_DATA`
    // is always used.
    //
    // The expected ENR textual form `expected_enr_base64` is constructed by a Python script:
    // ```
    // key = SigningKey.from_secret_exponent(
    //     0xb71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291, curve=SECP256k1)
    //
    // # Builds content RLP
    // rlp_data = encode([1, 'id', 'v4', 'ip', 0x7f000001, 'secp256k1', bytes.fromhex(
    //     '03ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd3138'), 'udp', 0x765f])
    // rlp_data_hash = keccak(rlp_data)
    //
    // # Signs the content RLP **with** the additional data.
    // additional_data = bytes.fromhex(
    //     'baaaaaadbaaaaaadbaaaaaadbaaaaaadbaaaaaadbaaaaaadbaaaaaadbaaaaaad')
    // content_signature = key.sign_digest_deterministic(rlp_data_hash, hashfunc=sha256,
    //                                                   sigencode=sigencode_string_canonize,
    //                                                   extra_entropy=additional_data)
    // rlp_with_signature = encode(
    //     [content_signature, 1, 'id', 'v4', 'ip', 0x7f000001, 'secp256k1', bytes.fromhex(
    //         '03ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd3138'), 'udp', 0x765f])
    // textual_form = "enr:" + urlsafe_b64encode(rlp_with_signature).decode('utf-8').rstrip('=')
    // ```
    let expected_enr_base64 = "enr:-IS4QLJYdRwxdy-AbzWC6wL9ooB6O6uvCvJsJ36rbJztiAs1JzPY0__YkgFzZwNUuNhm1BDN6c4-UVRCJP9bXNCmoDYBgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQPKY0yuDUmstAHYpMa2_oxVtw0RW_QAdpzBQA8yWM0xOIN1ZHCCdl8";

    let key_data =
        hex::decode("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291").unwrap();
    let ip = Ipv4Addr::new(127, 0, 0, 1);
    let udp = 30303;

    let key = secp256k1::SecretKey::from_slice(&key_data).unwrap();
    let enr = EnrBuilder::new("v4").ip4(ip).udp4(udp).build(&key).unwrap();
    let enr_base64 = enr.to_base64();
    assert_eq!(enr_base64, expected_enr_base64);

    let enr = enr_base64.parse::<Enr<secp256k1::SecretKey>>().unwrap();
    assert!(enr.verify());
}

#[cfg(feature = "k256")]
#[test]
fn test_encode_decode_k256() {
    let key = k256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
    let ip = Ipv4Addr::new(127, 0, 0, 1);
    let tcp = 3000;

    let enr = {
        let mut builder = EnrBuilder::new("v4");
        builder.ip(ip.into());
        builder.tcp4(tcp);
        builder.build(&key).unwrap()
    };

    let encoded_enr = rlp::encode(&enr);

    let decoded_enr = rlp::decode::<Enr<k256::ecdsa::SigningKey>>(&encoded_enr).unwrap();

    assert_eq!(decoded_enr.id(), Some("v4".into()));
    assert_eq!(decoded_enr.ip4(), Some(ip));
    assert_eq!(decoded_enr.tcp4(), Some(tcp));
    // Must compare encoding as the public key itself can be different
    assert_eq!(decoded_enr.public_key().encode(), key.public().encode());
    decoded_enr.public_key().encode_uncompressed();
    assert!(decoded_enr.verify());
}

#[cfg(all(feature = "ed25519", feature = "k256"))]
#[test]
fn test_encode_decode_ed25519() {
    let mut rng = rand_07::thread_rng();
    let key = ed25519_dalek::Keypair::generate(&mut rng);
    let ip = Ipv4Addr::new(10, 0, 0, 1);
    let tcp = 30303;

    let enr = {
        let mut builder = EnrBuilder::new("v4");
        builder.ip4(ip);
        builder.tcp4(tcp);
        builder.build(&key).unwrap()
    };

    let encoded_enr = rlp::encode(&enr);
    let decoded_enr = rlp::decode::<Enr<CombinedKey>>(&encoded_enr).unwrap();

    assert_eq!(decoded_enr.id(), Some("v4".into()));
    assert_eq!(decoded_enr.ip4(), Some(ip));
    assert_eq!(decoded_enr.tcp4(), Some(tcp));
    assert_eq!(decoded_enr.public_key().encode(), key.public().encode());
    assert!(decoded_enr.verify());
}

#[test]
fn test_add_key() {
    let mut rng = rand::thread_rng();
    let key = k256::ecdsa::SigningKey::random(&mut rng);
    let ip = Ipv4Addr::new(10, 0, 0, 1);
    let tcp = 30303;

    let mut enr = {
        let mut builder = EnrBuilder::new("v4");
        builder.ip(ip.into());
        builder.tcp4(tcp);
        builder.build(&key).unwrap()
    };

    enr.insert("random", &Vec::new(), &key).unwrap();
    assert!(enr.verify());
}

#[test]
fn test_set_ip() {
    let mut rng = rand::thread_rng();
    let key = k256::ecdsa::SigningKey::random(&mut rng);
    let tcp = 30303;
    let ip = Ipv4Addr::new(10, 0, 0, 1);

    let mut enr = {
        let mut builder = EnrBuilder::new("v4");
        builder.tcp4(tcp);
        builder.build(&key).unwrap()
    };

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

    let mut enr = {
        let mut builder = EnrBuilder::new("v4");
        builder.ip(ip.into());
        builder.tcp4(tcp);
        builder.udp4(udp);
        builder.build(&key).unwrap()
    };

    let node_id = enr.node_id();

    enr.set_udp_socket("192.168.0.1:800".parse::<SocketAddr>().unwrap(), &key)
        .unwrap();
    assert_eq!(node_id, enr.node_id());
    assert_eq!(
        enr.udp4_socket(),
        "192.168.0.1:800".parse::<SocketAddrV4>().unwrap().into()
    );
}

#[cfg(all(feature = "ed25519", feature = "k256"))]
#[test]
fn combined_key_can_decode_all() {
    // generate a random secp256k1 key
    let key = k256::ecdsa::SigningKey::random(&mut rand::thread_rng());
    let ip = Ipv4Addr::new(192, 168, 0, 1);
    let enr_secp256k1 = EnrBuilder::new("v4")
        .ip(ip.into())
        .tcp4(8000)
        .build(&key)
        .unwrap();

    // encode to base64
    let base64_string_secp256k1 = enr_secp256k1.to_base64();

    // generate a random ed25519 key
    let key = ed25519_dalek::Keypair::generate(&mut rand_07::thread_rng());
    let enr_ed25519 = EnrBuilder::new("v4")
        .ip(ip.into())
        .tcp4(8000)
        .build(&key)
        .unwrap();

    // encode to base64
    let base64_string_ed25519 = enr_ed25519.to_base64();

    // decode base64 strings of varying key types
    // decode the secp256k1 with default Enr
    let _decoded_enr_secp256k1: DefaultEnr = base64_string_secp256k1.parse().unwrap();
    // decode ed25519 ENRs
    let _decoded_enr_ed25519: Enr<ed25519_dalek::Keypair> = base64_string_ed25519.parse().unwrap();

    // use the combined key to be able to decode either
    let _decoded_enr: Enr<CombinedKey> = base64_string_secp256k1
        .parse()
        .expect("Can decode both secp");
    let _decoded_enr: Enr<CombinedKey> = base64_string_ed25519.parse().unwrap();
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

    let mut enr = {
        let mut builder = EnrBuilder::new("v4");
        builder.tcp4(tcp);
        builder.build(&key).unwrap()
    };

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
    assert_eq!(enr.get("topics"), Some(topics));

    // Compare the encoding as the key itself can be different
    assert_eq!(enr.public_key().encode(), key.public().encode());
}
