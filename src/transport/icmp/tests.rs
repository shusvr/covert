use super::*;
use crate::codec::PacketLayout;

#[tokio::test]
#[ignore = "requires an isolated network namespace with CAP_NET_RAW, CAP_NET_ADMIN and nft"]
async fn raw_receive_processes_data_suppresses_kernel_reply_and_cleans_up() {
    use crate::{
        codec::{Data, DataFlags},
        config::{Interface, ListenerConfig},
        crypto::Cipher,
    };
    use tokio::time::{Duration, timeout};
    let listener = IcmpListenerConfig {
        id: 1339,
        mode: IcmpMode::EchoReply,
    };
    let config = Arc::new(Config {
        dev_name: String::new(),
        layout: PacketLayout::default(),
        interface: Interface {
            hooks: Default::default(),
            liveness: Default::default(),
            addresses: vec![],
            mtu: 1400,
            private_key: [7; 32].into(),
            listener: ListenerConfig::Icmp {
                icmp: listener.clone(),
            },
        },
        peers: vec![],
    });
    let (tx, mut rx) = tokio::sync::mpsc::channel(4);
    let state = Arc::new(State::new(tx));
    let key = |role| {
        Cipher::new(
            aws_lc_rs::aead::LessSafeKey::new(
                aws_lc_rs::aead::UnboundKey::new(&aws_lc_rs::aead::CHACHA20_POLY1305, &[9; 32])
                    .unwrap(),
            ),
            role,
        )
    };
    let remote = key(true);
    state.established.insert(
        42,
        crate::transport::PeerHandle::new(
            uuid::Uuid::new_v4(),
            7,
            key(false),
            0,
            config
                .interface
                .liveness
                .unpack_with_fallback(&Default::default()),
        ),
    );
    let endpoint = create_icmp_endpoint(&state, &config, &listener)
        .await
        .unwrap();
    let peer_id = state.established.get(&42).unwrap().peer_id;
    endpoint.routing.insert(
        peer_id,
        IcmpRoute::response(Ipv4Addr::LOCALHOST, listener.id, 1),
    );
    let raw = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)).unwrap();
    raw.set_nonblocking(true).unwrap();
    let raw = unsafe {
        AsyncFd::register(raw)
            .map_err(|err| err.into_parts().1)
            .unwrap()
    };
    let (counter, ciphertext) = remote.encrypt(b"ICMP tunnel data".to_vec()).unwrap();
    let mut packet = BytesMut::new();
    codec::append(
        &mut packet,
        Packet::Data(Data {
            receiver_idx: 42,
            counter,
            ciphertext,
            flags: DataFlags::empty(),
        }),
        &PacketLayout::default(),
    )
    .unwrap();
    let header = etherparse::Icmpv4Header::with_checksum(
        etherparse::Icmpv4Type::EchoRequest(etherparse::IcmpEchoHeader {
            id: listener.id,
            seq: 1,
        }),
        &packet,
    );
    let mut wire = header.to_bytes().to_vec();
    wire.extend_from_slice(&packet);
    raw.get_ref()
        .send_to(&wire, &SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0).into())
        .unwrap();
    assert_eq!(
        timeout(Duration::from_secs(3), rx.recv())
            .await
            .unwrap()
            .unwrap(),
        b"ICMP tunnel data"
    );
    // The observer sees the request, but the kernel's automatic reply must be dropped.
    let mut buffer = [MaybeUninit::<u8>::uninit(); 65535];
    let len = raw
        .async_io(tokio::io::Interest::READABLE, |s| s.recv(&mut buffer))
        .await
        .unwrap();
    let received = unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), len) };
    assert_eq!(received[(received[0] as usize & 15) * 4], 8);
    assert!(
        timeout(
            Duration::from_millis(100),
            raw.async_io(tokio::io::Interest::READABLE, |s| s.recv(&mut buffer))
        )
        .await
        .is_err()
    );
    drop(rx);
    drop(endpoint);
    for _ in 0..100 {
        let out = Command::new("nft")
            .args(["list", "tables"])
            .output()
            .unwrap();
        if !String::from_utf8_lossy(&out.stdout).contains("covert_icmp_") {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("ICMP firewall table was not cleaned up");
}

#[test]
fn filters_echo_identifier_checksum_and_ipv4_options() {
    for ty in [false, true] {
        let echo = etherparse::IcmpEchoHeader { id: 1339, seq: 7 };
        let kind = if ty {
            etherparse::Icmpv4Type::EchoReply(echo)
        } else {
            etherparse::Icmpv4Type::EchoRequest(echo)
        };
        let payload = b"odd-length!";
        let header = etherparse::Icmpv4Header::with_checksum(kind, payload);
        let mut bytes = vec![0_u8; 24];
        bytes[0] = 0x46;
        bytes[9] = 1;
        bytes[12..16].copy_from_slice(&[192, 0, 2, 1]);
        bytes.extend_from_slice(&header.to_bytes());
        bytes.extend_from_slice(payload);
        let len = bytes.len() as u16;
        bytes[2..4].copy_from_slice(&len.to_be_bytes());
        assert_eq!(
            echo_payload(&bytes, 1339, IcmpMode::EchoReply),
            Some((Ipv4Addr::new(192, 0, 2, 1), &payload[..]))
        );
        assert!(echo_payload(&bytes, 1340, IcmpMode::EchoReply).is_none());
        for end in 0..bytes.len() {
            assert!(echo_payload(&bytes[..end], 1339, IcmpMode::EchoReply).is_none());
        }
        bytes[6] = 0x20;
        assert!(echo_payload(&bytes, 1339, IcmpMode::EchoReply).is_none());
        bytes[6] = 0;
        *bytes.last_mut().unwrap() ^= 1;
        assert!(echo_payload(&bytes, 1339, IcmpMode::EchoReply).is_none());
    }
}

#[test]
fn initiator_requests_increment_and_responder_replies_echo_query_metadata() {
    let request = IcmpRoute::request(Ipv4Addr::LOCALHOST);
    let reply = IcmpRoute::response(Ipv4Addr::LOCALHOST, 5555, 321);
    let queued = reply.clone();
    let mut sequence = 7;
    assert_eq!(
        request.echo_type(false, 5555, &mut sequence),
        etherparse::Icmpv4Type::EchoRequest(etherparse::IcmpEchoHeader { id: 5555, seq: 7 })
    );
    assert_eq!(
        request.echo_type(false, 5555, &mut sequence),
        etherparse::Icmpv4Type::EchoRequest(etherparse::IcmpEchoHeader { id: 5555, seq: 8 })
    );
    assert_eq!(
        reply.echo_type(false, 5555, &mut sequence),
        etherparse::Icmpv4Type::EchoReply(etherparse::IcmpEchoHeader { id: 5555, seq: 321 })
    );
    assert_eq!(sequence, 9);
    reply
        .reply
        .as_ref()
        .unwrap()
        .store((5555 << 16) | 322, Ordering::Relaxed);
    assert_eq!(
        queued.echo_type(false, 5555, &mut sequence),
        etherparse::Icmpv4Type::EchoReply(etherparse::IcmpEchoHeader { id: 5555, seq: 322 })
    );
    assert!(matches!(
        reply.echo_type(true, 5555, &mut sequence),
        etherparse::Icmpv4Type::EchoRequest(_)
    ));
}

#[tokio::test]
#[ignore = "requires an isolated network namespace with CAP_NET_RAW, CAP_NET_ADMIN and nft"]
async fn request_reply_handshake_and_bidirectional_data() {
    for mode in [IcmpMode::EchoReply, IcmpMode::OnlyEcho] {
        use crate::{
            config::{Interface, ListenerConfig, Peer, PeerTransport},
            crypto::{pk_to_bytes, random_sk, sk_to_bytes},
        };
        use tokio::time::{Duration, timeout};
        let a = random_sk().unwrap();
        let b = random_sk().unwrap();
        let make_config = |sk, pk, endpoint| {
            Arc::new(Config {
                dev_name: String::new(),
                layout: PacketLayout::default(),
                interface: Interface {
                    hooks: Default::default(),
                    liveness: Default::default(),
                    addresses: vec![],
                    mtu: 1400,
                    private_key: sk,
                    listener: ListenerConfig::Icmp {
                        icmp: IcmpListenerConfig { id: 5555, mode },
                    },
                },
                peers: vec![Peer {
                    liveness: Default::default(),
                    id: uuid::Uuid::new_v4(),
                    public_key: pk,
                    pre_shared_key: None,
                    allowed_ips: vec![],
                    transport: PeerTransport::Icmp {
                        icmp: IcmpTransportPeerConfig { endpoint },
                    },
                }],
            })
        };
        let a_config = make_config(
            sk_to_bytes(&a).into(),
            pk_to_bytes(&b.compute_public_key().unwrap()).into(),
            Some(Ipv4Addr::LOCALHOST),
        );
        let b_config = make_config(
            sk_to_bytes(&b).into(),
            pk_to_bytes(&a.compute_public_key().unwrap()).into(),
            None,
        );
        let (a_tx, mut a_rx) = tokio::sync::mpsc::channel(4);
        let (b_tx, mut b_rx) = tokio::sync::mpsc::channel(4);
        let a_state = Arc::new(State::new(a_tx));
        let b_state = Arc::new(State::new(b_tx));
        let listener = IcmpListenerConfig { id: 5555, mode };
        let mut a_endpoint = create_icmp_endpoint(&a_state, &a_config, &listener)
            .await
            .unwrap();
        let mut b_endpoint = create_icmp_endpoint(&b_state, &b_config, &listener)
            .await
            .unwrap();
        timeout(Duration::from_secs(3), async {
            while !a_state.has_live_connection(a_config.peers[0].id)
                || !b_state.has_live_connection(b_config.peers[0].id)
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert!(
            a_endpoint
                .routing
                .get(&a_config.peers[0].id)
                .unwrap()
                .reply
                .is_none()
        );
        assert!(
            b_endpoint
                .routing
                .get(&b_config.peers[0].id)
                .unwrap()
                .reply
                .is_some()
                == (mode == IcmpMode::EchoReply)
        );
        a_endpoint
            .trasmit(
                &a_state,
                &a_config,
                a_config.peers[0].id,
                b"request data",
            )
            .await
            .unwrap();
        assert_eq!(
            timeout(Duration::from_secs(3), b_rx.recv())
                .await
                .unwrap()
                .unwrap(),
            b"request data"
        );
        b_endpoint
            .trasmit(
                &b_state,
                &b_config,
                b_config.peers[0].id,
                b"reply data",
            )
            .await
            .unwrap();
        assert_eq!(
            timeout(Duration::from_secs(3), a_rx.recv())
                .await
                .unwrap()
                .unwrap(),
            b"reply data"
        );
        drop(a_rx);
        drop(b_rx);
        drop(a_endpoint);
        drop(b_endpoint);
        let mut cleaned = false;
        for _ in 0..100 {
            let out = Command::new("nft")
                .args(["list", "tables"])
                .output()
                .unwrap();
            if !String::from_utf8_lossy(&out.stdout).contains("covert_icmp_") {
                cleaned = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(cleaned, "firewall cleanup timed out");
    }
}
