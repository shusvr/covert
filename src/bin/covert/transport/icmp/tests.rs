use super::*;
use crate::codec::PacketLayout;

#[tokio::test]
#[ignore = "requires an isolated network namespace with CAP_NET_RAW, CAP_NET_ADMIN and nft"]
async fn raw_socket_suppresses_kernel_reply_and_cleans_up() {
    use tokio::time::timeout;
    let listener = IcmpListenerConfig {
        id: 1339,
        mode: IcmpMode::EchoReply,
    };
    let config = config([1; 32], public_key(&[2; 32]), None, &listener);
    let (tx, rx) = mpsc::channel(4);
    let state = Arc::new(State::new(tx));
    let endpoint = create_icmp_endpoint(&state, &config, &listener)
        .await
        .unwrap();
    let raw = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)).unwrap();
    raw.set_nonblocking(true).unwrap();
    let raw = unsafe {
        AsyncFd::register(raw)
            .map_err(|err| err.into_parts().1)
            .unwrap()
    };
    let payload = b"kernel probe";
    let header = etherparse::Icmpv4Header::with_checksum(
        etherparse::Icmpv4Type::EchoRequest(etherparse::IcmpEchoHeader {
            id: listener.id,
            seq: 1,
        }),
        payload,
    );
    let mut wire = header.to_bytes().to_vec();
    wire.extend_from_slice(payload);
    raw.get_ref()
        .send_to(&wire, &SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0).into())
        .unwrap();
    let mut buffer = vec![MaybeUninit::<u8>::uninit(); 65535];
    let len = timeout(
        Duration::from_secs(3),
        raw.async_io(tokio::io::Interest::READABLE, |s| s.recv(&mut buffer)),
    )
    .await
    .unwrap()
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
    wait_for_firewall_cleanup().await;
}

async fn wait_for_firewall_cleanup() {
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
    panic!("ICMP firewall cleanup timed out");
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
    let mut reply = IcmpRoute::response(Ipv4Addr::LOCALHOST, 5555, 321);
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
    reply.reply = Some(etherparse::IcmpEchoHeader { id: 5555, seq: 322 });
    assert_eq!(
        reply.echo_type(false, 5555, &mut sequence),
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
        a_endpoint
            .trasmit(&a_state, &a_config, a_config.peers[0].id, b"request data")
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
            .trasmit(&b_state, &b_config, b_config.peers[0].id, b"reply data")
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
        wait_for_firewall_cleanup().await;
    }
}

fn public_key(sk: &covert::crypto::Key) -> covert::crypto::Key {
    crate::crypto::pk_to_bytes(&crate::crypto::to_sk(sk).compute_public_key().unwrap())
}

fn config(
    sk: covert::crypto::Key,
    pk: covert::crypto::Key,
    endpoint: Option<Ipv4Addr>,
    listener: &IcmpListenerConfig,
) -> Arc<Config> {
    use crate::config::{Interface, ListenerConfig, Peer, PeerTransport};
    Arc::new(Config {
        dev_name: String::new(),
        layout: PacketLayout::default(),
        interface: Interface {
            hooks: Default::default(),
            liveness: Default::default(),
            addresses: vec![],
            mtu: 1400,
            private_key: sk.into(),
            listener: ListenerConfig::Icmp {
                icmp: listener.clone(),
            },
        },
        peers: vec![Peer {
            liveness: Default::default(),
            id: Uuid::new_v4(),
            public_key: pk.into(),
            pre_shared_key: Some([7; 32].into()),
            allowed_ips: vec![],
            transport: PeerTransport::Icmp {
                icmp: IcmpTransportPeerConfig { endpoint },
            },
        }],
    })
}

// Exercise the actual ICMP framing, dispatch and TUN delivery without requiring
// a raw socket or changing the host firewall.
struct Node {
    config: Arc<Config>,
    state: State,
    rx: mpsc::Receiver<Vec<u8>>,
    peers: HashMap<Uuid, PeerTunnel<IcmpRoute>>,
    encoder: EchoEncoder,
    listener: IcmpListenerConfig,
    source: Ipv4Addr,
}

impl Node {
    fn new(
        sk: covert::crypto::Key,
        pk: covert::crypto::Key,
        source: Ipv4Addr,
        remote: Option<Ipv4Addr>,
        mode: IcmpMode,
    ) -> Self {
        let listener = IcmpListenerConfig { id: 5555, mode };
        let config = config(sk, pk, remote, &listener);
        let (tx, rx) = mpsc::channel(16);
        let state = State::new(tx);
        let id = config.peers[0].id;
        let peer =
            PeerTunnel::new(&config, &config.peers[0], remote.map(IcmpRoute::request)).unwrap();
        let peers = HashMap::from([(id, peer)]);
        let encoder = EchoEncoder::new(config.layout, &listener);
        Self {
            config,
            state,
            rx,
            peers,
            encoder,
            listener,
            source,
        }
    }

    fn id(&self) -> Uuid {
        self.config.peers[0].id
    }
    fn peer(&mut self) -> &mut PeerTunnel<IcmpRoute> {
        self.peers.get_mut(&self.config.peers[0].id).unwrap()
    }

    fn advance(&mut self) {
        let id = self.id();
        self.peers
            .get_mut(&id)
            .unwrap()
            .advance(id, &self.state)
            .unwrap();
    }

    fn outgoing(&mut self) -> Vec<u8> {
        let peer = self.peers.get_mut(&self.config.peers[0].id).unwrap();
        let packet = peer.tunnel.read_outbound_packet().unwrap();
        let route = peer.address.as_ref().unwrap();
        let icmp = self.encoder.encode(packet, route).unwrap();
        let mut wire = etherparse::Ipv4Header::new(
            icmp.len() as u16,
            64,
            etherparse::IpNumber::ICMP,
            self.source.octets(),
            route.address.octets(),
        )
        .unwrap()
        .to_bytes()
        .to_vec();
        wire.extend_from_slice(icmp);
        wire
    }

    async fn receive(&mut self, wire: &[u8]) -> Result<Option<Uuid>> {
        let id = process_echo(
            &self.config,
            &mut self.peers,
            &self.state,
            wire,
            &self.listener,
        )?;
        if let Some(id) = id {
            self.peers
                .get_mut(&id)
                .unwrap()
                .deliver(id, &self.state)
                .await?;
        }
        Ok(id)
    }
}

async fn connected_pair(mode: IcmpMode) -> (Node, Node) {
    let a_ip = Ipv4Addr::new(192, 0, 2, 1);
    let b_ip = Ipv4Addr::new(192, 0, 2, 2);
    let mut a = Node::new([1; 32], public_key(&[2; 32]), a_ip, Some(b_ip), mode);
    let mut b = Node::new([2; 32], public_key(&[1; 32]), b_ip, None, mode);
    a.advance();
    let initiation = a.outgoing();
    assert_eq!(initiation[20], 8);
    assert!(b.receive(&initiation).await.unwrap().is_some());
    let reply = b.outgoing();
    assert_eq!(reply[20], if mode == IcmpMode::EchoReply { 0 } else { 8 });
    if mode == IcmpMode::EchoReply {
        assert_eq!(&reply[24..28], &initiation[24..28]);
    }
    assert!(a.receive(&reply).await.unwrap().is_some());
    assert!(a.peer().tunnel.is_live());
    assert!(b.peer().tunnel.is_live());
    (a, b)
}

#[tokio::test]
async fn sans_handshake_bidirectional_data_and_rekey_in_both_echo_modes() {
    for mode in [IcmpMode::EchoReply, IcmpMode::OnlyEcho] {
        let (mut a, mut b) = connected_pair(mode).await;
        a.peer().tunnel.push_packet(b"request data");
        a.advance();
        let request = a.outgoing();
        assert_eq!(request[20], 8);
        b.receive(&request).await.unwrap();
        assert_eq!(b.rx.try_recv().unwrap(), b"request data");
        b.peer().tunnel.push_packet(b"reply data");
        b.advance();
        let reply = b.outgoing();
        assert_eq!(reply[20], if mode == IcmpMode::EchoReply { 0 } else { 8 });
        if mode == IcmpMode::EchoReply {
            assert_eq!(&reply[24..28], &request[24..28]);
        }
        a.receive(&reply).await.unwrap();
        assert_eq!(a.rx.try_recv().unwrap(), b"reply data");
        assert_eq!(b.state.status(&b.config).peers[0].received, 12);
        assert_eq!(a.state.status(&a.config).peers[0].status, "connected");

        // A former responder must send a fresh initiation as an Echo Request,
        // then switch roles once the new session is established.
        b.peer().tunnel.initiate().unwrap();
        b.advance();
        let initiation = b.outgoing();
        assert_eq!(initiation[20], 8);
        a.receive(&initiation).await.unwrap();
        b.receive(&a.outgoing()).await.unwrap();
        b.peer().tunnel.push_packet(b"rekeyed");
        b.advance();
        a.receive(&b.outgoing()).await.unwrap();
        assert_eq!(a.rx.try_recv().unwrap(), b"rekeyed");
    }
}

fn recalculate_checksum(wire: &mut [u8]) {
    let (header, payload) = etherparse::Icmpv4Header::from_slice(&wire[20..]).unwrap();
    let header = etherparse::Icmpv4Header::with_checksum(header.icmp_type, payload);
    wire[20..28].copy_from_slice(&header.to_bytes());
}

#[tokio::test]
async fn invalid_data_does_not_change_session_route_or_reply_metadata() {
    for mode in [IcmpMode::EchoReply, IcmpMode::OnlyEcho] {
        let (mut a, mut b) = connected_pair(mode).await;
        a.peer().tunnel.push_packet(b"authenticated");
        a.advance();
        let valid = a.outgoing();
        let before = b.peer().address.clone().unwrap();
        let established = b.peer().tunnel.established_at();
        let mut wrong_source = valid.clone();
        wrong_source[15] ^= 1;
        assert!(b.receive(&wrong_source).await.unwrap().is_none());
        let mut wrong_id = valid.clone();
        wrong_id[24] ^= 1;
        recalculate_checksum(&mut wrong_id);
        assert!(b.receive(&wrong_id).await.unwrap().is_none());
        let mut trailing = valid.clone();
        trailing.push(0);
        let len = trailing.len() as u16;
        trailing[2..4].copy_from_slice(&len.to_be_bytes());
        recalculate_checksum(&mut trailing);
        assert!(b.receive(&trailing).await.unwrap().is_none());
        let mut tampered = valid.clone();
        tampered[26..28].copy_from_slice(&999u16.to_be_bytes());
        *tampered.last_mut().unwrap() ^= 1;
        recalculate_checksum(&mut tampered);
        assert!(b.receive(&tampered).await.is_err());
        assert_eq!(b.peer().tunnel.established_at(), established);
        let after = b.peer().address.as_ref().unwrap();
        assert_eq!(after.address, before.address);
        assert_eq!(after.reply, before.reply);
        assert!(b.rx.try_recv().is_err());
        assert_eq!(b.state.status(&b.config).peers[0].received, 0);
        b.receive(&valid).await.unwrap();
        assert_eq!(b.rx.try_recv().unwrap(), b"authenticated");
    }
}

#[tokio::test]
async fn passive_icmp_flushes_queued_data_after_reply_and_ignores_unknown_identity() {
    let a_ip = Ipv4Addr::new(192, 0, 2, 1);
    let b_ip = Ipv4Addr::new(192, 0, 2, 2);
    let mode = IcmpMode::EchoReply;
    let mut b = Node::new([2; 32], public_key(&[1; 32]), b_ip, None, mode);
    b.peer().tunnel.push_packet(b"queued");
    b.advance();
    assert!(b.peer().tunnel.read_outbound_packet().is_none());
    let mut unknown = Node::new([4; 32], public_key(&[2; 32]), a_ip, Some(b_ip), mode);
    unknown.advance();
    assert!(b.receive(&unknown.outgoing()).await.unwrap().is_none());
    assert!(!b.peer().tunnel.is_live());
    let mut a = Node::new([1; 32], public_key(&[2; 32]), a_ip, Some(b_ip), mode);
    a.advance();
    b.receive(&a.outgoing()).await.unwrap();
    let reply = b.outgoing();
    assert!(matches!(
        codec::parse_slice(&reply[28..], &b.config.layout),
        Some(Ok((Packet::Reply(_), _)))
    ));
    a.receive(&reply).await.unwrap();
    a.receive(&b.outgoing()).await.unwrap();
    assert_eq!(a.rx.try_recv().unwrap(), b"queued");
}

#[tokio::test]
async fn simultaneous_icmp_initiations_converge_in_both_modes() {
    let mut keys = [[1; 32], [2; 32]];
    keys.sort_by_key(public_key);
    let a_ip = Ipv4Addr::new(192, 0, 2, 1);
    let b_ip = Ipv4Addr::new(192, 0, 2, 2);
    for mode in [IcmpMode::EchoReply, IcmpMode::OnlyEcho] {
        let mut a = Node::new(keys[0], public_key(&keys[1]), a_ip, Some(b_ip), mode);
        let mut b = Node::new(keys[1], public_key(&keys[0]), b_ip, Some(a_ip), mode);
        a.advance();
        b.advance();
        let request = a.outgoing();
        let competing = b.outgoing();
        a.receive(&competing).await.unwrap();
        b.receive(&request).await.unwrap();
        a.receive(&b.outgoing()).await.unwrap();
        a.peer().tunnel.push_packet(b"winning initiation");
        a.advance();
        b.receive(&a.outgoing()).await.unwrap();
        assert_eq!(b.rx.try_recv().unwrap(), b"winning initiation");
        b.peer().tunnel.push_packet(b"responder");
        b.advance();
        a.receive(&b.outgoing()).await.unwrap();
        assert_eq!(a.rx.try_recv().unwrap(), b"responder");
    }
}

#[tokio::test]
async fn closed_channels_return_concrete_errors() {
    let (mut a, mut b) = connected_pair(IcmpMode::EchoReply).await;
    let (sender, receiver) = mpsc::channel(1);
    drop(receiver);
    let mut endpoint = IcmpEndpoint { sender };
    assert!(matches!(
        endpoint
            .trasmit(&b.state, &b.config, b.id(), b"closed")
            .await,
        Err(crate::error::Error::EndpointStopped { transport: "ICMP" })
    ));
    b.rx.close();
    a.peer().tunnel.push_packet(b"closed TUN");
    a.advance();
    assert!(matches!(
        b.receive(&a.outgoing()).await,
        Err(crate::error::Error::TunReceiverClosed)
    ));
}
