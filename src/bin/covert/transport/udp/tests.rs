use super::*;
use crate::{
    codec::{Data, DataFlags, PacketLayout},
    config::{Interface, ListenerConfig, Peer},
    crypto,
};
use tokio::time::timeout;

fn public_key(sk: &covert::crypto::Key) -> covert::crypto::Key {
    crypto::pk_to_bytes(&crypto::to_sk(sk).compute_public_key().unwrap())
}

fn config(
    sk: covert::crypto::Key,
    peers: &[(covert::crypto::Key, Option<SocketAddr>)],
) -> Arc<Config> {
    Arc::new(Config {
        dev_name: String::new(),
        layout: PacketLayout::default(),
        interface: Interface {
            hooks: Default::default(),
            liveness: Default::default(),
            addresses: vec![],
            mtu: 1460,
            private_key: sk.into(),
            listener: ListenerConfig::Udp {
                udp: UdpListenerConfig { port: 0 },
            },
        },
        peers: peers
            .iter()
            .map(|(key, address)| Peer {
                liveness: Default::default(),
                id: Uuid::new_v4(),
                public_key: (*key).into(),
                pre_shared_key: Some([7; 32].into()),
                allowed_ips: vec![],
                transport: PeerTransport::Udp {
                    udp: UdpTransportPeerConfig { endpoint: *address },
                },
            })
            .collect(),
    })
}

async fn endpoint(config: &Arc<Config>) -> (UdpEndpoint, Arc<State>, mpsc::Receiver<Vec<u8>>) {
    let (tx, rx) = mpsc::channel(32);
    let state = Arc::new(State::new(tx));
    let endpoint = create_udp_endpoint(&state, config, &UdpListenerConfig { port: 0 })
        .await
        .unwrap();
    (endpoint, state, rx)
}

fn localhost(endpoint: &UdpEndpoint) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, endpoint.local_addr().port()))
}

async fn receive(socket: &UdpSocket, layout: &PacketLayout) -> (Packet, SocketAddr) {
    let mut buf = vec![0; 65535];
    let (len, address) = timeout(Duration::from_secs(3), socket.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let (packet, consumed) = codec::parse_slice(&buf[..len], layout).unwrap().unwrap();
    assert_eq!(consumed, len);
    (packet, address)
}

async fn plaintext(rx: &mut mpsc::Receiver<Vec<u8>>) -> Vec<u8> {
    timeout(Duration::from_secs(3), rx.recv())
        .await
        .unwrap()
        .unwrap()
}

#[tokio::test]
async fn passive_peer_learns_address_and_flushes_queued_bidirectional_data() {
    let server_config = config([2; 32], &[(public_key(&[1; 32]), None)]);
    let (mut server, server_state, mut server_rx) = endpoint(&server_config).await;
    // Queue before the passive peer has learned a destination.
    server
        .trasmit(
            &server_state,
            &server_config,
            server_config.peers[0].id,
            b"queued server",
        )
        .await
        .unwrap();
    let client_config = config([1; 32], &[(public_key(&[2; 32]), Some(localhost(&server)))]);
    let (mut client, client_state, mut client_rx) = endpoint(&client_config).await;
    for message in [b"first".as_slice(), b"second", b"third"] {
        client
            .trasmit(
                &client_state,
                &client_config,
                client_config.peers[0].id,
                message,
            )
            .await
            .unwrap();
    }
    assert_eq!(plaintext(&mut client_rx).await, b"queued server");
    for message in [b"first".as_slice(), b"second", b"third"] {
        assert_eq!(plaintext(&mut server_rx).await, message);
    }
    let snapshot = server_state.status(&server_config);
    assert_eq!(snapshot.peers[0].status, "connected");
    assert_eq!(snapshot.peers[0].sent, 13);
    assert_eq!(snapshot.peers[0].received, 16);
    assert!(snapshot.peers[0].first_established_at.is_some());
}

#[tokio::test]
async fn multiple_passive_peers_are_dispatched_by_identity_and_session_index() {
    let server_config = config(
        [3; 32],
        &[(public_key(&[1; 32]), None), (public_key(&[2; 32]), None)],
    );
    let (mut server, server_state, mut server_rx) = endpoint(&server_config).await;
    for (index, sk) in [[1; 32], [2; 32]].into_iter().enumerate() {
        let client_config = config(sk, &[(public_key(&[3; 32]), Some(localhost(&server)))]);
        let (mut client, client_state, mut client_rx) = endpoint(&client_config).await;
        client
            .trasmit(
                &client_state,
                &client_config,
                client_config.peers[0].id,
                &[index as u8],
            )
            .await
            .unwrap();
        assert_eq!(plaintext(&mut server_rx).await, [index as u8]);
        server
            .trasmit(
                &server_state,
                &server_config,
                server_config.peers[index].id,
                &[10 + index as u8],
            )
            .await
            .unwrap();
        assert_eq!(plaintext(&mut client_rx).await, [10 + index as u8]);
    }
}

#[tokio::test]
async fn malformed_datagrams_do_not_poison_handshake_or_data_and_invalid_data_does_not_move_route()
{
    let remote = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let config = config(
        [1; 32],
        &[(public_key(&[2; 32]), Some(remote.local_addr().unwrap()))],
    );
    let (mut endpoint, state, mut rx) = endpoint(&config).await;
    let (Packet::Initiating(initiation), address) = receive(&remote, &config.layout).await else {
        panic!("expected initiation");
    };
    let (reply, cipher) =
        crypto::post_reply(&public_key(&[1; 32]), Some(&[7; 32]), 123, &initiation).unwrap();
    let valid_reply = Packet::Reply(reply).to_bytes(&config.layout).unwrap();
    for bytes in [
        vec![],
        vec![253],
        valid_reply[..10].to_vec(),
        [valid_reply.as_ref(), b"trailing"].concat(),
    ] {
        remote.send_to(&bytes, address).await.unwrap();
    }
    remote.send_to(&valid_reply, address).await.unwrap();
    let (counter, ciphertext) = cipher.encrypt(b"authenticated".to_vec()).unwrap();
    let data = Packet::Data(Data {
        receiver_idx: initiation.sender_idx,
        flags: DataFlags::empty(),
        counter,
        ciphertext,
    })
    .to_bytes(&config.layout)
    .unwrap();
    remote.send_to(&data, address).await.unwrap();
    assert_eq!(plaintext(&mut rx).await, b"authenticated");

    let attacker = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let forged = Packet::Data(Data {
        receiver_idx: initiation.sender_idx,
        flags: DataFlags::JUNK,
        counter: 99,
        ciphertext: vec![0; 16],
    })
    .to_bytes(&config.layout)
    .unwrap();
    attacker.send_to(&forged, address).await.unwrap();
    // A subsequent authenticated frame acts as a barrier for processing traffic.
    let (counter, ciphertext) = cipher.encrypt(b"still connected".to_vec()).unwrap();
    let data = Packet::Data(Data {
        receiver_idx: initiation.sender_idx,
        flags: DataFlags::empty(),
        counter,
        ciphertext,
    })
    .to_bytes(&config.layout)
    .unwrap();
    remote.send_to(&data, address).await.unwrap();
    assert_eq!(plaintext(&mut rx).await, b"still connected");
    endpoint
        .trasmit(&state, &config, config.peers[0].id, b"reply")
        .await
        .unwrap();
    let (Packet::Data(data), _) = receive(&remote, &config.layout).await else {
        panic!("expected data");
    };
    assert_eq!(
        cipher.decrypt(data.counter, data.ciphertext).unwrap(),
        b"reply"
    );
    assert_eq!(state.status(&config).peers[0].received, 28);
}

#[tokio::test]
async fn authenticated_data_can_move_peer_to_a_new_udp_address() {
    let original = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let config = config(
        [1; 32],
        &[(public_key(&[2; 32]), Some(original.local_addr().unwrap()))],
    );
    let (mut endpoint, state, mut rx) = endpoint(&config).await;
    let (Packet::Initiating(initiation), address) = receive(&original, &config.layout).await else {
        panic!("expected initiation");
    };
    let (reply, cipher) =
        crypto::post_reply(&public_key(&[1; 32]), Some(&[7; 32]), 123, &initiation).unwrap();
    original
        .send_to(
            &Packet::Reply(reply).to_bytes(&config.layout).unwrap(),
            address,
        )
        .await
        .unwrap();
    let moved = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let (counter, ciphertext) = cipher.encrypt(b"moved".to_vec()).unwrap();
    let data = Packet::Data(Data {
        receiver_idx: initiation.sender_idx,
        flags: DataFlags::empty(),
        counter,
        ciphertext,
    })
    .to_bytes(&config.layout)
    .unwrap();
    moved.send_to(&data, address).await.unwrap();
    assert_eq!(plaintext(&mut rx).await, b"moved");
    endpoint
        .trasmit(&state, &config, config.peers[0].id, b"new route")
        .await
        .unwrap();
    let (Packet::Data(data), _) = receive(&moved, &config.layout).await else {
        panic!("expected data");
    };
    assert_eq!(
        cipher.decrypt(data.counter, data.ciphertext).unwrap(),
        b"new route"
    );
}

#[tokio::test]
async fn closing_tun_stops_udp_worker_and_plaintext_sender() {
    let config = config([1; 32], &[(public_key(&[2; 32]), None)]);
    let (mut endpoint, state, rx) = endpoint(&config).await;
    drop(rx);
    timeout(Duration::from_secs(3), endpoint.sender.closed())
        .await
        .unwrap();
    assert!(matches!(
        endpoint
            .trasmit(&state, &config, config.peers[0].id, b"closed")
            .await,
        Err(crate::error::Error::EndpointStopped { transport: "UDP" })
    ));
    assert_eq!(state.status(&config).peers[0].status, "disconnected");
}

#[tokio::test]
async fn background_retry_recovers_lost_reply_and_keepalives_do_not_reach_tun() {
    let remote = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let mut config = config(
        [1; 32],
        &[(public_key(&[2; 32]), Some(remote.local_addr().unwrap()))],
    );
    let options = &mut Arc::get_mut(&mut config).unwrap().interface.liveness;
    options.keepalive = Some(1);
    options.keepalive_jitter = Some(0);
    let (_endpoint, state, mut rx) = endpoint(&config).await;
    let (Packet::Initiating(first), address) = receive(&remote, &config.layout).await else {
        panic!("expected initial handshake");
    };
    // The peer accepts the first request, but its reply is lost. With no TUN
    // traffic, the adapter's timer must eventually send a fresh initiation.
    let (lost_reply, _) =
        crypto::post_reply(&public_key(&[1; 32]), Some(&[7; 32]), 123, &first).unwrap();
    let (Packet::Initiating(retry), retry_address) = timeout(Duration::from_secs(12), async {
        let mut buf = vec![0; 65535];
        let (len, from) = remote.recv_from(&mut buf).await.unwrap();
        (
            codec::parse_slice(&buf[..len], &config.layout)
                .unwrap()
                .unwrap()
                .0,
            from,
        )
    })
    .await
    .unwrap() else {
        panic!("expected retry");
    };
    assert_eq!(retry_address, address);
    assert_ne!(retry.ephemeral, first.ephemeral);
    let (_, first_timestamp) = crypto::pre_reply(&[2; 32], &first).unwrap();
    let (_, retry_timestamp) = crypto::pre_reply(&[2; 32], &retry).unwrap();
    assert!(retry_timestamp > first_timestamp);
    remote
        .send_to(
            &Packet::Reply(lost_reply).to_bytes(&config.layout).unwrap(),
            address,
        )
        .await
        .unwrap();
    let (reply, cipher) =
        crypto::post_reply(&public_key(&[1; 32]), Some(&[7; 32]), 124, &retry).unwrap();
    remote
        .send_to(
            &Packet::Reply(reply).to_bytes(&config.layout).unwrap(),
            address,
        )
        .await
        .unwrap();
    let (Packet::Data(keepalive), _) = receive(&remote, &config.layout).await else {
        panic!("expected keepalive");
    };
    assert_eq!(keepalive.receiver_idx, 124);
    assert!(keepalive.flags.contains(DataFlags::JUNK));
    assert!(
        cipher
            .decrypt(keepalive.counter, keepalive.ciphertext)
            .unwrap()
            .is_empty()
    );
    assert!(rx.try_recv().is_err());
    let snapshot = state.status(&config);
    assert_eq!(snapshot.peers[0].status, "connected");
    assert_eq!(snapshot.peers[0].sent, 0);
    assert_eq!(snapshot.peers[0].received, 0);
}

#[tokio::test]
async fn padded_layout_preserves_large_datagrams_and_rejects_unknown_peers() {
    let layout = PacketLayout {
        mask: 0x12345678,
        oip: 200,
        orp: 180,
        odp: 100,
        ..PacketLayout::default()
    };
    let mut server_config = config([2; 32], &[(public_key(&[1; 32]), None)]);
    Arc::get_mut(&mut server_config).unwrap().layout = layout;
    let (mut server, server_state, mut server_rx) = endpoint(&server_config).await;
    let stranger = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let initiation = crypto::initiate(&[4; 32], &public_key(&[2; 32]), 1, 42).unwrap();
    stranger
        .send_to(
            &Packet::Initiating(initiation).to_bytes(&layout).unwrap(),
            localhost(&server),
        )
        .await
        .unwrap();
    let mut client_config = config([1; 32], &[(public_key(&[2; 32]), Some(localhost(&server)))]);
    Arc::get_mut(&mut client_config).unwrap().layout = layout;
    let (mut client, client_state, mut client_rx) = endpoint(&client_config).await;
    let large = vec![42; 60000];
    client
        .trasmit(
            &client_state,
            &client_config,
            client_config.peers[0].id,
            &large,
        )
        .await
        .unwrap();
    assert_eq!(plaintext(&mut server_rx).await, large);
    // A failed oversized send must not terminate the worker or block the next packet.
    server
        .trasmit(
            &server_state,
            &server_config,
            server_config.peers[0].id,
            &vec![0; 65536],
        )
        .await
        .unwrap();
    server
        .trasmit(
            &server_state,
            &server_config,
            server_config.peers[0].id,
            b"small",
        )
        .await
        .unwrap();
    assert_eq!(plaintext(&mut client_rx).await, b"small");
    assert_eq!(server_state.status(&server_config).peers[0].sent, 5);
    assert!(
        timeout(Duration::from_millis(30), stranger.recv_from(&mut [0; 512]))
            .await
            .is_err()
    );
}
