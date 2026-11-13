use super::*;
use crate::{
    config::{Interface, ListenerConfig, Peer, PeerTransport},
    crypto::{pk_to_bytes, random_sk, sk_to_bytes},
};
use tokio::{sync::mpsc, time::timeout};

fn config(local_sk: crate::Key, remote_pk: crate::Key, endpoint: SocketAddr) -> Config {
    Config {
        dev_name: String::new(),
        interface: Interface {
            addresses: vec![],
            mtu: 1460,
            private_key: local_sk.into(),
            listener: ListenerConfig::Udp {
                udp: UdpListenerConfig { port: 0 },
            },
        },
        peers: vec![Peer {
            peer_id: Uuid::new_v4(),
            public_key: remote_pk.into(),
            pre_shared_key: Some([7; 32].into()),
            allowed_ips: vec![],
            transport: PeerTransport::Udp {
                udp: UdpTransportPeerConfig {
                    endpoint: Some(endpoint),
                },
            },
        }],
    }
}

async fn receive(listener: &mut UdpListener) -> (Packet, SocketAddr) {
    timeout(Duration::from_secs(3), listener.framed.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
}

#[tokio::test]
async fn background_task_retries_peers_with_known_endpoints() {
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let local_key = random_sk().unwrap();
    let remote_key = random_sk().unwrap();
    let mut config = config(
        sk_to_bytes(&local_key),
        pk_to_bytes(&remote_key.compute_public_key().unwrap()),
        socket.local_addr().unwrap(),
    );
    let known_peer = config.peers[0].peer_id;
    let mut unknown = config.peers[0].clone();
    unknown.peer_id = Uuid::new_v4();
    unknown.transport = PeerTransport::Udp {
        udp: UdpTransportPeerConfig { endpoint: None },
    };
    config.peers.push(unknown);
    let (tx, _rx) = mpsc::channel(4);
    let state = Arc::new(State::new(tx));
    let config = Arc::new(config);
    let _listener = create_udp_listener(&state, &config, &UdpListenerConfig { port: 0 })
        .await
        .unwrap();
    let mut receiver = UdpListener {
        framed: UdpFramed::new(socket, Codec::new(PacketLayout::default())),
        peer_addresses: Arc::new(DashMap::new()),
    };
    let (packet, _) = receive(&mut receiver).await;
    let Packet::Initiating(initiation) = packet else {
        panic!("expected startup initiation")
    };
    assert_eq!(state.initiated.len(), 1);
    assert_eq!(
        state.initiated.get(&initiation.sender_idx).unwrap().peer_id,
        known_peer
    );
    pre_reply(
        &sk_to_bytes(&remote_key),
        initiation.enc_pub_key,
        initiation.ephemeral,
        initiation.enc_ts,
    )
    .unwrap();
    // No response: the background task must retry without any TUN traffic.
    let (packet, _) = timeout(Duration::from_secs(7), receiver.framed.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let Packet::Initiating(retry) = packet else {
        panic!("expected handshake retry")
    };
    assert_ne!(retry.sender_idx, initiation.sender_idx);
    assert_eq!(state.initiated.len(), 2);
    assert!(
        state
            .initiated
            .iter()
            .all(|entry| entry.peer_id == known_peer)
    );
}

#[tokio::test]
async fn handshake_and_bidirectional_data_use_local_and_remote_indexes() {
    let socket_a = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let socket_b = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let key_a = random_sk().unwrap();
    let key_b = random_sk().unwrap();
    let config_a = config(
        sk_to_bytes(&key_a),
        pk_to_bytes(&key_b.compute_public_key().unwrap()),
        socket_b.local_addr().unwrap(),
    );
    let config_b = config(
        sk_to_bytes(&key_b),
        pk_to_bytes(&key_a.compute_public_key().unwrap()),
        socket_a.local_addr().unwrap(),
    );
    let peer_a = config_a.peers[0].peer_id;
    let peer_b = config_b.peers[0].peer_id;
    let (tx_a, mut rx_a) = mpsc::channel(4);
    let (tx_b, mut rx_b) = mpsc::channel(4);
    let state_a = Arc::new(State::new(tx_a));
    let state_b = Arc::new(State::new(tx_b));
    let mut a = UdpListener {
        framed: UdpFramed::new(socket_a, Codec::new(PacketLayout::default())),
        peer_addresses: Arc::new(
            [(peer_a, socket_b.local_addr().unwrap())]
                .into_iter()
                .collect(),
        ),
    };
    let mut b = UdpListener {
        framed: UdpFramed::new(socket_b, Codec::new(PacketLayout::default())),
        peer_addresses: Arc::new(DashMap::new()),
    };

    // Queue traffic on both sides before their sessions exist.
    a.transmit(&state_a, &config_a, peer_a, b"queued first")
        .await
        .unwrap();
    state_a
        .queued
        .entry(peer_a)
        .or_default()
        .push_back(b"queued second".to_vec());
    b.transmit(&state_b, &config_b, peer_b, b"queued first")
        .await
        .unwrap();
    b.transmit(&state_b, &config_b, peer_b, b"queued second")
        .await
        .unwrap();
    let unrelated_peer = Uuid::new_v4();
    state_a
        .queued
        .entry(unrelated_peer)
        .or_default()
        .push_back(b"unrelated".to_vec());
    let (packet, from) = receive(&mut b).await;
    let Packet::Initiating(ref initiation) = packet else {
        panic!("expected initiation")
    };
    let local_a = initiation.sender_idx;
    assert!(state_a.initiated.contains_key(&local_a));
    process_incoming(
        &state_b,
        &mut b.framed,
        &config_b,
        &b.peer_addresses,
        packet,
        from,
    )
    .await
    .unwrap();
    let (packet, from) = receive(&mut a).await;
    let Packet::Reply(ref reply) = packet else {
        panic!("expected reply")
    };
    let local_b = reply.sender_idx;
    assert_eq!(reply.receiver_idx, local_a);
    process_incoming(
        &state_a,
        &mut a.framed,
        &config_a,
        &a.peer_addresses,
        packet,
        from,
    )
    .await
    .unwrap();
    assert!(state_a.initiated.is_empty());
    assert_eq!(state_a.peering.get(&peer_a).unwrap().index, local_a);
    assert_eq!(state_b.peering.get(&peer_b).unwrap().index, local_b);
    assert_eq!(
        state_a.established.get(&local_a).unwrap().receiver_idx,
        local_b
    );
    assert_eq!(
        state_b.established.get(&local_b).unwrap().receiver_idx,
        local_a
    );

    assert!(!state_a.queued.contains_key(&peer_a));
    assert!(!state_b.queued.contains_key(&peer_b));
    assert_eq!(state_a.queued.get(&unrelated_peer).unwrap().len(), 1);
    for expected in [b"queued first".as_slice(), b"queued second".as_slice()] {
        let (packet, from) = receive(&mut b).await;
        process_incoming(
            &state_b,
            &mut b.framed,
            &config_b,
            &b.peer_addresses,
            packet,
            from,
        )
        .await
        .unwrap();
        assert_eq!(rx_b.try_recv().unwrap(), expected);
        let (packet, from) = receive(&mut a).await;
        process_incoming(
            &state_a,
            &mut a.framed,
            &config_a,
            &a.peer_addresses,
            packet,
            from,
        )
        .await
        .unwrap();
        assert_eq!(rx_a.try_recv().unwrap(), expected);
    }

    a.transmit(&state_a, &config_a, peer_a, b"hello")
        .await
        .unwrap();
    let (packet, from) = receive(&mut b).await;
    assert!(matches!(packet, Packet::Data { receiver_idx, .. } if receiver_idx == local_b));
    process_incoming(
        &state_b,
        &mut b.framed,
        &config_b,
        &b.peer_addresses,
        packet,
        from,
    )
    .await
    .unwrap();
    assert_eq!(
        timeout(Duration::from_secs(3), rx_b.recv())
            .await
            .unwrap()
            .unwrap(),
        b"hello"
    );

    assert_eq!(*b.peer_addresses.get(&peer_b).unwrap(), from);
    b.transmit(&state_b, &config_b, peer_b, b"reply")
        .await
        .unwrap();
    let (packet, from) = receive(&mut a).await;
    assert!(matches!(packet, Packet::Data { receiver_idx, .. } if receiver_idx == local_a));
    process_incoming(
        &state_a,
        &mut a.framed,
        &config_a,
        &a.peer_addresses,
        packet,
        from,
    )
    .await
    .unwrap();
    assert_eq!(
        timeout(Duration::from_secs(3), rx_a.recv())
            .await
            .unwrap()
            .unwrap(),
        b"reply"
    );

    // The periodic check skips both live connections, including learned endpoints.
    initiate_disconnected_peers(&mut a, &state_a, &config_a).await;
    initiate_disconnected_peers(&mut b, &state_b, &config_b).await;
    assert!(state_a.initiated.is_empty());
    assert!(state_b.initiated.is_empty());

    // A missing session is retried even when the peering entry still exists.
    state_a.established.remove(&local_a);
    initiate_disconnected_peers(&mut a, &state_a, &config_a).await;
    let (packet, _) = receive(&mut b).await;
    assert!(matches!(packet, Packet::Initiating(_)));
    assert_eq!(state_a.initiated.len(), 1);

    // Old unanswered attempts do not accumulate indefinitely.
    for mut pending in state_a.initiated.iter_mut() {
        pending.when = std::time::Instant::now() - Duration::from_secs(61);
    }
    initiate_disconnected_peers(&mut a, &state_a, &config_a).await;
    assert_eq!(state_a.initiated.len(), 1);
}

#[tokio::test]
async fn background_task_sends_encrypted_keepalive_with_jitter() {
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let local_key = random_sk().unwrap();
    let remote_key = random_sk().unwrap();
    let config = Arc::new(config(
        sk_to_bytes(&local_key),
        pk_to_bytes(&remote_key.compute_public_key().unwrap()),
        socket.local_addr().unwrap(),
    ));
    let (tx, mut rx) = mpsc::channel(4);
    let state = Arc::new(State::new(tx));
    let started = Instant::now();
    let _listener = create_udp_listener(&state, &config, &UdpListenerConfig { port: 0 })
        .await
        .unwrap();
    let mut remote = UdpListener {
        framed: UdpFramed::new(socket, Codec::new(PacketLayout::default())),
        peer_addresses: Arc::new(DashMap::new()),
    };
    let (packet, from) = receive(&mut remote).await;
    let Packet::Initiating(initiation) = packet else {
        panic!("expected initiation")
    };
    let (remote_pk, _) = pre_reply(
        &sk_to_bytes(&remote_key),
        initiation.enc_pub_key,
        initiation.ephemeral,
        initiation.enc_ts,
    )
    .unwrap();
    let (reply, cipher) =
        post_reply(&remote_pk, Some(&[7; 32]), 123, initiation.sender_idx).unwrap();
    remote
        .framed
        .send((Packet::Reply(reply), from))
        .await
        .unwrap();
    let (packet, _) = timeout(Duration::from_secs(13), remote.framed.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let Packet::Data {
        receiver_idx,
        counter,
        ciphertext,
    } = packet
    else {
        panic!("expected keepalive")
    };
    assert!(started.elapsed() >= Duration::from_secs(8));
    assert_eq!(receiver_idx, 123);
    assert_eq!(counter, 1);
    assert_eq!(ciphertext.len(), 16);
    assert!(cipher.decrypt(counter, ciphertext).unwrap().is_empty());
    assert!(rx.try_recv().is_err());
}
