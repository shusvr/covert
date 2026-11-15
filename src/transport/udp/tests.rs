use super::*;
use crate::codec::{Packet, PacketLayout};
use crate::transport::{initiate_disconnected_peers, process_packet};
use crate::{
    config::{Interface, ListenerConfig, Peer, PeerTransport},
    crypto::{finish, pk_to_bytes, post_reply, pre_reply, random_sk, sk_to_bytes},
    transport::{PeerHandle, transmit},
};
use futures::SinkExt;
use std::time::{Duration, Instant};
type UdpListener = Endpoint<UdpPacketSender, UdpRoute>;
use tokio::{sync::mpsc, time::timeout};

fn config(local_sk: crate::Key, remote_pk: crate::Key, endpoint: SocketAddr) -> Config {
    Config {
        dev_name: String::new(),
        layout: PacketLayout::default(),
        interface: Interface {
            hooks: Default::default(),
            liveness: Default::default(),
            addresses: vec![],
            mtu: 1460,
            private_key: local_sk.into(),
            listener: ListenerConfig::Udp {
                udp: UdpListenerConfig { port: 0 },
            },
        },
        peers: vec![Peer {
            liveness: Default::default(),
            id: Uuid::new_v4(),
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
    timeout(Duration::from_secs(3), listener.sender.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
}

fn default_liveness() -> crate::config::Liveness {
    crate::config::LivenessOptions::default().unpack_with_fallback(&Default::default())
}

fn session_ciphers() -> (crate::crypto::Cipher, crate::crypto::Cipher) {
    let initiator = random_sk().unwrap();
    let (reply, responder) = post_reply(
        &pk_to_bytes(&initiator.compute_public_key().unwrap()),
        None,
        0,
        0,
    )
    .unwrap();
    let initiator = finish(&sk_to_bytes(&initiator), None, reply.eph).unwrap();
    (initiator, responder)
}

#[tokio::test]
async fn generic_send_only_sink_registers_handshake_and_rolls_back_on_failure() {
    for fail_send in [false, true] {
        let local_key = random_sk().unwrap();
        let remote_key = random_sk().unwrap();
        let config = config(
            sk_to_bytes(&local_key),
            pk_to_bytes(&remote_key.compute_public_key().unwrap()),
            "127.0.0.1:1234".parse().unwrap(),
        );
        let peer_id = config.peers[0].id;
        let (tx, _rx) = mpsc::channel(4);
        let state = Arc::new(State::new(tx));
        let routing: DashMap<_, _> = [(peer_id, String::from("test-route"))]
            .into_iter()
            .collect();
        let observed_state = state.clone();
        let remote_sk = sk_to_bytes(&remote_key);
        // This sink deliberately has no Stream implementation or socket address.
        let mut sender = Box::pin(futures::sink::unfold(
            (),
            move |(), (packet, route): (Packet, String)| {
                let state = observed_state.clone();
                async move {
                    assert_eq!(route, "test-route");
                    let Packet::Initiating(initiation) = packet else {
                        panic!("expected a handshake initiation");
                    };
                    // A synchronous reply must be able to find this pending session.
                    assert!(state.initiated.contains_key(&initiation.sender_idx));
                    pre_reply(
                        &remote_sk,
                        initiation.enc_pub_key,
                        initiation.ephemeral,
                        initiation.enc_ts,
                    )
                    .unwrap();
                    if fail_send {
                        Err(crate::codec::Error::from(std::io::Error::other(
                            "send failed",
                        )))
                    } else {
                        Ok(())
                    }
                }
            },
        ));
        let result =
            crate::transport::initiate(&state, &config, &routing, &mut sender, peer_id).await;
        assert_eq!(result.is_err(), fail_send);
        assert_eq!(state.initiated.len(), usize::from(!fail_send));
    }
}

#[test]
fn keepalive_refreshes_idle_timeout_but_not_session_lifetime() {
    let (cipher, _) = session_ciphers();
    let liveness = default_liveness();
    let mut session = PeerHandle::new(Uuid::new_v4(), 0, cipher, 0, liveness);
    assert!(session.is_live());

    session.since = std::time::Instant::now() - Duration::from_secs(liveness.timeout / 2);
    session.keep_alive();
    // Beyond the original idle deadline, but still within the refreshed deadline.
    session.since -= Duration::from_secs(liveness.timeout / 2 + 1);
    assert!(session.is_live());
    session.since -= Duration::from_secs(liveness.timeout / 2);
    assert!(!session.is_live());

    session.since = std::time::Instant::now() - Duration::from_secs(liveness.max_age - 1);
    session.keep_alive();
    assert!(session.is_live());
    session.since -= Duration::from_secs(2);
    // Only two seconds idle: expiration must come from max_age, not timeout.
    assert!(!session.is_live());
}

#[test]
fn zero_expiry_limits_are_independent_and_keepalives_remain_enabled() {
    for (timeout, max_age, age, expected) in [
        (0, 0, 3600, true),
        (0, 300, 100, true),
        (0, 300, 301, false),
        (28, 0, 15, true),
        (28, 0, 29, false),
    ] {
        let (cipher, _) = session_ciphers();
        let liveness = crate::config::Liveness {
            timeout,
            max_age,
            ..default_liveness()
        };
        let mut session = PeerHandle::new(Uuid::new_v4(), 0, cipher, 0, liveness);
        session.since = std::time::Instant::now() - Duration::from_secs(age);
        assert_eq!(
            session.is_live(),
            expected,
            "timeout={timeout}, max_age={max_age}, age={age}"
        );
        assert!(
            session
                .next_keepalive_ms
                .load(std::sync::atomic::Ordering::Relaxed)
                > 0
        );
        if timeout > 0 && max_age == 0 {
            // Refreshing activity still revives idle state without an age limit.
            session.keep_alive();
            session.since -= Duration::from_secs(3600);
            session.keep_alive();
            assert!(session.is_live());
        }
    }
}

#[tokio::test]
async fn expired_session_queues_traffic_and_reinitiates() {
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let remote = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let local_key = random_sk().unwrap();
    let remote_key = random_sk().unwrap();
    let config = config(
        sk_to_bytes(&local_key),
        pk_to_bytes(&remote_key.compute_public_key().unwrap()),
        remote.local_addr().unwrap(),
    );
    let peer_id = config.peers[0].id;
    let (tx, _rx) = mpsc::channel(4);
    let state = State::new(tx);
    let (cipher, _) = session_ciphers();
    let mut session = PeerHandle::new(peer_id, 2, cipher, 0, default_liveness());
    session.since = std::time::Instant::now() - Duration::from_secs(default_liveness().timeout + 1);
    state.established.insert(1, session);
    state.peering.insert(peer_id, 1);
    let mut listener = UdpListener {
        sender: UdpFramed::new(socket, Codec::new(PacketLayout::default())),
        routing: Arc::new(
            [(peer_id, remote.local_addr().unwrap())]
                .into_iter()
                .collect(),
        ),
    };

    timeout(
        Duration::from_secs(3),
        transmit(
            &state,
            &config,
            &listener.routing,
            &mut listener.sender,
            peer_id,
            b"queued after expiry",
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(!state.established.contains_key(&1));
    assert!(!state.has_live_connection(peer_id));
    assert_eq!(
        state.queued.get_mut(&peer_id).unwrap().pop_front().unwrap(),
        b"queued after expiry"
    );
    let mut remote = UdpFramed::new(remote, Codec::new(PacketLayout::default()));
    let (packet, _) = timeout(Duration::from_secs(3), remote.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(matches!(packet, Packet::Initiating(_)));
}

#[tokio::test]
async fn received_keepalive_refreshes_session_and_invalid_data_removes_it() {
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let local_key = random_sk().unwrap();
    let remote_key = random_sk().unwrap();
    let from = socket.local_addr().unwrap();
    let config = config(
        sk_to_bytes(&local_key),
        pk_to_bytes(&remote_key.compute_public_key().unwrap()),
        from,
    );
    let peer_id = config.peers[0].id;
    let (tx, mut rx) = mpsc::channel(4);
    let state = Arc::new(State::new(tx));
    let (sender, receiver) = session_ciphers();
    let mut session = PeerHandle::new(peer_id, 2, receiver, 0, default_liveness());
    session.since = std::time::Instant::now() - Duration::from_secs(default_liveness().timeout / 2);
    state.established.insert(1, session);
    state.peering.insert(peer_id, 1);
    let mut framed = UdpFramed::new(socket, Codec::new(PacketLayout::default()));
    let addresses = DashMap::new();
    let (counter, ciphertext) = sender.encrypt(vec![]).unwrap();
    process_packet(
        &state,
        &config,
        Packet::Data(crate::codec::Data {
            receiver_idx: 1,
            counter,
            ciphertext,
            flags: crate::codec::DataFlags::empty(),
        }),
        from,
        &addresses,
        &mut framed,
    )
    .await
    .unwrap();
    assert!(rx.try_recv().is_err());
    state.established.get_mut(&1).unwrap().since -=
        Duration::from_secs(default_liveness().timeout / 2 + 1);
    assert!(state.has_live_connection(peer_id));

    // Authenticated application data also refreshes liveness and suppresses keepalives.
    let (counter, ciphertext) = sender.encrypt(b"active peer".to_vec()).unwrap();
    state
        .established
        .get(&1)
        .unwrap()
        .next_keepalive_ms
        .store(0, std::sync::atomic::Ordering::Relaxed);
    process_packet(
        &state,
        &config,
        Packet::Data(crate::codec::Data {
            receiver_idx: 1,
            counter,
            ciphertext,
            flags: crate::codec::DataFlags::empty(),
        }),
        from,
        &addresses,
        &mut framed,
    )
    .await
    .unwrap();
    assert_eq!(rx.try_recv().unwrap(), b"active peer");
    addresses.insert(peer_id, from);
    crate::transport::send_keepalives(&state, &config, &addresses, &mut framed).await;
    assert!(
        timeout(Duration::from_millis(50), framed.next())
            .await
            .is_err()
    );
    // Once that peer's deadline expires, its keepalives resume.
    state
        .established
        .get(&1)
        .unwrap()
        .next_keepalive_ms
        .store(0, std::sync::atomic::Ordering::Relaxed);
    crate::transport::send_keepalives(&state, &config, &addresses, &mut framed).await;
    let (packet, _) = timeout(Duration::from_secs(3), framed.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(
        matches!(packet, Packet::Data(data) if data.flags.contains(crate::codec::DataFlags::JUNK))
    );

    let (counter, mut ciphertext) = sender.encrypt(b"tampered".to_vec()).unwrap();
    ciphertext[0] ^= 1;
    timeout(
        Duration::from_secs(3),
        process_packet(
            &state,
            &config,
            Packet::Data(crate::codec::Data {
                receiver_idx: 1,
                counter,
                ciphertext,
                flags: crate::codec::DataFlags::empty(),
            }),
            from,
            &addresses,
            &mut framed,
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(!state.established.contains_key(&1));
    assert!(!state.has_live_connection(peer_id));
    assert!(rx.try_recv().is_err());
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
    let known_peer = config.peers[0].id;
    let mut unknown = config.peers[0].clone();
    unknown.id = Uuid::new_v4();
    unknown.transport = PeerTransport::Udp {
        udp: UdpTransportPeerConfig { endpoint: None },
    };
    config.peers.push(unknown);
    let (tx, _rx) = mpsc::channel(4);
    let state = Arc::new(State::new(tx));
    let config = Arc::new(config);
    let _listener = create_udp_endpoint(&state, &config, &UdpListenerConfig { port: 0 })
        .await
        .unwrap();
    let mut receiver = UdpListener {
        sender: UdpFramed::new(socket, Codec::new(PacketLayout::default())),
        routing: Arc::new(DashMap::new()),
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
    let (packet, _) = timeout(Duration::from_secs(7), receiver.sender.next())
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
    let peer_a = config_a.peers[0].id;
    let peer_b = config_b.peers[0].id;
    let (tx_a, mut rx_a) = mpsc::channel(4);
    let (tx_b, mut rx_b) = mpsc::channel(4);
    let state_a = Arc::new(State::new(tx_a));
    let state_b = Arc::new(State::new(tx_b));
    let mut a = UdpListener {
        sender: UdpFramed::new(socket_a, Codec::new(PacketLayout::default())),
        routing: Arc::new(
            [(peer_a, socket_b.local_addr().unwrap())]
                .into_iter()
                .collect(),
        ),
    };
    let mut b = UdpListener {
        sender: UdpFramed::new(socket_b, Codec::new(PacketLayout::default())),
        routing: Arc::new(DashMap::new()),
    };

    // Queue traffic on both sides before their sessions exist.
    transmit(
        &state_a,
        &config_a,
        &a.routing,
        &mut a.sender,
        peer_a,
        b"queued first",
    )
    .await
    .unwrap();
    state_a
        .queued
        .entry(peer_a)
        .or_default()
        .push_back(b"queued second".to_vec());
    transmit(
        &state_b,
        &config_b,
        &b.routing,
        &mut b.sender,
        peer_b,
        b"queued first",
    )
    .await
    .unwrap();
    transmit(
        &state_b,
        &config_b,
        &b.routing,
        &mut b.sender,
        peer_b,
        b"queued second",
    )
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
    process_packet(&state_b, &config_b, packet, from, &b.routing, &mut b.sender)
        .await
        .unwrap();
    let (packet, from) = receive(&mut a).await;
    let Packet::Reply(ref reply) = packet else {
        panic!("expected reply")
    };
    let local_b = reply.sender_idx;
    assert_eq!(reply.receiver_idx, local_a);
    process_packet(&state_a, &config_a, packet, from, &a.routing, &mut a.sender)
        .await
        .unwrap();
    assert!(state_a.initiated.is_empty());
    assert_eq!(*state_a.peering.get(&peer_a).unwrap().value(), local_a);
    assert_eq!(*state_b.peering.get(&peer_b).unwrap().value(), local_b);
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
        process_packet(&state_b, &config_b, packet, from, &b.routing, &mut b.sender)
            .await
            .unwrap();
        assert_eq!(rx_b.try_recv().unwrap(), expected);
        let (packet, from) = receive(&mut a).await;
        process_packet(&state_a, &config_a, packet, from, &a.routing, &mut a.sender)
            .await
            .unwrap();
        assert_eq!(rx_a.try_recv().unwrap(), expected);
    }

    transmit(
        &state_a,
        &config_a,
        &a.routing,
        &mut a.sender,
        peer_a,
        b"hello",
    )
    .await
    .unwrap();
    let (packet, from) = receive(&mut b).await;
    assert!(
        matches!(packet, Packet::Data(crate::codec::Data { receiver_idx, .. }) if receiver_idx == local_b)
    );
    process_packet(&state_b, &config_b, packet, from, &b.routing, &mut b.sender)
        .await
        .unwrap();
    assert_eq!(
        timeout(Duration::from_secs(3), rx_b.recv())
            .await
            .unwrap()
            .unwrap(),
        b"hello"
    );

    assert_eq!(*b.routing.get(&peer_b).unwrap(), from);
    transmit(
        &state_b,
        &config_b,
        &b.routing,
        &mut b.sender,
        peer_b,
        b"reply",
    )
    .await
    .unwrap();
    let (packet, from) = receive(&mut a).await;
    assert!(
        matches!(packet, Packet::Data(crate::codec::Data { receiver_idx, .. }) if receiver_idx == local_a)
    );
    process_packet(&state_a, &config_a, packet, from, &a.routing, &mut a.sender)
        .await
        .unwrap();
    assert_eq!(
        timeout(Duration::from_secs(3), rx_a.recv())
            .await
            .unwrap()
            .unwrap(),
        b"reply"
    );

    for (state, config) in [(&state_a, &config_a), (&state_b, &config_b)] {
        let snapshot = state.status(config);
        let peer = &snapshot.peers[0];
        assert_eq!(peer.status, "connected");
        assert_eq!(peer.sent, 30); // queued first + queued second + hello/reply
        assert_eq!(peer.received, 30);
        assert!(peer.first_established_at.is_some());
        assert_eq!(peer.first_established_at, peer.last_established_at);
    }

    // The periodic check skips both live connections, including learned endpoints.
    initiate_disconnected_peers(&state_a, &config_a, &a.routing, &mut a.sender).await;
    initiate_disconnected_peers(&state_b, &config_b, &b.routing, &mut b.sender).await;
    assert!(state_a.initiated.is_empty());
    assert!(state_b.initiated.is_empty());

    // A missing session is retried even when the peering entry still exists.
    state_a.established.remove(&local_a);
    assert_eq!(state_a.status(&config_a).peers[0].status, "disconnected");
    assert_eq!(state_a.status(&config_a).peers[0].sent, 30);
    initiate_disconnected_peers(&state_a, &config_a, &a.routing, &mut a.sender).await;
    let (packet, _) = receive(&mut b).await;
    assert!(matches!(packet, Packet::Initiating(_)));
    assert_eq!(state_a.initiated.len(), 1);

    // Old unanswered attempts do not accumulate indefinitely.
    for mut pending in state_a.initiated.iter_mut() {
        pending.when = std::time::Instant::now() - Duration::from_secs(61);
    }
    initiate_disconnected_peers(&state_a, &config_a, &a.routing, &mut a.sender).await;
    assert_eq!(state_a.initiated.len(), 1);
}

#[tokio::test]
async fn background_task_recovers_from_invalid_datagrams_and_sends_keepalive() {
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
    let _listener = create_udp_endpoint(&state, &config, &UdpListenerConfig { port: 0 })
        .await
        .unwrap();
    let mut remote = UdpListener {
        sender: UdpFramed::new(socket, Codec::new(PacketLayout::default())),
        routing: Arc::new(DashMap::new()),
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
    // Both an unknown type and a truncated handshake must be discarded, allowing
    // the subsequent valid reply to establish a session and timers to keep running.
    for malformed in [&[][..], &[253_u8][..], &[0_u8, 1][..]] {
        remote
            .sender
            .get_ref()
            .send_to(malformed, from)
            .await
            .unwrap();
    }
    remote
        .sender
        .send((Packet::Reply(reply), from))
        .await
        .unwrap();
    let (packet, _) = timeout(Duration::from_secs(14), remote.sender.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let Packet::Data(crate::codec::Data {
        receiver_idx,
        counter,
        ciphertext,
        ..
    }) = packet
    else {
        panic!("expected keepalive")
    };
    // Default Keepalive=10 and KeepaliveJitter=3 permit 7..13 seconds.
    assert!(started.elapsed() >= Duration::from_secs(7));
    assert_eq!(receiver_idx, 123);
    assert_eq!(counter, 1);
    assert_eq!(ciphertext.len(), 16);
    assert!(cipher.decrypt(counter, ciphertext).unwrap().is_empty());
    assert!(rx.try_recv().is_err());
}

#[tokio::test]
async fn maintenance_initiates_without_a_socket_and_stops_when_tun_closes() {
    let local = random_sk().unwrap();
    let remote = random_sk().unwrap();
    let config = Arc::new(config(
        sk_to_bytes(&local),
        pk_to_bytes(&remote.compute_public_key().unwrap()),
        "127.0.0.1:1234".parse().unwrap(),
    ));
    let peer_id = config.peers[0].id;
    let (tun_tx, tun_rx) = mpsc::channel(1);
    let state = Arc::new(State::new(tun_tx));
    let routing = Arc::new(
        [(peer_id, String::from("test-route"))]
            .into_iter()
            .collect(),
    );
    let (sent_tx, mut sent_rx) = mpsc::unbounded_channel();
    let sender = Box::pin(futures::sink::unfold((), move |(), packet| {
        let sent_tx = sent_tx.clone();
        async move {
            sent_tx.send(packet).unwrap();
            Ok::<_, crate::codec::Error>(())
        }
    }));
    let task = tokio::spawn(crate::transport::maintain_peers(
        state, config, routing, sender,
    ));
    let (packet, route) = timeout(Duration::from_secs(3), sent_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(packet, Packet::Initiating(_)));
    assert_eq!(route, "test-route");
    drop(tun_rx);
    timeout(Duration::from_secs(3), task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn batch_sender_preserves_datagrams_destinations_order_and_layout() {
    use crate::codec::{Data, DataFlags};
    let left = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let right = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addresses = [left.local_addr().unwrap(), right.local_addr().unwrap()];
    let socket = Arc::new(UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap());
    let layout = PacketLayout {
        mask: 0x12345678,
        odp: 80,
        ..PacketLayout::default()
    };
    let (mut sender, recv) = futures::channel::mpsc::channel(512);
    // Prequeue more than two batches plus a partial tail before starting the worker.
    let count = BATCH_SIZE * 2 + 7;
    for index in 0..count {
        sender
            .send((
                Packet::Data(Data {
                    receiver_idx: index as u32,
                    counter: index as u64,
                    flags: DataFlags::empty(),
                    ciphertext: vec![index as u8; index % 20],
                }),
                addresses[index % 2],
            ))
            .await
            .unwrap();
    }
    drop(sender);
    let worker = tokio::spawn(sender_task(socket.clone(), layout, recv));
    let socket_source = socket.local_addr().unwrap();
    let check = |socket: UdpSocket, parity: usize| async move {
        let mut framed = UdpFramed::new(socket, Codec::new(layout));
        for index in (parity..count).step_by(2) {
            let (packet, source) = timeout(Duration::from_secs(3), framed.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert_eq!(source, socket_source);
            let Packet::Data(data) = packet else {
                panic!("expected data");
            };
            assert_eq!(data.receiver_idx, index as u32);
            assert_eq!(data.counter, index as u64);
            assert_eq!(data.ciphertext, vec![index as u8; index % 20]);
        }
    };
    tokio::join!(check(left, 0), check(right, 1));
    timeout(Duration::from_secs(3), worker)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn batch_sender_keeps_unsent_tail_after_partial_send_and_bad_packet() {
    use crate::codec::{Data, DataFlags};
    let receiver = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let destination = receiver.local_addr().unwrap();
    let socket = Arc::new(UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap());
    let (mut sender, recv) = futures::channel::mpsc::channel(8);
    for (counter, size) in [(1, 8), (2, 65536), (3, 9)] {
        sender
            .send((
                Packet::Data(Data {
                    receiver_idx: 7,
                    counter,
                    flags: DataFlags::empty(),
                    ciphertext: vec![42; size],
                }),
                destination,
            ))
            .await
            .unwrap();
    }
    drop(sender);
    let worker = tokio::spawn(sender_task(socket, PacketLayout::default(), recv));
    let mut framed = UdpFramed::new(receiver, Codec::new(PacketLayout::default()));
    for expected in [1, 3] {
        let (packet, _) = timeout(Duration::from_secs(3), framed.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let Packet::Data(data) = packet else {
            panic!("expected data");
        };
        assert_eq!(data.counter, expected);
    }
    timeout(Duration::from_secs(3), worker)
        .await
        .unwrap()
        .unwrap();
    assert!(
        timeout(Duration::from_millis(30), framed.next())
            .await
            .is_err(),
        "a successful datagram was resent"
    );
}

#[tokio::test]
async fn batch_receiver_preserves_boundaries_sources_and_partial_tail() {
    use crate::codec::{Data, DataFlags};
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let destination = socket.local_addr().unwrap();
    let senders = [
        UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap(),
        UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap(),
    ];
    let sources = [
        senders[0].local_addr().unwrap(),
        senders[1].local_addr().unwrap(),
    ];
    let layout = PacketLayout {
        mask: 0x12345678,
        odp: 80,
        ..PacketLayout::default()
    };
    for bytes in [&[][..], &[253][..], &[0, 1][..]] {
        senders[0].send_to(bytes, destination).await.unwrap();
    }
    let count = BATCH_SIZE * 2 + 7;
    for index in 0..count {
        let mut bytes = BytesMut::new();
        crate::codec::append(
            &mut bytes,
            Packet::Data(Data {
                receiver_idx: index as u32,
                counter: index as u64,
                flags: DataFlags::empty(),
                ciphertext: vec![index as u8; index % 20],
            }),
            &layout,
        )
        .unwrap();
        senders[index % 2]
            .send_to(&bytes, destination)
            .await
            .unwrap();
    }
    let mut batch: Vec<_> = (0..BATCH_SIZE).map(|_| ReceivedDatagram::new()).collect();
    let mut received = 0;
    while received < count + 3 {
        let n = timeout(
            Duration::from_secs(3),
            socket.async_io(tokio::io::Interest::READABLE, || {
                try_receive_batch(&socket, &mut batch)
            }),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(n > 0 && n <= BATCH_SIZE);
        #[cfg(target_os = "linux")]
        if received == 0 {
            assert_eq!(n, BATCH_SIZE);
        }
        for packet in &batch[..n] {
            assert!(!packet.truncated);
            let decoded = crate::codec::parse_slice(&packet.bytes[..packet.len], &layout);
            if received < 3 {
                assert!(!matches!(decoded, Some(Ok(_))));
            } else {
                let index = received - 3;
                assert_eq!(packet.address, sources[index % 2]);
                let Some(Ok((Packet::Data(data), consumed))) = decoded else {
                    panic!("expected data");
                };
                assert_eq!(consumed, packet.len);
                assert_eq!(data.receiver_idx, index as u32);
                assert_eq!(data.counter, index as u64);
                assert_eq!(data.ciphertext, vec![index as u8; index % 20]);
            }
            received += 1;
        }
    }
    assert_eq!(
        try_receive_batch(&socket, &mut batch).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[tokio::test]
async fn batch_receiver_reports_truncation_and_reuses_buffers_for_large_and_small_packets() {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let mut batch = vec![ReceivedDatagram::new()];
    batch[0].bytes.truncate(128);
    for size in [512, 65507, 5, 0] {
        let bytes = vec![42; size];
        sender
            .send_to(&bytes, socket.local_addr().unwrap())
            .await
            .unwrap();
        let n = timeout(
            Duration::from_secs(3),
            socket.async_io(tokio::io::Interest::READABLE, || {
                try_receive_batch(&socket, &mut batch)
            }),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(n, 1);
        assert_eq!(batch[0].address, sender.local_addr().unwrap());
        assert_eq!(batch[0].truncated, size == 512);
        assert_eq!(batch[0].len, size.min(batch[0].bytes.len()));
        assert_eq!(&batch[0].bytes[..batch[0].len], &bytes[..batch[0].len]);
        batch[0].bytes.resize(MAX_DATAGRAM_SIZE, 0);
    }
}

#[tokio::test]
async fn peer_statistics_survive_rekeys_and_exclude_failed_sends_and_invalid_packets() {
    use crate::codec::{Data, DataFlags};
    let address: SocketAddr = "127.0.0.1:12345".parse().unwrap();
    let key = random_sk().unwrap();
    let config = config(
        sk_to_bytes(&key),
        pk_to_bytes(&key.compute_public_key().unwrap()),
        address,
    );
    let id = config.peers[0].id;
    let (tx, mut rx) = mpsc::channel(4);
    let state = Arc::new(State::new(tx));
    let snapshot = state.status(&config);
    assert_eq!(snapshot.peers[0].status, "disconnected");
    assert!(snapshot.peers[0].first_established_at.is_none());
    let (remote, local) = session_ciphers();
    let mut handle = PeerHandle::new(id, 2, local, 0, default_liveness());
    state.register_statistics(&mut handle);
    state.established.insert(1, handle);
    state.peering.insert(id, 1);
    let routes = DashMap::new();
    routes.insert(id, address);
    let mut successful = futures::sink::unfold((), |(), _: (Packet, SocketAddr)| {
        futures::future::ready(Ok::<_, crate::codec::Error>(()))
    });
    transmit(&state, &config, &routes, &mut successful, id, b"hello")
        .await
        .unwrap();
    let mut failing = futures::sink::unfold((), |(), _: (Packet, SocketAddr)| {
        futures::future::ready(Err::<(), _>(crate::codec::Error::Io(
            std::io::Error::other("test failure"),
        )))
    });
    assert!(
        transmit(&state, &config, &routes, &mut failing, id, b"not counted")
            .await
            .is_err()
    );
    for (bytes, flags) in [
        (b"reply".to_vec(), DataFlags::empty()),
        (vec![], DataFlags::JUNK),
        (b"junk".to_vec(), DataFlags::JUNK),
    ] {
        let (counter, ciphertext) = remote.encrypt(bytes).unwrap();
        process_packet(
            &state,
            &config,
            Packet::Data(Data {
                receiver_idx: 1,
                counter,
                ciphertext,
                flags,
            }),
            address,
            &routes,
            &mut successful,
        )
        .await
        .unwrap();
    }
    assert_eq!(rx.try_recv().unwrap(), b"reply");
    assert!(rx.try_recv().is_err());
    let before = state.status(&config);
    assert_eq!(before.peers[0].sent, 5);
    assert_eq!(before.peers[0].received, 5);
    process_packet(
        &state,
        &config,
        Packet::Data(Data {
            receiver_idx: 1,
            counter: 99,
            ciphertext: vec![0; 32],
            flags: DataFlags::empty(),
        }),
        address,
        &routes,
        &mut successful,
    )
    .await
    .unwrap();
    assert_eq!(state.status(&config).peers[0].status, "disconnected");
    let (_, cipher) = session_ciphers();
    let mut rekey = PeerHandle::new(id, 3, cipher, 1, default_liveness());
    state.register_statistics(&mut rekey);
    state.established.insert(2, rekey);
    state.peering.insert(id, 2);
    let after = state.status(&config);
    assert_eq!(after.session, snapshot.session);
    assert_eq!(after.peers[0].status, "connected");
    assert_eq!(
        after.peers[0].first_established_at,
        before.peers[0].first_established_at
    );
    assert!(after.peers[0].last_established_at >= before.peers[0].last_established_at);
    assert_eq!(after.peers[0].sent, 5);
    assert_eq!(after.peers[0].received, 5);
}
