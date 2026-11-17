use super::*;

const PSK: Option<Key> = Some([3; 32]);

fn public_key(sk: &Key) -> Key {
    crypto::pk_to_bytes(&crypto::to_sk(sk).compute_public_key().unwrap())
}

fn liveness() -> Liveness {
    Liveness {
        timeout: 28,
        max_age: 300,
        ka_delay: 10,
        ka_jitter: 0,
    }
}

fn pair(layout: PacketLayout) -> (Tunnel, Tunnel) {
    let mut initiator = Tunnel::new(layout, [1; 32], liveness(), public_key(&[2; 32]), PSK);
    initiator.initiate().unwrap();
    (
        initiator,
        Tunnel::new(layout, [2; 32], liveness(), public_key(&[1; 32]), PSK),
    )
}

fn establish(initiator: &mut Tunnel, responder: &mut Tunnel) {
    initiator.process_new_packets().unwrap();
    let initiation = initiator.read_outbound().unwrap().unwrap();
    responder.write_incoming(&initiation);
    responder.process_new_packets().unwrap();
    let reply = responder.read_outbound().unwrap().unwrap();
    initiator.write_incoming(&reply);
    initiator.process_new_packets().unwrap();
    assert!(initiator.is_live());
    assert!(responder.is_live());
}

fn transfer(sender: &mut Tunnel, receiver: &mut Tunnel, payload: &[u8]) {
    sender.push_packet(payload);
    sender.process_new_packets().unwrap();
    let wire = sender.read_outbound().unwrap().unwrap();
    receiver.write_incoming(&wire);
    receiver.process_new_packets().unwrap();
    assert_eq!(receiver.read_packet().unwrap(), payload);
    assert!(receiver.read_packet().is_none());
}

#[test]
fn handshake_delivers_queued_packets_in_order() {
    for layout in [PacketLayout::default(), PacketLayout::random()] {
        let (mut initiator, mut responder) = pair(layout);
        initiator.push_packet(b"first");
        initiator.push_packet(b"second");
        responder.push_packet(b"return");
        establish(&mut initiator, &mut responder);
        while let Some(wire) = initiator.read_outbound().unwrap() {
            responder.write_incoming(&wire);
        }
        responder.process_new_packets().unwrap();
        assert_eq!(responder.read_packet().unwrap(), b"first");
        assert_eq!(responder.read_packet().unwrap(), b"second");
        assert!(responder.read_packet().is_none());
        let wire = responder.read_outbound().unwrap().unwrap();
        initiator.write_incoming(&wire);
        initiator.process_new_packets().unwrap();
        assert_eq!(initiator.read_packet().unwrap(), b"return");
    }
}

#[test]
fn unknown_identity_preserves_existing_session() {
    let (mut initiator, mut responder) = pair(PacketLayout::default());
    establish(&mut initiator, &mut responder);
    let timestamp = match responder.state {
        State::Established { timestamp, .. } => timestamp + 1,
        _ => unreachable!(),
    };
    let stranger =
        crypto::initiate(&[4; 32], &public_key(&responder.local_sk), timestamp, 42).unwrap();
    let wire = Packet::Initiating(stranger)
        .to_bytes(&responder.layout)
        .unwrap();
    responder.write_incoming(&wire);
    let established = responder.established_at();
    responder.process_new_packets().unwrap();
    assert_eq!(responder.established_at(), established);
    assert_eq!(responder.remote_pk, public_key(&[1; 32]));
    assert!(responder.read_outbound().unwrap().is_none());
    transfer(&mut initiator, &mut responder, b"original session");
    transfer(&mut responder, &mut initiator, b"still works");
}

#[test]
fn fragmented_handshake_and_data_wait_for_complete_frames() {
    let (mut initiator, mut responder) = pair(PacketLayout::default());
    initiator.process_new_packets().unwrap();
    let initiation = initiator.read_outbound().unwrap().unwrap();
    for byte in &initiation[..initiation.len() - 1] {
        responder.write_incoming(&[*byte]);
        responder.process_new_packets().unwrap();
        assert!(responder.read_outbound().unwrap().is_none());
    }
    responder.write_incoming(&initiation[initiation.len() - 1..]);
    responder.process_new_packets().unwrap();
    let reply = responder.read_outbound().unwrap().unwrap();
    initiator.write_incoming(&reply);
    initiator.process_new_packets().unwrap();
    initiator.push_packet(b"fragmented");
    initiator.process_new_packets().unwrap();
    let wire = initiator.read_outbound().unwrap().unwrap();
    for byte in &wire[..wire.len() - 1] {
        responder.write_incoming(&[*byte]);
        responder.process_new_packets().unwrap();
        assert!(responder.read_packet().is_none());
    }
    responder.write_incoming(&wire[wire.len() - 1..]);
    responder.process_new_packets().unwrap();
    assert_eq!(responder.read_packet().unwrap(), b"fragmented");
}

#[test]
fn retry_refreshes_handshake_and_ignores_superseded_reply() {
    let (mut initiator, mut responder) = pair(PacketLayout::default());
    initiator.process_new_packets().unwrap();
    let original = initiator.read_outbound().unwrap().unwrap();
    responder.write_incoming(&original);
    responder.process_new_packets().unwrap();
    let delayed_reply = responder.read_outbound().unwrap().unwrap();
    initiator.process_new_packets().unwrap();
    assert!(initiator.read_outbound().unwrap().is_none());
    if let State::Initiated { last_initiated, .. } = &mut initiator.state {
        *last_initiated = Some(Instant::now() - Duration::from_secs(11));
    }
    // Simulate the original request having been accepted in a previous second.
    if let State::Established { timestamp, .. } = &mut responder.state {
        *timestamp = timestamp.saturating_sub(1);
    }
    initiator.process_new_packets().unwrap();
    let retry = initiator.read_outbound().unwrap().unwrap();
    assert_ne!(retry, original);
    initiator.write_incoming(&delayed_reply);
    initiator.process_new_packets().unwrap();
    assert!(matches!(initiator.state, State::Initiated { .. }));
    responder.write_incoming(&retry);
    responder.process_new_packets().unwrap();
    let reply = responder.read_outbound().unwrap().unwrap();
    initiator.write_incoming(&reply);
    initiator.process_new_packets().unwrap();
    transfer(&mut initiator, &mut responder, b"recovered");
}

#[test]
fn wrong_psk_cannot_establish_initiator() {
    let (mut initiator, _) = pair(PacketLayout::default());
    let mut responder = Tunnel::new(
        PacketLayout::default(),
        [2; 32],
        liveness(),
        public_key(&[1; 32]),
        Some([9; 32]),
    );
    initiator.process_new_packets().unwrap();
    responder.write_incoming(&initiator.read_outbound().unwrap().unwrap());
    responder.process_new_packets().unwrap();
    initiator.write_incoming(&responder.read_outbound().unwrap().unwrap());
    assert!(initiator.process_new_packets().is_err());
    assert!(matches!(initiator.state, State::Initiated { .. }));
    assert!(initiator.read_packet().is_none());
}

#[test]
fn keepalive_is_authenticated_discarded_and_rescheduled() {
    let (mut initiator, mut responder) = pair(PacketLayout::default());
    establish(&mut initiator, &mut responder);
    if let State::Established { next_ka, .. } = &mut initiator.state {
        *next_ka = Instant::now() - Duration::from_secs(1);
    }
    initiator.process_new_packets().unwrap();
    let wire = initiator.read_outbound().unwrap().unwrap();
    let mut buf = BytesMut::from(wire.as_ref());
    let Packet::Data(mut data) = codec::parse(&mut buf, &initiator.layout).unwrap().unwrap() else {
        panic!("expected keepalive data");
    };
    assert!(data.flags.contains(DataFlags::JUNK));
    data.ciphertext[0] ^= 1;
    let tampered = Packet::Data(data).to_bytes(&initiator.layout).unwrap();
    let seen = match responder.state {
        State::Established { last_seen, .. } => last_seen,
        _ => unreachable!(),
    };
    responder.write_incoming(&tampered);
    assert!(responder.process_new_packets().is_err());
    assert!(matches!(responder.state, State::Established { last_seen, .. } if last_seen == seen));
    responder.write_incoming(&wire);
    responder.process_new_packets().unwrap();
    assert!(responder.read_packet().is_none());
    initiator.process_new_packets().unwrap();
    assert!(initiator.read_outbound().unwrap().is_none());
    transfer(&mut initiator, &mut responder, b"after keepalive");
}

#[test]
fn responder_rekeys_with_fixed_identity_psk_and_liveness() {
    let (mut initiator, mut responder) = pair(PacketLayout::default());
    establish(&mut initiator, &mut responder);
    if let State::Established { last_seen, .. } = &mut responder.state {
        *last_seen = Instant::now() - Duration::from_secs(29);
    }
    responder.process_new_packets().unwrap();
    responder.process_new_packets().unwrap();
    let initiation = responder.read_outbound().unwrap().unwrap();
    initiator.write_incoming(&initiation);
    initiator.process_new_packets().unwrap();
    let reply = initiator.read_outbound().unwrap().unwrap();
    responder.write_incoming(&reply);
    responder.process_new_packets().unwrap();
    transfer(&mut responder, &mut initiator, b"rekeyed");
    transfer(&mut initiator, &mut responder, b"return after rekey");
}

#[test]
fn simultaneous_initiation_exchanges_data() {
    // Cover an initiation already delivered to the winning peer, and
    // one still queued when the losing peer accepts the winning handshake.
    for deliver_competing in [false, true] {
        let public_key =
            |sk: &Key| crypto::pk_to_bytes(&crypto::to_sk(sk).compute_public_key().unwrap());
        let mut keys = [[1; 32], [2; 32]];
        keys.sort_by_key(public_key);
        let liveness = Liveness {
            timeout: 28,
            max_age: 300,
            ka_delay: 10,
            ka_jitter: 0,
        };
        let psk = Some([3; 32]);
        let mut initiator = Tunnel::new(
            PacketLayout::default(),
            keys[0],
            liveness,
            public_key(&keys[1]),
            psk,
        );
        let mut responder = Tunnel::new(
            PacketLayout::default(),
            keys[1],
            liveness,
            public_key(&keys[0]),
            psk,
        );
        initiator.initiate().unwrap();
        responder.initiate().unwrap();
        initiator.push_packet(b"to responder");
        responder.push_packet(b"to initiator");
        initiator.process_new_packets().unwrap();
        responder.process_new_packets().unwrap();

        if deliver_competing {
            let competing = responder.read_outbound().unwrap().unwrap();
            initiator.write_incoming(&competing);
            initiator.process_new_packets().unwrap();
            assert!(matches!(initiator.state, State::Initiated { .. }));
        }

        let initiation = initiator.read_outbound().unwrap().unwrap();
        responder.write_incoming(&initiation);
        responder.process_new_packets().unwrap();
        let reply = responder.read_outbound().unwrap().unwrap();
        let mut parsed = BytesMut::from(reply.as_ref());
        assert!(matches!(
            codec::parse(&mut parsed, &responder.layout),
            Some(Ok(Packet::Reply(_)))
        ));
        initiator.write_incoming(&reply);
        initiator.process_new_packets().unwrap();

        let data = initiator.read_outbound().unwrap().unwrap();
        responder.write_incoming(&data);
        responder.process_new_packets().unwrap();
        assert_eq!(responder.read_packet().unwrap(), b"to responder");
        let data = responder.read_outbound().unwrap().unwrap();
        initiator.write_incoming(&data);
        initiator.process_new_packets().unwrap();
        assert_eq!(initiator.read_packet().unwrap(), b"to initiator");
    }
}

#[test]
fn parsed_packets_establish_and_deliver_without_stream_buffering() {
    let (mut initiator, mut responder) = pair(PacketLayout::default());
    initiator.process_new_packets().unwrap();
    responder
        .process_incoming_packet(initiator.read_outbound_packet().unwrap())
        .unwrap();
    responder.process_new_packets().unwrap();
    assert!(responder.is_live());
    initiator
        .process_incoming_packet(responder.read_outbound_packet().unwrap())
        .unwrap();
    assert!(initiator.is_live());
    assert!(responder.is_live());
    for reverse in [false, true] {
        let (sender, receiver) = if reverse {
            (&mut responder, &mut initiator)
        } else {
            (&mut initiator, &mut responder)
        };
        sender.push_packet(b"parsed payload");
        sender.process_new_packets().unwrap();
        receiver
            .process_incoming_packet(sender.read_outbound_packet().unwrap())
            .unwrap();
        assert_eq!(receiver.read_packet().unwrap(), b"parsed payload");
        assert!(receiver.received.is_empty());
    }
}

#[test]
fn parsed_data_checks_index_and_authentication_before_delivery() {
    let (mut initiator, mut responder) = pair(PacketLayout::default());
    establish(&mut initiator, &mut responder);
    initiator.push_packet(b"authenticated payload");
    initiator.process_new_packets().unwrap();
    let Packet::Data(mut data) = initiator.read_outbound_packet().unwrap() else {
        panic!("expected data");
    };
    let seen = match responder.state {
        State::Established { last_seen, .. } => last_seen,
        _ => unreachable!(),
    };
    let wrong_index = Data {
        receiver_idx: data.receiver_idx ^ 1,
        flags: DataFlags::empty(),
        counter: data.counter,
        ciphertext: data.ciphertext.clone(),
    };
    responder
        .process_incoming_packet(Packet::Data(wrong_index))
        .unwrap();
    assert!(responder.read_packet().is_none());
    let ciphertext = data.ciphertext.clone();
    data.ciphertext[0] ^= 1;
    assert!(
        responder
            .process_incoming_packet(Packet::Data(data))
            .is_err()
    );
    assert!(responder.read_packet().is_none());
    assert!(matches!(responder.state, State::Established { last_seen, .. } if last_seen == seen));
    responder
        .process_incoming_packet(Packet::Data(Data {
            receiver_idx: responder.local_index().unwrap(),
            flags: DataFlags::empty(),
            counter: 1,
            ciphertext,
        }))
        .unwrap();
    assert_eq!(responder.read_packet().unwrap(), b"authenticated payload");
}

#[test]
fn decoded_initiation_exposes_identity_and_retains_replay_checks() {
    let (mut initiator, mut responder) = pair(PacketLayout::default());
    initiator.process_new_packets().unwrap();
    let Packet::Initiating(initiation) = initiator.read_outbound_packet().unwrap() else {
        panic!("expected initiation");
    };
    let decoded = DecodedInitiation::decode(&responder.local_sk, initiation.clone()).unwrap();
    assert_eq!(decoded.public_key, public_key(&initiator.local_sk));
    responder.accept_initiation(decoded).unwrap();
    responder.process_new_packets().unwrap();
    let reply = responder.read_outbound_packet().unwrap();
    initiator.process_incoming_packet(reply).unwrap();
    let established = responder.established_at();

    let replay = DecodedInitiation::decode(&responder.local_sk, initiation.clone()).unwrap();
    responder.accept_initiation(replay).unwrap();
    responder.process_new_packets().unwrap();
    assert_eq!(responder.established_at(), established);
    assert!(responder.read_outbound_packet().is_none());
    transfer(&mut initiator, &mut responder, b"session preserved");

    let mut tampered = initiation;
    tampered.enc_ts[0] ^= 1;
    assert!(DecodedInitiation::decode(&responder.local_sk, tampered).is_err());
}

#[test]
fn configured_tunnel_stays_passive_until_explicitly_initiated() {
    let mut tunnel = Tunnel::new(
        PacketLayout::default(),
        [1; 32],
        liveness(),
        public_key(&[2; 32]),
        PSK,
    );
    tunnel.push_packet(b"waiting for a route");
    tunnel.process_new_packets().unwrap();
    assert!(tunnel.local_index().is_none());
    assert!(!tunnel.is_live());
    assert!(tunnel.read_outbound_packet().is_none());
    tunnel.initiate().unwrap();
    tunnel.process_new_packets().unwrap();
    assert!(matches!(
        tunnel.read_outbound_packet(),
        Some(Packet::Initiating(_))
    ));
    assert_eq!(tunnel.queue.front().unwrap(), b"waiting for a route");
}
