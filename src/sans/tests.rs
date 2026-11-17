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
    (
        Tunnel::new(layout, [1; 32], liveness(), Some(public_key(&[2; 32])), PSK).unwrap(),
        Tunnel::new(layout, [2; 32], liveness(), None, None).unwrap(),
    )
}

fn establish(initiator: &mut Tunnel, responder: &mut Tunnel) {
    assert!(initiator.process_new_packets().unwrap().is_none());
    let initiation = initiator.read_outbound().unwrap().unwrap();
    responder.write_incoming(&initiation);
    let pending = responder.process_new_packets().unwrap().unwrap();
    assert_eq!(pending.public_key, public_key(&initiator.local_sk));
    // Approval must precede both the reply and the responder session.
    assert!(responder.read_outbound().unwrap().is_none());
    assert!(matches!(responder.state, State::Idle));
    responder.approve_pending(PSK, liveness()).unwrap();
    let reply = responder.read_outbound().unwrap().unwrap();
    initiator.write_incoming(&reply);
    assert!(initiator.process_new_packets().unwrap().is_none());
    assert!(matches!(initiator.state, State::Established { .. }));
    assert!(matches!(responder.state, State::Established { .. }));
}

fn transfer(sender: &mut Tunnel, receiver: &mut Tunnel, payload: &[u8]) {
    sender.push_packet(payload);
    assert!(sender.process_new_packets().unwrap().is_none());
    let wire = sender.read_outbound().unwrap().unwrap();
    receiver.write_incoming(&wire);
    assert!(receiver.process_new_packets().unwrap().is_none());
    assert_eq!(receiver.read_packet().unwrap(), payload);
    assert!(receiver.read_packet().is_none());
}

#[test]
fn approved_handshake_delivers_queued_packets_in_order() {
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
fn rejecting_initiation_preserves_existing_session() {
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
    let pending = responder.process_new_packets().unwrap().unwrap();
    assert_eq!(pending.public_key, public_key(&[4; 32]));
    responder.reject_pending();
    assert!(responder.pending.is_none());
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
        assert!(responder.process_new_packets().unwrap().is_none());
        assert!(responder.read_outbound().unwrap().is_none());
    }
    responder.write_incoming(&initiation[initiation.len() - 1..]);
    assert!(responder.process_new_packets().unwrap().is_some());
    responder.approve_pending(PSK, liveness()).unwrap();
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
    responder.approve_pending(PSK, liveness()).unwrap();
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
    assert!(initiator.process_new_packets().unwrap().is_none());
    assert!(matches!(initiator.state, State::Initiated { .. }));
    responder.write_incoming(&retry);
    assert!(responder.process_new_packets().unwrap().is_some());
    responder.approve_pending(PSK, liveness()).unwrap();
    let reply = responder.read_outbound().unwrap().unwrap();
    initiator.write_incoming(&reply);
    initiator.process_new_packets().unwrap();
    transfer(&mut initiator, &mut responder, b"recovered");
}

#[test]
fn wrong_psk_cannot_establish_initiator() {
    let (mut initiator, mut responder) = pair(PacketLayout::default());
    initiator.process_new_packets().unwrap();
    responder.write_incoming(&initiator.read_outbound().unwrap().unwrap());
    responder.process_new_packets().unwrap();
    responder
        .approve_pending(Some([9; 32]), liveness())
        .unwrap();
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
fn responder_can_rekey_with_approved_identity_and_psk() {
    let (mut initiator, mut responder) = pair(PacketLayout::default());
    establish(&mut initiator, &mut responder);
    if let State::Established { last_seen, .. } = &mut responder.state {
        *last_seen = Instant::now() - Duration::from_secs(29);
    }
    responder.process_new_packets().unwrap();
    responder.process_new_packets().unwrap();
    let initiation = responder.read_outbound().unwrap().unwrap();
    initiator.write_incoming(&initiation);
    assert!(initiator.process_new_packets().unwrap().is_some());
    initiator.approve_pending(PSK, liveness()).unwrap();
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
            Some(public_key(&keys[1])),
            psk,
        )
        .unwrap();
        let mut responder = Tunnel::new(
            PacketLayout::default(),
            keys[1],
            liveness,
            Some(public_key(&keys[0])),
            psk,
        )
        .unwrap();
        initiator.push_packet(b"to responder");
        responder.push_packet(b"to initiator");
        assert!(initiator.process_new_packets().unwrap().is_none());
        assert!(responder.process_new_packets().unwrap().is_none());

        if deliver_competing {
            let competing = responder.read_outbound().unwrap().unwrap();
            initiator.write_incoming(&competing);
            assert!(initiator.process_new_packets().unwrap().is_none());
            assert!(matches!(initiator.state, State::Initiated { .. }));
        }

        let initiation = initiator.read_outbound().unwrap().unwrap();
        responder.write_incoming(&initiation);
        assert!(responder.process_new_packets().unwrap().is_some());
        responder.approve_pending(psk, liveness).unwrap();
        let reply = responder.read_outbound().unwrap().unwrap();
        let mut parsed = BytesMut::from(reply.as_ref());
        assert!(matches!(
            codec::parse(&mut parsed, &responder.layout),
            Some(Ok(Packet::Reply(_)))
        ));
        initiator.write_incoming(&reply);
        assert!(initiator.process_new_packets().unwrap().is_none());

        let data = initiator.read_outbound().unwrap().unwrap();
        responder.write_incoming(&data);
        assert!(responder.process_new_packets().unwrap().is_none());
        assert_eq!(responder.read_packet().unwrap(), b"to responder");
        let data = responder.read_outbound().unwrap().unwrap();
        initiator.write_incoming(&data);
        assert!(initiator.process_new_packets().unwrap().is_none());
        assert_eq!(initiator.read_packet().unwrap(), b"to initiator");
    }
}
