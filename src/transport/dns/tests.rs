use super::*;
use crate::codec::PacketLayout;
use hickory_proto::serialize::binary::BinEncodable;

#[tokio::test]
async fn handshake_data_roles_and_reply_correlation() {
    use crate::{
        config::{Interface, ListenerConfig, Peer, PeerTransport},
        crypto::{pk_to_bytes, random_sk, sk_to_bytes},
    };
    use tokio::time::timeout;
    let a = random_sk().unwrap();
    let b = random_sk().unwrap();
    let reservation = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let server_address = reservation.local_addr().unwrap();
    let proxy = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let proxy_address = proxy.local_addr().unwrap();
    drop(reservation);
    let make_config = |sk, pk, endpoint, port| {
        Arc::new(Config {
            dev_name: String::new(),
            layout: PacketLayout {
                oip: 1300,
                orp: 1300,
                odp: 1300,
                ..PacketLayout::default()
            },
            interface: Interface {
                addresses: vec![],
                mtu: 1400,
                private_key: sk,
                hooks: Default::default(),
                liveness: crate::config::LivenessOptions {
                    timeout: Some(8),
                    max_age: Some(0),
                    keepalive: Some(1),
                    keepalive_jitter: Some(0),
                },
                listener: ListenerConfig::Dns {
                    dns: DnsListenerConfig {
                        port,
                        domain: "tunnel.example".to_owned(),
                        poll_interval: 1,
                    },
                },
            },
            peers: vec![Peer {
                peer_id: Uuid::new_v4(),
                public_key: pk,
                pre_shared_key: None,
                allowed_ips: vec![],
                liveness: Default::default(),
                transport: PeerTransport::Dns {
                    dns: DnsTransportPeerConfig { endpoint },
                },
            }],
        })
    };
    let a_config = make_config(
        sk_to_bytes(&a).into(),
        pk_to_bytes(&b.compute_public_key().unwrap()).into(),
        Some(proxy_address),
        0,
    );
    let b_config = make_config(
        sk_to_bytes(&b).into(),
        pk_to_bytes(&a.compute_public_key().unwrap()).into(),
        None,
        server_address.port(),
    );
    let (a_tx, mut a_rx) = tokio::sync::mpsc::channel(4);
    let (b_tx, mut b_rx) = tokio::sync::mpsc::channel(4);
    let a_state = Arc::new(State::new(a_tx));
    let b_state = Arc::new(State::new(b_tx));
    let (events_tx, mut events) = tokio::sync::mpsc::unbounded_channel();
    let relay = tokio::spawn(async move {
        let mut buffer = vec![0; 65535];
        let mut client = None;
        let mut dropped_query = false;
        let mut dropped_reply = false;
        loop {
            let (len, source) = proxy.recv_from(&mut buffer).await.unwrap();
            let decoded = decode(&buffer[..len], &Domain::new("tunnel.example").unwrap()).unwrap();
            if !decoded.server && !decoded.payload.is_empty() && !dropped_query {
                dropped_query = true;
                continue;
            }
            if decoded.server && !decoded.payload.is_empty() && !dropped_reply {
                dropped_reply = true;
                continue;
            }
            events_tx
                .send((decoded.server, decoded.token, decoded.token))
                .unwrap();
            if source == server_address {
                proxy
                    .send_to(&buffer[..len], client.unwrap())
                    .await
                    .unwrap();
            } else {
                client = Some(source);
                proxy.send_to(&buffer[..len], server_address).await.unwrap();
            }
        }
    });
    let mut b_endpoint = create_dns_endpoint(
        &b_state,
        &b_config,
        &DnsListenerConfig {
            port: server_address.port(),
            domain: "tunnel.example".to_owned(),
            poll_interval: 1,
        },
    )
    .await
    .unwrap();
    let mut a_endpoint = create_dns_endpoint(
        &a_state,
        &a_config,
        &DnsListenerConfig {
            port: 0,
            domain: "tunnel.example".to_owned(),
            poll_interval: 1,
        },
    )
    .await
    .unwrap();
    timeout(Duration::from_secs(6), async {
        while !a_state.has_live_connection(a_config.peers[0].peer_id)
            || !b_state.has_live_connection(b_config.peers[0].peer_id)
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert!(
        !a_endpoint
            .routing
            .get(&a_config.peers[0].peer_id)
            .unwrap()
            .server
    );
    assert!(
        b_endpoint
            .routing
            .get(&b_config.peers[0].peer_id)
            .unwrap()
            .server
    );
    // Polls must refresh authenticated activity on both sides while idle.
    let a_index = *a_state
        .peering
        .get(&a_config.peers[0].peer_id)
        .unwrap()
        .value();
    let b_index = *b_state
        .peering
        .get(&b_config.peers[0].peer_id)
        .unwrap()
        .value();
    tokio::time::sleep(Duration::from_secs(9)).await;
    assert!(a_state.has_live_connection(a_config.peers[0].peer_id));
    assert!(b_state.has_live_connection(b_config.peers[0].peer_id));
    assert_eq!(
        *a_state
            .peering
            .get(&a_config.peers[0].peer_id)
            .unwrap()
            .value(),
        a_index
    );
    assert_eq!(
        *b_state
            .peering
            .get(&b_config.peers[0].peer_id)
            .unwrap()
            .value(),
        b_index
    );
    a_endpoint
        .trasmit(
            &a_state,
            &a_config,
            a_config.peers[0].peer_id,
            b"client data",
        )
        .await
        .unwrap();
    assert_eq!(
        timeout(Duration::from_secs(3), b_rx.recv())
            .await
            .unwrap()
            .unwrap(),
        b"client data"
    );
    b_endpoint
        .trasmit(
            &b_state,
            &b_config,
            b_config.peers[0].peer_id,
            b"server data",
        )
        .await
        .unwrap();
    assert_eq!(
        timeout(Duration::from_secs(3), a_rx.recv())
            .await
            .unwrap()
            .unwrap(),
        b"server data"
    );
    let mut requests = std::collections::HashSet::new();
    let mut replies = 0;
    while let Ok((server, origin, transmit)) = events.try_recv() {
        if server {
            assert!(
                requests.remove(&origin),
                "unsolicited or repeated DNS reply"
            );
            replies += 1;
        } else {
            requests.insert(transmit);
        }
    }
    assert!(replies >= 2);
    drop(a_rx);
    drop(b_rx);
    drop(a_endpoint);
    drop(b_endpoint);
    relay.abort();
    let _ = relay.await;
}

#[test]
fn configuration_defaults_and_transport_selection() {
    let text = include_str!("../../../config.toml")
        .replace(
            "[Interface.Listener.Udp.udp]\nPort = 40676",
            "[Interface.Listener.Dns.dns]",
        )
        .replace("[Peer.Transport.Udp.udp]", "[Peer.Transport.Dns.dns]");
    let config: Config = toml::from_str(&text).unwrap();
    let crate::config::ListenerConfig::Dns { dns } = config.interface.listener else {
        panic!("expected DNS listener");
    };
    assert_eq!(dns.port, 53);
    assert_eq!(dns.poll_interval, 1);
    assert!(config.peers[0].transport.dns().unwrap().endpoint.is_some());
}

#[test]
fn dns_framing_limits_and_malformed_input() {
    let domain = Domain::new("vpn.example.com").unwrap();
    assert!(Domain::new("bad..example").is_err());
    assert!(Domain::new(&"x".repeat(64)).is_err());
    let frame = vec![0xab; 108];
    let query = encode(&frame, &domain, None, 0x1234567890abcdef).unwrap();
    let decoded = decode(&query, &domain).unwrap();
    assert!(!decoded.server);
    assert_eq!(decoded.payload, frame);
    assert!(decoded.question.name.to_bytes().unwrap().len() <= 255);
    let reply = encode(&frame, &domain, Some(&decoded), 0).unwrap();
    let response = decode(&reply, &domain).unwrap();
    assert!(response.server);
    assert_eq!(response.question, decoded.question);
    assert_eq!(response.token, decoded.token);
    assert_eq!(response.payload, frame);
    assert!(query.len() <= 512 && reply.len() <= 512);
    for bytes in [&query, &reply] {
        for len in 0..bytes.len() {
            assert!(decode(&bytes[..len], &domain).is_err());
        }
        for offset in [0, 2, 5, 11, 12] {
            let mut bad = bytes.clone();
            bad[offset] ^= 0xff;
            assert!(decode(&bad, &domain).is_err(), "offset {offset}");
        }
    }
    assert!(decode(&query, &Domain::new("other.example").unwrap()).is_err());
    // Empty polls are ordinary valid TXT questions, with empty TXT answers.
    let poll = encode(&[], &domain, None, 1).unwrap();
    let poll = decode(&poll, &domain).unwrap();
    assert!(poll.payload.is_empty());
    assert!(
        decode(&encode(&[], &domain, Some(&poll), 0).unwrap(), &domain)
            .unwrap()
            .payload
            .is_empty()
    );
}

#[test]
fn reassembly_handles_reordering_duplicates_and_conflicts() {
    use crate::codec::{Data, DataFlags};
    let layout = PacketLayout {
        odp: 1300,
        ..PacketLayout::default()
    };
    let packet = Packet::Data(Data {
        receiver_idx: 1,
        counter: 42,
        flags: DataFlags::empty(),
        ciphertext: vec![0x55; 1200],
    });
    let frames = fragments(packet, &layout, 96).unwrap();
    let peer = "127.0.0.1:53".parse().unwrap();
    let mut assembly = Reassembly::default();
    assert!(assembly.push(peer, false, &frames[0]).unwrap().is_none());
    assert!(assembly.push(peer, false, &frames[0]).unwrap().is_none());
    let mut bad = frames[0].clone();
    bad[12] ^= 1;
    assert!(assembly.push(peer, false, &bad).is_err());
    let mut result = None;
    for frame in frames[1..].iter().rev() {
        if let Some(packet) = assembly.push(peer, false, frame).unwrap() {
            result = Some(packet);
        }
    }
    let mut packet = result.unwrap();
    let Packet::Data(packet) = codec::parse(&mut packet, &layout).unwrap().unwrap() else {
        panic!("expected data");
    };
    assert_eq!(packet.ciphertext, vec![0x55; 1200]);
    assert_eq!(packet.counter, 42);
    assert!(assembly.0.is_empty());
    let mut bad = frames[0].clone();
    bad[6..8].copy_from_slice(&u16::MAX.to_be_bytes());
    assert!(assembly.push(peer, false, &bad).is_err());
    for len in 1..13 {
        assert!(assembly.push(peer, false, &frames[0][..len]).is_err());
    }
}

#[test]
fn accepts_compressed_and_uncompressed_answers_and_split_txt() {
    use base64::prelude::*;
    use hickory_proto::serialize::binary::BinEncoder;
    let domain = Domain::new("vpn.example.com").unwrap();
    let query = encode(&[1, 2, 3], &domain, None, 0x1234).unwrap();
    let query = decode(&query, &domain).unwrap();
    let fragment: Vec<u8> = (0..108).collect();
    let compressed = encode(&fragment, &domain, Some(&query), 0).unwrap();
    let mut packet = DnsMessage::from_vec(&compressed).unwrap();
    // TXT payloads may legally be divided across multiple character strings.
    let text = BASE64_STANDARD.encode(&fragment);
    packet.answers[0].data = RData::TXT(TXT::from_bytes(text.as_bytes().chunks(5).collect()));
    // These standard flags and EDNS changes must not affect the tunnel payload.
    packet.metadata.recursion_available = true;
    packet
        .edns
        .as_mut()
        .unwrap()
        .set_dnssec_ok(true)
        .set_max_payload(1400);
    let mut uncompressed = Vec::new();
    let mut encoder = BinEncoder::new(&mut uncompressed);
    encoder.set_canonical_form(true);
    packet.emit(&mut encoder).unwrap();
    assert!(uncompressed.len() > compressed.len());
    let parsed = decode(&uncompressed, &domain).unwrap();
    assert_eq!(parsed.question, query.question);
    assert_eq!(parsed.payload, fragment);
    // Question identity is semantic and case-insensitive, independent of encoding.
    packet.queries[0].name =
        Name::from_ascii(packet.queries[0].name.to_ascii().to_uppercase()).unwrap();
    packet.answers[0].name = packet.queries[0].name.clone();
    packet.edns = None;
    let parsed = decode(&packet.to_vec().unwrap(), &domain).unwrap();
    assert_eq!(parsed.question, query.question);
    assert_eq!(parsed.payload, fragment);
    packet.answers[0].name = Name::from_ascii("wrong.example").unwrap();
    assert!(decode(&packet.to_vec().unwrap(), &domain).is_err());
}

#[test]
fn preserves_legacy_wire_format_and_rejects_trailing_data() {
    let domain = Domain::new("tunnel.example").unwrap();
    // Original encoder's empty TXT query, with EDNS(0) payload size 1232.
    let legacy = b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01\x100000000000000001\x06tunnel\x07example\x00\x00\x10\x00\x01\x00\x00\x29\x04\xd0\x00\x00\x00\x00\x00\x00";
    assert_eq!(&encode(&[], &domain, None, 1).unwrap()[..], legacy);
    let query = decode(legacy, &domain).unwrap();
    let mut legacy_reply = legacy[..12].to_vec();
    legacy_reply[2..4].copy_from_slice(&0x8500u16.to_be_bytes());
    legacy_reply[7] = 1;
    legacy_reply.extend_from_slice(&legacy[12..legacy.len() - 11]);
    legacy_reply.extend_from_slice(b"\xc0\x0c\x00\x10\x00\x01\x00\x00\x00\x00\x00\x05\x04AQID");
    legacy_reply.extend_from_slice(&legacy[legacy.len() - 11..]);
    let parsed = decode(&legacy_reply, &domain).unwrap();
    assert_eq!(parsed.question, query.question);
    assert_eq!(parsed.payload, [1, 2, 3]);
    assert_eq!(
        &encode(&[1, 2, 3], &domain, Some(&query), 0).unwrap()[..],
        legacy_reply
    );
    legacy_reply.push(0);
    assert!(decode(&legacy_reply, &domain).is_err());
}
