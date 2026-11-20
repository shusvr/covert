use super::*;
use crate::{
    Error,
    codec::{self, Data, DataFlags},
    config::{DEFAULT_FWMARK, Interface, ListenerConfig, PeerTransport},
    crypto,
};
use std::{cell::RefCell, sync::atomic::Ordering};

#[derive(Default)]
struct Capture(RefCell<Vec<(u8, Packet)>>);
impl Adapter for Capture {
    type Route = u8;
    fn peer_route(&self, peer: &Peer) -> Option<u8> {
        matches!(peer.transport, PeerTransport::Udp { .. }).then_some(1)
    }
    fn deliver(&self, route: u8, packet: Packet) {
        self.0.borrow_mut().push((route, packet));
    }
}

fn endpoint(local: u8, remote: u8, active: bool) -> Endpoint<Capture> {
    let pk = crypto::pk_to_bytes(&crypto::to_sk(&[remote; 32]).compute_public_key().unwrap());
    Endpoint::new(
        Capture::default(),
        Config {
            dev_name: String::new(),
            layout: Default::default(),
            interface: Interface {
                addresses: vec![],
                mtu: 1400,
                private_key: [local; 32].into(),
                liveness: Default::default(),
                hooks: Default::default(),
                listener: ListenerConfig::Udp {
                    udp: UdpListenerConfig { port: 40676 },
                },
                fwmark: DEFAULT_FWMARK,
                table: false,
            },
            peers: vec![Peer {
                id: Uuid::new_v4(),
                public_key: pk.into(),
                pre_shared_key: None,
                allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
                liveness: Default::default(),
                transport: if active {
                    PeerTransport::Udp {
                        udp: UdpTransportPeerConfig {
                            endpoint: Some("127.0.0.1:40676".parse().unwrap()),
                        },
                    }
                } else {
                    PeerTransport::None
                },
                metric: 600,
            }],
        },
    )
    .unwrap()
}

fn outgoing(endpoint: &Endpoint<Capture>) -> Packet {
    endpoint.adapter.0.borrow_mut().remove(0).1
}
fn route(endpoint: &Endpoint<Capture>) -> Option<u8> {
    endpoint.peers.values().next().unwrap().address
}
fn index(endpoint: &Endpoint<Capture>) -> u32 {
    endpoint
        .peers
        .values()
        .next()
        .unwrap()
        .tunnel
        .local_index()
        .unwrap()
}
fn invalid_data(receiver_idx: u32) -> Packet {
    Packet::Data(Data {
        receiver_idx,
        flags: DataFlags::empty(),
        counter: 1,
        ciphertext: vec![0; 16],
    })
}

#[test]
fn ignored_and_invalid_packets_cannot_move_routes_but_authenticated_data_can() {
    let mut a = endpoint(1, 2, true);
    let mut b = endpoint(2, 1, false);
    a.advance();
    // Data targeting an unfinished handshake is ignored, not authenticated.
    a.process_incoming(9, invalid_data(index(&a))).unwrap();
    assert_eq!(route(&a), Some(1));
    let initiation = outgoing(&a);
    let replay = match &initiation {
        Packet::Initiating(p) => p.clone(),
        _ => unreachable!(),
    };
    b.process_incoming(2, initiation).unwrap();
    assert_eq!(route(&b), Some(2));
    let reply = outgoing(&b);
    let stale_reply = match &reply {
        Packet::Reply(p) => *p,
        _ => unreachable!(),
    };
    a.process_incoming(3, reply).unwrap();
    assert_eq!(route(&a), Some(3));
    // Ignored replies and replayed initiations must not overwrite the route.
    a.process_incoming(9, Packet::Reply(stale_reply)).unwrap();
    b.process_incoming(9, Packet::Initiating(replay)).unwrap();
    assert_eq!(route(&a), Some(3));
    assert_eq!(route(&b), Some(2));
    assert!(b.process_incoming(9, invalid_data(index(&b))).is_err());
    assert_eq!(route(&b), Some(2));
    let peer = a.peers.values_mut().next().unwrap();
    peer.tunnel.push_packet(b"authenticated migration");
    a.advance();
    b.process_incoming(4, outgoing(&a)).unwrap();
    assert_eq!(route(&b), Some(4));
    assert_eq!(
        b.tun_read().collect::<Vec<_>>(),
        vec![b"authenticated migration".to_vec()]
    );
}

#[test]
fn pre_handshake_traffic_is_counted_without_recording_establishment() {
    let mut a = endpoint(1, 2, true);
    let packet = etherparse::Ipv4Header::new(
        0,
        64,
        etherparse::IpNumber::UDP,
        [10, 0, 0, 1],
        [10, 0, 0, 2],
    )
    .unwrap()
    .to_bytes();
    a.tun_write(&packet).unwrap();
    let id = a.config.peers[0].id;
    let stats = &a.state.peer_statistics[&id];
    assert_eq!(stats.sent.load(Ordering::Relaxed), packet.len() as u64);
    assert_eq!(stats.first_established_at.load(Ordering::Relaxed), 0);
    assert_eq!(stats.received.load(Ordering::Relaxed), 0);
}

// Most scenarios below cross the serialized public API boundary. The capture
// adapter supplies an in-memory network without sockets or privileged fixtures.
fn take_wire(endpoint: &Endpoint<Capture>) -> Vec<(u8, Vec<u8>)> {
    endpoint
        .adapter
        .0
        .take()
        .into_iter()
        .map(|(route, packet)| {
            (
                route,
                packet.to_bytes(&endpoint.config.layout).unwrap().to_vec(),
            )
        })
        .collect()
}

fn relay(from: &Endpoint<Capture>, to: &mut Endpoint<Capture>, source: u8) -> usize {
    let packets = take_wire(from);
    let count = packets.len();
    for (_, wire) in packets {
        to.out_write(source, &wire);
    }
    count
}

fn connect(a: &mut Endpoint<Capture>, b: &mut Endpoint<Capture>) {
    a.advance();
    assert!(relay(a, b, 2) > 0);
    assert!(relay(b, a, 3) > 0);
    // Deliver any plaintext queued before the handshake.
    relay(a, b, 2);
    relay(b, a, 3);
    assert!(a.state.connected.values().all(|live| *live));
    assert!(b.state.connected.values().all(|live| *live));
}

fn ipv4(tag: u8) -> Vec<u8> {
    let mut packet = etherparse::Ipv4Header::new(
        3,
        64,
        etherparse::IpNumber::UDP,
        [10, 0, 0, 1],
        [10, 0, 0, 2],
    )
    .unwrap()
    .to_bytes()
    .to_vec();
    packet.extend_from_slice(&[tag; 3]);
    packet
}

fn ipv6(tag: u8) -> Vec<u8> {
    let mut packet = vec![0; 43];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&3u16.to_be_bytes());
    packet[6] = 17;
    packet[7] = 64;
    packet[23] = 1;
    packet[39] = 2;
    packet[40..].fill(tag);
    packet
}

fn configure(
    mut config: Config,
    layout: crate::codec::PacketLayout,
    psk: Option<u8>,
) -> Endpoint<Capture> {
    config.layout = layout;
    for peer in &mut config.peers {
        peer.pre_shared_key = psk.map(|key| [key; 32].into());
    }
    Endpoint::new(Capture::default(), config).unwrap()
}

fn sent(endpoint: &Endpoint<Capture>) -> u64 {
    endpoint
        .state
        .peer_statistics
        .values()
        .map(|s| s.sent.load(Ordering::Relaxed))
        .sum()
}
fn received(endpoint: &Endpoint<Capture>) -> u64 {
    endpoint
        .state
        .peer_statistics
        .values()
        .map(|s| s.received.load(Ordering::Relaxed))
        .sum()
}

#[test]
fn empty_endpoint_and_passive_endpoint_are_idle() {
    let mut config = endpoint(1, 2, false).config;
    config.peers.clear();
    let mut empty = Endpoint::new(Capture::default(), config).unwrap();
    let mut passive = endpoint(1, 2, false);
    for node in [&mut empty, &mut passive] {
        node.advance();
        node.tun_write(&ipv4(1)).unwrap();
        node.out_write(9, &[]);
        assert!(node.tun_read().next().is_none());
        assert!(take_wire(node).is_empty());
        assert!(node.state.connected.values().all(|live| !live));
    }
    assert_eq!(route(&passive), None);
}

#[test]
fn queued_bidirectional_ipv4_and_ipv6_roundtrip_with_layouts_and_psk() {
    for layout in [Default::default(), crate::codec::PacketLayout::random()] {
        for psk in [None, Some(7)] {
            let mut a = configure(endpoint(1, 2, true).config, layout, psk);
            let mut b = configure(endpoint(2, 1, false).config, layout, psk);
            a.config.peers[0].allowed_ips.push("::/0".parse().unwrap());
            b.config.peers[0].allowed_ips.push("::/0".parse().unwrap());
            let requests = vec![ipv4(1), ipv6(2), ipv4(3)];
            let responses = vec![ipv6(4), ipv4(5)];
            for packet in &requests {
                a.tun_write(packet).unwrap();
            }
            for packet in &responses {
                b.tun_write(packet).unwrap();
            }
            // a has already emitted the initiation from tun_write.
            connect(&mut a, &mut b);
            assert_eq!(b.tun_read().collect::<Vec<_>>(), requests);
            assert_eq!(a.tun_read().collect::<Vec<_>>(), responses);
            assert!(a.tun_read().next().is_none());
            assert!(b.tun_read().next().is_none());
            assert_eq!(
                sent(&a),
                requests.iter().map(|p| p.len() as u64).sum::<u64>()
            );
            assert_eq!(received(&b), sent(&a));
            assert_eq!(
                sent(&b),
                responses.iter().map(|p| p.len() as u64).sum::<u64>()
            );
            assert_eq!(received(&a), sent(&b));
            assert_eq!(route(&a), Some(3));
            assert_eq!(route(&b), Some(2));
        }
    }
}

#[test]
fn tun_read_can_be_partially_consumed_without_losing_remaining_packets() {
    let (mut a, mut b) = (endpoint(1, 2, true), endpoint(2, 1, false));
    connect(&mut a, &mut b);
    for tag in 1..=3 {
        a.tun_write(&ipv4(tag)).unwrap();
    }
    relay(&a, &mut b, 2);
    assert_eq!(b.tun_read().next(), Some(ipv4(1)));
    assert_eq!(received(&b), ipv4(1).len() as u64);
    assert_eq!(b.tun_read().collect::<Vec<_>>(), vec![ipv4(2), ipv4(3)]);
    assert_eq!(received(&b), (ipv4(1).len() * 3) as u64);
}

#[test]
fn malformed_tun_input_and_unmatched_destinations_have_no_side_effects() {
    let mut a = endpoint(1, 2, false);
    a.config.peers[0].allowed_ips = vec!["192.0.2.0/24".parse().unwrap()];
    for bytes in [vec![], vec![0; 20], vec![0x45], vec![0x60; 10]] {
        assert!(a.tun_write(&bytes).is_err());
    }
    a.tun_write(&ipv4(1)).unwrap();
    a.tun_write(&ipv6(2)).unwrap();
    assert_eq!(sent(&a), 0);
    assert!(take_wire(&a).is_empty());
    assert_eq!(route(&a), None);
}

#[test]
fn malformed_truncated_and_unknown_packets_do_not_poison_next_datagram() {
    for layout in [Default::default(), crate::codec::PacketLayout::random()] {
        let mut a = configure(endpoint(1, 2, true).config, layout, None);
        let mut b = configure(endpoint(2, 1, false).config, layout, None);
        a.advance();
        let initiation = take_wire(&a).remove(0).1;
        for end in 0..initiation.len() {
            b.out_write(9, &initiation[..end]);
        }
        // Corrupt each possible discriminator, including invalid packet types.
        for ty in 0..=255 {
            b.out_write(9, &vec![ty; 512]);
        }
        assert_eq!(route(&b), None);
        assert!(take_wire(&b).is_empty());
        b.out_write(2, &initiation);
        assert_eq!(relay(&b, &mut a, 3), 1);
        a.tun_write(&ipv4(8)).unwrap();
        relay(&a, &mut b, 2);
        assert_eq!(b.tun_read().collect::<Vec<_>>(), vec![ipv4(8)]);
    }
}

#[test]
fn concatenated_packets_are_consumed_once_and_in_order() {
    let (mut a, mut b) = (endpoint(1, 2, true), endpoint(2, 1, false));
    connect(&mut a, &mut b);
    for tag in 1..=3 {
        a.tun_write(&ipv4(tag)).unwrap();
    }
    let wire: Vec<u8> = take_wire(&a)
        .into_iter()
        .flat_map(|(_, wire)| wire)
        .collect();
    b.out_write(2, &wire);
    assert_eq!(
        b.tun_read().collect::<Vec<_>>(),
        vec![ipv4(1), ipv4(2), ipv4(3)]
    );
    assert!(take_wire(&b).is_empty());
}

#[test]
fn authentication_error_in_batch_does_not_discard_next_valid_packet() {
    let (mut a, mut b) = (endpoint(1, 2, true), endpoint(2, 1, false));
    connect(&mut a, &mut b);
    a.tun_write(&ipv4(1)).unwrap();
    let good = take_wire(&a).remove(0).1;
    let mut bad = good.clone();
    *bad.last_mut().unwrap() ^= 1;
    bad.extend_from_slice(&good);
    b.out_write(2, &bad);
    assert_eq!(b.tun_read().collect::<Vec<_>>(), vec![ipv4(1)]);
    assert_eq!(received(&b), ipv4(1).len() as u64);
}

#[test]
fn unknown_peer_and_unknown_session_index_are_ignored() {
    let mut b = endpoint(2, 1, false);
    let mut stranger = endpoint(3, 2, true);
    stranger.advance();
    relay(&stranger, &mut b, 9);
    let wire = invalid_data(123).to_bytes(&b.config.layout).unwrap();
    b.out_write(9, &wire);
    assert_eq!(route(&b), None);
    assert!(take_wire(&b).is_empty());
    assert_eq!(received(&b), 0);
    let mut a = endpoint(1, 2, true);
    connect(&mut a, &mut b);
}

#[test]
fn mismatched_psk_never_establishes_initiator_or_delivers_plaintext() {
    let layout = Default::default();
    let mut a = configure(endpoint(1, 2, true).config, layout, Some(7));
    let mut b = configure(endpoint(2, 1, false).config, layout, Some(8));
    a.tun_write(&ipv4(1)).unwrap();
    relay(&a, &mut b, 2);
    relay(&b, &mut a, 9);
    assert_eq!(route(&a), Some(1));
    assert!(!a.state.connected.values().any(|v| *v));
    assert!(a.tun_read().next().is_none());
    assert!(b.tun_read().next().is_none());
    assert_eq!(received(&b), 0);
}

#[test]
fn reordered_packets_are_accepted_but_packets_beyond_nonce_window_cannot_move_route() {
    let (mut a, mut b) = (endpoint(1, 2, true), endpoint(2, 1, false));
    connect(&mut a, &mut b);
    for tag in 1..=3 {
        a.tun_write(&ipv4(tag)).unwrap();
    }
    let wires = take_wire(&a);
    for i in [2, 0, 1] {
        b.out_write(4, &wires[i].1);
    }
    assert_eq!(
        b.tun_read().collect::<Vec<_>>(),
        vec![ipv4(3), ipv4(1), ipv4(2)]
    );
    // Move the receiver past the cipher's 200-counter lag window.
    for _ in 0..202 {
        a.tun_write(&ipv4(4)).unwrap();
    }
    let recent = take_wire(&a).pop().unwrap().1;
    b.out_write(4, &recent);
    assert_eq!(b.tun_read().collect::<Vec<_>>(), vec![ipv4(4)]);
    for (_, wire) in &wires {
        b.out_write(9, wire);
    }
    assert_eq!(route(&b), Some(4));
    assert!(b.tun_read().next().is_none());
    assert_eq!(received(&b), (ipv4(1).len() * 4) as u64);
}

#[test]
fn simultaneous_initiators_converge_and_transfer_both_ways() {
    let (mut a, mut b) = (endpoint(1, 2, true), endpoint(2, 1, true));
    a.advance();
    b.advance();
    for _ in 0..4 {
        relay(&a, &mut b, 2);
        relay(&b, &mut a, 3);
    }
    assert!(a.peers.values().all(|p| p.tunnel.is_live()));
    assert!(b.peers.values().all(|p| p.tunnel.is_live()));
    a.tun_write(&ipv4(1)).unwrap();
    b.tun_write(&ipv4(2)).unwrap();
    relay(&a, &mut b, 2);
    relay(&b, &mut a, 3);
    assert_eq!(b.tun_read().collect::<Vec<_>>(), vec![ipv4(1)]);
    assert_eq!(a.tun_read().collect::<Vec<_>>(), vec![ipv4(2)]);
}

#[test]
fn multiple_peers_dispatch_by_identity_and_index_and_drain_all_tun_queues() {
    let mut cfg = endpoint(2, 1, false).config;
    cfg.peers[0].allowed_ips = vec!["10.0.0.2/32".parse().unwrap()];
    let mut third = endpoint(2, 3, false).config.peers.remove(0);
    third.allowed_ips = vec!["::2/128".parse().unwrap()];
    cfg.peers.push(third);
    let mut hub = Endpoint::new(Capture::default(), cfg).unwrap();
    let (mut a, mut c) = (endpoint(1, 2, true), endpoint(3, 2, true));
    connect(&mut a, &mut hub);
    connect(&mut c, &mut hub);
    for tag in 1..=2 {
        a.tun_write(&ipv4(tag)).unwrap();
        c.tun_write(&ipv4(tag + 2)).unwrap();
    }
    relay(&a, &mut hub, 2);
    relay(&c, &mut hub, 4);
    let mut got = hub.tun_read().collect::<Vec<_>>();
    got.sort();
    let mut expected = vec![ipv4(1), ipv4(2), ipv4(3), ipv4(4)];
    expected.sort();
    assert_eq!(got, expected);
    hub.tun_write(&ipv4(5)).unwrap();
    hub.tun_write(&ipv6(6)).unwrap();
    for (route, wire) in take_wire(&hub) {
        match route {
            2 => a.out_write(3, &wire),
            4 => c.out_write(3, &wire),
            _ => panic!("unexpected route"),
        }
    }
    assert_eq!(a.tun_read().collect::<Vec<_>>(), vec![ipv4(5)]);
    assert_eq!(c.tun_read().collect::<Vec<_>>(), vec![ipv6(6)]);
}

#[test]
fn maintenance_emits_keepalives_without_plaintext_or_byte_counters() {
    let mut acfg = endpoint(1, 2, true).config;
    acfg.interface.liveness.keepalive = Some(1);
    acfg.interface.liveness.keepalive_jitter = Some(0);
    let mut a = Endpoint::new(Capture::default(), acfg).unwrap();
    let mut b = endpoint(2, 1, false);
    connect(&mut a, &mut b);
    std::thread::sleep(std::time::Duration::from_millis(1050));
    a.advance();
    let wire = take_wire(&a);
    assert_eq!(wire.len(), 1);
    b.out_write(4, &wire[0].1);
    assert_eq!(route(&b), Some(4));
    assert!(b.tun_read().next().is_none());
    assert_eq!(sent(&a), 0);
    assert_eq!(received(&b), 0);
    let pong = take_wire(&b);
    assert_eq!(pong.len(), 1);
    a.out_write(1, &pong[0].1);
    assert!(a.tun_read().next().is_none());
    assert!(take_wire(&a).is_empty());
    assert_eq!(sent(&b), 0);
    assert_eq!(received(&a), 0);
}

#[test]
fn maintenance_rekeys_expired_session_and_preserves_queued_plaintext() {
    let mut cfg = endpoint(1, 2, true).config;
    cfg.interface.liveness.max_age = Some(1);
    cfg.interface.liveness.timeout = Some(0);
    let mut a = Endpoint::new(Capture::default(), cfg).unwrap();
    let mut b = endpoint(2, 1, false);
    connect(&mut a, &mut b);
    let first = index(&a);
    std::thread::sleep(std::time::Duration::from_millis(1050));
    a.tun_write(&ipv4(1)).unwrap();
    a.advance();
    assert_ne!(index(&a), first);
    relay(&a, &mut b, 2);
    relay(&b, &mut a, 3);
    relay(&a, &mut b, 2);
    assert_eq!(b.tun_read().collect::<Vec<_>>(), vec![ipv4(1)]);
    assert!(a.state.connected.values().all(|v| *v));
    let status = a.state.status(&a.config);
    assert!(status.peers[0].last_established_at > status.peers[0].first_established_at);
    assert_eq!(status.peers[0].sent, ipv4(1).len() as u64);
}

#[test]
fn maintenance_retries_lost_initiation_then_recovers() {
    let (mut a, mut b) = (endpoint(1, 2, true), endpoint(2, 1, false));
    a.advance();
    let first = index(&a);
    assert_eq!(take_wire(&a).len(), 1); // Drop the first initiation.
    a.tun_write(&ipv4(1)).unwrap();
    assert!(take_wire(&a).is_empty());
    std::thread::sleep(std::time::Duration::from_millis(10050));
    a.advance();
    assert_ne!(index(&a), first);
    assert_eq!(relay(&a, &mut b, 2), 1);
    relay(&b, &mut a, 3);
    relay(&a, &mut b, 2);
    assert_eq!(b.tun_read().collect::<Vec<_>>(), vec![ipv4(1)]);
}

#[test]
fn malformed_suffix_preserves_valid_prefix_and_next_datagram_recovers() {
    let (mut a, mut b) = (endpoint(1, 2, true), endpoint(2, 1, false));
    connect(&mut a, &mut b);
    a.tun_write(&ipv4(1)).unwrap();
    let mut wire = take_wire(&a).remove(0).1;
    // A complete invalid discriminator, rather than an incomplete tail.
    let bad = (0..=255)
        .map(|ty| vec![ty; 512])
        .find(|bytes| matches!(codec::parse_slice(bytes, &b.config.layout), Some(Err(_))))
        .unwrap();
    wire.extend_from_slice(&bad);
    b.out_write(2, &wire);
    assert_eq!(b.tun_read().collect::<Vec<_>>(), vec![ipv4(1)]);
    a.tun_write(&ipv4(2)).unwrap();
    relay(&a, &mut b, 2);
    assert_eq!(b.tun_read().collect::<Vec<_>>(), vec![ipv4(2)]);
}

#[test]
fn establishment_statistics_stay_stable_during_normal_traffic() {
    let (mut a, mut b) = (endpoint(1, 2, true), endpoint(2, 1, false));
    connect(&mut a, &mut b);
    let initial = a.state.status(&a.config);
    assert_eq!(initial.peers[0].status, "connected");
    assert!(initial.peers[0].first_established_at.is_some());
    assert_eq!(
        initial.peers[0].first_established_at,
        initial.peers[0].last_established_at
    );
    for tag in 0..4 {
        a.tun_write(&ipv4(tag)).unwrap();
    }
    relay(&a, &mut b, 2);
    b.tun_read().for_each(drop);
    for _ in 0..4 {
        a.advance();
        b.advance();
    }
    let after = a.state.status(&a.config);
    assert_eq!(after.session, initial.session);
    assert_eq!(
        after.peers[0].first_established_at,
        initial.peers[0].first_established_at
    );
    assert_eq!(
        after.peers[0].last_established_at,
        initial.peers[0].last_established_at
    );
    assert_eq!(after.peers[0].sent, (ipv4(0).len() * 4) as u64);
    assert_eq!(after.peers[0].received, 0);
    assert!(take_wire(&a).is_empty());
}

#[test]
fn unknown_identity_during_live_session_preserves_route_and_data_flow() {
    let (mut a, mut b) = (endpoint(1, 2, true), endpoint(2, 1, false));
    connect(&mut a, &mut b);
    let before = b.state.status(&b.config).peers[0].last_established_at;
    let mut stranger = endpoint(3, 2, true);
    stranger.advance();
    relay(&stranger, &mut b, 9);
    assert_eq!(route(&b), Some(2));
    assert_eq!(
        b.state.status(&b.config).peers[0].last_established_at,
        before
    );
    assert!(take_wire(&b).is_empty());
    a.tun_write(&ipv4(1)).unwrap();
    relay(&a, &mut b, 2);
    assert_eq!(b.tun_read().collect::<Vec<_>>(), vec![ipv4(1)]);
}

#[test]
fn tampered_handshake_is_rejected_without_preventing_valid_handshake() {
    let (mut a, mut b) = (endpoint(1, 2, true), endpoint(2, 1, false));
    a.advance();
    let initiation = take_wire(&a).remove(0).1;
    let mut bad = initiation.clone();
    *bad.last_mut().unwrap() ^= 1;
    b.out_write(9, &bad);
    assert_eq!(route(&b), None);
    assert!(take_wire(&b).is_empty());
    b.out_write(2, &initiation);
    let reply = take_wire(&b).remove(0).1;
    let mut bad = reply.clone();
    *bad.last_mut().unwrap() ^= 1;
    a.out_write(9, &bad);
    assert_eq!(route(&a), Some(1));
    assert!(!a.state.connected.values().any(|live| *live));
    a.out_write(3, &reply);
    assert_eq!(route(&a), Some(3));
    a.tun_write(&ipv4(1)).unwrap();
    relay(&a, &mut b, 2);
    assert_eq!(b.tun_read().collect::<Vec<_>>(), vec![ipv4(1)]);
}

#[test]
fn full_mtu_packets_survive_padded_layout_without_truncation() {
    let layout = crate::codec::PacketLayout::random();
    let mut a = configure(endpoint(1, 2, true).config, layout, None);
    let mut b = configure(endpoint(2, 1, false).config, layout, None);
    connect(&mut a, &mut b);
    let mut packet = etherparse::Ipv4Header::new(
        1380,
        64,
        etherparse::IpNumber::UDP,
        [10, 0, 0, 1],
        [10, 0, 0, 2],
    )
    .unwrap()
    .to_bytes()
    .to_vec();
    packet.extend((0..1380).map(|n| (n % 251) as u8));
    assert_eq!(packet.len(), 1400);
    a.tun_write(&packet).unwrap();
    relay(&a, &mut b, 2);
    assert_eq!(b.tun_read().collect::<Vec<_>>(), vec![packet]);
    assert_eq!(received(&b), 1400);
}

#[test]
fn maintenance_recovers_lost_handshake_reply() {
    let (mut a, mut b) = (endpoint(1, 2, true), endpoint(2, 1, false));
    a.tun_write(&ipv4(1)).unwrap();
    relay(&a, &mut b, 2);
    assert_eq!(take_wire(&b).len(), 1); // Drop responder's reply.
    std::thread::sleep(std::time::Duration::from_millis(10050));
    a.advance();
    relay(&a, &mut b, 2);
    relay(&b, &mut a, 3);
    relay(&a, &mut b, 2);
    assert_eq!(b.tun_read().collect::<Vec<_>>(), vec![ipv4(1)]);
    assert!(a.state.connected.values().all(|v| *v));
}

#[test]
fn peer_liveness_override_expires_idle_session_despite_disabled_interface_timeout() {
    let mut cfg = endpoint(1, 2, true).config;
    cfg.interface.liveness.timeout = Some(0);
    cfg.interface.liveness.max_age = Some(0);
    cfg.peers[0].liveness.timeout = Some(1);
    let mut a = Endpoint::new(Capture::default(), cfg).unwrap();
    let mut b = endpoint(2, 1, false);
    connect(&mut a, &mut b);
    let old = index(&a);
    std::thread::sleep(std::time::Duration::from_millis(1050));
    a.advance();
    assert!(!a.state.connected.values().any(|v| *v));
    a.advance();
    assert_ne!(index(&a), old);
    relay(&a, &mut b, 2);
    relay(&b, &mut a, 3);
    a.tun_write(&ipv4(1)).unwrap();
    relay(&a, &mut b, 2);
    assert_eq!(b.tun_read().collect::<Vec<_>>(), vec![ipv4(1)]);
}

#[test]
fn datagram_api_rejects_truncated_trailing_and_concatenated_frames_atomically() {
    let (mut a, mut b) = (endpoint(1, 2, true), endpoint(2, 1, false));
    a.advance();
    let initiation = take_wire(&a).remove(0).1;
    for end in 0..initiation.len() {
        b.out_write_datagram(9, &initiation[..end]);
    }
    let mut trailing = initiation.clone();
    trailing.push(0);
    b.out_write_datagram(9, &trailing);
    let mut concatenated = initiation.clone();
    concatenated.extend_from_slice(&initiation);
    b.out_write_datagram(9, &concatenated);
    assert_eq!(route(&b), None);
    assert!(take_wire(&b).is_empty());
    b.out_write_datagram(2, &initiation);
    assert_eq!(route(&b), Some(2));
    relay(&b, &mut a, 3);
    assert_eq!(a.status().peers[0].status, "connected");
}

struct Hooks {
    capture: Capture,
    calls: RefCell<Vec<(Option<u8>, u8, Vec<u8>)>>,
}
impl Adapter for Hooks {
    type Route = u8;
    fn peer_route(&self, peer: &Peer) -> Option<u8> {
        self.capture.peer_route(peer)
    }
    fn deliver(&self, route: u8, packet: Packet) {
        self.capture.deliver(route, packet);
    }
    fn accepts(&self, _: Option<&u8>, incoming: &u8, _: &Packet) -> bool {
        *incoming != 9
    }
    fn route_changed<'a>(
        &self,
        previous: Option<&u8>,
        next: &u8,
        others: impl Iterator<Item = &'a u8>,
    ) -> Result<()> {
        self.calls
            .borrow_mut()
            .push((previous.copied(), *next, others.copied().collect()));
        if *next == 8 {
            return Err(Error::adapter("route side effect failed"));
        }
        Ok(())
    }
}

#[test]
fn adapter_validation_prevents_processing_and_route_hook_precedes_commit() {
    let mut a = endpoint(1, 2, true);
    let mut config = endpoint(2, 1, false).config;
    let other = endpoint(2, 3, true).config.peers.remove(0);
    config.peers.push(other);
    let peer_id = config.peers[0].id;
    let mut b = Endpoint::new(
        Hooks {
            capture: Capture::default(),
            calls: RefCell::new(Vec::new()),
        },
        config,
    )
    .unwrap();
    a.advance();
    let initiation = take_wire(&a).remove(0).1;
    b.out_write_datagram(9, &initiation);
    assert!(b.adapter().calls.borrow().is_empty());
    assert!(!b.peers[&peer_id].tunnel.is_live());
    b.out_write_datagram(2, &initiation);
    assert_eq!(*b.adapter().calls.borrow(), vec![(None, 2, vec![1])]);
    assert_eq!(b.peers[&peer_id].address, Some(2));
    let reply = b
        .adapter()
        .capture
        .0
        .take()
        .remove(0)
        .1
        .to_bytes(&b.config.layout)
        .unwrap();
    a.out_write_datagram(3, &reply);
    a.tun_write(&ipv4(1)).unwrap();
    b.out_write_datagram(8, &take_wire(&a).remove(0).1);
    assert_eq!(b.peers[&peer_id].address, Some(2));
    a.tun_write(&ipv4(2)).unwrap();
    b.out_write_datagram(4, &take_wire(&a).remove(0).1);
    assert_eq!(b.peers[&peer_id].address, Some(4));
    let calls = b.adapter().calls.borrow();
    assert_eq!(calls[1], (Some(2), 8, vec![1]));
    assert_eq!(calls[2], (Some(2), 4, vec![1]));
}

#[test]
fn unsupported_peers_cannot_handshake_or_receive_tun_traffic() {
    struct Reject;
    impl Adapter for Reject {
        type Route = u8;
        fn supports_peer(&self, _: &Peer) -> bool {
            false
        }
        fn peer_route(&self, _: &Peer) -> Option<u8> {
            panic!("unsupported peer should not be initialized")
        }
        fn deliver(&self, _: u8, _: Packet) {
            panic!("unsupported peer should not receive traffic")
        }
    }
    let mut a = endpoint(1, 2, true);
    let mut b = Endpoint::new(Reject, endpoint(2, 1, false).config).unwrap();
    a.advance();
    b.out_write_datagram(2, &take_wire(&a).remove(0).1);
    b.tun_write(&ipv4(1)).unwrap();
    b.advance();
    assert!(b.peers.is_empty());
    assert_eq!(b.status().peers[0].status, "disconnected");
    assert_eq!(b.status().peers[0].sent, 0);
}
