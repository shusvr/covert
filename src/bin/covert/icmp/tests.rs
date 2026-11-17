use super::*;
use crate::network::tests::{self as harness, packet};
use covert::transport::IcmpTransportPeerConfig;
use std::time::Duration;
use tokio::time::timeout;

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
        assert_eq!(
            echo_payload(&bytes, 1340, IcmpMode::EchoReply).is_some(),
            !ty
        );
        assert_eq!(
            echo_payload(&bytes, 1340, IcmpMode::OnlyEcho).is_some(),
            !ty
        );
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

fn config(local: u8, remote: u8, active: bool, mode: IcmpMode) -> Config {
    let mut cfg = harness::config(local, &[(remote, None)]);
    cfg.interface.listener = covert::config::ListenerConfig::Icmp {
        icmp: IcmpListenerConfig { mode },
    };
    cfg.peers[0].transport = PeerTransport::Icmp {
        icmp: IcmpTransportPeerConfig {
            endpoint: active.then_some(Ipv4Addr::new(192, 0, 2, remote)),
        },
    };
    cfg
}

struct Node {
    endpoint: Endpoint<EchoAdapter>,
    encoder: EchoEncoder,
    address: Ipv4Addr,
}
impl Node {
    fn new(local: u8, remote: u8, active: bool, mode: IcmpMode, layout: PacketLayout) -> Self {
        let mut cfg = config(local, remote, active, mode);
        cfg.layout = layout;
        let adapter = EchoAdapter {
            mode,
            pending: Mutex::new(Vec::new()),
            firewall: None,
        };
        let endpoint = Endpoint::new(adapter, cfg).unwrap();
        let mut encoder = EchoEncoder::new(layout, &IcmpListenerConfig { mode });
        encoder.id = 5000 + u16::from(local);
        Self {
            endpoint,
            encoder,
            address: Ipv4Addr::new(192, 0, 2, local),
        }
    }
    fn outgoing(&mut self) -> Vec<Vec<u8>> {
        let pending = std::mem::take(&mut *self.endpoint.adapter().pending.lock().unwrap());
        pending
            .into_iter()
            .map(|(route, packet)| {
                let icmp = self.encoder.encode(packet, &route).unwrap();
                let mut wire = etherparse::Ipv4Header::new(
                    icmp.len() as u16,
                    64,
                    etherparse::IpNumber::ICMP,
                    self.address.octets(),
                    route.address.octets(),
                )
                .unwrap()
                .to_bytes()
                .to_vec();
                wire.extend_from_slice(icmp);
                wire
            })
            .collect()
    }
    fn receive(&mut self, wire: &[u8]) {
        if let Some((route, payload)) = incoming(wire, &self.encoder) {
            self.endpoint.out_write_datagram(route, &wire[payload]);
        }
    }
    fn send(&mut self, packet: &[u8]) {
        self.endpoint.tun_write(packet).unwrap();
    }
    fn read(&mut self) -> Vec<Vec<u8>> {
        self.endpoint.tun_read().collect()
    }
}
fn transfer(from: &mut Node, to: &mut Node) -> Vec<Vec<u8>> {
    let wires = from.outgoing();
    for wire in &wires {
        to.receive(wire);
    }
    wires
}
fn pair(mode: IcmpMode, layout: PacketLayout) -> (Node, Node) {
    let mut a = Node::new(1, 2, true, mode, layout);
    let mut b = Node::new(2, 1, false, mode, layout);
    a.endpoint.advance();
    let request = transfer(&mut a, &mut b);
    assert_eq!(request[0][20], 8);
    let reply = transfer(&mut b, &mut a);
    assert_eq!(
        reply[0][20],
        if mode == IcmpMode::EchoReply { 0 } else { 8 }
    );
    if mode == IcmpMode::EchoReply {
        assert_eq!(&reply[0][24..28], &request[0][24..28]);
    }
    assert_eq!(a.endpoint.status().peers[0].status, "connected");
    assert_eq!(b.endpoint.status().peers[0].status, "connected");
    (a, b)
}

#[test]
fn handshake_and_bidirectional_data_preserve_icmp_metadata_in_both_modes() {
    for mode in [IcmpMode::EchoReply, IcmpMode::OnlyEcho] {
        for layout in [PacketLayout::default(), PacketLayout::random()] {
            let (mut a, mut b) = pair(mode, layout);
            a.send(&packet(1, 2, 40));
            let request = transfer(&mut a, &mut b);
            assert_eq!(b.read(), vec![packet(1, 2, 40)]);
            b.send(&packet(2, 1, 50));
            let reply = transfer(&mut b, &mut a);
            assert_eq!(a.read(), vec![packet(2, 1, 50)]);
            if mode == IcmpMode::EchoReply {
                assert_eq!(&reply[0][24..28], &request[0][24..28]);
            }
            assert_eq!(a.endpoint.status().peers[0].sent, 60);
            assert_eq!(b.endpoint.status().peers[0].received, 60);
        }
    }
}

fn rewrite(wire: &mut [u8], id: u16, reply: bool) {
    let offset = usize::from(wire[0] & 15) * 4;
    let seq = u16::from_be_bytes([wire[offset + 6], wire[offset + 7]]);
    let echo = etherparse::IcmpEchoHeader { id, seq };
    let kind = if reply {
        etherparse::Icmpv4Type::EchoReply(echo)
    } else {
        etherparse::Icmpv4Type::EchoRequest(echo)
    };
    let header = etherparse::Icmpv4Header::with_checksum(kind, &wire[offset + 8..]);
    wire[offset..offset + 8].copy_from_slice(&header.to_bytes());
}

#[test]
fn nat_rewritten_ids_are_authenticated_and_echoed_in_replies() {
    let (mut a, mut b) = (
        Node::new(1, 2, true, IcmpMode::EchoReply, Default::default()),
        Node::new(2, 1, false, IcmpMode::EchoReply, Default::default()),
    );
    a.endpoint.advance();
    let mut initiation = a.outgoing().remove(0);
    rewrite(&mut initiation, 14655, false);
    let mut bad = initiation.clone();
    *bad.last_mut().unwrap() ^= 1;
    rewrite(&mut bad, 14655, false);
    b.receive(&bad);
    assert!(b.outgoing().is_empty());
    b.receive(&initiation);
    let mut reply = b.outgoing().remove(0);
    assert_eq!(u16::from_be_bytes([reply[24], reply[25]]), 14655);
    rewrite(&mut reply, a.encoder.id, true);
    a.receive(&reply);
    a.send(&packet(1, 2, 25));
    let mut data = a.outgoing().remove(0);
    rewrite(&mut data, 14656, false);
    b.receive(&data);
    assert_eq!(b.read(), vec![packet(1, 2, 25)]);
    b.send(&packet(2, 1, 30));
    let mut response = b.outgoing().remove(0);
    assert_eq!(u16::from_be_bytes([response[24], response[25]]), 14656);
    rewrite(&mut response, a.encoder.id, true);
    a.receive(&response);
    assert_eq!(a.read(), vec![packet(2, 1, 30)]);
}

#[test]
fn malformed_or_unauthenticated_requests_cannot_replace_reply_metadata() {
    for mode in [IcmpMode::EchoReply, IcmpMode::OnlyEcho] {
        let (mut a, mut b) = pair(mode, Default::default());
        a.send(&packet(1, 2, 25));
        let valid = a.outgoing().remove(0);
        let mut bad = valid.clone();
        *bad.last_mut().unwrap() ^= 1;
        rewrite(&mut bad, 9999, false);
        b.receive(&bad);
        let mut moved = valid.clone();
        moved[15] ^= 1;
        b.receive(&moved);
        let mut trailing = valid.clone();
        trailing.push(0);
        let len = trailing.len() as u16;
        trailing[2..4].copy_from_slice(&len.to_be_bytes());
        rewrite(&mut trailing, 9999, false);
        b.receive(&trailing);
        assert!(b.read().is_empty());
        b.send(&packet(2, 1, 30));
        let reply = b.outgoing().remove(0);
        if mode == IcmpMode::EchoReply {
            assert_eq!(u16::from_be_bytes([reply[24], reply[25]]), a.encoder.id);
        }
        b.receive(&valid);
        assert_eq!(b.read(), vec![packet(1, 2, 25)]);
    }
}

#[test]
fn wrong_echo_type_and_wrong_reply_identifier_are_rejected() {
    let (mut a, mut b) = (
        Node::new(1, 2, true, IcmpMode::EchoReply, Default::default()),
        Node::new(2, 1, false, IcmpMode::EchoReply, Default::default()),
    );
    a.endpoint.advance();
    let initiation = a.outgoing().remove(0);
    let mut bad = initiation.clone();
    rewrite(&mut bad, b.encoder.id, true);
    b.receive(&bad);
    assert!(b.outgoing().is_empty());
    b.receive(&initiation);
    let reply = b.outgoing().remove(0);
    let mut bad = reply.clone();
    rewrite(&mut bad, a.encoder.id + 1, true);
    a.receive(&bad);
    assert_eq!(a.endpoint.status().peers[0].status, "disconnected");
    let mut bad = reply.clone();
    rewrite(&mut bad, a.encoder.id, false);
    a.receive(&bad);
    assert_eq!(a.endpoint.status().peers[0].status, "disconnected");
    a.receive(&reply);
    assert_eq!(a.endpoint.status().peers[0].status, "connected");
}

#[test]
fn simultaneous_initiations_converge_with_icmp_role_checks() {
    for mode in [IcmpMode::EchoReply, IcmpMode::OnlyEcho] {
        let (mut a, mut b) = (
            Node::new(1, 2, true, mode, Default::default()),
            Node::new(2, 1, true, mode, Default::default()),
        );
        a.endpoint.advance();
        b.endpoint.advance();
        for _ in 0..4 {
            transfer(&mut a, &mut b);
            transfer(&mut b, &mut a);
        }
        a.send(&packet(1, 2, 30));
        transfer(&mut a, &mut b);
        assert_eq!(b.read(), vec![packet(1, 2, 30)]);
        b.send(&packet(2, 1, 30));
        transfer(&mut b, &mut a);
        assert_eq!(a.read(), vec![packet(2, 1, 30)]);
    }
}

#[test]
fn passive_peer_flushes_queued_plaintext_after_authenticated_handshake() {
    let (mut a, mut b) = (
        Node::new(1, 2, true, IcmpMode::EchoReply, Default::default()),
        Node::new(2, 1, false, IcmpMode::EchoReply, Default::default()),
    );
    b.send(&packet(2, 1, 40));
    assert!(b.outgoing().is_empty());
    a.endpoint.advance();
    transfer(&mut a, &mut b);
    transfer(&mut b, &mut a);
    assert_eq!(a.read(), vec![packet(2, 1, 40)]);
}

#[test]
fn responder_rekey_is_sent_as_request_and_switches_roles() {
    let mode = IcmpMode::EchoReply;
    let (_, mut b) = pair(mode, Default::default());
    // Reconstruct a configured responder with a short maximum age, then drive
    // rekey through public maintenance rather than reaching into tunnel state.
    let mut cfg = config(2, 1, false, mode);
    cfg.interface.liveness.max_age = Some(1);
    b.endpoint = Endpoint::new(
        EchoAdapter {
            mode,
            pending: Mutex::new(Vec::new()),
            firewall: None,
        },
        cfg,
    )
    .unwrap();
    // Establish this fresh responder with a new initiator.
    let mut a = Node::new(1, 2, true, mode, Default::default());
    a.endpoint.advance();
    transfer(&mut a, &mut b);
    transfer(&mut b, &mut a);
    std::thread::sleep(Duration::from_millis(1050));
    b.endpoint.advance();
    b.endpoint.advance();
    let request = transfer(&mut b, &mut a);
    assert_eq!(request[0][20], 8);
    let reply = transfer(&mut a, &mut b);
    assert_eq!(reply[0][20], 0);
    b.send(&packet(2, 1, 40));
    transfer(&mut b, &mut a);
    assert_eq!(a.read(), vec![packet(2, 1, 40)]);
}

#[tokio::test]
#[ignore = "requires isolated net namespace with CAP_NET_RAW, CAP_NET_ADMIN and nft"]
async fn raw_socket_handshake_and_bidirectional_data_in_both_modes() {
    for mode in [IcmpMode::EchoReply, IcmpMode::OnlyEcho] {
        let mut bcfg = config(2, 1, false, mode);
        bcfg.peers[0].transport = PeerTransport::None;
        let (bs, be) = Icmp::bind(&bcfg, &IcmpListenerConfig { mode }).unwrap();
        let mut b = harness::spawn(bs, be);
        let mut acfg = config(1, 2, true, mode);
        acfg.peers[0].transport = PeerTransport::Icmp {
            icmp: IcmpTransportPeerConfig {
                endpoint: Some(Ipv4Addr::LOCALHOST),
            },
        };
        let (asocket, ae) = Icmp::bind(&acfg, &IcmpListenerConfig { mode }).unwrap();
        let mut a = harness::spawn(asocket, ae);
        a.sender.send(packet(1, 2, 40)).await.unwrap();
        assert_eq!(harness::receive(&mut b).await, packet(1, 2, 40));
        b.sender.send(packet(2, 1, 50)).await.unwrap();
        assert_eq!(harness::receive(&mut a).await, packet(2, 1, 50));
        a.task.abort();
        b.task.abort();
        let _ = (&mut a.task).await;
        let _ = (&mut b.task).await;
    }
}

#[test]
#[ignore = "requires isolated net namespace with CAP_NET_ADMIN and nft"]
fn reply_filter_migrates_and_retains_shared_pairs() {
    let filter = ReplyFilter::install(43396).unwrap();
    let address = Ipv4Addr::new(192, 0, 2, 1);
    let old = IcmpRoute::response(address, 14655, 7);
    let new = IcmpRoute::response(address, 14656, 7);
    filter
        .update_route(None, old.reply_key(), std::iter::empty())
        .unwrap();
    // Another peer already shares the old ID, so migration must retain it.
    filter
        .update_route(old.reply_key(), new.reply_key(), std::iter::once(&old))
        .unwrap();
    let dump = Command::new("nft")
        .args(["list", "set", "ip", &filter.table, "reply_peers"])
        .output()
        .unwrap();
    let dump = String::from_utf8_lossy(&dump.stdout);
    assert!(dump.contains("14655") && dump.contains("14656"));
    filter
        .update_route(old.reply_key(), new.reply_key(), std::iter::once(&new))
        .unwrap();
    let dump = Command::new("nft")
        .args(["list", "set", "ip", &filter.table, "reply_peers"])
        .output()
        .unwrap();
    let dump = String::from_utf8_lossy(&dump.stdout);
    assert!(!dump.contains("14655") && dump.contains("14656"));
    let table = filter.table.clone();
    drop(filter);
    assert!(
        !Command::new("nft")
            .args(["list", "table", "ip", &table])
            .output()
            .unwrap()
            .status
            .success()
    );
}

#[tokio::test]
#[ignore = "requires isolated net namespace with CAP_NET_RAW, CAP_NET_ADMIN and nft"]
async fn suppresses_automatic_kernel_replies_and_cleans_up() {
    let cfg = config(2, 1, false, IcmpMode::EchoReply);
    let (socket, endpoint) = Icmp::bind(
        &cfg,
        &IcmpListenerConfig {
            mode: IcmpMode::EchoReply,
        },
    )
    .unwrap();
    let table = endpoint.adapter().firewall.as_ref().unwrap().table.clone();
    let id = socket.encoder.lock().unwrap().id;
    let mut node = harness::spawn(socket, endpoint);
    let raw = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)).unwrap();
    raw.set_nonblocking(true).unwrap();
    let raw = unsafe {
        AsyncFd::register(raw)
            .map_err(|e| e.into_parts().1)
            .unwrap()
    };
    let payload = b"probe";
    let mut wire = etherparse::Icmpv4Header::with_checksum(
        etherparse::Icmpv4Type::EchoRequest(etherparse::IcmpEchoHeader { id, seq: 1 }),
        payload,
    )
    .to_bytes()
    .to_vec();
    wire.extend_from_slice(payload);
    raw.get_ref()
        .send_to(&wire, &SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0).into())
        .unwrap();
    let mut buffer = [MaybeUninit::uninit(); 4096];
    let len = timeout(
        Duration::from_secs(1),
        raw.async_io(tokio::io::Interest::READABLE, |s| s.recv(&mut buffer)),
    )
    .await
    .unwrap()
    .unwrap();
    let bytes = unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), len) };
    assert_eq!(bytes[20], 8);
    assert!(
        timeout(
            Duration::from_millis(100),
            raw.async_io(tokio::io::Interest::READABLE, |s| s.recv(&mut buffer))
        )
        .await
        .is_err()
    );
    node.receiver.close();
    timeout(Duration::from_secs(1), &mut node.task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(
        !Command::new("nft")
            .args(["list", "table", "ip", &table])
            .output()
            .unwrap()
            .status
            .success()
    );
}
