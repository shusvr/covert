use super::*;
use crate::network::tests::{self as harness, Node, connected, packet, receive};
use covert::codec;
use covert::{
    codec::{Data, DataFlags},
    tunnel::Tunnel,
};
use tokio::time::{Duration, timeout};

async fn start(config: &Config) -> (SocketAddr, Node) {
    let (socket, endpoint) = Udp::bind(config, &UdpListenerConfig { port: 0 })
        .await
        .unwrap();
    let address = SocketAddr::from((
        Ipv4Addr::LOCALHOST,
        socket.socket.local_addr().unwrap().port(),
    ));
    (address, harness::spawn(socket, endpoint))
}

#[tokio::test]
async fn passive_peer_flushes_queued_bidirectional_packets_and_updates_status() {
    let (server_addr, mut server) = start(&harness::config(2, &[(1, None)])).await;
    server.sender.send(packet(2, 1, 25)).await.unwrap();
    let (_, mut client) = start(&harness::config(1, &[(2, Some(server_addr))])).await;
    for size in [25, 50, 100] {
        client.sender.send(packet(1, 2, size)).await.unwrap();
    }
    for size in [25, 50, 100] {
        assert_eq!(receive(&mut server).await, packet(1, 2, size));
    }
    assert_eq!(receive(&mut client).await, packet(2, 1, 25));
    connected(&client).await;
    connected(&server).await;
    let status = server.status.borrow().clone();
    assert_eq!(status.peers[0].sent, 45);
    assert_eq!(status.peers[0].received, 235);
    assert!(status.peers[0].first_established_at.is_some());
}

#[tokio::test]
async fn malformed_datagrams_do_not_poison_live_sessions() {
    let cfg = harness::config(2, &[(1, None)]);
    let (address, mut server) = start(&cfg).await;
    let (_, mut client) = start(&harness::config(1, &[(2, Some(address))])).await;
    connected(&client).await;
    let noise = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    for bytes in [vec![], vec![255; 512], vec![0; 3]] {
        noise.send_to(&bytes, address).await.unwrap();
    }
    let bogus = Packet::Data(Data {
        receiver_idx: 123,
        counter: 1,
        flags: DataFlags::empty(),
        ciphertext: vec![0; 16],
    })
    .to_bytes(&cfg.layout)
    .unwrap();
    noise.send_to(&bogus, address).await.unwrap();
    client.sender.send(packet(1, 2, 40)).await.unwrap();
    assert_eq!(receive(&mut server).await, packet(1, 2, 40));
    server.sender.send(packet(2, 1, 40)).await.unwrap();
    assert_eq!(receive(&mut client).await, packet(2, 1, 40));
}

#[tokio::test]
async fn padded_layout_preserves_full_mtu_and_multiple_peers() {
    let layout = PacketLayout::random();
    let mut cfg = harness::config(2, &[(1, None), (3, None)]);
    cfg.layout = layout;
    let (address, mut server) = start(&cfg).await;
    let mut cfg = harness::config(1, &[(2, Some(address))]);
    cfg.layout = layout;
    let (_, mut a) = start(&cfg).await;
    let mut cfg = harness::config(3, &[(2, Some(address))]);
    cfg.layout = layout;
    let (_, mut c) = start(&cfg).await;
    a.sender.send(packet(1, 2, 1380)).await.unwrap();
    c.sender.send(packet(3, 2, 1380)).await.unwrap();
    let mut got = vec![receive(&mut server).await, receive(&mut server).await];
    got.sort();
    let mut expected = vec![packet(1, 2, 1380), packet(3, 2, 1380)];
    expected.sort();
    assert_eq!(got, expected);
    server.sender.send(packet(2, 1, 30)).await.unwrap();
    server.sender.send(packet(2, 3, 40)).await.unwrap();
    assert_eq!(receive(&mut a).await, packet(2, 1, 30));
    assert_eq!(receive(&mut c).await, packet(2, 3, 40));
}

async fn recv_packet(socket: &UdpSocket, cfg: &Config) -> Packet {
    let mut bytes = vec![0; 65535];
    let len = timeout(Duration::from_secs(3), socket.recv(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    codec::parse_slice(&bytes[..len], &cfg.layout)
        .unwrap()
        .unwrap()
        .0
}

#[tokio::test]
async fn rejects_trailing_frames_and_only_authenticated_data_can_move_udp_route() {
    let cfg = harness::config(2, &[(1, None)]);
    let (address, mut server) = start(&cfg).await;
    let a = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let b = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let pk = covert::crypto::pk_to_bytes(
        &covert::crypto::to_sk(&[2; 32])
            .compute_public_key()
            .unwrap(),
    );
    let mut client = Tunnel::new(
        cfg.layout,
        [1; 32],
        cfg.interface
            .liveness
            .unpack_with_fallback(&cfg.interface.liveness),
        pk,
        Some([7; 32]),
    );
    client.initiate().unwrap();
    client.process_new_packets(true).unwrap();
    let initiation = client.read_outbound().unwrap().unwrap();
    let mut trailing = initiation.to_vec();
    trailing.push(0);
    a.send_to(&trailing, address).await.unwrap();
    assert!(
        timeout(Duration::from_millis(100), a.recv(&mut [0; 1024]))
            .await
            .is_err()
    );
    a.send_to(&initiation, address).await.unwrap();
    let reply = recv_packet(&a, &cfg).await;
    client.process_incoming_packet(reply).unwrap();
    client.push_packet(&packet(1, 2, 30));
    client.process_new_packets(true).unwrap();
    let data = client.read_outbound().unwrap().unwrap();
    let mut forged = data.to_vec();
    *forged.last_mut().unwrap() ^= 1;
    b.send_to(&forged, address).await.unwrap();
    server.sender.send(packet(2, 1, 40)).await.unwrap();
    client
        .process_incoming_packet(recv_packet(&a, &cfg).await)
        .unwrap();
    assert_eq!(client.read_packet().unwrap(), packet(2, 1, 40));
    b.send_to(&data, address).await.unwrap();
    assert_eq!(receive(&mut server).await, packet(1, 2, 30));
    server.sender.send(packet(2, 1, 50)).await.unwrap();
    client
        .process_incoming_packet(recv_packet(&b, &cfg).await)
        .unwrap();
    assert_eq!(client.read_packet().unwrap(), packet(2, 1, 50));
}

#[tokio::test]
async fn closing_tun_receiver_stops_socket_worker() {
    let (_, mut node) = start(&harness::config(2, &[(1, None)])).await;
    node.receiver.close();
    timeout(Duration::from_secs(1), &mut node.task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(node.sender.send(packet(2, 1, 1)).await.is_err());
}
