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

#[cfg(target_os = "linux")]
#[tokio::test]
async fn recvmmsg_reads_multiple_sources_in_one_batch_and_reuses_storage() {
    use crate::{
        network::Socket as _,
        network::{MAX_DATAGRAM, ReceiveBatch},
    };
    let cfg = harness::config(2, &[(1, None)]);
    let (socket, _) = Udp::bind(&cfg, &UdpListenerConfig { port: 0 })
        .await
        .unwrap();
    let address = SocketAddr::from((
        Ipv4Addr::LOCALHOST,
        socket.socket.local_addr().unwrap().port(),
    ));
    let a = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let b = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    for i in 0..batch::BATCH_SIZE {
        let source = if i % 2 == 0 { &a } else { &b };
        source.send_to(&[i as u8; 17], address).await.unwrap();
    }
    let mut received = ReceiveBatch::new(batch::BATCH_SIZE, MAX_DATAGRAM);
    let allocation = received.buffer.as_ptr();
    timeout(Duration::from_secs(1), socket.receive(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received.packets.len(), batch::BATCH_SIZE);
    for (i, (source, range)) in received.packets.iter().enumerate() {
        assert_eq!(
            *source,
            if i % 2 == 0 {
                a.local_addr().unwrap()
            } else {
                b.local_addr().unwrap()
            }
        );
        assert_eq!(&received.buffer[range.clone()], &[i as u8; 17]);
    }
    received.packets.clear();
    a.send_to(b"x", address).await.unwrap();
    timeout(Duration::from_secs(1), socket.receive(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received.buffer.as_ptr(), allocation);
    assert_eq!(received.packets.len(), 1);
    assert_eq!(&received.buffer[received.packets[0].1.clone()], b"x");
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn recvmmsg_drops_truncation_but_preserves_empty_and_following_datagrams() {
    use std::os::fd::AsRawFd;
    let receiver = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = receiver.local_addr().unwrap();
    sender.send_to(&[1; 20], address).await.unwrap();
    sender.send_to(&[], address).await.unwrap();
    sender.send_to(b"abc", address).await.unwrap();
    let mut received = crate::network::ReceiveBatch::new(4, 4);
    batch::receive(receiver.as_raw_fd(), &mut received).unwrap();
    assert_eq!(received.packets.len(), 2);
    assert!(received.packets[0].1.is_empty());
    assert_eq!(&received.buffer[received.packets[1].1.clone()], b"abc");
    received.packets.clear();
    assert_eq!(
        batch::receive(receiver.as_raw_fd(), &mut received)
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn sendmmsg_partial_prefix_reports_progress_before_invalid_datagram() {
    use bytes::Bytes;
    use std::os::fd::AsRawFd;
    let receiver = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = receiver.local_addr().unwrap();
    let packets = vec![
        (address, Bytes::from_static(b"first")),
        (address, Bytes::from(vec![0; 65508])),
        (address, Bytes::from_static(b"last")),
    ];
    assert_eq!(batch::send(sender.as_raw_fd(), &packets).unwrap(), 1);
    assert_eq!(
        batch::send(sender.as_raw_fd(), &packets[1..])
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EMSGSIZE)
    );
    assert_eq!(batch::send(sender.as_raw_fd(), &packets[2..]).unwrap(), 1);
    let mut buffer = [0; 32];
    for expected in [b"first".as_slice(), b"last"] {
        let len = timeout(Duration::from_secs(1), receiver.recv(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buffer[..len], expected);
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn flush_handles_multiple_batches_and_partial_sends_without_duplicates() {
    use crate::network::Socket as _;
    let cfg = harness::config(2, &[(1, None)]);
    let (socket, endpoint) = Udp::bind(&cfg, &UdpListenerConfig { port: 0 })
        .await
        .unwrap();
    let receiver = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = receiver.local_addr().unwrap();
    let count = batch::BATCH_SIZE * 2 + 3;
    for i in 0..count {
        // Force sendmmsg to stop after a valid prefix, then fail on its tail.
        if i == 3 {
            endpoint.adapter().deliver(
                address,
                Packet::Data(Data {
                    receiver_idx: 1,
                    counter: 9999,
                    flags: DataFlags::empty(),
                    ciphertext: vec![0; 65536],
                }),
            );
        }
        endpoint.adapter().deliver(
            address,
            Packet::Data(Data {
                receiver_idx: 1,
                counter: i as u64,
                flags: DataFlags::empty(),
                ciphertext: vec![i as u8; 16],
            }),
        );
    }
    socket.flush(endpoint.adapter()).await.unwrap();
    let mut buffer = [0; 1024];
    for i in 0..count {
        let len = timeout(Duration::from_secs(1), receiver.recv(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        let (packet, used) = codec::parse_slice(&buffer[..len], &cfg.layout)
            .unwrap()
            .unwrap();
        assert_eq!(used, len);
        let Packet::Data(data) = packet else {
            panic!("expected data")
        };
        assert_eq!(data.counter, i as u64);
        assert_eq!(data.ciphertext, vec![i as u8; 16]);
    }
    assert!(receiver.try_recv(&mut buffer).is_err());
    assert!(endpoint.adapter().pending.lock().unwrap().is_empty());
}

#[tokio::test]
async fn encrypted_udp_burst_survives_receive_and_send_batch_boundaries() {
    let (address, mut server) = start(&harness::config(2, &[(1, None)])).await;
    let (_, mut client) = start(&harness::config(1, &[(2, Some(address))])).await;
    connected(&client).await;
    // More than two syscall batches, with concurrent draining to exercise the
    // bounded TUN queues in both directions rather than overflowing them.
    let count = 75;
    let send = async {
        for i in 0..count {
            client.sender.send(packet(1, 2, i + 1)).await.unwrap();
        }
    };
    let read = async {
        for i in 0..count {
            assert_eq!(receive(&mut server).await, packet(1, 2, i + 1));
        }
    };
    timeout(Duration::from_secs(5), async {
        tokio::join!(send, read);
    })
    .await
    .unwrap();
    let send = async {
        for i in 0..count {
            server.sender.send(packet(2, 1, i + 1)).await.unwrap();
        }
    };
    let read = async {
        for i in 0..count {
            assert_eq!(receive(&mut client).await, packet(2, 1, i + 1));
        }
    };
    timeout(Duration::from_secs(5), async {
        tokio::join!(send, read);
    })
    .await
    .unwrap();
}
