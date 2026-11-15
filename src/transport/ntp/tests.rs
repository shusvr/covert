use super::*;
use crate::codec::{Data, DataFlags, PacketLayout};

#[test]
fn framing_timestamps_padding_and_malformed_packets() {
    let layout = PacketLayout {
        odp: 1300,
        ..PacketLayout::default()
    };
    let packet = Packet::Data(Data {
        receiver_idx: 5,
        counter: 3,
        flags: DataFlags::empty(),
        ciphertext: vec![7; 17],
    });
    let request = encode(Some(packet), &layout, None, 4, 123).unwrap();
    assert_eq!(request.len() % 4, 0);
    let parsed = decode(&request).unwrap();
    assert!(!parsed.server);
    assert_eq!(parsed.transmit, 123);
    assert_eq!(parsed.payload.len(), 1300);
    let mut data = BytesMut::from(parsed.payload);
    assert!(matches!(
        codec::parse(&mut data, &layout),
        Some(Ok(Packet::Data(_)))
    ));
    assert!(data.is_empty());
    let reply = encode(
        None,
        &layout,
        Some(Query {
            transmit: 123,
            received: 124,
            poll: 4,
        }),
        4,
        125,
    )
    .unwrap();
    let parsed = decode(&reply).unwrap();
    assert!(parsed.server);
    assert_eq!(parsed.origin, 123);
    assert_eq!(parsed.transmit, 125);
    assert!(parsed.payload.is_empty());
    let mut bad_padding = reply.clone();
    let last = bad_padding.len() - 1;
    bad_padding[last] = 1;
    assert!(decode(&bad_padding).is_err());
    for len in 0..request.len() {
        assert!(decode(&request[..len]).is_err());
    }
    for offset in [0, 48, 50, 52] {
        let mut bad = request.clone();
        bad[offset] ^= 0xff;
        assert!(decode(&bad).is_err(), "offset {offset}");
    }
}

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
                liveness: Default::default(),
                listener: ListenerConfig::Ntp {
                    ntp: NtpListenerConfig {
                        port,
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
                transport: PeerTransport::Ntp {
                    ntp: NtpTransportPeerConfig { endpoint },
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
        loop {
            let (len, source) = proxy.recv_from(&mut buffer).await.unwrap();
            let decoded = decode(&buffer[..len]).unwrap();
            events_tx
                .send((decoded.server, decoded.origin, decoded.transmit))
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
    let mut b_endpoint = create_ntp_endpoint(
        &b_state,
        &b_config,
        &NtpListenerConfig {
            port: server_address.port(),
            poll_interval: 1,
        },
    )
    .await
    .unwrap();
    let mut a_endpoint = create_ntp_endpoint(
        &a_state,
        &a_config,
        &NtpListenerConfig {
            port: 0,
            poll_interval: 1,
        },
    )
    .await
    .unwrap();
    timeout(Duration::from_secs(3), async {
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
                "unsolicited or repeated NTP reply"
            );
            replies += 1;
        } else {
            assert_eq!(origin, 0);
            assert!(requests.insert(transmit));
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
            "[Interface.Listener.Ntp.ntp]",
        )
        .replace("[Peer.Transport.Udp.udp]", "[Peer.Transport.Ntp.ntp]");
    let config: Config = toml::from_str(&text).unwrap();
    let crate::config::ListenerConfig::Ntp { ntp } = config.interface.listener else {
        panic!("expected NTP listener");
    };
    assert_eq!(ntp.port, 123);
    assert_eq!(ntp.poll_interval, 1);
    assert!(config.peers[0].transport.ntp().unwrap().endpoint.is_some());
}
