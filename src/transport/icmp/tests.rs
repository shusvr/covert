#[cfg(test)]
use super::*;

#[tokio::test]
#[ignore = "requires an isolated network namespace with CAP_NET_RAW, CAP_NET_ADMIN and nft"]
async fn raw_receive_processes_data_suppresses_kernel_reply_and_cleans_up() {
    use crate::{
        codec::{Data, DataFlags},
        config::{Interface, ListenerConfig},
        crypto::Cipher,
    };
    use tokio::time::{Duration, timeout};
    let listener = IcmpListenerConfig { id: 1339 };
    let config = Arc::new(Config {
        dev_name: String::new(),
        interface: Interface {
            addresses: vec![],
            mtu: 1400,
            private_key: [7; 32].into(),
            listener: ListenerConfig::Icmp {
                icmp: listener.clone(),
            },
        },
        peers: vec![],
    });
    let (tx, mut rx) = tokio::sync::mpsc::channel(4);
    let state = Arc::new(State::new(tx));
    let key = |role| {
        Cipher::new(
            aws_lc_rs::aead::LessSafeKey::new(
                aws_lc_rs::aead::UnboundKey::new(&aws_lc_rs::aead::CHACHA20_POLY1305, &[9; 32])
                    .unwrap(),
            ),
            role,
        )
    };
    let remote = key(true);
    state.established.insert(
        42,
        crate::transport::establish(key(false), 0, uuid::Uuid::new_v4(), 7),
    );
    let endpoint = create_icmp_endpoint(&state, &config, &listener)
        .await
        .unwrap();
    let raw = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)).unwrap();
    raw.set_nonblocking(true).unwrap();
    let raw = unsafe {
        AsyncFd::register(raw)
            .map_err(|err| err.into_parts().1)
            .unwrap()
    };
    let (counter, ciphertext) = remote.encrypt(b"ICMP tunnel data".to_vec()).unwrap();
    let mut packet = BytesMut::new();
    codec::append(
        &mut packet,
        Packet::Data(Data {
            receiver_idx: 42,
            counter,
            ciphertext,
            flags: DataFlags::empty(),
        }),
        &PacketLayout::default(),
    )
    .unwrap();
    let header = etherparse::Icmpv4Header::with_checksum(
        etherparse::Icmpv4Type::EchoRequest(etherparse::IcmpEchoHeader {
            id: listener.id,
            seq: 1,
        }),
        &packet,
    );
    let mut wire = header.to_bytes().to_vec();
    wire.extend_from_slice(&packet);
    raw.get_ref()
        .send_to(&wire, &SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0).into())
        .unwrap();
    assert_eq!(
        timeout(Duration::from_secs(3), rx.recv())
            .await
            .unwrap()
            .unwrap(),
        b"ICMP tunnel data"
    );
    // The observer sees the request, but the kernel's automatic reply must be dropped.
    let mut buffer = [MaybeUninit::<u8>::uninit(); 65535];
    let len = raw
        .async_io(tokio::io::Interest::READABLE, |s| s.recv(&mut buffer))
        .await
        .unwrap();
    let received = unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), len) };
    assert_eq!(received[(received[0] as usize & 15) * 4], 8);
    assert!(
        timeout(
            Duration::from_millis(100),
            raw.async_io(tokio::io::Interest::READABLE, |s| s.recv(&mut buffer))
        )
        .await
        .is_err()
    );
    drop(rx);
    drop(endpoint);
    for _ in 0..100 {
        let out = Command::new("nft")
            .args(["list", "tables"])
            .output()
            .unwrap();
        if !String::from_utf8_lossy(&out.stdout).contains("covert_icmp_") {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("ICMP firewall table was not cleaned up");
}

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
            echo_payload(&bytes, 1339),
            Some((Ipv4Addr::new(192, 0, 2, 1), &payload[..]))
        );
        assert!(echo_payload(&bytes, 1340).is_none());
        for end in 0..bytes.len() {
            assert!(echo_payload(&bytes[..end], 1339).is_none());
        }
        bytes[6] = 0x20;
        assert!(echo_payload(&bytes, 1339).is_none());
        bytes[6] = 0;
        *bytes.last_mut().unwrap() ^= 1;
        assert!(echo_payload(&bytes, 1339).is_none());
    }
}
