//! Keep Linux virtio/offload framing local to the TUN; transports carry plain IP.
use std::io;
use tokio::sync::mpsc;
use tun::AsyncDevice;

#[cfg(target_os = "linux")]
use tun::{GROTable, IDEAL_BATCH_SIZE, VIRTIO_NET_HDR_LEN};

pub struct Reader {
    packets: Vec<Vec<u8>>,
    sizes: Vec<usize>,
    #[cfg(target_os = "linux")]
    original: Vec<u8>,
}

impl Reader {
    pub fn new(mtu: u16) -> Self {
        let mtu = usize::from(mtu);
        #[cfg(target_os = "linux")]
        // Cover a full 64KiB GSO read, allowing room for IP/TCP headers in
        // each output segment even with a small configured MTU.
        let slots = IDEAL_BATCH_SIZE.max(65535usize.div_ceil(mtu.saturating_sub(128).max(1)));
        #[cfg(not(target_os = "linux"))]
        let slots = 1;
        Self {
            packets: vec![vec![0; mtu]; slots],
            sizes: vec![0; slots],
            #[cfg(target_os = "linux")]
            original: vec![0; VIRTIO_NET_HDR_LEN + 65535],
        }
    }

    pub async fn recv(&mut self, device: &AsyncDevice) -> io::Result<usize> {
        #[cfg(target_os = "linux")]
        {
            device
                .recv_multiple(&mut self.original, &mut self.packets, &mut self.sizes, 0)
                .await
        }
        #[cfg(not(target_os = "linux"))]
        {
            self.sizes[0] = device.recv(&mut self.packets[0]).await?;
            Ok(1)
        }
    }

    pub fn packet(&self, index: usize) -> &[u8] {
        &self.packets[index][..self.sizes[index]]
    }
}

#[derive(Default)]
pub struct Writer {
    #[cfg(target_os = "linux")]
    gro: GROTable,
    #[cfg(target_os = "linux")]
    packets: Vec<Vec<u8>>,
}

impl Writer {
    pub async fn send(
        &mut self,
        device: &AsyncDevice,
        packet: Vec<u8>,
        receiver: &mut mpsc::Receiver<Vec<u8>>,
    ) -> Result<(), crate::error::Error> {
        #[cfg(target_os = "linux")]
        {
            self.packets.clear();
            self.packets.push(with_headroom(packet));
            // Coalesce only packets already queued; never wait for a batch timer.
            while self.packets.len() < IDEAL_BATCH_SIZE {
                match receiver.try_recv() {
                    Ok(packet) => self.packets.push(with_headroom(packet)),
                    Err(_) => break,
                }
            }
            tracing::trace!(packets = self.packets.len(), "Writing TUN batch");
            device
                .send_multiple(&mut self.gro, &mut self.packets, VIRTIO_NET_HDR_LEN)
                .await?;
            // Release packets after writing, retaining the outer batch allocation.
            self.packets.clear();
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = receiver;
            let written = device.send(&packet).await?;
            if written != packet.len() {
                return Err(crate::error::Error::IncompleteTunWrite {
                    written,
                    expected: packet.len(),
                });
            }
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn with_headroom(mut packet: Vec<u8>) -> Vec<u8> {
    let length = packet.len();
    packet.resize(length + VIRTIO_NET_HDR_LEN, 0);
    packet.copy_within(..length, VIRTIO_NET_HDR_LEN);
    packet[..VIRTIO_NET_HDR_LEN].fill(0);
    packet
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use etherparse::{PacketBuilder, UdpHeader};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use tokio::{
        net::UdpSocket,
        time::{Duration, timeout},
    };

    #[tokio::test]
    #[ignore = "requires an isolated network namespace with CAP_NET_ADMIN and /dev/net/tun"]
    async fn offloaded_tun_preserves_ipv4_ipv6_datagrams_and_checksums() {
        let local4 = Ipv4Addr::new(10, 89, 0, 1);
        let peer4 = Ipv4Addr::new(10, 89, 0, 2);
        let local6: Ipv6Addr = "fd89::1".parse().unwrap();
        let peer6: Ipv6Addr = "fd89::2".parse().unwrap();
        let dev = tun::DeviceBuilder::new()
            .name("covert-offtest")
            .mtu(1400)
            .ipv4(local4, 24, None)
            .ipv6(local6, 64)
            .offload(true)
            .enable(true)
            .build_async()
            .unwrap();
        assert!(dev.tcp_gso());
        let mut writer = Writer::default();
        let mut reader = Reader::new(1400);
        for (local, peer) in [
            (IpAddr::V4(local4), IpAddr::V4(peer4)),
            (IpAddr::V6(local6), IpAddr::V6(peer6)),
        ] {
            let socket = UdpSocket::bind((local, 0)).await.unwrap();
            let port = socket.local_addr().unwrap().port();
            let (tx, mut rx) = mpsc::channel(16);
            let mut packets = Vec::new();
            for index in 0..6u8 {
                let payload = vec![index; 64];
                let builder = match (local, peer) {
                    (IpAddr::V4(local), IpAddr::V4(peer)) => {
                        PacketBuilder::ipv4(peer.octets(), local.octets(), 64)
                    }
                    (IpAddr::V6(local), IpAddr::V6(peer)) => {
                        PacketBuilder::ipv6(peer.octets(), local.octets(), 64)
                    }
                    _ => unreachable!(),
                }
                .udp(9999, port);
                let mut packet = Vec::with_capacity(builder.size(payload.len()) + 16);
                builder.write(&mut packet, &payload).unwrap();
                packets.push(packet);
            }
            let first = packets.remove(0);
            for packet in packets {
                tx.send(packet).await.unwrap();
            }
            writer.send(&dev, first, &mut rx).await.unwrap();
            for index in 0..6u8 {
                let mut data = [0; 128];
                let (len, source) = timeout(Duration::from_secs(3), socket.recv_from(&mut data))
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(source.ip(), peer);
                assert_eq!(&data[..len], &vec![index; 64]);
                socket.send_to(&data[..len], source).await.unwrap();
            }
            let mut seen = 0;
            timeout(Duration::from_secs(3), async {
                while seen < 6 {
                    let count = reader.recv(&dev).await.unwrap();
                    for index in 0..count {
                        let packet = reader.packet(index);
                        let offset = match packet.first().map(|b| b >> 4) {
                            Some(4) if packet[9] == 17 => 20,
                            Some(6) if packet[6] == 17 => 40,
                            _ => continue,
                        };
                        let (udp, payload) = UdpHeader::from_slice(&packet[offset..]).unwrap();
                        if udp.destination_port != 9999 {
                            continue;
                        }
                        assert_eq!(payload, &vec![seen as u8; 64]);
                        let expected = match (local, peer) {
                            (IpAddr::V4(local), IpAddr::V4(peer)) => udp
                                .calc_checksum_ipv4_raw(local.octets(), peer.octets(), payload)
                                .unwrap(),
                            (IpAddr::V6(local), IpAddr::V6(peer)) => udp
                                .calc_checksum_ipv6_raw(local.octets(), peer.octets(), payload)
                                .unwrap(),
                            _ => unreachable!(),
                        };
                        assert_eq!(udp.checksum, expected);
                        assert!(packet.len() <= 1400);
                        seen += 1;
                    }
                }
            })
            .await
            .unwrap();
        }
    }
}
