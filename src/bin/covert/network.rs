//! Async socket plumbing around the library's transport-independent endpoint.
use anyhow::{Context, Result};
use covert::transport::{Adapter, Endpoint, StatusSnapshot};
use std::{ops::Range, time::Duration};
use tokio::{
    sync::{mpsc, watch},
    time::{MissedTickBehavior, interval},
};

pub const MAX_DATAGRAM: usize = 65535;
const WORK_BATCH: usize = 32;

/// Reusable receive slots; each packet retains its own source and byte range.
pub struct ReceiveBatch<R> {
    pub buffer: Vec<u8>,
    pub packets: Vec<(R, Range<usize>)>,
    pub slot_size: usize,
}
impl<R> ReceiveBatch<R> {
    pub fn new(slots: usize, slot_size: usize) -> Self {
        Self {
            buffer: vec![0; slots * slot_size],
            packets: Vec::with_capacity(slots),
            slot_size,
        }
    }
}

pub trait Socket: Send + Sync {
    type Adapter: Adapter + Send + Sync;
    const RECEIVE_BATCH: usize = 1;
    fn receive(
        &self,
        batch: &mut ReceiveBatch<<Self::Adapter as Adapter>::Route>,
    ) -> impl Future<Output = Result<()>> + Send;
    fn flush(&self, adapter: &Self::Adapter) -> impl Future<Output = Result<()>> + Send;
}

pub async fn run<S: Socket>(
    socket: S,
    mut endpoint: Endpoint<S::Adapter>,
    mut requests: mpsc::Receiver<Vec<u8>>,
    tun: mpsc::Sender<Vec<u8>>,
    status: watch::Sender<StatusSnapshot>,
) -> Result<()> {
    let mut incoming_batch = ReceiveBatch::new(S::RECEIVE_BATCH, MAX_DATAGRAM);
    let mut timer = interval(Duration::from_millis(100));
    timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = tun.closed() => return Ok(()),
            request = requests.recv() => {
                let Some(packet) = request else { return Ok(()) };
                if let Err(err) = endpoint.tun_write(&packet) {
                    tracing::trace!(%err, "Discarding invalid TUN packet");
                }
                // Coalesce already queued TUN packets without waiting for a timer.
                // Bound work so maintenance and inbound traffic remain responsive.
                for _ in 1..WORK_BATCH {
                    let Ok(packet) = requests.try_recv() else { break };
                    if let Err(err) = endpoint.tun_write(&packet) {
                        tracing::trace!(%err, "Discarding invalid TUN packet");
                    }
                }
            }
            _ = timer.tick() => {
                endpoint.advance();
                status.send_replace(endpoint.status());
            }
            incoming = socket.receive(&mut incoming_batch) => {
                incoming?;
                for (route, bytes) in incoming_batch.packets.drain(..) {
                    endpoint.out_write_datagram(route, &incoming_batch.buffer[bytes]);
                }
            }
        }
        socket.flush(endpoint.adapter()).await?;
        for packet in endpoint.tun_read() {
            tun.send(packet).await.context("TUN receiver closed")?;
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use tokio::{task::JoinHandle, time::timeout};
    pub struct Node {
        pub sender: mpsc::Sender<Vec<u8>>,
        pub receiver: mpsc::Receiver<Vec<u8>>,
        pub status: watch::Receiver<StatusSnapshot>,
        pub task: JoinHandle<Result<()>>,
    }
    impl Drop for Node {
        fn drop(&mut self) {
            self.task.abort();
        }
    }
    pub fn spawn<S: Socket + 'static>(socket: S, endpoint: Endpoint<S::Adapter>) -> Node
    where
        <S::Adapter as Adapter>::Route: Send,
    {
        let (sender, requests) = mpsc::channel(32);
        let (tun, receiver) = mpsc::channel(32);
        let (status_tx, status) = watch::channel(endpoint.status());
        let task = tokio::spawn(run(socket, endpoint, requests, tun, status_tx));
        Node {
            sender,
            receiver,
            status,
            task,
        }
    }
    pub async fn receive(node: &mut Node) -> Vec<u8> {
        timeout(Duration::from_secs(3), node.receiver.recv())
            .await
            .unwrap()
            .unwrap()
    }
    pub async fn connected(node: &Node) {
        timeout(Duration::from_secs(3), async {
            while !node
                .status
                .borrow()
                .peers
                .iter()
                .all(|p| p.status == "connected")
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
    }
    pub fn packet(source: u8, destination: u8, size: usize) -> Vec<u8> {
        let mut packet = etherparse::Ipv4Header::new(
            size as u16,
            64,
            etherparse::IpNumber::UDP,
            [10, 0, 0, source],
            [10, 0, 0, destination],
        )
        .unwrap()
        .to_bytes()
        .to_vec();
        packet.resize(packet.len() + size, source);
        packet
    }
    pub fn config(
        local: u8,
        peers: &[(u8, Option<std::net::SocketAddr>)],
    ) -> covert::config::Config {
        use covert::{config::*, transport::*};
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
                    udp: UdpListenerConfig { port: 0 },
                },
            },
            peers: peers
                .iter()
                .map(|(remote, endpoint)| Peer {
                    id: uuid::Uuid::new_v4(),
                    public_key: covert::crypto::pk_to_bytes(
                        &covert::crypto::to_sk(&[*remote; 32])
                            .compute_public_key()
                            .unwrap(),
                    )
                    .into(),
                    pre_shared_key: Some([7; 32].into()),
                    allowed_ips: vec![format!("10.0.0.{remote}/32").parse().unwrap()],
                    liveness: Default::default(),
                    transport: PeerTransport::Udp {
                        udp: UdpTransportPeerConfig {
                            endpoint: *endpoint,
                        },
                    },
                })
                .collect(),
        }
    }
}
