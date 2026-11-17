use crate::{
    codec::{DataFlags, Packet},
    config::{Config, Peer},
    error::Result,
    sans::{DecodedInitiation, Tunnel},
};
use dashmap::DashMap;
use serde::Serialize;
use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Instant, SystemTime},
};
use tokio::sync::mpsc;
use uuid::Uuid;

#[derive(Default)]
struct PeerStatistics {
    sent: AtomicU64,
    received: AtomicU64,
    first_established_at: AtomicU64,
    last_established_at: AtomicU64,
}

#[derive(Serialize)]
pub struct StatusSnapshot {
    pub session: Uuid,
    pub peers: Vec<PeerStatus>,
}

#[derive(Serialize)]
pub struct PeerStatus {
    pub id: Uuid,
    pub psk: bool,
    pub allowed_ips: Vec<String>,
    pub transport: &'static str,
    pub status: &'static str,
    /// Unix milliseconds, absent until the first successful handshake.
    pub first_established_at: Option<u64>,
    pub last_established_at: Option<u64>,
    /// Plaintext bytes accepted by the transport sender / authenticated on receive.
    pub sent: u64,
    pub received: u64,
}

pub struct State {
    session_id: Uuid,
    peer_statistics: DashMap<Uuid, Arc<PeerStatistics>>,
    connected: DashMap<Uuid, bool>,
    tun_in_tx: mpsc::Sender<Vec<u8>>,
}

impl State {
    pub fn new(tun_in_tx: mpsc::Sender<Vec<u8>>) -> Self {
        Self {
            session_id: Uuid::new_v4(),
            peer_statistics: Default::default(),
            connected: Default::default(),
            tun_in_tx,
        }
    }

    fn record_established(&self, peer_id: Uuid) -> Arc<PeerStatistics> {
        let statistics = self.peer_statistics.entry(peer_id).or_default().clone();
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let _ = statistics.first_established_at.compare_exchange(
            0,
            now,
            Ordering::Relaxed,
            Ordering::Relaxed,
        );
        statistics.last_established_at.store(now, Ordering::Relaxed);
        statistics
    }

    pub fn status(&self, config: &Config) -> StatusSnapshot {
        let peers = config
            .peers
            .iter()
            .map(|peer| {
                let statistics = self
                    .peer_statistics
                    .get(&peer.id)
                    .map(|entry| entry.value().clone());
                let load = |value: fn(&PeerStatistics) -> &AtomicU64| {
                    statistics
                        .as_ref()
                        .map_or(0, |s| value(s).load(Ordering::Relaxed))
                };
                let first = load(|s| &s.first_established_at);
                let last = load(|s| &s.last_established_at);
                let transport = peer.transport.tag();
                PeerStatus {
                    id: peer.id,
                    psk: peer.pre_shared_key.is_some(),
                    allowed_ips: peer.allowed_ips.iter().map(ToString::to_string).collect(),
                    transport: if transport == "none" {
                        config.interface.listener.tag()
                    } else {
                        transport
                    },
                    status: if self.has_live_connection(peer.id) {
                        "connected"
                    } else {
                        "disconnected"
                    },
                    first_established_at: (first != 0).then_some(first),
                    last_established_at: (last != 0).then_some(last),
                    sent: load(|s| &s.sent),
                    received: load(|s| &s.received),
                }
            })
            .collect();
        StatusSnapshot {
            session: self.session_id,
            peers,
        }
    }

    fn has_live_connection(&self, peer_id: Uuid) -> bool {
        self.connected
            .get(&peer_id)
            .is_some_and(|connected| *connected)
    }
}

pub mod icmp;
pub mod udp;

/// Plaintext interface shared by the socket adapters.
pub trait TransportEndpoint {
    fn trasmit(
        &mut self,
        state: &State,
        config: &Config,
        peer_id: Uuid,
        packet: &[u8],
    ) -> impl std::future::Future<Output = Result<()>>;
}

pub(super) struct PeerTunnel<R> {
    tunnel: Tunnel,
    address: Option<R>,
    established: Option<Instant>,
}

impl<R> PeerTunnel<R> {
    fn new(config: &Config, peer: &Peer, address: Option<R>) -> Result<Self> {
        let mut tunnel = Tunnel::new(
            config.layout,
            *config.interface.private_key.0,
            peer.liveness
                .unpack_with_fallback(&config.interface.liveness),
            *peer.public_key.0,
            peer.pre_shared_key.as_ref().map(|key| *key.0),
        );
        if address.is_some() {
            tunnel.initiate()?;
        }
        Ok(Self {
            tunnel,
            address,
            established: None,
        })
    }

    fn advance(&mut self, id: Uuid, state: &State) -> Result<()> {
        self.tunnel.process_new_packets()?;
        let established = self.tunnel.established_at();
        if established.is_some() && established != self.established {
            state.record_established(id);
        }
        self.established = established;
        state.connected.insert(id, self.tunnel.is_live());
        Ok(())
    }

    async fn deliver(&mut self, id: Uuid, state: &State) -> Result<()> {
        while let Some(packet) = self.tunnel.read_packet() {
            if packet.is_empty() {
                continue;
            }
            state
                .peer_statistics
                .entry(id)
                .or_default()
                .received
                .fetch_add(packet.len() as u64, Ordering::Relaxed);
            state
                .tun_in_tx
                .send(packet)
                .await
                .map_err(|_| crate::error::Error::TunReceiverClosed)?;
        }
        Ok(())
    }
}

fn identify<R>(
    config: &Config,
    peers: &HashMap<Uuid, PeerTunnel<R>>,
    packet: &Packet,
) -> Result<Option<(Uuid, Option<DecodedInitiation>)>> {
    let receiver_idx = match packet {
        Packet::Initiating(initiation) => {
            let decoded =
                DecodedInitiation::decode(&config.interface.private_key.0, initiation.clone())?;
            return Ok(config
                .peers
                .iter()
                .find(|peer| {
                    *peer.public_key.0 == decoded.public_key && peers.contains_key(&peer.id)
                })
                .map(|peer| (peer.id, Some(decoded))));
        }
        Packet::Reply(reply) => reply.receiver_idx,
        Packet::Data(data) => data.receiver_idx,
    };
    Ok(peers
        .iter()
        .find(|(_, peer)| peer.tunnel.local_index() == Some(receiver_idx))
        .map(|(&id, _)| (id, None)))
}

fn plaintext_len(packet: &Packet) -> usize {
    match packet {
        Packet::Data(data) if !data.flags.contains(DataFlags::JUNK) => {
            data.ciphertext.len().saturating_sub(16)
        }
        _ => 0,
    }
}
