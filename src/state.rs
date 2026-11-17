use serde::Serialize;
use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::SystemTime,
};
use uuid::Uuid;

use crate::config::Config;

#[derive(Default)]
pub struct PeerStatistics {
    pub sent: AtomicU64,
    pub received: AtomicU64,
    pub first_established_at: AtomicU64,
    pub last_established_at: AtomicU64,
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
    pub peer_statistics: HashMap<Uuid, Arc<PeerStatistics>>,
    pub connected: HashMap<Uuid, bool>,
}

impl State {
    pub fn new() -> Self {
        Self {
            session_id: Uuid::new_v4(),
            peer_statistics: Default::default(),
            connected: Default::default(),
        }
    }

    pub fn record_peer_sent(&self, peer_id: &Uuid, bytes_len: u64) {
        if let Some(stats) = self.peer_statistics.get(&peer_id) {
            stats.sent.fetch_add(bytes_len, Ordering::Relaxed);
        }
    }

    pub fn record_peer_received(&self, peer_id: Uuid, bytes_len: u64) {
        if let Some(stats) = self.peer_statistics.get(&peer_id) {
            stats.received.fetch_add(bytes_len, Ordering::Relaxed);
        }
    }

    pub fn record_established(&mut self, peer_id: Uuid) -> Arc<PeerStatistics> {
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
                    .map(|entry| entry.clone());
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
