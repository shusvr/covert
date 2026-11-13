use circular_buffer::FixedCircularBuffer;
use dashmap::DashMap;
use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::{
    Key, Result,
    config::{Config, ListenerConfig},
    crypto::{Cipher, Initiating},
    transport::udp::UdpListener,
};

pub struct PeerHandle {
    #[expect(dead_code)]
    peer_id: Uuid,
    receiver_idx: u32,
    timestamp: u64,
    // two different fields because timestamp is used to prevent reply attack and remote clock might be different
    cipher: Arc<Cipher>,
    // Monotonic milliseconds since `since`, updated by authenticated keepalives.
    last_keepalive_ms: AtomicU64,
    since: Instant,

    // for statistical purposes
    #[expect(dead_code)]
    sent: AtomicU64,
    #[expect(dead_code)]
    received: AtomicU64,
}

impl PeerHandle {
    pub fn new(peer_id: Uuid, receiver_idx: u32, cipher: Arc<Cipher>, timestamp: u64) -> Self {
        Self {
            peer_id,
            receiver_idx,
            timestamp,
            cipher,
            sent: 0.into(),
            received: 0.into(),
            last_keepalive_ms: AtomicU64::new(0),
            since: Instant::now(),
        }
    }

    fn is_live(&self) -> bool {
        let elapsed = self.since.elapsed();
        let last_keepalive = Duration::from_millis(self.last_keepalive_ms.load(Ordering::Relaxed));
        elapsed < Duration::from_secs(300)
            && elapsed.saturating_sub(last_keepalive) < Duration::from_secs(60)
    }

    fn keep_alive(&self) {
        self.last_keepalive_ms
            .store(self.since.elapsed().as_millis() as u64, Ordering::Relaxed);
    }
}

pub struct Initiated {
    when: Instant,
    peer_id: Uuid,
    psk: Option<Key>,
    initiating: Initiating,
}

impl Initiated {
    pub fn new(peer_id: Uuid, psk: Option<Key>, initiating: Initiating) -> Self {
        Self {
            peer_id,
            psk,
            initiating,
            when: Instant::now(),
        }
    }
}

pub struct Peering {
    index: u32,
}

impl Peering {
    pub fn new(index: u32) -> Self {
        Self { index }
    }
}

pub struct State {
    established: DashMap<u32, PeerHandle>,
    initiated: DashMap<u32, Initiated>,
    peering: DashMap<Uuid, Peering>,
    queued: DashMap<Uuid, FixedCircularBuffer<Vec<u8>, 16>>,
    tun_in_tx: mpsc::Sender<Vec<u8>>,
}

impl State {
    pub fn new(tun_in_tx: mpsc::Sender<Vec<u8>>) -> Self {
        Self {
            tun_in_tx,
            established: Default::default(),
            initiated: Default::default(),
            peering: Default::default(),
            queued: Default::default(),
        }
    }

    // Clone the cipher so no map guard is held during asynchronous I/O.
    fn session(&self, local_idx: u32) -> Option<(Arc<Cipher>, u32)> {
        let handle = self.established.get(&local_idx)?;
        handle
            .is_live()
            .then(|| (handle.cipher.clone(), handle.receiver_idx))
    }
}

pub mod icmp;
pub mod udp;

pub enum Listener {
    Udp(UdpListener),
}

impl Listener {
    // pub fn initiate(&self, state: &State, config: &Arc<Config>, peer_id: Uuid) {}

    #[tracing::instrument(skip(self, state, config, packet))]
    pub async fn trasmit(
        &mut self,
        state: &State,
        config: &Config,
        peer_id: Uuid,
        packet: &[u8],
    ) -> Result<()> {
        match self {
            Listener::Udp(udp) => {
                udp.transmit(state, config, peer_id, packet).await?;
            }
        }

        Ok(())
    }
}

pub async fn create_listener(state: &Arc<State>, config: &Arc<Config>) -> Result<Listener> {
    let listener = match &config.interface.listener {
        ListenerConfig::Udp { udp } => {
            let udp = udp::create_udp_listener(state, config, udp).await?;
            Listener::Udp(udp)
        }
        ListenerConfig::Icmp { .. } => todo!(),
        ListenerConfig::Other { .. } => todo!(),
    };

    Ok(listener)
}

fn establish(cipher: Cipher, timestamp: u64, peer_id: Uuid, receiver_idx: u32) -> PeerHandle {
    PeerHandle::new(peer_id, receiver_idx, Arc::new(cipher), timestamp)
}
