use dashmap::DashMap;
use kameo::{Actor, actor::WeakActorRef};
use std::sync::{Arc, atomic::AtomicU64};
use tokio::sync::{Notify, mpsc};
use uuid::Uuid;

use crate::{
    Key, Result,
    config::{Config, ListenerConfig},
    crypto::Initiating,
    transport::udp::UdpPeer,
};

pub struct PeerHandle<T: Actor> {
    peer_id: Uuid,
    timestamp: u64,
    sent: AtomicU64,
    received: AtomicU64,
    handle: WeakActorRef<T>,
    notify: Arc<Notify>,
}

impl<T: Actor> PeerHandle<T> {
    pub fn new(peer_id: Uuid, handle: WeakActorRef<T>, timestamp: u64) -> Self {
        Self {
            timestamp,
            handle,
            peer_id,
            sent: 0.into(),
            received: 0.into(),
            notify: Arc::new(Notify::new()),
        }
    }
}

pub struct Initiated {
    peer_id: Uuid,
    psk: Key,
    initiating: Initiating,
}

pub struct State<T: Actor> {
    established: DashMap<u32, PeerHandle<T>>,
    initiated: DashMap<u32, Initiated>,
    peering: DashMap<Uuid, u32>,
    tun_in_tx: mpsc::Sender<Vec<u8>>,
}

impl<T: Actor> State<T> {
    pub fn new(tun_in_tx: mpsc::Sender<Vec<u8>>) -> Self {
        Self {
            tun_in_tx,
            established: Default::default(),
            initiated: Default::default(),
            peering: Default::default(),
        }
    }
}

pub mod icmp;
pub mod udp;

pub enum Listener {
    Udp { state: Arc<State<UdpPeer>> },
}

pub async fn create_listener(
    config: &Arc<Config>,
    tun_in_tx: mpsc::Sender<Vec<u8>>,
) -> Result<Listener> {
    let listener = match &config.interface.listener {
        ListenerConfig::Udp { udp } => {
            let state = udp::create_udp_listener(config, udp, tun_in_tx).await?;
            Listener::Udp { state }
        }
        ListenerConfig::Icmp { .. } => todo!(),
        ListenerConfig::Other { .. } => todo!(),
    };

    Ok(listener)
}
