use circular_buffer::FixedCircularBuffer;
use dashmap::DashMap;
use kameo::prelude::*;
use std::{
    pin::pin,
    sync::{Arc, atomic::AtomicU64},
    time::{Duration, Instant},
};
use tokio::{
    sync::{Notify, mpsc},
    time::sleep,
};
use tracing::debug;
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
    handle: WeakActorRef<PeerActor>,
    notify: Arc<Notify>,

    // for statistical purposes
    #[expect(dead_code)]
    since: Instant,
    #[expect(dead_code)]
    sent: AtomicU64,
    #[expect(dead_code)]
    received: AtomicU64,
}

impl PeerHandle {
    pub fn new(
        peer_id: Uuid,
        receiver_idx: u32,
        handle: WeakActorRef<PeerActor>,
        timestamp: u64,
    ) -> Self {
        Self {
            peer_id,
            receiver_idx,
            timestamp,
            handle,
            sent: 0.into(),
            received: 0.into(),
            notify: Arc::new(Notify::new()),
            since: Instant::now(),
        }
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

#[derive(Actor)]
pub struct PeerActor {
    cipher: Cipher,
}

pub struct EncryptPacket(Vec<u8>);
pub struct DecryptPacket(u64, Vec<u8>);

impl Message<DecryptPacket> for PeerActor {
    type Reply = Option<Vec<u8>>;

    async fn handle(
        &mut self,
        DecryptPacket(nonce, ciphertext): DecryptPacket,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        if let Ok(plaintext) = self.cipher.decrypt(nonce, ciphertext) {
            Some(plaintext)
        } else {
            debug!("Actor failed to decrypt, stopping");
            ctx.stop();
            None
        }
    }
}

impl Message<EncryptPacket> for PeerActor {
    type Reply = Option<(u64, Vec<u8>)>;

    async fn handle(
        &mut self,
        EncryptPacket(packet): EncryptPacket,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let Ok(result) = self.cipher.encrypt(packet) else {
            debug!("Actor failed to encrypt, stopping");
            ctx.stop();
            return None;
        };

        Some(result)
    }
}

async fn retain(actor_ref: ActorRef<PeerActor>, notify: Arc<Notify>, ttl: u64, idle: u64) {
    // this ensures actor lives at most `ttl` seconds
    let mut ttl_fut = pin!(sleep(Duration::from_secs(ttl)));

    loop {
        tokio::select! {
            biased;
            // by not putting sleep future in select! we do not reset the timer on each poll
            _ = &mut ttl_fut => {
                debug!("Actor has reached end of life");
                break;
            }
            // here we recreate the sleep future each poll to only resolve when actually idle
            _ = sleep(Duration::from_secs(idle)) => {
                debug!("Actor has expired");
                break;
            }
            _ = notify.notified() => {
                debug!("Actor has received keep alive");
                continue;
            }
        }
    }

    drop(actor_ref)
}

fn establish(cipher: Cipher, timestamp: u64, peer_id: Uuid, receiver_idx: u32) -> PeerHandle {
    let notify = Arc::new(Notify::new());
    let actor = PeerActor { cipher };

    let handle = PeerActor::spawn(actor);
    tokio::spawn(upkeep(handle.clone(), notify.clone(), 300, 60));

    let weak = handle.downgrade();
    PeerHandle::new(peer_id, receiver_idx, weak, timestamp)
}
