use circular_buffer::FixedCircularBuffer;
use dashmap::DashMap;
use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime},
};
use tokio::sync::mpsc;
use tracing::{debug, warn};
use uuid::Uuid;

use crate::{
    Key, Result,
    codec::Packet,
    config::{Config, ListenerConfig, PubKey},
    crypto::{Cipher, Initiating, Replying, finish, post_reply, pre_reply},
    transport::udp::UdpListener,
};

pub struct PeerHandle {
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

pub struct State {
    established: DashMap<u32, PeerHandle>,
    initiated: DashMap<u32, Initiated>,
    peering: DashMap<Uuid, u32>,
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

enum ProcessResult {
    Established {
        local_idx: u32,
        replying: Option<Replying>,
        handle: PeerHandle,
    },
    Packet {
        plaintext: Vec<u8>,
    },
}

async fn process_incoming(
    state: &Arc<State>,
    config: &Config,
    packet: Packet,
) -> Result<Option<ProcessResult>> {
    let out = match packet {
        Packet::Initiating(initiating) => {
            debug!(
                remote_idx = initiating.sender_idx,
                "Handshake initiation received"
            );
            let (remote_pk, timestamp) = pre_reply(
                &config.interface.private_key.0,
                initiating.enc_pub_key,
                initiating.ephemeral,
                initiating.enc_ts,
            )?;

            let Some(peer) = config
                .peers
                .iter()
                .find(|p| p.public_key.0 == remote_pk.as_ref())
            else {
                let pubkey: PubKey = remote_pk.into();
                warn!(?pubkey, "Received initiating from an unknown peer");
                return Ok(None);
            };

            debug!(peer_id = ?peer.peer_id, remote_idx = initiating.sender_idx, timestamp, "Handshake initiation accepted");

            // Established sessions are indexed by our own index, not the sender's.
            let local_idx = state.peering.get(&peer.peer_id).map(|entry| *entry.value());
            if let Some(existing) = local_idx.and_then(|index| state.established.get(&index))
                && existing.timestamp >= timestamp
            {
                warn!("Possible replay attack, received old timestamp");
                return Ok(None);
            }

            let sender_idx = fastrand::u32(..);
            let (replying, cipher) = post_reply(
                &remote_pk,
                peer.pre_shared_key.as_ref().map(|k| &k.0),
                sender_idx,
                initiating.sender_idx,
            )?;

            let handle = establish(cipher, timestamp, peer.peer_id, initiating.sender_idx);
            ProcessResult::Established {
                local_idx: sender_idx,
                replying: Some(replying),
                handle,
            }
        }
        Packet::Reply(replying) => {
            debug!(
                local_idx = replying.receiver_idx,
                remote_idx = replying.sender_idx,
                "Handshake reply received"
            );
            let Some((_, initiated)) = state.initiated.remove(&replying.receiver_idx) else {
                warn!(
                    receiver_idx = replying.receiver_idx,
                    "Received a reply to an unknown index"
                );
                return Ok(None);
            };

            if initiated.initiating.sender_idx != replying.receiver_idx {
                warn!(
                    sender_idx = initiated.initiating.sender_idx,
                    receiver_idx = replying.receiver_idx,
                    "Misbehaving peer, i.sender_idx != r.receiver_idx"
                );
            }

            let cipher = finish(
                &config.interface.private_key.0,
                initiated.psk.as_ref(),
                replying.eph,
            )?;

            let timestamp = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)?
                .as_secs();

            let handle = establish(cipher, timestamp, initiated.peer_id, replying.sender_idx);
            ProcessResult::Established {
                local_idx: replying.receiver_idx,
                replying: None,
                handle,
            }
        }
        Packet::Data {
            receiver_idx,
            counter,
            ciphertext,
        } => {
            let Some(handle) = state.established.get(&receiver_idx) else {
                debug!(receiver_idx, "Received data for an unknown session");
                return Ok(None);
            };
            if !handle.is_live() {
                debug!(receiver_idx, "Session has expired, cleaning up");
                drop(handle);
                state.established.remove(&receiver_idx);
                return Ok(None);
            }
            let plaintext = match handle.cipher.decrypt(counter, ciphertext) {
                Ok(plaintext) => plaintext,
                Err(_) => {
                    debug!(receiver_idx, "Cipher failed to decrypt, cleaning up");
                    drop(handle);
                    state.established.remove(&receiver_idx);
                    return Ok(None);
                }
            };
            if plaintext.is_empty() {
                debug!(receiver_idx, "Plaintext is empty, keepalive");
                handle.keep_alive();
                return Ok(None);
            }
            // Decryption is synchronous; release the map guard before TUN delivery.
            drop(handle);
            debug!(
                receiver_idx,
                plaintext_len = plaintext.len(),
                "Decrypted ciphertext"
            );

            ProcessResult::Packet { plaintext }
        }
    };

    Ok(Some(out))
}
