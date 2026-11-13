use circular_buffer::FixedCircularBuffer;
use dashmap::DashMap;
use futures::{Sink, SinkExt, Stream};
use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime},
};
use tokio::sync::mpsc;
use tracing::{debug, error, warn};
use uuid::Uuid;

use crate::{
    Key, Result,
    codec::{self, Packet},
    config::{Config, ListenerConfig, PubKey},
    crypto::{self, Cipher, Initiating, Replying, finish, post_reply, pre_reply},
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

    fn has_live_connection(&self, peer_id: Uuid) -> bool {
        let index = self.peering.get(&peer_id).map(|entry| *entry.value());
        index
            .and_then(|index| self.established.get(&index))
            .is_some_and(|handle| handle.is_live())
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
                transmit(
                    state,
                    config,
                    &udp.peer_addresses,
                    &mut udp.framed,
                    peer_id,
                    packet,
                )
                .await?;
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

pub trait PacketSender<R>:
    Sink<(Packet, R), Error = codec::Error> + Stream<Item = Result<(Packet, R), codec::Error>> + Unpin
{
}

impl<R, T> PacketSender<R> for T where
    T: Sink<(Packet, R), Error = codec::Error>
        + Stream<Item = Result<(Packet, R), codec::Error>>
        + Unpin
{
}

pub async fn initiate<R: Clone>(
    state: &State,
    config: &Config,
    routing: &DashMap<Uuid, R>,
    sender: &mut impl PacketSender<R>,
    peer_id: Uuid,
) -> Result<()> {
    debug!(?peer_id, "Handshake initiation requested");

    let Some(addr) = routing.get(&peer_id).map(|e| e.value().clone()) else {
        debug!(
            ?peer_id,
            "Peer has no address associated, skipping initiation"
        );
        return Ok(());
    };

    if state.has_live_connection(peer_id) {
        debug!(
            ?peer_id,
            "Peer already has a live connection, skipping initiation"
        );
        return Ok(());
    }

    if let Some(peer) = config.peers.iter().find(|p| p.peer_id == peer_id) {
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let sender_idx = fastrand::u32(..);
        let initiating = crypto::initiate(
            &config.interface.private_key.0,
            &peer.public_key.0,
            timestamp,
            sender_idx,
        )?;

        // Register before sending: the receive task may process the reply immediately.
        state.initiated.insert(
            sender_idx,
            Initiated::new(
                peer_id,
                peer.pre_shared_key.as_ref().map(|key| key.0),
                initiating.clone(),
            ),
        );
        debug!(
            ?peer_id,
            local_idx = sender_idx,
            "Sending handshake initiation"
        );
        let packet = Packet::Initiating(initiating);
        if let Err(err) = sender.send((packet, addr)).await {
            state.initiated.remove(&sender_idx);
            return Err(err.into());
        }
        debug!(
            ?peer_id,
            local_idx = sender_idx,
            "Handshake initiation sent"
        );
    } else {
        warn!(?peer_id, "Trying to initiate by unknown peer id");
    }

    Ok(())
}

pub async fn transmit<R: Clone>(
    state: &State,
    config: &Config,
    routing: &DashMap<Uuid, R>,
    sender: &mut impl PacketSender<R>,
    peer_id: Uuid,
    packet: &[u8],
) -> Result<()> {
    debug!(?peer_id, len = packet.len(), "Transmitting");

    let Some(addr) = routing.get(&peer_id).map(|x| x.value().clone()) else {
        debug!(?peer_id, "Peer has not been reached yet, skipping transmit");
        state
            .queued
            .entry(peer_id)
            .or_default()
            .push_back(packet.to_owned());
        return Ok(());
    };

    let local_idx = state.peering.get(&peer_id).map(|entry| *entry.value());
    if let Some(local_idx) = local_idx
        && let Some((cipher, receiver_idx)) = state.session(local_idx)
    {
        let (counter, ciphertext) = match cipher.encrypt(packet.to_owned()) {
            Ok(encrypted) => encrypted,
            Err(err) => {
                debug!(?peer_id, "Cipher failed to encrypt, cleaning up");
                state.established.remove(&local_idx);
                return Err(err.into());
            }
        };
        debug!(?peer_id, "Sending data");
        let packet = Packet::Data {
            receiver_idx,
            counter,
            ciphertext,
        };
        sender.send((packet, addr)).await?;
        return Ok(());
    }

    if let Some(local_idx) = local_idx {
        state.established.remove(&local_idx);
    }
    // Queue traffic while a missing or expired session is re-established.
    state
        .queued
        .entry(peer_id)
        .or_default()
        .push_back(packet.to_owned());
    initiate(state, config, routing, sender, peer_id).await?;

    Ok(())
}

async fn initiate_disconnected_peers<R: Clone>(
    state: &State,
    config: &Config,
    routing: &DashMap<Uuid, R>,
    sender: &mut impl PacketSender<R>,
) {
    state.established.retain(|_, handle| handle.is_live());
    state
        .initiated
        .retain(|_, pending| pending.when.elapsed() < Duration::from_secs(60));
    for peer in &config.peers {
        if routing.contains_key(&peer.peer_id) && !state.has_live_connection(peer.peer_id) {
            if let Err(err) = initiate(state, config, routing, &mut *sender, peer.peer_id).await {
                error!(peer_id = ?peer.peer_id, "Failed to initiate handshake: {err}");
            }
        }
    }
}

async fn send_keepalives<R: Clone>(
    state: &State,
    config: &Config,
    routing: &DashMap<Uuid, R>,
    sender: &mut impl PacketSender<R>,
) {
    for peer in &config.peers {
        let Some(addr) = routing
            .get(&peer.peer_id)
            .map(|entry| entry.value().clone())
        else {
            continue;
        };
        let Some(index) = state.peering.get(&peer.peer_id).map(|entry| *entry.value()) else {
            continue;
        };
        let Some((cipher, receiver_idx)) = state.session(index) else {
            continue;
        };
        match cipher.encrypt(Vec::new()) {
            Ok((counter, ciphertext)) => {
                let packet = Packet::Data {
                    receiver_idx,
                    counter,
                    ciphertext,
                };
                match sender.send((packet, addr)).await {
                    Ok(()) => {
                        debug!(peer_id = ?peer.peer_id, receiver_idx, counter, "Keepalive sent")
                    }
                    Err(err) => error!(peer_id = ?peer.peer_id, "Failed to send keepalive: {err}"),
                }
            }
            Err(_) => {
                debug!(peer_id = ?peer.peer_id, "Cipher failed to encrypt keepalive, cleaning up");
                state.established.remove(&index);
            }
        }
    }
}
