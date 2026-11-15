use circular_buffer::FixedCircularBuffer;
use dashmap::DashMap;
use futures::{Sink, SinkExt};
use std::{
    fmt::Debug,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime},
};
use tokio::{
    sync::mpsc,
    time::{MissedTickBehavior, interval},
};
use tracing::{debug, error, trace, warn};
use uuid::Uuid;

use crate::{
    Key, Result,
    codec::{self, Data, DataFlags, Packet},
    config::{Config, Liveness, PubKey},
    crypto::{self, Cipher, Initiating, Replying, finish, post_reply, pre_reply},
};

pub struct PeerHandle {
    peer_id: Uuid,
    receiver_idx: u32,
    timestamp: u64,
    // two different fields because timestamp is used to prevent reply attack and remote clock might be different
    cipher: Arc<Cipher>,
    // Monotonic milliseconds since `since`, updated by authenticated traffic.
    last_keepalive_ms: AtomicU64,
    next_keepalive_ms: AtomicU64,
    liveness: Liveness,
    since: Instant,

    // for statistical purposes
    #[expect(dead_code)]
    sent: AtomicU64,
    #[expect(dead_code)]
    received: AtomicU64,
}

impl PeerHandle {
    pub fn new(
        peer_id: Uuid,
        receiver_idx: u32,
        cipher: Cipher,
        timestamp: u64,
        liveness: Liveness,
    ) -> Self {
        Self {
            peer_id,
            receiver_idx,
            timestamp,
            cipher: cipher.into(),
            last_keepalive_ms: AtomicU64::new(0),
            next_keepalive_ms: AtomicU64::new(liveness.next_ka()),
            liveness,
            since: Instant::now(),
            sent: 0.into(),
            received: 0.into(),
        }
    }

    fn is_live(&self) -> bool {
        let elapsed = self.since.elapsed();
        let last_keepalive = Duration::from_millis(self.last_keepalive_ms.load(Ordering::Relaxed));
        (self.liveness.max_age == 0 || elapsed < Duration::from_secs(self.liveness.max_age))
            && (self.liveness.timeout == 0
                || elapsed.saturating_sub(last_keepalive)
                    < Duration::from_secs(self.liveness.timeout))
    }

    fn keep_alive(&self) {
        let now = self.since.elapsed().as_millis() as u64;
        self.last_keepalive_ms.store(now, Ordering::Relaxed);
        self.next_keepalive_ms
            .store(now + self.liveness.next_ka(), Ordering::Relaxed);
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

pub mod dns;
pub mod icmp;
pub mod ntp;
pub mod udp;

pub struct Endpoint<S, R> {
    pub sender: S,
    pub routing: Arc<DashMap<Uuid, R>>,
}

impl<S: PacketSender<R>, R: Clone> Endpoint<S, R> {
    #[tracing::instrument(level = "trace", skip(self, state, config, packet))]
    pub async fn trasmit(
        &mut self,
        state: &State,
        config: &Config,
        peer_id: Uuid,
        packet: &[u8],
    ) -> Result<()> {
        transmit(
            state,
            config,
            &self.routing,
            &mut self.sender,
            peer_id,
            packet,
        )
        .await?;

        Ok(())
    }
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

            let liveness = peer
                .liveness
                .unpack_with_fallback(&config.interface.liveness);
            let handle = PeerHandle::new(
                peer.peer_id,
                initiating.sender_idx,
                cipher,
                timestamp,
                liveness,
            );
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

            let peer = config
                .peers
                .iter()
                .find(|p| p.peer_id == initiated.peer_id)
                .unwrap();
            let liveness = peer
                .liveness
                .unpack_with_fallback(&config.interface.liveness);
            let handle = PeerHandle::new(
                initiated.peer_id,
                replying.sender_idx,
                cipher,
                timestamp,
                liveness,
            );
            ProcessResult::Established {
                local_idx: replying.receiver_idx,
                replying: None,
                handle,
            }
        }
        Packet::Data(Data {
            receiver_idx,
            counter,
            ciphertext,
            flags,
        }) => {
            let Some(handle) = state.established.get(&receiver_idx) else {
                trace!(receiver_idx, "Received data for an unknown session");
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
            handle.keep_alive();
            if plaintext.is_empty() || flags.contains(DataFlags::JUNK) {
                trace!(receiver_idx, "Plaintext is empty, keepalive");
                return Ok(None);
            }
            // Decryption is synchronous; release the map guard before TUN delivery.
            drop(handle);
            trace!(
                receiver_idx,
                plaintext_len = plaintext.len(),
                "Decrypted ciphertext"
            );

            ProcessResult::Packet { plaintext }
        }
    };

    Ok(Some(out))
}

pub trait PacketSender<R>: Sink<(Packet, R), Error = codec::Error> + Unpin {}

impl<T, R> PacketSender<R> for T where T: Sink<(Packet, R), Error = codec::Error> + Unpin {}

pub async fn initiate<R: Clone>(
    state: &State,
    config: &Config,
    routing: &DashMap<Uuid, R>,
    sender: &mut impl PacketSender<R>,
    peer_id: Uuid,
) -> Result<()> {
    trace!(?peer_id, "Handshake initiation requested");

    let Some(addr) = routing.get(&peer_id).map(|e| e.value().clone()) else {
        trace!(
            ?peer_id,
            "Peer has no address associated, skipping initiation"
        );
        return Ok(());
    };

    if state.has_live_connection(peer_id) {
        trace!(
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
    trace!(?peer_id, len = packet.len(), "Transmitting");

    let Some(addr) = routing.get(&peer_id).map(|x| x.value().clone()) else {
        trace!(?peer_id, "Peer has not been reached yet, skipping transmit");
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
        trace!(?peer_id, "Sending data");
        let packet = Packet::Data(Data {
            receiver_idx,
            flags: DataFlags::empty(),
            counter,
            ciphertext,
        });
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
        let Some((cipher, receiver_idx)) = state.established.get(&index).and_then(|handle| {
            (handle.is_live()
                && handle.since.elapsed().as_millis() as u64
                    >= handle.next_keepalive_ms.load(Ordering::Relaxed))
            .then(|| (handle.cipher.clone(), handle.receiver_idx))
        }) else {
            continue;
        };
        match cipher.encrypt(Vec::new()) {
            Ok((counter, ciphertext)) => {
                let packet = Packet::Data(Data {
                    receiver_idx,
                    counter,
                    flags: DataFlags::JUNK,
                    ciphertext,
                });
                match sender.send((packet, addr)).await {
                    Ok(()) => {
                        if let Some(handle) = state.established.get(&index) {
                            handle.next_keepalive_ms.fetch_max(
                                handle.since.elapsed().as_millis() as u64
                                    + handle.liveness.next_ka(),
                                Ordering::Relaxed,
                            );
                        }
                        trace!(peer_id = ?peer.peer_id, receiver_idx, counter, "Keepalive sent")
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

async fn process_packet<R: Debug + Clone>(
    state: &Arc<State>,
    config: &Config,
    packet: Packet,
    route: R,
    routing: &DashMap<Uuid, R>,
    sender: &mut impl PacketSender<R>,
) -> Result<bool> {
    match process_incoming(state, config, packet).await? {
        Some(ProcessResult::Established {
            local_idx,
            replying,
            handle,
        }) => {
            let peer_id = handle.peer_id;
            routing.insert(peer_id, route.clone());
            state.established.insert(local_idx, handle);
            state.peering.insert(peer_id, local_idx);

            // Send the handshake reply before flushing encrypted data.
            if let Some(replying) = replying {
                sender
                    .send((Packet::Reply(replying), route.clone()))
                    .await?;
            }
            debug!(?peer_id, remote_addr = ?route, local_idx, "Connection established");
            flush_queued(state, peer_id, local_idx, route, sender).await?;
        }
        Some(ProcessResult::Packet { plaintext }) => {
            if state.tun_in_tx.send(plaintext).await.is_err() {
                debug!("tun_in_rx is closed, exiting socket_listener_task");
                return Ok(false);
            }
        }
        None => {}
    }
    Ok(true)
}

async fn flush_queued<R: Debug + Clone>(
    state: &State,
    peer_id: Uuid,
    local_idx: u32,
    route: R,
    sender: &mut impl PacketSender<R>,
) -> Result<()> {
    if !state.queued.contains_key(&peer_id) {
        return Ok(());
    }
    let mut sent = 0;
    loop {
        let (cipher, receiver_idx) = state
            .session(local_idx)
            .ok_or(crate::Error::ConnectionUnavailable { peer_id, local_idx })?;
        // Release the queue guard before awaiting socket operations.
        let packet = state
            .queued
            .get_mut(&peer_id)
            .and_then(|mut queue| queue.pop_front());
        let Some(plaintext) = packet else { break };
        let (counter, ciphertext) = match cipher.encrypt(plaintext) {
            Ok(encrypted) => encrypted,
            Err(err) => {
                state.established.remove(&local_idx);
                return Err(err.into());
            }
        };

        let packet = Packet::Data(Data {
            receiver_idx,
            counter,
            ciphertext,
            flags: DataFlags::empty(),
        });

        sender.send((packet, route.clone())).await?;
        sent += 1;
    }
    state
        .queued
        .remove_if(&peer_id, |_, queue| queue.is_empty());
    debug!(
        ?peer_id,
        remote_addr =? route,
        sent,
        "Flushed queued packets"
    );
    Ok(())
}

// Runs independently of receiving packets; only requires a packet sink and routes.
async fn maintain_peers<R: Clone, S: PacketSender<R>>(
    state: Arc<State>,
    config: Arc<Config>,
    routing: Arc<DashMap<Uuid, R>>,
    mut sender: S,
) {
    let mut retries = interval(Duration::from_secs(5));
    retries.set_missed_tick_behavior(MissedTickBehavior::Skip);
    // Per-peer deadlines are refreshed on receive; this only checks which are due.
    let mut keepalive = interval(Duration::from_millis(100));
    keepalive.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = state.tun_in_tx.closed() => break,
            _ = keepalive.tick() => {
                send_keepalives(&state, &config, &routing, &mut sender).await;
            }
            _ = retries.tick() => {
                initiate_disconnected_peers(&state, &config, &routing, &mut sender).await;
            }
        }
    }
}
