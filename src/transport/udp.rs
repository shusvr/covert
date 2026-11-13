use crate::{
    Result,
    codec::{Codec, Packet, PacketLayout},
    config::{Config, PubKey},
    crypto::{finish, initiate, post_reply, pre_reply},
    transport::{DecryptPacket, EncryptPacket, Initiated, Peering, State, establish},
};
use dashmap::DashMap;
use futures::{SinkExt, StreamExt};
use serde::Deserialize;
use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio::{
    net::UdpSocket,
    time::{MissedTickBehavior, interval},
};
use tokio_util::udp::UdpFramed;
use tracing::{debug, error, trace, warn};
use uuid::Uuid;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct UdpListenerConfig {
    #[serde(default = "default_listen_port")]
    port: u16,
}

fn default_listen_port() -> u16 {
    40676
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct UdpTransportPeerConfig {
    endpoint: Option<SocketAddr>,
}

pub struct UdpListener {
    pub(super) framed: UdpFramed<Codec, Arc<UdpSocket>>,
    pub(super) peer_addresses: Arc<DashMap<Uuid, SocketAddr>>,
}

impl UdpListener {
    pub async fn initiate(&mut self, state: &State, config: &Config, peer_id: Uuid) -> Result<()> {
        debug!(?peer_id, "Handshake initiation requested");

        let Some(addr) = self.peer_addresses.get(&peer_id).map(|e| *e.value()) else {
            debug!(
                ?peer_id,
                "Peer has no address associated, skipping initiation"
            );
            return Ok(());
        };

        if has_live_connection(state, peer_id) {
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
            let initiating = initiate(
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
            debug!(?peer_id, remote_addr = %addr, local_idx = sender_idx, "Sending handshake initiation");
            let packet = Packet::Initiating(initiating);
            if let Err(err) = self.framed.send((packet, addr)).await {
                state.initiated.remove(&sender_idx);
                return Err(err.into());
            }
            debug!(?peer_id, remote_addr = %addr, local_idx = sender_idx, "Handshake initiation sent");
        } else {
            warn!(?peer_id, "Trying to initiate by unknown peer id");
        }

        Ok(())
    }

    pub async fn transmit(
        &mut self,
        state: &State,
        config: &Config,
        peer_id: Uuid,
        packet: &[u8],
    ) -> Result<()> {
        debug!(?peer_id, len = packet.len(), "Transmitting");

        let Some(addr) = self.peer_addresses.get(&peer_id).map(|x| *x.value()) else {
            debug!(?peer_id, "Peer has not been reached yet, skipping transmit");
            state
                .queued
                .entry(peer_id)
                .or_default()
                .push_back(packet.to_owned());
            return Ok(());
        };

        if let Some(index) = state.peering.get(&peer_id) {
            if let Some(handle) = state.established.get(&index.value().index) {
                if let Some(actor) = handle.handle.upgrade() {
                    if let Some((counter, ciphertext)) =
                        actor.ask(EncryptPacket(packet.to_owned())).await.unwrap()
                    {
                        debug!(?peer_id, dst=?addr, "Sending data");
                        let packet = Packet::Data {
                            receiver_idx: handle.receiver_idx,
                            counter,
                            ciphertext,
                        };
                        self.framed.send((packet, addr)).await.unwrap();
                    } else {
                        debug!(?peer_id, "Actor can not encrypt, cleaning up");
                        state.established.remove(&index.value().index);
                    }
                } else {
                    debug!(?peer_id, "Actor has been dropped, cleaning up");
                    state.established.remove(&index.value().index);
                }
            } else {
                debug!(?peer_id, "Actor has expired, cleaning up");
                state.established.remove(&index.value().index);
            }
        } else {
            // no connection to peer, try to initiate if possible
            state
                .queued
                .entry(peer_id)
                .or_default()
                .push_back(packet.to_owned());
            self.initiate(state, config, peer_id).await?;
        }

        Ok(())
    }
}

pub(super) async fn create_udp_listener(
    state: &Arc<State>,
    config: &Arc<Config>,
    listener: &UdpListenerConfig,
) -> Result<UdpListener> {
    let addr = (Ipv4Addr::UNSPECIFIED, listener.port);
    let socket = Arc::new(UdpSocket::bind(addr).await?);

    let peer_addresses = Arc::new(
        config
            .peers
            .iter()
            .filter_map(|p| p.transport.unwrap_udp().endpoint.map(|e| (p.peer_id, e)))
            .collect::<DashMap<_, _>>(),
    );
    tokio::spawn(socket_listener_task(
        state.clone(),
        socket.clone(),
        config.clone(),
        peer_addresses.clone(),
    ));

    let framed = UdpFramed::new(socket, Codec::new(PacketLayout::default()));
    Ok(UdpListener {
        peer_addresses,
        framed,
    })
}

fn has_live_connection(state: &State, peer_id: Uuid) -> bool {
    let index = state.peering.get(&peer_id).map(|entry| entry.index);
    index
        .and_then(|index| state.established.get(&index))
        .is_some_and(|handle| handle.handle.upgrade().is_some())
}

async fn initiate_disconnected_peers(listener: &mut UdpListener, state: &State, config: &Config) {
    state
        .initiated
        .retain(|_, pending| pending.when.elapsed() < Duration::from_secs(60));
    for peer in &config.peers {
        if listener.peer_addresses.contains_key(&peer.peer_id)
            && !has_live_connection(state, peer.peer_id)
        {
            if let Err(err) = listener.initiate(state, config, peer.peer_id).await {
                error!(peer_id = ?peer.peer_id, "Failed to initiate handshake: {err}");
            }
        }
    }
}

async fn socket_listener_task(
    state: Arc<State>,
    socket: Arc<UdpSocket>,
    config: Arc<Config>,
    peer_addresses: Arc<DashMap<Uuid, SocketAddr>>,
) {
    let mut framed = UdpFramed::new(socket.clone(), Codec::new(PacketLayout::default()));
    let mut outgoing = UdpListener {
        framed: UdpFramed::new(socket, Codec::new(PacketLayout::default())),
        peer_addresses: peer_addresses.clone(),
    };
    let mut retries = interval(Duration::from_secs(5));
    retries.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = retries.tick() => {
                initiate_disconnected_peers(&mut outgoing, &state, &config).await;
            }
            result = framed.next() => {
                match result {
                    Some(Ok((packet, addr))) => {
                        trace!(?addr, "Received a packet on udp socket");
                        if let Err(err) = process_incoming(
                            &state, &mut framed, &config, &peer_addresses, packet, addr,
                        ).await {
                            error!("Failed to process incoming packet: {err}");
                        }
                    }
                    Some(Err(err)) => error!("Failed to parse the packet on udp socket: {err}"),
                    None => break,
                }
            }
        }
    }
}

#[tracing::instrument(skip(state, framed, packet, config, peer_addresses))]
async fn process_incoming(
    state: &Arc<State>,
    framed: &mut UdpFramed<Codec, Arc<UdpSocket>>,
    config: &Config,
    peer_addresses: &DashMap<Uuid, SocketAddr>,
    packet: Packet,
    from: SocketAddr,
) -> Result<()> {
    match packet {
        Packet::Initiating(initiating) => {
            debug!(remote_addr = %from, remote_idx = initiating.sender_idx, "Handshake initiation received");
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
                return Ok(());
            };

            debug!(peer_id = ?peer.peer_id, remote_addr = %from, remote_idx = initiating.sender_idx, timestamp, "Handshake initiation accepted");

            // Established sessions are indexed by our own index, not the sender's.
            let local_idx = state.peering.get(&peer.peer_id).map(|entry| entry.index);
            if let Some(existing) = local_idx.and_then(|index| state.established.get(&index))
                && existing.timestamp >= timestamp
            {
                warn!(?from, "Possible replay attack, received old timestamp");
                return Ok(());
            }

            let sender_idx = fastrand::u32(..);
            let (replying, cipher) = post_reply(
                &remote_pk,
                peer.pre_shared_key.as_ref().map(|k| &k.0),
                sender_idx,
                initiating.sender_idx,
            )?;

            peer_addresses.insert(peer.peer_id, from);
            let handle = establish(cipher, timestamp, peer.peer_id, initiating.sender_idx);
            state.established.insert(sender_idx, handle);
            let peering = Peering::new(sender_idx);
            state.peering.insert(peer.peer_id, peering);

            debug!(peer_id = ?peer.peer_id, remote_addr = %from, local_idx = sender_idx,
                remote_idx = initiating.sender_idx, "Sending handshake reply");
            framed.send((Packet::Reply(replying), from)).await?;
            debug!(peer_id = ?peer.peer_id, remote_addr = %from, local_idx = sender_idx,
                remote_idx = initiating.sender_idx, "Handshake reply sent");
            debug!(peer_id = ?peer.peer_id, remote_addr = %from, local_idx = sender_idx,
                remote_idx = initiating.sender_idx, role = "responder", "Connection established");
        }
        Packet::Reply(replying) => {
            debug!(remote_addr = %from, local_idx = replying.receiver_idx,
                remote_idx = replying.sender_idx, "Handshake reply received");
            let Some((_, initiated)) = state.initiated.remove(&replying.receiver_idx) else {
                warn!(
                    receiver_idx = replying.receiver_idx,
                    "Received a reply to an unknown index"
                );
                return Ok(());
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
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_err(std::io::Error::other)?
                .as_secs();

            peer_addresses.insert(initiated.peer_id, from);
            let handle = establish(cipher, timestamp, initiated.peer_id, replying.sender_idx);
            state.established.insert(replying.receiver_idx, handle);
            let peering = Peering::new(replying.receiver_idx);
            state.peering.insert(initiated.peer_id, peering);
            debug!(peer_id = ?initiated.peer_id, remote_addr = %from,
                local_idx = replying.receiver_idx, remote_idx = replying.sender_idx,
                role = "initiator", "Connection established");
        }
        Packet::Data {
            receiver_idx,
            counter,
            ciphertext,
        } => {
            if let Some(handle) = state.established.get(&receiver_idx) {
                if let Some(actor) = handle.handle.upgrade() {
                    if let Some(plaintext) =
                        actor.ask(DecryptPacket(counter, ciphertext)).await.unwrap()
                    {
                        if plaintext.is_empty() {
                            debug!(receiver_idx, "Plaintext is empty, keepalive");
                            handle.notify.notify_waiters();
                        } else {
                            debug!(
                                receiver_idx,
                                plaintext_len = plaintext.len(),
                                "Actor decrypted ciphertext"
                            );

                            if state.tun_in_tx.send(plaintext).await.is_err() {
                                debug!("tun_in_tx is closed");
                            }
                        }
                    } else {
                        debug!(receiver_idx, "Actor failed to decrypt, cleaning ip");

                        drop(handle);
                        state.established.remove(&receiver_idx);
                    }
                } else {
                    debug!(receiver_idx, "Actor has expired, cleaning up");

                    drop(handle);
                    state.established.remove(&receiver_idx);
                }
            } else {
                debug!("Received data to unknown")
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests;
