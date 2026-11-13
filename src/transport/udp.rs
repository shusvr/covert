use crate::{
    Result,
    codec::{Codec, Packet, PacketLayout},
    config::{Config, PubKey},
    crypto::{finish, initiate, post_reply, pre_reply},
    transport::{DecryptPacket, EncryptPacket, Peering, State, establish},
};
use dashmap::DashMap;
use futures::{SinkExt, StreamExt};
use serde::Deserialize;
use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio::net::UdpSocket;
use tokio_util::udp::UdpFramed;
use tracing::{debug, error, warn};
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
    pub(super) peer_addresses: DashMap<Uuid, SocketAddr>,
}

impl UdpListener {
    pub async fn initiate(&mut self, state: &State, config: &Config, peer_id: Uuid) -> Result<()> {
        debug!(?peer_id, "Initiating");

        let Some(addr) = self.peer_addresses.get(&peer_id).map(|e| *e.value()) else {
            debug!(
                ?peer_id,
                "Peer has no address associated, skipping initiation"
            );
            return Ok(());
        };

        if let Some(when) = state.peering.get(&peer_id).map(|p| p.when)
            && when.elapsed() < Duration::from_secs(20)
        {
            debug!(
                ?peer_id,
                "Initiated within last 20 seconds, skipping another initiation attempt"
            );
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

            let packet = Packet::Initiating(initiating);
            self.framed.send((packet, addr)).await.unwrap();
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

    tokio::spawn(socket_listener_task(
        state.clone(),
        socket.clone(),
        config.clone(),
    ));

    let framed = UdpFramed::new(socket, Codec::new(PacketLayout::default()));
    Ok(UdpListener {
        peer_addresses: config
            .peers
            .iter()
            .filter_map(|p| p.transport.unwrap_udp().endpoint.map(|e| (p.peer_id, e)))
            .collect(),
        framed,
    })
}

async fn socket_listener_task(state: Arc<State>, socket: Arc<UdpSocket>, config: Arc<Config>) {
    let mut framed = UdpFramed::new(socket.clone(), Codec::new(PacketLayout::default()));
    loop {
        if let Some(result) = framed.next().await {
            match result {
                Ok((packet, addr)) => {
                    debug!(?addr, "Received a packet on udp socket");

                    if let Err(err) =
                        process_incoming(&state, &mut framed, &config, packet, addr).await
                    {
                        error!("Failed to process incoming packet: {err}");
                    }
                }
                Err(err) => error!("Failed to parse the packet on udp socket: {err}"),
            }
        }
    }
}

#[tracing::instrument(skip(state, framed, packet, config))]
async fn process_incoming(
    state: &Arc<State>,
    framed: &mut UdpFramed<Codec, Arc<UdpSocket>>,
    config: &Config,
    packet: Packet,
    from: SocketAddr,
) -> Result<()> {
    match packet {
        Packet::Initiating(initiating) => {
            let (remote_pk, timestamp) = pre_reply(
                &config.interface.private_key.0,
                initiating.enc_pub_key,
                initiating.ephemeral,
                initiating.enc_ts,
            )?;

            if let Some(existing) = state.established.get(&initiating.sender_idx)
                && existing.timestamp >= timestamp
            {
                warn!(?from, "Possible reply attack, received old timestamp");
            }

            let Some(peer) = config
                .peers
                .iter()
                .find(|p| p.public_key.0 == remote_pk.as_ref())
            else {
                let pubkey: PubKey = remote_pk.into();
                warn!(?pubkey, "Received initiating from an unknown peer");
                return Ok(());
            };

            let sender_idx = fastrand::u32(..);
            let (replying, cipher) = post_reply(
                &remote_pk,
                peer.pre_shared_key.as_ref().map(|k| &k.0),
                sender_idx,
                initiating.sender_idx,
            )?;

            let handle = establish(cipher, timestamp, peer.peer_id, sender_idx);
            state.established.insert(initiating.sender_idx, handle);
            let peering = Peering::new(initiating.sender_idx);
            state.peering.insert(peer.peer_id, peering);

            framed.send((Packet::Reply(replying), from)).await?;
        }
        Packet::Reply(replying) => {
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

            let handle = establish(cipher, timestamp, initiated.peer_id, replying.receiver_idx);
            state.established.insert(replying.receiver_idx, handle);
            let peering = Peering::new(replying.receiver_idx);
            state.peering.insert(initiated.peer_id, peering);
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
