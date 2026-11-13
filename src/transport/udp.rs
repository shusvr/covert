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
    pub(super) peer_addresses: Arc<DashMap<Uuid, SocketAddr>>,
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
            let packet = Packet::Initiating(initiating);
            if let Err(err) = self.framed.send((packet, addr)).await {
                state.initiated.remove(&sender_idx);
                return Err(err.into());
            }
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

async fn socket_listener_task(
    state: Arc<State>,
    socket: Arc<UdpSocket>,
    config: Arc<Config>,
    peer_addresses: Arc<DashMap<Uuid, SocketAddr>>,
) {
    let mut framed = UdpFramed::new(socket.clone(), Codec::new(PacketLayout::default()));
    loop {
        if let Some(result) = framed.next().await {
            match result {
                Ok((packet, addr)) => {
                    debug!(?addr, "Received a packet on udp socket");

                    if let Err(err) = process_incoming(
                        &state,
                        &mut framed,
                        &config,
                        &peer_addresses,
                        packet,
                        addr,
                    )
                    .await
                    {
                        error!("Failed to process incoming packet: {err}");
                    }
                }
                Err(err) => error!("Failed to parse the packet on udp socket: {err}"),
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

            peer_addresses.insert(initiated.peer_id, from);
            let handle = establish(cipher, timestamp, initiated.peer_id, replying.sender_idx);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::{Interface, ListenerConfig, Peer, PeerTransport},
        crypto::{pk_to_bytes, random_sk, sk_to_bytes},
    };
    use tokio::{sync::mpsc, time::timeout};

    fn config(local_sk: crate::Key, remote_pk: crate::Key, endpoint: SocketAddr) -> Config {
        Config {
            dev_name: String::new(),
            interface: Interface {
                addresses: vec![],
                mtu: 1460,
                private_key: local_sk.into(),
                listener: ListenerConfig::Udp {
                    udp: UdpListenerConfig { port: 0 },
                },
            },
            peers: vec![Peer {
                peer_id: Uuid::new_v4(),
                public_key: remote_pk.into(),
                pre_shared_key: Some([7; 32].into()),
                allowed_ips: vec![],
                transport: PeerTransport::Udp {
                    udp: UdpTransportPeerConfig {
                        endpoint: Some(endpoint),
                    },
                },
            }],
        }
    }

    async fn receive(listener: &mut UdpListener) -> (Packet, SocketAddr) {
        timeout(Duration::from_secs(3), listener.framed.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
    }

    #[tokio::test]
    async fn handshake_and_bidirectional_data_use_local_and_remote_indexes() {
        let socket_a = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let socket_b = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let key_a = random_sk().unwrap();
        let key_b = random_sk().unwrap();
        let config_a = config(
            sk_to_bytes(&key_a),
            pk_to_bytes(&key_b.compute_public_key().unwrap()),
            socket_b.local_addr().unwrap(),
        );
        let config_b = config(
            sk_to_bytes(&key_b),
            pk_to_bytes(&key_a.compute_public_key().unwrap()),
            socket_a.local_addr().unwrap(),
        );
        let peer_a = config_a.peers[0].peer_id;
        let peer_b = config_b.peers[0].peer_id;
        let (tx_a, mut rx_a) = mpsc::channel(4);
        let (tx_b, mut rx_b) = mpsc::channel(4);
        let state_a = Arc::new(State::new(tx_a));
        let state_b = Arc::new(State::new(tx_b));
        let mut a = UdpListener {
            framed: UdpFramed::new(socket_a, Codec::new(PacketLayout::default())),
            peer_addresses: Arc::new(
                [(peer_a, socket_b.local_addr().unwrap())]
                    .into_iter()
                    .collect(),
            ),
        };
        let mut b = UdpListener {
            framed: UdpFramed::new(socket_b, Codec::new(PacketLayout::default())),
            peer_addresses: Arc::new(DashMap::new()),
        };

        a.initiate(&state_a, &config_a, peer_a).await.unwrap();
        let (packet, from) = receive(&mut b).await;
        let Packet::Initiating(ref initiation) = packet else {
            panic!("expected initiation")
        };
        let local_a = initiation.sender_idx;
        assert!(state_a.initiated.contains_key(&local_a));
        process_incoming(
            &state_b,
            &mut b.framed,
            &config_b,
            &b.peer_addresses,
            packet,
            from,
        )
        .await
        .unwrap();
        let (packet, from) = receive(&mut a).await;
        let Packet::Reply(ref reply) = packet else {
            panic!("expected reply")
        };
        let local_b = reply.sender_idx;
        assert_eq!(reply.receiver_idx, local_a);
        process_incoming(
            &state_a,
            &mut a.framed,
            &config_a,
            &a.peer_addresses,
            packet,
            from,
        )
        .await
        .unwrap();
        assert!(state_a.initiated.is_empty());
        assert_eq!(state_a.peering.get(&peer_a).unwrap().index, local_a);
        assert_eq!(state_b.peering.get(&peer_b).unwrap().index, local_b);
        assert_eq!(
            state_a.established.get(&local_a).unwrap().receiver_idx,
            local_b
        );
        assert_eq!(
            state_b.established.get(&local_b).unwrap().receiver_idx,
            local_a
        );

        a.transmit(&state_a, &config_a, peer_a, b"hello")
            .await
            .unwrap();
        let (packet, from) = receive(&mut b).await;
        assert!(matches!(packet, Packet::Data { receiver_idx, .. } if receiver_idx == local_b));
        process_incoming(
            &state_b,
            &mut b.framed,
            &config_b,
            &b.peer_addresses,
            packet,
            from,
        )
        .await
        .unwrap();
        assert_eq!(
            timeout(Duration::from_secs(3), rx_b.recv())
                .await
                .unwrap()
                .unwrap(),
            b"hello"
        );

        assert_eq!(*b.peer_addresses.get(&peer_b).unwrap(), from);
        b.transmit(&state_b, &config_b, peer_b, b"reply")
            .await
            .unwrap();
        let (packet, from) = receive(&mut a).await;
        assert!(matches!(packet, Packet::Data { receiver_idx, .. } if receiver_idx == local_a));
        process_incoming(
            &state_a,
            &mut a.framed,
            &config_a,
            &a.peer_addresses,
            packet,
            from,
        )
        .await
        .unwrap();
        assert_eq!(
            timeout(Duration::from_secs(3), rx_a.recv())
                .await
                .unwrap()
                .unwrap(),
            b"reply"
        );
    }
}
