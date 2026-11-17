use crate::{
    Result,
    codec::{self, DataFlags, Packet},
    config::{Config, PeerTransport},
    crypto,
    sans::Tunnel,
    transport::{State, TransportEndpoint},
};
use serde::Deserialize;
use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, atomic::Ordering},
    time::{Duration, Instant},
};
use tokio::{
    net::UdpSocket,
    sync::mpsc,
    time::{MissedTickBehavior, interval},
};
use tracing::{error, trace};
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

/// Sends plaintext to the task owning the socket and all UDP tunnels.
pub struct UdpEndpoint {
    sender: mpsc::Sender<(Uuid, Vec<u8>)>,
    local_addr: SocketAddr,
}

impl UdpEndpoint {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

impl TransportEndpoint for UdpEndpoint {
    async fn trasmit(
        &mut self,
        _state: &State,
        _config: &Config,
        peer_id: Uuid,
        packet: &[u8],
    ) -> Result<()> {
        self.sender
            .send((peer_id, packet.to_vec()))
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::BrokenPipe, "UDP endpoint stopped")
            })?;
        Ok(())
    }
}

struct PeerTunnel {
    tunnel: Tunnel,
    address: Option<SocketAddr>,
    established: Option<Instant>,
}

pub async fn create_udp_endpoint(
    state: &Arc<State>,
    config: &Arc<Config>,
    listener: &UdpListenerConfig,
) -> Result<UdpEndpoint> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, listener.port)).await?;
    let local_addr = socket.local_addr()?;
    let mut peers = HashMap::new();
    for peer in &config.peers {
        let address = match &peer.transport {
            PeerTransport::Udp { udp } => udp.endpoint,
            PeerTransport::None => None,
            _ => continue,
        };
        let liveness = peer
            .liveness
            .unpack_with_fallback(&config.interface.liveness);
        let tunnel = Tunnel::new(
            config.layout,
            *config.interface.private_key.0,
            liveness,
            address.map(|_| *peer.public_key.0),
            peer.pre_shared_key.as_ref().map(|key| *key.0),
        )?;
        peers.insert(
            peer.id,
            PeerTunnel {
                tunnel,
                address,
                established: None,
            },
        );
    }
    let (sender, receiver) = mpsc::channel(512);
    let state = state.clone();
    let config = config.clone();
    tokio::spawn(async move {
        for id in peers.keys() {
            state.sans_connected.insert(*id, false);
        }
        if let Err(err) = run_udp(&socket, &state, &config, &mut peers, receiver).await {
            error!(%err, "UDP endpoint stopped");
        }
        for id in peers.keys() {
            state.sans_connected.insert(*id, false);
        }
    });
    Ok(UdpEndpoint { sender, local_addr })
}

async fn run_udp(
    socket: &UdpSocket,
    state: &State,
    config: &Config,
    peers: &mut HashMap<Uuid, PeerTunnel>,
    mut receiver: mpsc::Receiver<(Uuid, Vec<u8>)>,
) -> Result<()> {
    let mut buffer = vec![0; 65535];
    let mut timer = interval(Duration::from_millis(100));
    timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = state.tun_in_tx.closed() => return Ok(()),
            request = receiver.recv() => {
                let Some((id, packet)) = request else { return Ok(()) };
                if let Some(peer) = peers.get_mut(&id) {
                    peer.tunnel.push_packet(&packet);
                    if let Err(err) = advance(peer, id, config, state) {
                        trace!(%id, %err, "Failed to process UDP tunnel");
                    }
                    flush(socket, peer, id, state, config).await?;
                }
            }
            _ = timer.tick() => {
                for (&id, peer) in peers.iter_mut() {
                    if let Err(err) = advance(peer, id, config, state) {
                        trace!(%id, %err, "Failed to maintain UDP tunnel");
                    }
                    flush(socket, peer, id, state, config).await?;
                }
            }
            incoming = socket.recv_from(&mut buffer) => {
                let (len, address) = incoming?;
                let bytes = &buffer[..len];
                // A UDP datagram must contain exactly one complete frame. Never
                // let partial or trailing bytes pollute a tunnel's stream buffer.
                let packet = match codec::parse_slice(bytes, &config.layout) {
                    Some(Ok((packet, consumed))) if consumed == len => packet,
                    _ => { trace!(%address, "Discarding malformed UDP datagram"); continue; }
                };
                let id = match &packet {
                    Packet::Initiating(initiation) => {
                        // Identify the configured peer before selecting its tunnel.
                        // Acceptance, replay checks and key establishment stay in Tunnel.
                        let Ok((key, _)) = crypto::pre_reply(&config.interface.private_key.0, initiation) else {
                            continue;
                        };
                        config.peers.iter().find(|peer| *peer.public_key.0 == key).map(|peer| peer.id)
                    }
                    Packet::Reply(reply) => peers.iter().find(|(_, peer)| {
                        peer.tunnel.local_index() == Some(reply.receiver_idx)
                    }).map(|(&id, _)| id),
                    Packet::Data(data) => peers.iter().find(|(_, peer)| {
                        peer.tunnel.local_index() == Some(data.receiver_idx)
                    }).map(|(&id, _)| id),
                };
                let Some(id) = id else { continue };
                let Some(peer) = peers.get_mut(&id) else { continue };
                let before = peer.tunnel.established_at();
                let is_data = matches!(packet, Packet::Data(_));
                match peer.tunnel.process_incoming_packet(packet)
                    .and_then(|()| advance(peer, id, config, state))
                {
                    Ok(()) => {
                        // Learn/migrate routes only after accepted handshakes or
                        // successfully authenticated data, never from invalid packets.
                        if peer.tunnel.is_live() && (is_data || peer.tunnel.established_at() != before) {
                            peer.address = Some(address);
                        }
                    }
                    Err(err) => trace!(%id, %address, %err, "Discarding invalid UDP packet"),
                }
                flush(socket, peer, id, state, config).await?;
            }
        }
    }
}

fn advance(peer: &mut PeerTunnel, id: Uuid, config: &Config, state: &State) -> Result<()> {
    if let Some(pending) = peer.tunnel.process_new_packets()? {
        let configured = config.peers.iter().find(|p| p.id == id).unwrap();
        if pending.public_key == *configured.public_key.0 {
            peer.tunnel.approve_pending(
                configured.pre_shared_key.as_ref().map(|key| *key.0),
                configured
                    .liveness
                    .unpack_with_fallback(&config.interface.liveness),
            )?;
            // Emit the reply before any queued data.
            peer.tunnel.process_new_packets()?;
        } else {
            peer.tunnel.reject_pending();
        }
    }
    let established = peer.tunnel.established_at();
    if established.is_some() && established != peer.established {
        state.record_established(id);
    }
    peer.established = established;
    state.sans_connected.insert(id, peer.tunnel.is_live());
    Ok(())
}

async fn flush(
    socket: &UdpSocket,
    peer: &mut PeerTunnel,
    id: Uuid,
    state: &State,
    config: &Config,
) -> Result<()> {
    if let Some(address) = peer.address {
        while let Some(packet) = peer.tunnel.read_outbound_packet() {
            let plaintext_len = match &packet {
                Packet::Data(data) if !data.flags.contains(DataFlags::JUNK) => {
                    data.ciphertext.len().saturating_sub(16)
                }
                _ => 0,
            };
            let bytes = packet.to_bytes(&config.layout)?;
            match socket.send_to(&bytes, address).await {
                Ok(_) => {
                    state
                        .peer_statistics
                        .entry(id)
                        .or_default()
                        .sent
                        .fetch_add(plaintext_len as u64, Ordering::Relaxed);
                }
                Err(err) => trace!(%id, %address, %err, "Failed to send UDP datagram"),
            }
        }
    }
    while let Some(packet) = peer.tunnel.read_packet() {
        if packet.is_empty() {
            continue;
        }
        state
            .peer_statistics
            .entry(id)
            .or_default()
            .received
            .fetch_add(packet.len() as u64, Ordering::Relaxed);
        state.tun_in_tx.send(packet).await.map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::BrokenPipe, "TUN receiver closed")
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
