use crate::{
    codec::{self, Packet},
    config::{Config, PeerTransport},
    error::Result,
    transport::{PeerTunnel, State, TransportEndpoint, identify, plaintext_len},
};
use serde::Deserialize;
use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, atomic::Ordering},
    time::Duration,
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
    #[cfg(test)]
    local_addr: SocketAddr,
}

#[cfg(test)]
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
            .map_err(|_| crate::error::Error::EndpointStopped { transport: "UDP" })?;
        Ok(())
    }
}

pub async fn create_udp_endpoint(
    state: &Arc<State>,
    config: &Arc<Config>,
    listener: &UdpListenerConfig,
) -> Result<UdpEndpoint> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, listener.port)).await?;
    #[cfg(test)]
    let local_addr = socket.local_addr()?;
    let mut peers = HashMap::new();
    for peer in &config.peers {
        let address = match &peer.transport {
            PeerTransport::Udp { udp } => udp.endpoint,
            PeerTransport::None => None,
            _ => continue,
        };
        peers.insert(peer.id, PeerTunnel::new(config, peer, address)?);
    }
    let (sender, receiver) = mpsc::channel(512);
    let state = state.clone();
    let config = config.clone();
    tokio::spawn(async move {
        for id in peers.keys() {
            state.connected.insert(*id, false);
        }
        if let Err(err) = run_udp(&socket, &state, &config, &mut peers, receiver).await {
            error!(%err, "UDP endpoint stopped");
        }
        for id in peers.keys() {
            state.connected.insert(*id, false);
        }
    });
    Ok(UdpEndpoint {
        sender,
        #[cfg(test)]
        local_addr,
    })
}

async fn run_udp(
    socket: &UdpSocket,
    state: &State,
    config: &Config,
    peers: &mut HashMap<Uuid, PeerTunnel<SocketAddr>>,
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
                    if let Err(err) = peer.advance(id, state) {
                        trace!(%id, %err, "Failed to process UDP tunnel");
                    }
                    flush(socket, peer, id, state, config).await?;
                }
            }
            _ = timer.tick() => {
                for (&id, peer) in peers.iter_mut() {
                    if let Err(err) = peer.advance(id, state) {
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
                let (id, decoded_initiation) = match identify(config, peers, &packet) {
                    Ok(Some(incoming)) => incoming,
                    Ok(None) => continue,
                    Err(err) => { trace!(%address, %err, "Discarding invalid UDP handshake"); continue; }
                };
                let Some(peer) = peers.get_mut(&id) else { continue };
                let before = peer.tunnel.established_at();
                let is_data = matches!(packet, Packet::Data(_));
                let result = match decoded_initiation {
                    Some(decoded) => peer.tunnel.process_initiation(decoded),
                    None => peer.tunnel.process_incoming_packet(packet),
                };
                match result.map_err(crate::error::Error::from).and_then(|()| peer.advance(id, state))
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

async fn flush(
    socket: &UdpSocket,
    peer: &mut PeerTunnel<SocketAddr>,
    id: Uuid,
    state: &State,
    config: &Config,
) -> Result<()> {
    if let Some(address) = peer.address {
        while let Some(packet) = peer.tunnel.read_outbound_packet() {
            let plaintext_len = plaintext_len(&packet);
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
    peer.deliver(id, state).await
}

#[cfg(test)]
mod tests;
