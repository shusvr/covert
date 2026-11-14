use crate::{
    Result,
    codec::{Codec, Data, DataFlags, Packet, PacketLayout},
    config::Config,
    transport::{
        ProcessResult, State, initiate_disconnected_peers, process_incoming, send_keepalives,
    },
};
use dashmap::DashMap;
use futures::{SinkExt, StreamExt};
use serde::Deserialize;
use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{
    net::UdpSocket,
    time::{Instant, MissedTickBehavior, interval, sleep},
};
use tokio_util::udp::UdpFramed;
use tracing::{debug, error, trace};
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

fn keepalive_delay() -> Duration {
    Duration::from_secs_f64(8.0 + 4.0 * fastrand::f64())
}

async fn socket_listener_task(
    state: Arc<State>,
    socket: Arc<UdpSocket>,
    config: Arc<Config>,
    routing: Arc<DashMap<Uuid, SocketAddr>>,
) {
    let mut framed = UdpFramed::new(socket.clone(), Codec::new(PacketLayout::default()));

    let mut retries = interval(Duration::from_secs(5));
    retries.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let keepalive = sleep(keepalive_delay());
    tokio::pin!(keepalive);
    loop {
        tokio::select! {
            _ = &mut keepalive => {
                send_keepalives(&state, &config, &routing, &mut framed).await;
                keepalive.as_mut().reset(Instant::now() + keepalive_delay());
            }
            _ = retries.tick() => {
                initiate_disconnected_peers(&state, &config, &routing, &mut framed).await;
            }
            result = framed.next() => {
                match result {
                    Some(Ok((packet, addr))) => {
                        trace!(?addr, "Received a packet on udp socket");

                        match handle_udp_packet(&state, &mut framed, &config, &routing, packet, addr).await {
                            Ok(true) => {},
                            Ok(false) => break,
                            Err(err) => error!("Failed to process incoming packet: {err}"),
                        }
                    }
                    Some(Err(err)) => error!("Failed to parse the packet on udp socket: {err}"),
                    None => break,
                }
            }
        }
    }
}

// Return false when TUN delivery is closed and the receive loop should stop.
async fn handle_udp_packet(
    state: &Arc<State>,
    framed: &mut UdpFramed<Codec, Arc<UdpSocket>>,
    config: &Config,
    peer_addresses: &DashMap<Uuid, SocketAddr>,
    packet: Packet,
    addr: SocketAddr,
) -> Result<bool> {
    match process_incoming(state, config, packet).await? {
        Some(ProcessResult::Established {
            local_idx,
            replying,
            handle,
        }) => {
            let peer_id = handle.peer_id;
            peer_addresses.insert(peer_id, addr);
            state.established.insert(local_idx, handle);
            state.peering.insert(peer_id, local_idx);

            // Send the handshake reply before flushing encrypted data.
            if let Some(replying) = replying {
                framed.send((Packet::Reply(replying), addr)).await?;
            }
            debug!(?peer_id, remote_addr = %addr, local_idx, "Connection established");
            flush_queued(state, framed, peer_id, local_idx, addr).await?;
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

async fn flush_queued(
    state: &State,
    framed: &mut UdpFramed<Codec, Arc<UdpSocket>>,
    peer_id: Uuid,
    local_idx: u32,
    addr: SocketAddr,
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
        framed
            .send((
                Packet::Data(Data {
                    receiver_idx,
                    counter,
                    ciphertext,
                    flags: DataFlags::empty(),
                }),
                addr,
            ))
            .await?;
        sent += 1;
    }
    state
        .queued
        .remove_if(&peer_id, |_, queue| queue.is_empty());
    debug!(?peer_id, remote_addr = %addr, sent, "Flushed queued packets");
    Ok(())
}

#[cfg(test)]
mod tests;
