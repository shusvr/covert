use crate::{
    Result,
    codec::{Codec, PacketLayout},
    config::Config,
    transport::{State, initiate_disconnected_peers, process_packet, send_keepalives},
};
use dashmap::DashMap;
use futures::StreamExt;
use serde::Deserialize;
use std::{
    fmt::Debug,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{
    net::UdpSocket,
    time::{Instant, MissedTickBehavior, interval, sleep},
};
use tokio_util::udp::UdpFramed;
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

                        match process_packet(&state, &config, packet, addr, &routing, &mut framed).await {
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
#[cfg(test)]
mod tests;
