use crate::{
    Result,
    codec::Codec,
    config::Config,
    transport::{Endpoint, State, maintain_peers, process_packet},
};
use dashmap::DashMap;
use futures::StreamExt;
use serde::Deserialize;
use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};
use tokio::{net::UdpSocket, task::JoinSet};
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

type UdpPacketSender = UdpFramed<Codec, Arc<UdpSocket>>;
type UdpRoute = SocketAddr;

pub async fn create_udp_endpoint(
    state: &Arc<State>,
    config: &Arc<Config>,
    listener: &UdpListenerConfig,
) -> Result<Endpoint<UdpPacketSender, UdpRoute>> {
    let addr = (Ipv4Addr::UNSPECIFIED, listener.port);
    let socket = Arc::new(UdpSocket::bind(addr).await?);

    let routing = Arc::new(
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
        routing.clone(),
    ));

    let sender = UdpFramed::new(socket, Codec::new(config.layout));
    Ok(Endpoint { routing, sender })
}

async fn socket_listener_task(
    state: Arc<State>,
    socket: Arc<UdpSocket>,
    config: Arc<Config>,
    routing: Arc<DashMap<Uuid, SocketAddr>>,
) {
    let mut framed = UdpFramed::new(socket.clone(), Codec::new(config.layout));

    // Dropping the receive task also stops its independent maintenance task.
    let mut maintenance = JoinSet::new();
    maintenance.spawn(maintain_peers(
        state.clone(),
        config.clone(),
        routing.clone(),
        UdpFramed::new(socket, Codec::new(config.layout)),
    ));
    loop {
        tokio::select! {
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
                    Some(Err(err)) => {
                        // UdpFramed retains a datagram when decode_eof returns an error.
                        // Discard it so the next poll can receive a new datagram.
                        framed.read_buffer_mut().clear();
                        error!("Failed to parse the packet on udp socket: {err}");
                    }
                    None => break,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
