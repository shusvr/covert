use crate::{
    Result,
    config::Config,
    wire::{Codec, PacketLayout},
};
use futures::StreamExt;
use serde::Deserialize;
use std::net::{Ipv4Addr, SocketAddr};
use tokio::net::UdpSocket;
use tokio_util::udp::UdpFramed;
use tracing::{debug, error, trace};

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct UdpListenerConfig {
    #[serde(default = "default_listen_port")]
    port: u16,
}

fn default_listen_port() -> u16 {
    40676
}

fn default_mtu() -> u16 {
    1460
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct UdpTransportPeerConfig {
    endpoint: Option<SocketAddr>,
}

pub(super) async fn create_udp_listener(
    config: &Config,
    listener: &UdpListenerConfig,
) -> Result<()> {
    let addr = (Ipv4Addr::UNSPECIFIED, listener.port);
    let socket = UdpSocket::bind(addr).await?;
    // TODO: change packet layout
    let mut framed = UdpFramed::new(socket, Codec::new(PacketLayout::default()));

    loop {
        if let Some(result) = framed.next().await {
            match result {
                Ok((packet, addr)) => {
                    trace!(?addr, "Received a packet on udp socket");
                }
                Err(err) => error!("Failed to parse the packet on udp socket: {err}"),
            }
        }
    }
}
