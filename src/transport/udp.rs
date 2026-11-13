use crate::{
    Result,
    config::{Config, PubKey},
    crypto::{post_reply, pre_reply},
    wire::{Codec, Packet, PacketLayout},
};
use futures::StreamExt;
use serde::Deserialize;
use std::{
    net::{Ipv4Addr, SocketAddr},
    time::SystemTime,
};
use tokio::net::UdpSocket;
use tokio_util::udp::UdpFramed;
use tracing::{error, trace, warn};

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
                    if let Err(err) = process_incoming(&config, packet, addr).await {
                        error!("Failed to process incoming packet: {err}");
                    }
                }
                Err(err) => error!("Failed to parse the packet on udp socket: {err}"),
            }
        }
    }
}

#[tracing::instrument(skip(packet))]
async fn process_incoming(config: &Config, packet: Packet, addr: SocketAddr) -> Result<()> {
    match packet {
        Packet::Initiating(initiating) => {
            let remote_pk = pre_reply(
                &config.interface.private_key.0,
                initiating.enc_pub_key,
                initiating.ephemeral,
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

            let sender_idx = fastrand::u32(..);
            let timestamp = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let (replying, cipher) = post_reply(
                &remote_pk,
                peer.pre_shared_key.as_ref().map(|k| &k.0),
                timestamp,
                sender_idx,
                initiating.sender_idx,
            )?;
        }
        Packet::Reply(replying) => todo!(),
        Packet::Data { nonce, data } => todo!(),
    }

    Ok(())
}
