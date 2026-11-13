use crate::{
    Result,
    config::{Config, PubKey},
    crypto::{Cipher, Initiating, finish, post_reply, pre_reply},
    wire::{Codec, Packet, PacketLayout},
};
use futures::{SinkExt, StreamExt};
use kameo::{
    Actor,
    actor::{ActorRef, Spawn, WeakActorRef},
    message::Message,
    prelude::Context,
};
use serde::Deserialize;
use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddr},
    pin::pin,
    sync::{Arc, atomic::AtomicU64},
    time::{Duration, SystemTime},
};
use tokio::{net::UdpSocket, sync::Notify, time::sleep};
use tokio_util::udp::UdpFramed;
use tracing::{debug, error, trace, warn};

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
    let socket = Arc::new(UdpSocket::bind(addr).await?);
    // TODO: change packet layout
    let mut framed = UdpFramed::new(socket.clone(), Codec::new(PacketLayout::default()));

    loop {
        if let Some(result) = framed.next().await {
            match result {
                Ok((packet, addr)) => {
                    trace!(?addr, "Received a packet on udp socket");
                    if let Err(err) = process_incoming(&socket, &config, packet, addr).await {
                        error!("Failed to process incoming packet: {err}");
                    }
                }
                Err(err) => error!("Failed to parse the packet on udp socket: {err}"),
            }
        }
    }
}

pub struct PeerHandle {
    timestamp: u64,
    sent: AtomicU64,
    received: AtomicU64,
    handle: WeakActorRef<UdpPeer>,
}

impl PeerHandle {
    pub fn new(handle: WeakActorRef<UdpPeer>, timestamp: u64) -> Self {
        Self {
            timestamp,
            handle,
            sent: 0.into(),
            received: 0.into(),
        }
    }
}

#[tracing::instrument(skip(socket, packet, config))]
async fn process_incoming(
    socket: &Arc<UdpSocket>,
    config: &Config,
    packet: Packet,
    from: SocketAddr,
) -> Result<()> {
    let mut established = HashMap::<u32, PeerHandle>::new();
    let mut initiated = HashMap::<u32, _>::new();

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

            let handle = establish(cipher, socket, from, timestamp);
        }
        Packet::Reply(replying) => {
            let Some(initiated): Option<Initiating> = initiated.remove(&replying.receiver_idx)
            else {
                warn!(
                    receiver_idx = replying.receiver_idx,
                    "Received a reply to an unknown index"
                );
                return Ok(());
            };

            let (timestamp, cipher) = finish(
                &config.interface.private_key.0,
                None,
                replying.enc_ts,
                replying.eph,
            )?;

            let handle = establish(cipher, socket, from, timestamp);
        }
        Packet::Data {
            counter,
            ciphertext,
        } => todo!(),
    }

    Ok(())
}

#[derive(Actor)]
pub struct UdpPeer {
    framed: UdpFramed<Codec, Arc<UdpSocket>>,
    dst: SocketAddr,
    cipher: Cipher,
}

pub struct SendPacket(Vec<u8>);
pub struct RecvPacket(Vec<u8>);

impl Message<RecvPacket> for UdpPeer {
    type Reply = ();

    async fn handle(
        &mut self,
        RecvPacket(packet): RecvPacket,
        ctx: &mut Context<Self, Self::Reply>,
    ) {
    }
}

impl Message<SendPacket> for UdpPeer {
    type Reply = ();

    async fn handle(
        &mut self,
        SendPacket(packet): SendPacket,
        ctx: &mut Context<Self, Self::Reply>,
    ) {
        let Ok((counter, ciphertext)) = self.cipher.encrypt(packet) else {
            debug!("Actor failed to encrypt, stopping");
            ctx.stop();
            return;
        };

        let item = Packet::Data {
            counter,
            ciphertext,
        };
        if let Err(err) = self.framed.send((item, self.dst)).await {
            error!("Actor failed to send, stopping");
            ctx.stop();
        }
    }
}

async fn retain(actor_ref: ActorRef<UdpPeer>, notify: Arc<Notify>, ttl: u64, idle: u64) {
    // this ensures actor lives at most `ttl` seconds
    let mut ttl_fut = pin!(sleep(Duration::from_secs(ttl)));

    loop {
        tokio::select! {
            biased;
            // by not putting sleep future in select! we do not reset the timer on each poll
            _ = &mut ttl_fut => {
                debug!("Actor has reached end of life");
                break;
            }
            // here we recreate the sleep future each poll to only resolve when actually idle
            _ = sleep(Duration::from_secs(idle)) => {
                debug!("Actor has expired");
                break;
            }
            _ = notify.notified() => {
                debug!("Actor has received keep alive");
                continue;
            }
        }
    }

    drop(actor_ref)
}

fn establish(
    cipher: Cipher,
    socket: &Arc<UdpSocket>,
    from: SocketAddr,
    timestamp: u64,
) -> PeerHandle {
    let framed = UdpFramed::new(socket.clone(), Codec::new(PacketLayout::default()));
    let notify = Arc::new(Notify::new());
    let actor = UdpPeer {
        framed,
        dst: from,
        cipher,
    };

    let handle = UdpPeer::spawn(actor);
    tokio::spawn(retain(handle.clone(), notify.clone(), 300, 60));

    let weak = handle.downgrade();
    PeerHandle::new(weak, timestamp)
}
