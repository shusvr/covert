use crate::{
    Key, Result,
    config::{Config, PubKey},
    crypto::{Cipher, Initiating, finish, post_reply, pre_reply},
    wire::{Codec, Packet, PacketLayout},
};
use dashmap::DashMap;
use futures::{SinkExt, StreamExt};
use kameo::{
    Actor,
    actor::{ActorRef, Spawn, WeakActorRef},
    message::Message,
    prelude::Context,
};
use serde::Deserialize;
use std::{
    net::{Ipv4Addr, SocketAddr},
    pin::pin,
    sync::{Arc, atomic::AtomicU64},
    time::{Duration, SystemTime},
};
use tokio::{net::UdpSocket, sync::Notify, time::sleep};
use tokio_util::udp::UdpFramed;
use tracing::{debug, error, trace, warn};
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
    let state = Arc::new(State {
        established: DashMap::new(),
        initiated: DashMap::new(),
        peering: DashMap::new(),
    });
    let addr = (Ipv4Addr::UNSPECIFIED, listener.port);
    let socket = Arc::new(UdpSocket::bind(addr).await?);
    // TODO: change packet layout
    let mut framed = UdpFramed::new(socket.clone(), Codec::new(PacketLayout::default()));

    loop {
        if let Some(result) = framed.next().await {
            match result {
                Ok((packet, addr)) => {
                    trace!(?addr, "Received a packet on udp socket");
                    if let Err(err) = process_incoming(&state, &socket, &config, packet, addr).await
                    {
                        error!("Failed to process incoming packet: {err}");
                    }
                }
                Err(err) => error!("Failed to parse the packet on udp socket: {err}"),
            }
        }
    }
}

pub struct PeerHandle {
    peer_id: Uuid,
    timestamp: u64,
    sent: AtomicU64,
    received: AtomicU64,
    handle: WeakActorRef<UdpPeer>,
    notify: Arc<Notify>,
}

impl PeerHandle {
    pub fn new(peer_id: Uuid, handle: WeakActorRef<UdpPeer>, timestamp: u64) -> Self {
        Self {
            timestamp,
            handle,
            peer_id,
            sent: 0.into(),
            received: 0.into(),
            notify: Arc::new(Notify::new()),
        }
    }
}

pub struct Initiated {
    peer_id: Uuid,
    psk: Key,
    initiating: Initiating,
}

#[derive(Default)]
pub struct State {
    established: DashMap<u32, PeerHandle>,
    initiated: DashMap<u32, Initiated>,
    peering: DashMap<Uuid, u32>,
}

#[tracing::instrument(skip(state, socket, packet, config))]
async fn process_incoming(
    state: &Arc<State>,
    socket: &Arc<UdpSocket>,
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

            let handle = establish(
                cipher,
                socket,
                from,
                timestamp,
                initiating.sender_idx,
                peer.peer_id,
            );
            state.established.insert(initiating.sender_idx, handle);
            state.peering.insert(peer.peer_id, initiating.sender_idx);
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

            let cipher = finish(&config.interface.private_key.0, None, replying.eph)?;

            let timestamp = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_err(std::io::Error::other)?
                .as_secs();

            let handle = establish(
                cipher,
                socket,
                from,
                timestamp,
                replying.sender_idx,
                initiated.peer_id,
            );
            state.established.insert(replying.receiver_idx, handle);
            state
                .peering
                .insert(initiated.peer_id, replying.receiver_idx);
        }
        Packet::Data {
            receiver_idx,
            counter,
            ciphertext,
        } => {
            if let Some(handle) = state.established.get(&receiver_idx) {
                if let Some(actor) = handle.handle.upgrade() {
                    if let Some(plaintext) =
                        actor.ask(RecvPacket(counter, ciphertext)).await.unwrap()
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
                        }
                    } else {
                        debug!(receiver_idx, "Actor failed to decrypt, cleaning ip");

                        state.peering.remove(&handle.value().peer_id);
                        drop(handle);
                        state.established.remove(&receiver_idx);
                    }
                } else {
                    debug!(receiver_idx, "Actor has expired, cleaning up");

                    state.peering.remove(&handle.value().peer_id);
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

#[derive(Actor)]
pub struct UdpPeer {
    framed: UdpFramed<Codec, Arc<UdpSocket>>,
    receiver_idx: u32,
    dst: SocketAddr,
    cipher: Cipher,
}

pub struct SendPacket(Vec<u8>);
pub struct RecvPacket(u64, Vec<u8>);

impl Message<RecvPacket> for UdpPeer {
    type Reply = Option<Vec<u8>>;

    async fn handle(
        &mut self,
        RecvPacket(nonce, ciphertext): RecvPacket,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        if let Ok(plaintext) = self.cipher.decrypt(nonce, ciphertext) {
            Some(plaintext)
        } else {
            debug!("Actor failed to decrypt, stopping");
            ctx.stop();
            None
        }
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
            receiver_idx: self.receiver_idx,
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
    receiver_idx: u32,
    peer_id: Uuid,
) -> PeerHandle {
    let framed = UdpFramed::new(socket.clone(), Codec::new(PacketLayout::default()));
    let notify = Arc::new(Notify::new());
    let actor = UdpPeer {
        framed,
        dst: from,
        receiver_idx,
        cipher,
    };

    let handle = UdpPeer::spawn(actor);
    tokio::spawn(retain(handle.clone(), notify.clone(), 300, 60));

    let weak = handle.downgrade();
    PeerHandle::new(peer_id, weak, timestamp)
}
