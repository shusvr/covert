//! Genuine WebRTC data channels; TCP is used only for SDP signaling.
use crate::{
    Result,
    codec::{self, Packet},
    config::Config,
    transport::{Endpoint, PacketSender, State, maintain_peers, process_packet},
};
use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use futures::{SinkExt, StreamExt, channel::mpsc};
use serde::Deserialize;
use std::{
    collections::HashMap,
    io,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc as channel,
    task::JoinSet,
    time::timeout,
};
use uuid::Uuid;
use webrtc::{
    api::{APIBuilder, setting_engine::SettingEngine},
    data_channel::{RTCDataChannel, data_channel_init::RTCDataChannelInit},
    ice_transport::ice_server::RTCIceServer,
    peer_connection::{
        RTCPeerConnection, configuration::RTCConfiguration,
        sdp::session_description::RTCSessionDescription,
    },
};

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct WebrtcListenerConfig {
    /// TCP SDP signaling port. ICE selects separate UDP ports.
    #[serde(default = "default_port")]
    port: u16,
    #[serde(default)]
    ice_servers: Vec<String>,
}
fn default_port() -> u16 {
    40676
}
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct WebrtcTransportPeerConfig {
    endpoint: Option<SocketAddr>,
}
#[derive(Debug, Clone)]
pub struct WebrtcRoute {
    id: Uuid,
    address: Option<SocketAddr>,
}
fn other(e: impl std::fmt::Display) -> io::Error {
    io::Error::other(e.to_string())
}

pub async fn create_webrtc_endpoint(
    state: &Arc<State>,
    config: &Arc<Config>,
    listener: &WebrtcListenerConfig,
) -> Result<Endpoint<impl PacketSender<WebrtcRoute> + use<>, WebrtcRoute>> {
    let socket = TcpListener::bind((Ipv4Addr::UNSPECIFIED, listener.port)).await?;
    let routing = Arc::new(DashMap::new());
    for peer in &config.peers {
        if let Some(address) = peer.transport.webrtc().and_then(|p| p.endpoint) {
            routing.insert(
                peer.id,
                WebrtcRoute {
                    id: Uuid::new_v4(),
                    address: Some(address),
                },
            );
        }
    }
    let (sender, rx) = mpsc::channel(512);
    let maintenance = sender.clone().sink_map_err(Into::into);
    let outgoing = sender.clone().sink_map_err(Into::into);
    let (state, config, routes, settings) = (
        state.clone(),
        config.clone(),
        routing.clone(),
        listener.clone(),
    );
    tokio::spawn(async move {
        let mut tasks = JoinSet::new();
        tasks.spawn(maintain_peers(
            state.clone(),
            config.clone(),
            routes.clone(),
            maintenance,
        ));
        tokio::select! {
            _ = state.tun_in_tx.closed() => {},
            _ = socket_task(socket, rx, outgoing, state.clone(), config, routes, settings) => {},
        }
    });
    Ok(Endpoint {
        sender: sender.sink_map_err(Into::into),
        routing,
    })
}

// Close library-owned ICE/DTLS/SCTP tasks even when our owner is cancelled.
struct Connection(Arc<RTCPeerConnection>);
impl Drop for Connection {
    fn drop(&mut self) {
        let pc = self.0.clone();
        tokio::spawn(async move {
            let _ = pc.close().await;
        });
    }
}

async fn socket_task(
    socket: TcpListener,
    mut rx: mpsc::Receiver<(Packet, WebrtcRoute)>,
    outgoing: impl PacketSender<WebrtcRoute> + Clone + Send + 'static,
    state: Arc<State>,
    config: Arc<Config>,
    routes: Arc<DashMap<Uuid, WebrtcRoute>>,
    settings: WebrtcListenerConfig,
) {
    let mut connections: HashMap<Uuid, channel::Sender<Packet>> = HashMap::new();
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            accepted = socket.accept(), if tasks.len() < 64 => {
                let (stream, _) = match accepted { Ok(v) => v, Err(e) => { tracing::error!(%e, "WebRTC signaling accept failed"); break; } };
                let route = WebrtcRoute { id: Uuid::new_v4(), address: None };
                let (tx, recv) = channel::channel(16);
                connections.insert(route.id, tx);
                spawn_connection(&mut tasks, Some(stream), route, recv, outgoing.clone(), state.clone(), config.clone(), routes.clone(), settings.clone());
            }
            item = rx.next() => {
                let Some((packet, route)) = item else { break };
                if !connections.contains_key(&route.id) {
                    if route.address.is_none() || tasks.len() >= 64 { continue; }
                    let (tx, recv) = channel::channel(16);
                    connections.insert(route.id, tx);
                    spawn_connection(&mut tasks, None, route.clone(), recv, outgoing.clone(), state.clone(), config.clone(), routes.clone(), settings.clone());
                }
                // Never let a connecting or slow peer block other peers.
                if let Some(tx) = connections.get(&route.id) { let _ = tx.try_send(packet); }
            }
            result = tasks.join_next(), if !tasks.is_empty() => {
                if let Some(Ok(id)) = result { connections.remove(&id); }
            }
        }
    }
}
fn spawn_connection(
    tasks: &mut JoinSet<Uuid>,
    stream: Option<TcpStream>,
    route: WebrtcRoute,
    rx: channel::Receiver<Packet>,
    outgoing: impl PacketSender<WebrtcRoute> + Send + 'static,
    state: Arc<State>,
    config: Arc<Config>,
    routes: Arc<DashMap<Uuid, WebrtcRoute>>,
    settings: WebrtcListenerConfig,
) {
    tasks.spawn(async move {
        let id = route.id;
        if let Err(err) =
            connection(stream, route, rx, outgoing, state, config, routes, settings).await
        {
            tracing::debug!(%err, "WebRTC connection ended");
        }
        id
    });
}

async fn write_sdp(stream: &mut TcpStream, sdp: &RTCSessionDescription) -> io::Result<()> {
    let data = serde_json::to_vec(sdp).map_err(other)?;
    if data.len() > 65536 {
        return Err(other("SDP too large"));
    }
    stream.write_u32(data.len() as u32).await?;
    stream.write_all(&data).await
}
async fn read_sdp(stream: &mut TcpStream) -> io::Result<RTCSessionDescription> {
    let len = stream.read_u32().await? as usize;
    if len > 65536 {
        return Err(other("SDP too large"));
    }
    let mut data = vec![0; len];
    stream.read_exact(&mut data).await?;
    serde_json::from_slice(&data).map_err(other)
}
fn attach(
    dc: Arc<RTCDataChannel>,
    incoming: channel::Sender<Bytes>,
    opened: channel::Sender<Arc<RTCDataChannel>>,
) {
    dc.on_message(Box::new(move |msg| {
        let incoming = incoming.clone();
        Box::pin(async move {
            if !msg.is_string {
                let _ = incoming.send(msg.data).await;
            }
        })
    }));
    let channel = dc.clone();
    dc.on_open(Box::new(move || {
        Box::pin(async move {
            let _ = opened.send(channel).await;
        })
    }));
}
async fn connection(
    stream: Option<TcpStream>,
    route: WebrtcRoute,
    mut rx: channel::Receiver<Packet>,
    mut outgoing: impl PacketSender<WebrtcRoute>,
    state: Arc<State>,
    config: Arc<Config>,
    routes: Arc<DashMap<Uuid, WebrtcRoute>>,
    settings: WebrtcListenerConfig,
) -> io::Result<()> {
    let mut engine = SettingEngine::default();
    engine.set_include_loopback_candidate(true);
    let api = APIBuilder::new().with_setting_engine(engine).build();
    let pc = Arc::new(
        api.new_peer_connection(RTCConfiguration {
            ice_servers: settings
                .ice_servers
                .into_iter()
                .map(|url| RTCIceServer {
                    urls: vec![url],
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        })
        .await
        .map_err(other)?,
    );
    let _guard = Connection(pc.clone());
    let (incoming, mut messages) = channel::channel(64);
    let (opened, mut ready) = channel::channel(1);
    let (closed, mut closed_rx) = channel::channel(1);
    pc.on_peer_connection_state_change(Box::new(move |s| {
        let closed = closed.clone();
        Box::pin(async move {
            use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState as S;
            if matches!(s, S::Failed | S::Closed) {
                let _ = closed.try_send(());
            }
        })
    }));
    let dc = timeout(Duration::from_secs(30), async {
        if let Some(mut stream) = stream {
            pc.on_data_channel(Box::new(move |dc| {
                attach(dc, incoming.clone(), opened.clone());
                Box::pin(async {})
            }));
            pc.set_remote_description(read_sdp(&mut stream).await?)
                .await
                .map_err(other)?;
            let answer = pc.create_answer(None).await.map_err(other)?;
            let mut gathered = pc.gathering_complete_promise().await;
            pc.set_local_description(answer).await.map_err(other)?;
            gathered.recv().await;
            write_sdp(
                &mut stream,
                &pc.local_description()
                    .await
                    .ok_or_else(|| other("missing SDP"))?,
            )
            .await?;
        } else {
            let mut stream =
                TcpStream::connect(route.address.ok_or_else(|| other("missing endpoint"))?).await?;
            let dc = pc
                .create_data_channel(
                    "data",
                    Some(RTCDataChannelInit {
                        ordered: Some(false),
                        max_retransmits: Some(0),
                        ..Default::default()
                    }),
                )
                .await
                .map_err(other)?;
            attach(dc, incoming, opened);
            let offer = pc.create_offer(None).await.map_err(other)?;
            let mut gathered = pc.gathering_complete_promise().await;
            pc.set_local_description(offer).await.map_err(other)?;
            gathered.recv().await;
            write_sdp(
                &mut stream,
                &pc.local_description()
                    .await
                    .ok_or_else(|| other("missing SDP"))?,
            )
            .await?;
            pc.set_remote_description(read_sdp(&mut stream).await?)
                .await
                .map_err(other)?;
        }
        ready
            .recv()
            .await
            .ok_or_else(|| other("data channel did not open"))
    })
    .await
    .map_err(|_| other("WebRTC negotiation timed out"))??;
    tracing::debug!(?route, "WebRTC data channel opened");
    loop {
        tokio::select! {
            _ = closed_rx.recv() => break,
            _ = state.tun_in_tx.closed() => break,
            packet = rx.recv() => {
                let Some(packet) = packet else { break };
                let mut data = BytesMut::new();
                codec::append(&mut data, packet, &config.layout).map_err(other)?;
                dc.send(&data.freeze()).await.map_err(other)?;
            }
            data = messages.recv() => {
                let Some(data) = data else { break };
                let mut data = BytesMut::from(data.as_ref());
                match codec::parse(&mut data, &config.layout) {
                    Some(Ok(packet)) => match process_packet(&state, &config, packet, route.clone(), &routes, &mut outgoing).await {
                        Ok(true) => {}, Ok(false) => break,
                        Err(err) => tracing::trace!(%err, "Invalid WebRTC VPN packet"),
                    },
                    None => tracing::trace!("Incomplete WebRTC VPN packet"),
                    Some(Err(err)) => tracing::trace!(%err, "Malformed WebRTC VPN packet"),
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        codec::PacketLayout,
        config::{ListenerConfig, PeerTransport},
        crypto::{pk_to_bytes, random_sk, sk_to_bytes},
    };

    #[tokio::test]
    async fn genuine_data_channel_handshake_bidirectional_padded_data_and_reconnect() {
        let reservation = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = reservation.local_addr().unwrap();
        drop(reservation);
        let a = random_sk().unwrap();
        let b = random_sk().unwrap();
        let make = |private_key, public_key, endpoint, port| {
            let mut config: Config = toml::from_str(include_str!("../../config.toml")).unwrap();
            config.interface.private_key = private_key;
            config.interface.listener = ListenerConfig::Webrtc {
                webrtc: WebrtcListenerConfig {
                    port,
                    ice_servers: vec![],
                },
            };
            config.layout = PacketLayout {
                oip: 1300,
                orp: 1300,
                odp: 1300,
                ..Default::default()
            };
            config.peers.truncate(1);
            config.peers[0].public_key = public_key;
            config.peers[0].pre_shared_key = None;
            config.peers[0].transport = PeerTransport::Webrtc {
                webrtc: WebrtcTransportPeerConfig { endpoint },
            };
            Arc::new(config)
        };
        let a_config = make(
            sk_to_bytes(&a).into(),
            pk_to_bytes(&b.compute_public_key().unwrap()).into(),
            Some(address),
            0,
        );
        let b_config = make(
            sk_to_bytes(&b).into(),
            pk_to_bytes(&a.compute_public_key().unwrap()).into(),
            None,
            address.port(),
        );
        let (tx, mut a_rx) = channel::channel(4);
        let a_state = Arc::new(State::new(tx));
        let (tx, mut b_rx) = channel::channel(4);
        let b_state = Arc::new(State::new(tx));
        let ListenerConfig::Webrtc { webrtc: b_listener } = &b_config.interface.listener else {
            unreachable!()
        };
        let ListenerConfig::Webrtc { webrtc: a_listener } = &a_config.interface.listener else {
            unreachable!()
        };
        let mut b_endpoint = create_webrtc_endpoint(&b_state, &b_config, b_listener)
            .await
            .unwrap();
        let mut a_endpoint = create_webrtc_endpoint(&a_state, &a_config, a_listener)
            .await
            .unwrap();
        timeout(Duration::from_secs(20), async {
            a_endpoint
                .trasmit(&a_state, &a_config, a_config.peers[0].id, b"queued hello")
                .await
                .unwrap();
            assert_eq!(b_rx.recv().await.unwrap(), b"queued hello");
            b_endpoint
                .trasmit(&b_state, &b_config, b_config.peers[0].id, &vec![7; 4000])
                .await
                .unwrap();
            assert_eq!(a_rx.recv().await.unwrap(), vec![7; 4000]);
            assert!(a_state.has_live_connection(a_config.peers[0].id));
            assert!(b_state.has_live_connection(b_config.peers[0].id));
            assert_eq!(a_state.status(&a_config).peers[0].sent, 12);
            assert_eq!(b_state.status(&b_config).peers[0].received, 12);
            // Rekey over the same WebRTC channel.
            a_state.established.clear();
            a_endpoint
                .trasmit(&a_state, &a_config, a_config.peers[0].id, b"reconnected")
                .await
                .unwrap();
            assert_eq!(b_rx.recv().await.unwrap(), b"reconnected");
        })
        .await
        .expect("WebRTC handshake / traffic timed out");
    }

    #[tokio::test]
    async fn rejects_oversize_and_invalid_sdp() {
        for data in [
            65537u32.to_be_bytes().to_vec(),
            [2u32.to_be_bytes().as_slice(), b"{}"].concat(),
        ] {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let mut writer = TcpStream::connect(listener.local_addr().unwrap())
                .await
                .unwrap();
            writer.write_all(&data).await.unwrap();
            let (mut reader, _) = listener.accept().await.unwrap();
            assert!(read_sdp(&mut reader).await.is_err());
        }
    }
}
