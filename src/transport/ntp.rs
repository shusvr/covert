use crate::{
    Result,
    codec::{self, Packet},
    config::Config,
    transport::{Endpoint, PacketSender, State, maintain_peers, process_packet},
};
use bytes::BytesMut;
use dashmap::DashMap;
use futures::{SinkExt, StreamExt, channel::mpsc};
use serde::Deserialize;
use std::{
    collections::{HashMap, VecDeque},
    io,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    net::UdpSocket,
    task::JoinSet,
    time::{MissedTickBehavior, interval},
};
use tracing::{debug, error, trace};
use uuid::Uuid;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct NtpListenerConfig {
    #[serde(default = "default_port")]
    port: u16,
    /// Seconds between idle client polls. Zero is invalid.
    #[serde(default = "default_poll_interval")]
    poll_interval: u32,
}
fn default_port() -> u16 {
    123
}
fn default_poll_interval() -> u32 {
    1
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct NtpTransportPeerConfig {
    endpoint: Option<SocketAddr>,
}

#[derive(Debug, Clone)]
pub struct NtpRoute {
    address: SocketAddr,
    server: bool,
}

const HEADER: usize = 48;
// Custom tunnel extension, not a standardized NTP authentication mechanism.
const EXTENSION: u16 = 0xf501;
const MAX_QUEUE: usize = 16;
const MAX_OUTSTANDING: usize = 256;
type Outstanding = HashMap<(SocketAddr, u64), Instant>;
type Pending = HashMap<SocketAddr, VecDeque<Packet>>;

fn timestamp() -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let seconds = now.as_secs().wrapping_add(2_208_988_800) as u32;
    (u64::from(seconds) << 32) | ((u64::from(now.subsec_nanos()) << 32) / 1_000_000_000)
}

#[derive(Clone, Copy)]
struct Query {
    transmit: u64,
    received: u64,
    poll: u8,
}
struct Message<'a> {
    server: bool,
    origin: u64,
    transmit: u64,
    poll: u8,
    payload: &'a [u8],
}

fn encode(
    packet: Option<Packet>,
    layout: &codec::PacketLayout,
    query: Option<Query>,
    poll: u8,
    transmit: u64,
) -> std::result::Result<BytesMut, codec::Error> {
    let mut payload = BytesMut::new();
    if let Some(packet) = packet {
        codec::append(&mut payload, packet, layout)?;
    }
    // RFC 7822: 32-bit alignment and final extension >= 28 bytes without a MAC.
    let length = (8usize
        .checked_add(payload.len())
        .ok_or(codec::Error::PacketOverflow)?
        + 3)
        & !3;
    let length = length.max(28);
    if HEADER + length > 65507 {
        return Err(codec::Error::PacketOverflow);
    }
    let mut bytes = BytesMut::zeroed(HEADER + length);
    bytes[0] = (4 << 3) | if query.is_some() { 4 } else { 3 };
    bytes[2] = query.map_or(poll, |q| q.poll);
    bytes[3] = (-20i8) as u8;
    if let Some(query) = query {
        bytes[1] = 1; // Local reference clock; this endpoint does not discipline time.
        bytes[8..12].copy_from_slice(&66u32.to_be_bytes()); // ~1ms dispersion, 16.16.
        bytes[12..16].copy_from_slice(b"LOCL");
        bytes[16..24].copy_from_slice(&query.received.to_be_bytes());
        bytes[24..32].copy_from_slice(&query.transmit.to_be_bytes());
        bytes[32..40].copy_from_slice(&query.received.to_be_bytes());
    }
    bytes[40..48].copy_from_slice(&transmit.to_be_bytes());
    bytes[48..50].copy_from_slice(&EXTENSION.to_be_bytes());
    bytes[50..52].copy_from_slice(&(length as u16).to_be_bytes());
    bytes[52..56].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    bytes[56..56 + payload.len()].copy_from_slice(&payload);
    Ok(bytes)
}

fn decode(bytes: &[u8]) -> std::result::Result<Message<'_>, &'static str> {
    if bytes.len() < HEADER + 28 || bytes[0] >> 6 == 3 || (bytes[0] >> 3) & 7 != 4 {
        return Err("invalid NTPv4 header");
    }
    let server = match bytes[0] & 7 {
        3 => false,
        4 => true,
        _ => return Err("not NTP client/server mode"),
    };
    let origin = u64::from_be_bytes(bytes[24..32].try_into().unwrap());
    let transmit = u64::from_be_bytes(bytes[40..48].try_into().unwrap());
    if transmit == 0
        || (server && (bytes[1] == 0 || bytes[1] > 15 || origin == 0))
        || (!server && origin != 0)
    {
        return Err("invalid NTP timestamps or stratum");
    }
    if u16::from_be_bytes([bytes[48], bytes[49]]) != EXTENSION {
        return Err("not a Covert NTP extension");
    }
    let length = usize::from(u16::from_be_bytes([bytes[50], bytes[51]]));
    if length < 28 || length % 4 != 0 || HEADER + length != bytes.len() {
        return Err("invalid NTP extension length");
    }
    let size = u32::from_be_bytes(bytes[52..56].try_into().unwrap()) as usize;
    let end = 56usize.checked_add(size).ok_or("payload length overflow")?;
    if end > bytes.len() || bytes[end..].iter().any(|b| *b != 0) {
        return Err("invalid NTP extension payload or padding");
    }
    Ok(Message {
        server,
        origin,
        transmit,
        poll: bytes[2],
        payload: &bytes[56..end],
    })
}

pub async fn create_ntp_endpoint(
    state: &Arc<State>,
    config: &Arc<Config>,
    listener: &NtpListenerConfig,
) -> Result<Endpoint<impl PacketSender<NtpRoute> + use<>, NtpRoute>> {
    if listener.poll_interval == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "NTP PollInterval must be nonzero",
        )
        .into());
    }
    let socket = Arc::new(UdpSocket::bind((Ipv4Addr::UNSPECIFIED, listener.port)).await?);
    let routes = DashMap::new();
    for peer in &config.peers {
        if let Some(address) = peer.transport.ntp().and_then(|p| p.endpoint) {
            if !address.is_ipv4() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "NTP transport currently supports IPv4 only",
                )
                .into());
            }
            routes.insert(
                peer.id,
                NtpRoute {
                    address,
                    server: false,
                },
            );
        }
    }
    let routing = Arc::new(routes);
    let (sender, recv) = mpsc::channel(512);
    let maintenance = sender.clone().sink_map_err(Into::into);
    let outgoing = sender.clone().sink_map_err(Into::into);
    let (state, config, routes) = (state.clone(), config.clone(), routing.clone());
    let period = Duration::from_secs(u64::from(listener.poll_interval));
    tokio::spawn(async move {
        let mut tasks = JoinSet::new();
        tasks.spawn(maintain_peers(
            state.clone(),
            config.clone(),
            routes.clone(),
            maintenance,
        ));
        tokio::select! {
            _ = socket_task(state, config, routes, socket, recv, outgoing, period) => {},
            result = tasks.join_next() => { debug!(?result, "NTP maintenance stopped"); },
        }
    });
    Ok(Endpoint {
        sender: sender.sink_map_err(Into::into),
        routing,
    })
}

async fn send_request(
    socket: &UdpSocket,
    route: &NtpRoute,
    packet: Option<Packet>,
    config: &Config,
    poll: u8,
    outstanding: &mut Outstanding,
) -> Result<()> {
    outstanding.retain(|_, sent| sent.elapsed() < Duration::from_secs(60));
    // Bound memory even when no replies arrive, retaining the newest queries.
    if outstanding.len() >= MAX_OUTSTANDING {
        if let Some(key) = outstanding
            .iter()
            .min_by_key(|(_, when)| **when)
            .map(|(key, _)| *key)
        {
            outstanding.remove(&key);
        }
    }
    let mut transmit = timestamp();
    while outstanding.contains_key(&(route.address, transmit)) {
        transmit = transmit.wrapping_add(1);
    }
    let bytes = encode(packet, &config.layout, None, poll, transmit)?;
    socket.send_to(&bytes, route.address).await?;
    outstanding.insert((route.address, transmit), Instant::now());
    trace!(destination = %route.address, len = bytes.len(), "Sent NTP client request");
    Ok(())
}

async fn dispatch(
    socket: &UdpSocket,
    packet: Packet,
    route: NtpRoute,
    config: &Config,
    poll: u8,
    outstanding: &mut Outstanding,
    pending: &mut Pending,
) -> Result<()> {
    // A new initiation always starts a client association, including after expiry.
    if !route.server || matches!(&packet, Packet::Initiating(_)) {
        send_request(socket, &route, Some(packet), config, poll, outstanding).await
    } else {
        let queue = pending.entry(route.address).or_default();
        if queue.len() == MAX_QUEUE {
            queue.pop_front();
        }
        queue.push_back(packet);
        Ok(())
    }
}

async fn socket_task<S: PacketSender<NtpRoute>>(
    state: Arc<State>,
    config: Arc<Config>,
    routing: Arc<DashMap<Uuid, NtpRoute>>,
    socket: Arc<UdpSocket>,
    mut recv: mpsc::Receiver<(Packet, NtpRoute)>,
    mut outgoing: S,
    period: Duration,
) {
    let mut outstanding = Outstanding::new();
    let mut pending = Pending::new();
    let mut last_query = HashMap::<SocketAddr, u64>::new();
    let mut polls = interval(period);
    polls.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let poll = (period.as_secs().ilog2().min(17)) as u8;
    let mut bytes = vec![0; 65535];
    loop {
        let result: Result<()> = async {
            tokio::select! {
                _ = state.tun_in_tx.closed() => return Ok(()),
                item = recv.next() => {
                    let Some((packet, route)) = item else { return Ok(()); };
                    dispatch(&socket, packet, route, &config, poll, &mut outstanding, &mut pending).await?;
                }
                _ = polls.tick() => {
                    let routes: Vec<_> = routing.iter().map(|entry| (*entry.key(), entry.value().clone())).collect();
                    // Remove queues and duplicate-query history for removed/expired associations.
                    pending.retain(|address, _| routes.iter().any(|(id, route)| route.server && route.address == *address && state.has_live_connection(*id)));
                    last_query.retain(|address, _| routes.iter().any(|(id, route)| route.server && route.address == *address && state.has_live_connection(*id)));
                    for (id, route) in routes {
                        if !route.server && state.has_live_connection(id) {
                            if outstanding.iter().any(|((address, _), when)| *address == route.address && when.elapsed() < period) { continue; }
                            send_request(&socket, &route, None, &config, poll, &mut outstanding).await?;
                        }
                    }
                }
                received = socket.recv_from(&mut bytes) => {
                    let (len, address) = received?;
                    trace!(%address, len, "Received NTP datagram");
                    let message = match decode(&bytes[..len]) {
                        Ok(message) => message,
                        Err(reason) => { trace!(%address, reason, "Discarding NTP datagram"); return Ok(()); }
                    };
                    let received_at = timestamp();
                    if message.server {
                        let Some(sent) = outstanding.get(&(address, message.origin)) else { trace!(%address, "Unsolicited NTP server reply"); return Ok(()); };
                        if sent.elapsed() >= Duration::from_secs(60) { return Ok(()); }
                    } else if last_query.get(&address) == Some(&message.transmit) {
                        return Ok(());
                    }
                    let packet = if message.payload.is_empty() { None } else {
                        let mut data = BytesMut::from(message.payload);
                        match codec::parse(&mut data, &config.layout) {
                            Some(Ok(packet)) if data.is_empty() => Some(packet),
                            other => { trace!(%address, ?other, remaining = data.len(), "Invalid Covert NTP payload; check layout"); return Ok(()); }
                        }
                    };
                    // Handshakes establish the role. Data must match its session's role/address.
                    let known = routing.iter().find(|r| r.address == address && r.server != message.server && state.has_live_connection(*r.key())).map(|r| *r.key());
                    match &packet {
                        Some(Packet::Initiating(_)) if message.server => return Ok(()),
                        Some(Packet::Reply(_)) if !message.server => return Ok(()),
                        Some(Packet::Data(data)) => {
                            let Some(handle) = state.established.get(&data.receiver_idx) else { return Ok(()); };
                            if known != Some(handle.peer_id) { return Ok(()); }
                        }
                        None if known.is_none() => return Ok(()),
                        _ => {},
                    }
                    if let Some(packet) = packet {
                        let route = NtpRoute { address, server: !message.server };
                        if !process_packet(&state, &config, packet, route, &routing, &mut outgoing).await? { return Err(io::Error::new(io::ErrorKind::BrokenPipe, "TUN receiver closed").into()); }
                    }
                    if message.server {
                        outstanding.remove(&(address, message.origin));
                        // Drain a responder burst one response per fresh request;
                        // an empty response returns the client to its idle poll cadence.
                        if !message.payload.is_empty() {
                            let route = routing.iter().find(|r| r.address == address && !r.server && state.has_live_connection(*r.key())).map(|r| r.value().clone());
                            if let Some(route) = route {
                                send_request(&socket, &route, None, &config, poll, &mut outstanding).await?;
                            }
                        }
                    } else {
                        // Only authenticated associations get a response. Never answer ordinary NTP.
                        let live = routing.iter().any(|r| r.address == address && r.server && state.has_live_connection(*r.key()));
                        if !live { return Ok(()); }
                        last_query.insert(address, message.transmit);
                        // process_packet enqueued handshake replies/data; collect before responding.
                        while let Ok((packet, route)) = recv.try_recv() {
                            dispatch(&socket, packet, route, &config, poll, &mut outstanding, &mut pending).await?;
                        }
                        let packet = pending.get_mut(&address).and_then(|q| q.pop_front());
                        let query = Query { transmit: message.transmit, received: received_at, poll: message.poll };
                        let reply = encode(packet, &config.layout, Some(query), poll, timestamp())?;
                        socket.send_to(&reply, address).await?;
                        trace!(%address, len = reply.len(), "Sent NTP server reply");
                    }
                }
            }
            Ok(())
        }.await;
        if state.tun_in_tx.is_closed() {
            break;
        }
        if let Err(err) = result {
            error!("NTP transport: {err}");
        }
    }
}

#[cfg(test)]
mod tests;
