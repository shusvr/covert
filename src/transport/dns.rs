use crate::{
    Result,
    codec::{self, Data, DataFlags, Packet},
    config::Config,
    transport::{Endpoint, PacketSender, State, maintain_peers, process_packet},
};
use bytes::BytesMut;
use dashmap::DashMap;
use futures::{SinkExt, StreamExt, channel::mpsc};
use hickory_proto::{
    op::{Edns, Message as DnsMessage, MessageType, OpCode, Query, ResponseCode},
    rr::{DNSClass, Name, RData, Record, RecordType, rdata::TXT},
    serialize::binary::{BinDecodable, BinDecoder},
};
use serde::Deserialize;
use std::{
    collections::{HashMap, VecDeque},
    io,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
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
pub struct DnsListenerConfig {
    #[serde(default = "default_port")]
    port: u16,
    #[serde(default = "default_domain")]
    domain: String,
    /// Seconds between idle client polls. Zero is invalid.
    #[serde(default = "default_poll_interval")]
    poll_interval: u32,
}
fn default_port() -> u16 {
    53
}
fn default_domain() -> String {
    "tunnel.example".to_owned()
}
fn default_poll_interval() -> u32 {
    1
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DnsTransportPeerConfig {
    endpoint: Option<SocketAddr>,
}

#[derive(Debug, Clone)]
pub struct DnsRoute {
    address: SocketAddr,
    server: bool,
}

const MAX_QUEUE: usize = 1024;
const MAX_OUTSTANDING: usize = 1024;
type Outstanding = HashMap<(SocketAddr, u64), (Instant, Query, Vec<u8>, u8)>;
type Pending = HashMap<SocketAddr, VecDeque<Vec<u8>>>;

#[derive(Clone)]
struct Domain {
    name: Name,
    chunk: usize,
}
impl Domain {
    fn new(value: &str) -> io::Result<Self> {
        let name = Name::from_ascii(value)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?
            .to_lowercase();
        // This suffix is configured as a hostname, rather than arbitrary DNS labels.
        if name.is_root()
            || name.iter().any(|label| {
                label.first() == Some(&b'-')
                    || label.last() == Some(&b'-')
                    || !label
                        .iter()
                        .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
            })
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid DNS Domain",
            ));
        }
        let wire = name.iter().map(|label| label.len() + 1).sum::<usize>() + 1;
        // Reserve nonce label, base32 expansion/label lengths, and fragment header.
        let chunk = 255usize.saturating_sub(wire + 17 + 4) * 5 / 8;
        let chunk = chunk.saturating_sub(12).min(96);
        if chunk < 16 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "DNS Domain is too long for tunnel queries",
            ));
        }
        Ok(Self { name, chunk })
    }
}

fn base32(bytes: &[u8]) -> Vec<u8> {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut out = Vec::new();
    let mut bits = 0;
    let mut acc = 0u32;
    for byte in bytes {
        acc = (acc << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((acc >> bits) & 31) as usize]);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((acc << (5 - bits)) & 31) as usize]);
    }
    out
}
fn unbase32(bytes: &[u8]) -> std::result::Result<Vec<u8>, &'static str> {
    let mut out = Vec::new();
    let mut bits = 0;
    let mut acc = 0u32;
    for byte in bytes {
        let byte = byte.to_ascii_lowercase();
        let value = match byte {
            b'a'..=b'z' => byte - b'a',
            b'2'..=b'7' => byte - b'2' + 26,
            _ => return Err("invalid base32 query"),
        };
        acc = (acc << 5) | u32::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    if bits >= 5 || (bits > 0 && acc & ((1 << bits) - 1) != 0) {
        return Err("invalid base32 padding");
    }
    Ok(out)
}

struct Message {
    server: bool,
    token: u64,
    question: Query,
    recursion_desired: bool,
    payload: Vec<u8>,
}

fn encode(
    fragment: &[u8],
    domain: &Domain,
    query: Option<&Message>,
    token: u64,
) -> std::result::Result<BytesMut, codec::Error> {
    use base64::prelude::*;
    let question = if let Some(query) = query {
        query.question.clone()
    } else {
        let nonce = format!("{token:016x}");
        let encoded = base32(fragment);
        let labels = std::iter::once(nonce.as_bytes())
            .chain(encoded.chunks(63))
            .chain(domain.name.iter());
        let name = Name::from_labels(labels)
            .map_err(|err| codec::Error::Io(io::Error::new(io::ErrorKind::InvalidInput, err)))?;
        Query::query(name, RecordType::TXT)
    };
    let token = query.map_or(token, |q| q.token);
    let mode = if query.is_some() {
        MessageType::Response
    } else {
        MessageType::Query
    };
    let mut message = DnsMessage::new(token as u16, mode, OpCode::Query);
    message.metadata.recursion_desired = query.is_none_or(|q| q.recursion_desired);
    message.metadata.authoritative = query.is_some();
    if query.is_some() {
        let text = BASE64_STANDARD.encode(fragment);
        let strings = if text.is_empty() {
            vec![&b""[..]]
        } else {
            text.as_bytes().chunks(255).collect()
        };
        message.add_answer(Record::from_rdata(
            question.name.clone(),
            0,
            RData::TXT(TXT::from_bytes(strings)),
        ));
    }
    message.add_query(question);
    let mut edns = Edns::new();
    edns.set_max_payload(1232).set_version(0);
    message.set_edns(edns);
    let bytes = message
        .to_vec()
        .map_err(|err| codec::Error::Io(io::Error::new(io::ErrorKind::InvalidData, err)))?;
    if bytes.len() > 1232 {
        return Err(codec::Error::PacketOverflow);
    }
    Ok(BytesMut::from(bytes.as_slice()))
}

fn decode(bytes: &[u8], domain: &Domain) -> std::result::Result<Message, &'static str> {
    use base64::prelude::*;
    if bytes.len() > 1232 {
        return Err("invalid DNS length");
    }
    let mut decoder = BinDecoder::new(bytes);
    let packet = DnsMessage::read(&mut decoder).map_err(|_| "invalid DNS message")?;
    if !decoder.is_empty() {
        return Err("trailing DNS data");
    }
    if packet.metadata.op_code != OpCode::Query
        || packet.metadata.response_code != ResponseCode::NoError
        || packet.metadata.truncation
    {
        return Err("unexpected DNS opcode, response code, or truncation");
    }
    let server = packet.metadata.message_type == MessageType::Response;
    if packet.queries.len() != 1
        || packet.answers.len() != usize::from(server)
        || !packet.authorities.is_empty()
        || !packet.additionals.is_empty()
        || packet.signature.is_some()
    {
        return Err("unexpected DNS record counts");
    }
    if packet.edns.as_ref().is_some_and(|edns| edns.version() != 0) {
        return Err("unsupported EDNS version");
    }
    let question = &packet.queries[0];
    if question.query_type != RecordType::TXT || question.query_class != DNSClass::IN {
        return Err("not a TXT IN question");
    }
    let labels: Vec<_> = question.name.iter().collect();
    let suffix: Vec<_> = domain.name.iter().collect();
    if labels.len() < suffix.len() + 1 {
        return Err("wrong DNS domain");
    }
    let suffix_start = labels.len() - suffix.len();
    if labels[suffix_start..]
        .iter()
        .zip(suffix)
        .any(|(a, b)| !a.eq_ignore_ascii_case(b))
    {
        return Err("wrong DNS domain");
    }
    if labels[0].len() != 16 {
        return Err("invalid query nonce");
    }
    let token = u64::from_str_radix(
        std::str::from_utf8(labels[0]).map_err(|_| "invalid nonce")?,
        16,
    )
    .map_err(|_| "invalid nonce")?;
    if token as u16 != packet.metadata.id {
        return Err("DNS ID/nonce mismatch");
    }
    let payload = if server {
        let answer = &packet.answers[0];
        if answer.name != question.name || answer.dns_class != DNSClass::IN {
            return Err("TXT answer does not match question");
        }
        let RData::TXT(txt) = &answer.data else {
            return Err("not a TXT answer");
        };
        if txt.txt_data.is_empty() {
            return Err("empty TXT record");
        }
        let text: Vec<u8> = txt
            .txt_data
            .iter()
            .flat_map(|s| s.iter().copied())
            .collect();
        BASE64_STANDARD
            .decode(text)
            .map_err(|_| "invalid TXT base64")?
    } else {
        unbase32(&labels[1..suffix_start].concat())?
    };
    Ok(Message {
        server,
        token,
        question: question.clone(),
        recursion_desired: packet.metadata.recursion_desired,
        payload,
    })
}

fn fragments(
    packet: Packet,
    layout: &codec::PacketLayout,
    chunk: usize,
) -> std::result::Result<Vec<Vec<u8>>, codec::Error> {
    let mut bytes = BytesMut::new();
    codec::append(&mut bytes, packet, layout)?;
    if bytes.len() > 65507 {
        return Err(codec::Error::PacketOverflow);
    }
    let id = fastrand::u32(..);
    let count = bytes.len().div_ceil(chunk);
    if count > 1024 {
        return Err(codec::Error::PacketOverflow);
    }
    Ok(bytes
        .chunks(chunk)
        .enumerate()
        .map(|(index, data)| {
            let mut frame = Vec::with_capacity(12 + data.len());
            frame.extend_from_slice(&id.to_be_bytes());
            frame.extend_from_slice(&(index as u16).to_be_bytes());
            frame.extend_from_slice(&(count as u16).to_be_bytes());
            frame.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
            frame.extend_from_slice(data);
            frame
        })
        .collect())
}
struct Assembly {
    created: Instant,
    total: usize,
    parts: Vec<Option<Vec<u8>>>,
    size: usize,
}
#[derive(Default)]
struct Reassembly(HashMap<(SocketAddr, bool, u32), Assembly>);
impl Reassembly {
    fn push(
        &mut self,
        source: SocketAddr,
        server: bool,
        bytes: &[u8],
    ) -> std::result::Result<Option<BytesMut>, &'static str> {
        self.0
            .retain(|_, a| a.created.elapsed() < Duration::from_secs(10));
        if bytes.is_empty() {
            return Ok(None);
        }
        if bytes.len() < 13 || bytes.len() > 108 {
            return Err("invalid DNS fragment length");
        }
        let id = u32::from_be_bytes(bytes[..4].try_into().unwrap());
        let index = usize::from(u16::from_be_bytes(bytes[4..6].try_into().unwrap()));
        let count = usize::from(u16::from_be_bytes(bytes[6..8].try_into().unwrap()));
        let total = u32::from_be_bytes(bytes[8..12].try_into().unwrap()) as usize;
        if count == 0
            || count > 1024
            || index >= count
            || total == 0
            || total > 65507
            || count > total
        {
            return Err("invalid DNS fragment metadata");
        }
        let key = (source, server, id);
        if !self.0.contains_key(&key) && self.0.len() >= 64 {
            return Err("DNS reassembly limit");
        }
        let assembly = self.0.entry(key).or_insert_with(|| Assembly {
            created: Instant::now(),
            total,
            parts: vec![None; count],
            size: 0,
        });
        if assembly.total != total || assembly.parts.len() != count {
            return Err("inconsistent DNS fragments");
        }
        if let Some(previous) = &assembly.parts[index] {
            if previous != &bytes[12..] {
                return Err("conflicting DNS duplicate fragment");
            }
            return Ok(None);
        }
        if assembly.size + bytes.len() - 12 > total {
            return Err("DNS reassembly overflow");
        }
        assembly.size += bytes.len() - 12;
        assembly.parts[index] = Some(bytes[12..].to_vec());
        if assembly.parts.iter().any(Option::is_none) {
            return Ok(None);
        }
        let assembly = self.0.remove(&key).unwrap();
        if assembly.size != total {
            return Err("DNS reassembly length mismatch");
        }
        let mut result = BytesMut::with_capacity(total);
        for part in assembly.parts {
            result.extend_from_slice(&part.unwrap());
        }
        Ok(Some(result))
    }
}

pub async fn create_dns_endpoint(
    state: &Arc<State>,
    config: &Arc<Config>,
    listener: &DnsListenerConfig,
) -> Result<Endpoint<impl PacketSender<DnsRoute> + use<>, DnsRoute>> {
    if listener.poll_interval == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "DNS PollInterval must be nonzero",
        )
        .into());
    }
    let domain = Domain::new(&listener.domain)?;
    let socket = Arc::new(UdpSocket::bind((Ipv4Addr::UNSPECIFIED, listener.port)).await?);
    let routes = DashMap::new();
    for peer in &config.peers {
        if let Some(address) = peer.transport.dns().and_then(|p| p.endpoint) {
            if !address.is_ipv4() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "DNS transport currently supports IPv4 only",
                )
                .into());
            }
            routes.insert(
                peer.peer_id,
                DnsRoute {
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
            _ = socket_task(state, config, routes, socket, recv, outgoing, period, domain) => {},
            result = tasks.join_next() => { debug!(?result, "DNS maintenance stopped"); },
        }
    });
    Ok(Endpoint {
        sender: sender.sink_map_err(Into::into),
        routing,
    })
}

async fn send_request(
    socket: &UdpSocket,
    route: &DnsRoute,
    packet: Option<Packet>,
    config: &Config,
    domain: &Domain,
    outstanding: &mut Outstanding,
) -> Result<()> {
    let frames = match packet {
        Some(packet) => fragments(packet, &config.layout, domain.chunk)?,
        None => vec![vec![]],
    };
    for frame in frames {
        outstanding.retain(|_, (sent, _, _, _)| sent.elapsed() < Duration::from_secs(60));
        if outstanding.len() >= MAX_OUTSTANDING {
            if let Some(key) = outstanding
                .iter()
                .min_by_key(|(_, (when, _, _, _))| *when)
                .map(|(key, _)| *key)
            {
                outstanding.remove(&key);
            }
        }
        let mut token = fastrand::u64(..);
        while outstanding.contains_key(&(route.address, token)) {
            token = fastrand::u64(..);
        }
        let bytes = encode(&frame, domain, None, token)?;
        let question = decode(&bytes, domain).map_err(io::Error::other)?.question;
        socket.send_to(&bytes, route.address).await?;
        outstanding.insert(
            (route.address, token),
            (Instant::now(), question, bytes.to_vec(), 0),
        );
        trace!(destination = %route.address, len = bytes.len(), "Sent DNS TXT query");
    }
    Ok(())
}
async fn dispatch(
    socket: &UdpSocket,
    packet: Packet,
    route: DnsRoute,
    config: &Config,
    domain: &Domain,
    outstanding: &mut Outstanding,
    pending: &mut Pending,
) -> Result<()> {
    if !route.server || matches!(&packet, Packet::Initiating(_)) {
        send_request(socket, &route, Some(packet), config, domain, outstanding).await
    } else {
        let frames = fragments(packet, &config.layout, domain.chunk)?;
        let queue = pending.entry(route.address).or_default();
        if queue.len() + frames.len() > MAX_QUEUE {
            return Err(
                io::Error::new(io::ErrorKind::WouldBlock, "DNS response queue full").into(),
            );
        }
        queue.extend(frames);
        Ok(())
    }
}

fn authenticated_poll(state: &State, peer_id: Uuid) -> Result<Option<Packet>> {
    let index = state.peering.get(&peer_id).map(|entry| *entry.value());
    let Some((cipher, receiver_idx)) = index.and_then(|index| state.session(index)) else {
        return Ok(None);
    };
    let (counter, ciphertext) = cipher.encrypt(Vec::new())?;
    Ok(Some(Packet::Data(Data {
        receiver_idx,
        counter,
        ciphertext,
        flags: DataFlags::JUNK,
    })))
}

async fn socket_task<S: PacketSender<DnsRoute>>(
    state: Arc<State>,
    config: Arc<Config>,
    routing: Arc<DashMap<Uuid, DnsRoute>>,
    socket: Arc<UdpSocket>,
    mut recv: mpsc::Receiver<(Packet, DnsRoute)>,
    mut outgoing: S,
    period: Duration,
    domain: Domain,
) {
    let mut outstanding = Outstanding::new();
    let mut pending = Pending::new();
    let mut replies = HashMap::<(SocketAddr, u64), (Instant, Query, BytesMut)>::new();
    let mut polls = interval(period);
    polls.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut reassembly = Reassembly::default();
    let mut bytes = vec![0; 65535];
    loop {
        let result: Result<()> = async {
            tokio::select! {
                _ = state.tun_in_tx.closed() => return Ok(()),
                item = recv.next() => {
                    let Some((packet, route)) = item else { return Ok(()); };
                    dispatch(&socket, packet, route, &config, &domain, &mut outstanding, &mut pending).await?;
                }
                _ = polls.tick() => {
                    let routes: Vec<_> = routing.iter().map(|entry| (*entry.key(), entry.value().clone())).collect();
                    // Remove queues and duplicate-query history for removed/expired associations.
                    pending.retain(|address, _| routes.iter().any(|(id, route)| route.server && route.address == *address && state.has_live_connection(*id)));
                    replies.retain(|_, (created, _, _)| created.elapsed() < Duration::from_secs(12));
                    // Retry the same DNS question/ID so a lost UDP fragment is recoverable.
                    let retry: Vec<_> = outstanding.iter().filter(|(_, (sent, _, _, _))| sent.elapsed() >= Duration::from_secs(1)).map(|(key, _)| *key).collect();
                    for key in retry {
                        if let Some((sent, _, request, attempts)) = outstanding.get_mut(&key) {
                            if *attempts >= 5 { outstanding.remove(&key); continue; }
                            socket.send_to(request, key.0).await?;
                            *sent = Instant::now(); *attempts += 1;
                        }
                    }
                    for (id, route) in routes {
                        if !route.server && state.has_live_connection(id) {
                            // Idle polls authenticate traffic so server-side idle expiry
                            // is refreshed even when only the server has application data.
                            let packet = authenticated_poll(&state, id)?;
                            send_request(&socket, &route, packet, &config, &domain, &mut outstanding).await?;
                        }
                    }
                }
                received = socket.recv_from(&mut bytes) => {
                    let (len, address) = received?;
                    trace!(%address, len, "Received DNS datagram");
                    let message = match decode(&bytes[..len], &domain) {
                        Ok(message) => message,
                        Err(reason) => { trace!(%address, reason, "Discarding DNS datagram"); return Ok(()); }
                    };

                    if message.server {
                        let Some((sent, question, _, _)) = outstanding.get(&(address, message.token)) else { trace!(%address, "Unsolicited DNS server reply"); return Ok(()); };
                        if question != &message.question || sent.elapsed() >= Duration::from_secs(60) { return Ok(()); }
                    } else if let Some((_, question, reply)) = replies.get(&(address, message.token)) {
                        if question == &message.question { socket.send_to(reply, address).await?; }
                        return Ok(());
                    }
                    let assembled = match reassembly.push(address, message.server, &message.payload) {
                        Ok(packet) => packet,
                        Err(reason) => { trace!(%address, reason, "Invalid DNS fragment"); return Ok(()); }
                    };
                    let packet = if let Some(mut data) = assembled {
                        match codec::parse(&mut data, &config.layout) {
                            Some(Ok(packet)) if data.is_empty() => Some(packet),
                            other => { trace!(%address, ?other, remaining = data.len(), "Invalid Covert DNS payload; check layout"); return Ok(()); }
                        }
                    } else { None };
                    // Handshakes establish the role. Data must match its session's role/address.
                    let known = routing.iter().find(|r| r.address == address && r.server != message.server && state.has_live_connection(*r.key())).map(|r| *r.key());
                    match &packet {
                        Some(Packet::Initiating(_)) if message.server => return Ok(()),
                        Some(Packet::Reply(_)) if !message.server => return Ok(()),
                        Some(Packet::Data(data)) => {
                            let Some(handle) = state.established.get(&data.receiver_idx) else { return Ok(()); };
                            if known != Some(handle.peer_id) { return Ok(()); }
                        }

                        _ => {},
                    }
                    let completed = packet.is_some();
                    let keepalive = matches!(&packet, Some(Packet::Data(data)) if data.flags.contains(DataFlags::JUNK));
                    if let Some(packet) = packet {
                        let route = DnsRoute { address, server: !message.server };
                        if !process_packet(&state, &config, packet, route, &routing, &mut outgoing).await? { return Err(io::Error::new(io::ErrorKind::BrokenPipe, "TUN receiver closed").into()); }
                    }
                    if message.server {
                        outstanding.remove(&(address, message.token));
                        // Drain a responder burst one response per fresh request;
                        // an empty response returns the client to its idle poll cadence.
                        if !message.payload.is_empty() && !keepalive {
                            let route = routing.iter().find(|r| r.address == address && !r.server).map(|r| r.value().clone());
                            if let Some(route) = route {
                                send_request(&socket, &route, None, &config, &domain, &mut outstanding).await?;
                            }
                        }
                    } else {
                        // Only authenticated associations can drain server traffic.
                        let live = routing.iter().any(|r| r.address == address && r.server && state.has_live_connection(*r.key()));
                        // process_packet enqueued handshake replies/data; collect before responding.
                        while let Ok((packet, route)) = recv.try_recv() {
                            dispatch(&socket, packet, route, &config, &domain, &mut outstanding, &mut pending).await?;
                        }
                        // A completed authenticated client packet gets an authenticated
                        // reply even when no application data is pending. Partial fragments
                        // and empty drain polls must not create more keepalive work.
                        if live && completed && pending.get(&address).is_none_or(|q| q.is_empty()) {
                            let peer = routing.iter().find(|r| r.address == address && r.server).map(|r| (*r.key(), r.value().clone()));
                            if let Some((id, route)) = peer {
                                if let Some(packet) = authenticated_poll(&state, id)? {
                                    dispatch(&socket, packet, route, &config, &domain, &mut outstanding, &mut pending).await?;
                                }
                            }
                        }
                        let fragment = if live { pending.get_mut(&address).and_then(|q| q.pop_front()).unwrap_or_default() } else { Vec::new() };
                        let reply = encode(&fragment, &domain, Some(&message), message.token)?;
                        socket.send_to(&reply, address).await?;
                        replies.retain(|_, (created, _, _)| created.elapsed() < Duration::from_secs(12));
                        if replies.len() >= MAX_OUTSTANDING {
                            if let Some(key) = replies.iter().min_by_key(|(_, (when, _, _))| *when).map(|(key, _)| *key) { replies.remove(&key); }
                        }
                        replies.insert((address, message.token), (Instant::now(), message.question.clone(), reply.clone()));
                        trace!(%address, len = reply.len(), "Sent DNS server reply");
                    }
                }
            }
            Ok(())
        }.await;
        if state.tun_in_tx.is_closed() {
            break;
        }
        if let Err(err) = result {
            error!("DNS transport: {err}");
        }
    }
}

#[cfg(test)]
mod tests;
