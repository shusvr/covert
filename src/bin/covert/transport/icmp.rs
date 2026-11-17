use crate::{
    codec::{self, Packet, PacketLayout},
    config::{Config, PeerTransport},
    error::Result,
    transport::{PeerTunnel, State, TransportEndpoint, identify, plaintext_len},
};
use bytes::BytesMut;
use serde::Deserialize;
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    collections::HashMap,
    io::Write,
    mem::MaybeUninit,
    net::{Ipv4Addr, SocketAddrV4},
    process::{Command, Stdio},
    sync::{Arc, atomic::Ordering},
    time::Duration,
};
use tokio::{
    io::unix::AsyncFd,
    sync::mpsc,
    time::{MissedTickBehavior, interval},
};
use tracing::{error, trace};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq, Eq)]
pub enum IcmpMode {
    #[default]
    EchoReply,
    OnlyEcho,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct IcmpListenerConfig {
    #[serde(default = "default_icmp_id")]
    id: u16,
    #[serde(default)]
    mode: IcmpMode,
}

fn default_icmp_id() -> u16 {
    1339
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct IcmpTransportPeerConfig {
    endpoint: Option<Ipv4Addr>,
}

#[derive(Debug, Clone)]
struct IcmpRoute {
    address: Ipv4Addr,
    reply: Option<etherparse::IcmpEchoHeader>,
}

impl IcmpRoute {
    fn request(address: Ipv4Addr) -> Self {
        Self {
            address,
            reply: None,
        }
    }
    fn response(address: Ipv4Addr, id: u16, seq: u16) -> Self {
        Self {
            address,
            reply: Some(etherparse::IcmpEchoHeader { id, seq }),
        }
    }
    fn echo_type(&self, initiating: bool, id: u16, sequence: &mut u16) -> etherparse::Icmpv4Type {
        if !initiating && let Some(reply) = self.reply {
            return etherparse::Icmpv4Type::EchoReply(reply);
        }
        let echo = etherparse::IcmpEchoHeader { id, seq: *sequence };
        *sequence = sequence.wrapping_add(1);
        etherparse::Icmpv4Type::EchoRequest(echo)
    }
}

const SOCKET_MARK: u32 = 0x434f5654;

pub struct IcmpEndpoint {
    sender: mpsc::Sender<(Uuid, Vec<u8>)>,
}

impl TransportEndpoint for IcmpEndpoint {
    async fn trasmit(
        &mut self,
        _state: &State,
        _config: &Config,
        peer_id: Uuid,
        packet: &[u8],
    ) -> Result<()> {
        self.sender
            .send((peer_id, packet.to_vec()))
            .await
            .map_err(|_| crate::error::Error::EndpointStopped { transport: "ICMP" })?;
        Ok(())
    }
}

struct EchoEncoder {
    layout: PacketLayout,
    id: u16,
    mode: IcmpMode,
    sequence: u16,
    buffer: BytesMut,
}

impl EchoEncoder {
    fn new(layout: PacketLayout, listener: &IcmpListenerConfig) -> Self {
        Self {
            layout,
            id: listener.id,
            mode: listener.mode,
            sequence: 0,
            buffer: BytesMut::new(),
        }
    }

    fn encode(&mut self, packet: Packet, route: &IcmpRoute) -> Result<&[u8]> {
        let initiating = self.mode == IcmpMode::OnlyEcho || matches!(packet, Packet::Initiating(_));
        let kind = route.echo_type(initiating, self.id, &mut self.sequence);
        self.buffer.clear();
        self.buffer.resize(8, 0);
        codec::append(&mut self.buffer, packet, &self.layout)?;
        let header = etherparse::Icmpv4Header::with_checksum(kind, &self.buffer[8..]);
        self.buffer[..8].copy_from_slice(&header.to_bytes());
        Ok(&self.buffer)
    }
}

pub async fn create_icmp_endpoint(
    state: &Arc<State>,
    config: &Arc<Config>,
    listener: &IcmpListenerConfig,
) -> Result<IcmpEndpoint> {
    let mut peers = HashMap::new();
    for peer in &config.peers {
        let address = match &peer.transport {
            PeerTransport::Icmp { icmp } => icmp.endpoint.map(IcmpRoute::request),
            PeerTransport::None => None,
            _ => continue,
        };
        peers.insert(peer.id, PeerTunnel::new(config, peer, address)?);
    }
    let icmp = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))?;
    icmp.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, listener.id).into())?;
    icmp.set_mark(SOCKET_MARK)?;
    icmp.set_nonblocking(true)?;
    // The AsyncFd owns the descriptor until the worker exits.
    let socket = unsafe { AsyncFd::register(icmp).map_err(|err| err.into_parts().1)? };
    let firewall = ReplyFilter::install(listener.id)?;
    let (sender, receiver) = mpsc::channel(512);
    let state = state.clone();
    let config = config.clone();
    let listener = listener.clone();
    tokio::spawn(async move {
        let _firewall = firewall;
        for id in peers.keys() {
            state.connected.insert(*id, false);
        }
        if let Err(err) = run_icmp(&socket, &state, &config, &listener, &mut peers, receiver).await
        {
            error!(%err, "ICMP endpoint stopped");
        }
        for id in peers.keys() {
            state.connected.insert(*id, false);
        }
    });
    Ok(IcmpEndpoint { sender })
}

async fn run_icmp(
    socket: &AsyncFd<Socket>,
    state: &State,
    config: &Config,
    listener: &IcmpListenerConfig,
    peers: &mut HashMap<Uuid, PeerTunnel<IcmpRoute>>,
    mut receiver: mpsc::Receiver<(Uuid, Vec<u8>)>,
) -> Result<()> {
    let mut buffer = vec![MaybeUninit::<u8>::uninit(); 65535];
    let mut encoder = EchoEncoder::new(config.layout, listener);
    let mut timer = interval(Duration::from_millis(100));
    timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = state.tun_in_tx.closed() => return Ok(()),
            request = receiver.recv() => {
                let Some((id, packet)) = request else { return Ok(()) };
                if let Some(peer) = peers.get_mut(&id) {
                    peer.tunnel.push_packet(&packet);
                    if let Err(err) = peer.advance(id, state) {
                        trace!(%id, %err, "Failed to process ICMP tunnel");
                    }
                    flush(socket, peer, id, state, &mut encoder).await?;
                }
            }
            _ = timer.tick() => {
                for (&id, peer) in peers.iter_mut() {
                    if let Err(err) = peer.advance(id, state) {
                        trace!(%id, %err, "Failed to maintain ICMP tunnel");
                    }
                    flush(socket, peer, id, state, &mut encoder).await?;
                }
            }
            incoming = socket.async_io(tokio::io::Interest::READABLE, |socket| socket.recv(&mut buffer)) => {
                let len = incoming?;
                // recv initialized exactly the returned number of bytes.
                let bytes = unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), len) };
                match process_echo(config, peers, state, bytes, listener) {
                    Ok(Some(id)) => flush(socket, peers.get_mut(&id).unwrap(), id, state, &mut encoder).await?,
                    Ok(None) => {},
                    Err(err) => trace!(%err, "Discarding invalid ICMP packet"),
                }
            }
        }
    }
}

fn process_echo(
    config: &Config,
    peers: &mut HashMap<Uuid, PeerTunnel<IcmpRoute>>,
    state: &State,
    bytes: &[u8],
    listener: &IcmpListenerConfig,
) -> Result<Option<Uuid>> {
    let Some((address, payload)) = echo_payload(bytes, listener.id, listener.mode) else {
        return Ok(None);
    };
    let packet = match codec::parse_slice(payload, &config.layout) {
        Some(Ok((packet, consumed))) if consumed == payload.len() => packet,
        _ => return Ok(None),
    };
    let offset = (bytes[0] as usize & 15) * 4;
    let is_request = bytes[offset] == 8;
    let echo_id = u16::from_be_bytes([bytes[offset + 4], bytes[offset + 5]]);
    let sequence = u16::from_be_bytes([bytes[offset + 6], bytes[offset + 7]]);
    if listener.mode == IcmpMode::EchoReply
        && matches!(
            (&packet, is_request),
            (Packet::Initiating(_), false) | (Packet::Reply(_), true)
        )
    {
        return Ok(None);
    }
    let Some((id, decoded)) = identify(config, peers, &packet)? else {
        return Ok(None);
    };
    let peer = peers.get_mut(&id).unwrap();
    let is_data = matches!(packet, Packet::Data(_));
    if is_data
        && !peer.address.as_ref().is_some_and(|route| {
            route.address == address
                && (listener.mode == IcmpMode::OnlyEcho || route.reply.is_some() == is_request)
        })
    {
        return Ok(None);
    }
    let before = peer.tunnel.established_at();
    match decoded {
        Some(decoded) => peer.tunnel.process_initiation(decoded)?,
        None => peer.tunnel.process_incoming_packet(packet)?,
    }
    peer.advance(id, state)?;
    if peer.tunnel.is_live() && (is_data || peer.tunnel.established_at() != before) {
        peer.address = Some(if listener.mode == IcmpMode::EchoReply && is_request {
            IcmpRoute::response(address, echo_id, sequence)
        } else {
            IcmpRoute::request(address)
        });
    }
    Ok(Some(id))
}

async fn flush(
    socket: &AsyncFd<Socket>,
    peer: &mut PeerTunnel<IcmpRoute>,
    id: Uuid,
    state: &State,
    encoder: &mut EchoEncoder,
) -> Result<()> {
    if let Some(route) = &peer.address {
        while let Some(packet) = peer.tunnel.read_outbound_packet() {
            let size = plaintext_len(&packet);
            let bytes = encoder.encode(packet, route)?;
            let address = SocketAddrV4::new(route.address, 0).into();
            match socket
                .async_io(tokio::io::Interest::WRITABLE, |socket| {
                    socket.send_to(bytes, &address)
                })
                .await
            {
                Ok(sent) if sent == bytes.len() => {
                    state
                        .peer_statistics
                        .entry(id)
                        .or_default()
                        .sent
                        .fetch_add(size as u64, Ordering::Relaxed);
                }
                result => {
                    trace!(%id, address = %route.address, ?result, "Failed to send complete ICMP datagram")
                }
            }
        }
    }
    peer.deliver(id, state).await
}

// A private table keeps cleanup from modifying any existing firewall rules.
struct ReplyFilter(String);
impl ReplyFilter {
    fn install(id: u16) -> Result<Self> {
        let table = format!("covert_icmp_{}_{}", std::process::id(), fastrand::u32(..));
        let rules = format!(
            "add table ip {table}\nadd chain ip {table} output {{ type filter hook output priority 0; policy accept; }}\nadd rule ip {table} output icmp type echo-reply icmp id {id} meta mark != {SOCKET_MARK} drop\n"
        );
        let mut child = Command::new("nft")
            .args(["-f", "-"])
            .stdin(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        child.stdin.take().unwrap().write_all(rules.as_bytes())?;
        let output = child.wait_with_output()?;
        if !output.status.success() {
            return Err(crate::error::Error::IcmpFirewallSetup {
                status: output.status,
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            });
        }
        Ok(Self(table))
    }
}
impl Drop for ReplyFilter {
    fn drop(&mut self) {
        match Command::new("nft")
            .args(["delete", "table", "ip", &self.0])
            .output()
        {
            Ok(output) if output.status.success() => {}
            other => error!(?other, table = %self.0, "Failed to remove ICMP firewall table"),
        }
    }
}

// Raw IPv4 sockets include the IP header, including any IPv4 options.
fn echo_payload(bytes: &[u8], id: u16, mode: IcmpMode) -> Option<(Ipv4Addr, &[u8])> {
    if bytes.len() < 20 || bytes[0] >> 4 != 4 || bytes[9] != 1 {
        return None;
    }
    let header_len = (bytes[0] as usize & 15) * 4;
    let total_len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
    if header_len < 20
        || total_len < header_len + 8
        || total_len > bytes.len()
        || u16::from_be_bytes([bytes[6], bytes[7]]) & 0x3fff != 0
    {
        return None;
    }
    let icmp = &bytes[header_len..total_len];
    let (header, payload) = etherparse::Icmpv4Header::from_slice(icmp).ok()?;
    if header.checksum != header.icmp_type.calc_checksum(payload) {
        return None;
    }
    if !matches!(icmp[0], 0 | 8)
        || icmp[1] != 0
        || (mode == IcmpMode::OnlyEcho && icmp[0] != 8)
        || u16::from_be_bytes([icmp[4], icmp[5]]) != id
    {
        return None;
    }
    Some((
        Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]),
        payload,
    ))
}

#[cfg(test)]
mod tests;
