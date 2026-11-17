use crate::network;
use anyhow::Result;
use bytes::BytesMut;
use covert::{
    codec::{self, Packet, PacketLayout},
    config::{Config, Peer, PeerTransport},
    transport::{Adapter, Endpoint, IcmpListenerConfig, IcmpMode},
};
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    io::Write,
    mem::MaybeUninit,
    net::{Ipv4Addr, SocketAddrV4},
    ops::Range,
    process::{Command, Stdio},
    sync::Mutex,
};
use tokio::io::unix::AsyncFd;
use tracing::{error, trace};

#[derive(Debug, Clone)]
pub struct IcmpRoute {
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
    fn reply_key(&self) -> Option<(Ipv4Addr, u16)> {
        self.reply.map(|echo| (self.address, echo.id))
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
            id: fastrand::u16(1..=u16::MAX),
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

pub struct EchoAdapter {
    mode: IcmpMode,
    pending: Mutex<Vec<(IcmpRoute, Packet)>>,
    firewall: Option<ReplyFilter>,
}
impl Adapter for EchoAdapter {
    type Route = IcmpRoute;
    fn supports_peer(&self, peer: &Peer) -> bool {
        matches!(
            peer.transport,
            PeerTransport::Icmp { .. } | PeerTransport::None
        )
    }
    fn peer_route(&self, peer: &Peer) -> Option<IcmpRoute> {
        match &peer.transport {
            PeerTransport::Icmp { icmp } => icmp.endpoint.map(IcmpRoute::request),
            _ => None,
        }
    }
    fn deliver(&self, route: IcmpRoute, packet: Packet) {
        self.pending.lock().unwrap().push((route, packet));
    }
    fn accepts(&self, previous: Option<&IcmpRoute>, incoming: &IcmpRoute, packet: &Packet) -> bool {
        if self.mode == IcmpMode::EchoReply
            && matches!(
                (packet, incoming.reply.is_some()),
                (Packet::Initiating(_), false) | (Packet::Reply(_), true)
            )
        {
            return false;
        }
        !matches!(packet, Packet::Data(_))
            || previous.is_some_and(|previous| {
                previous.address == incoming.address
                    && (self.mode == IcmpMode::OnlyEcho
                        || previous.reply.is_some() == incoming.reply.is_some())
            })
    }
    fn route_changed<'a>(
        &self,
        previous: Option<&IcmpRoute>,
        next: &IcmpRoute,
        other_routes: impl Iterator<Item = &'a IcmpRoute>,
    ) -> covert::transport::Result<()> {
        if let Some(filter) = &self.firewall {
            filter.update_route(
                previous.and_then(IcmpRoute::reply_key),
                next.reply_key(),
                other_routes,
            )?;
        }
        Ok(())
    }
}

pub struct Icmp {
    socket: AsyncFd<Socket>,
    encoder: Mutex<EchoEncoder>,
}
impl Icmp {
    pub fn bind(
        config: &Config,
        listener: &IcmpListenerConfig,
    ) -> Result<(Self, Endpoint<EchoAdapter>)> {
        let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))?;
        socket.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0).into())?;
        socket.set_mark(SOCKET_MARK)?;
        socket.set_nonblocking(true)?;
        let socket = unsafe { AsyncFd::register(socket).map_err(|err| err.into_parts().1)? };
        let encoder = EchoEncoder::new(config.layout, listener);
        let firewall = ReplyFilter::install(encoder.id)?;
        let adapter = EchoAdapter {
            mode: listener.mode,
            pending: Mutex::new(Vec::new()),
            firewall: Some(firewall),
        };
        let endpoint = Endpoint::new(adapter, config.clone()).map_err(anyhow::Error::from_boxed)?;
        Ok((
            Self {
                socket,
                encoder: Mutex::new(encoder),
            },
            endpoint,
        ))
    }
}
impl network::Socket for Icmp {
    type Adapter = EchoAdapter;
    async fn receive(&self, buffer: &mut [u8]) -> Result<Option<(IcmpRoute, Range<usize>)>> {
        // Initialized bytes may safely be exposed as MaybeUninit to recv.
        let uninit = unsafe {
            std::slice::from_raw_parts_mut(
                buffer.as_mut_ptr().cast::<MaybeUninit<u8>>(),
                buffer.len(),
            )
        };
        let len = self
            .socket
            .async_io(tokio::io::Interest::READABLE, |socket| socket.recv(uninit))
            .await?;
        let encoder = self.encoder.lock().unwrap();
        Ok(incoming(&buffer[..len], &encoder))
    }
    async fn flush(&self, adapter: &EchoAdapter) -> Result<()> {
        let pending = std::mem::take(&mut *adapter.pending.lock().unwrap());
        for (route, packet) in pending {
            let bytes = self
                .encoder
                .lock()
                .unwrap()
                .encode(packet, &route)?
                .to_vec();
            let address = SocketAddrV4::new(route.address, 0).into();
            match self
                .socket
                .async_io(tokio::io::Interest::WRITABLE, |socket| {
                    socket.send_to(&bytes, &address)
                })
                .await
            {
                Ok(sent) if sent == bytes.len() => {}
                result => {
                    trace!(address = %route.address, ?result, "Failed to send complete ICMP datagram")
                }
            }
        }
        Ok(())
    }
}

fn incoming(bytes: &[u8], encoder: &EchoEncoder) -> Option<(IcmpRoute, Range<usize>)> {
    let (address, payload) = echo_payload(bytes, encoder.id, encoder.mode)?;
    let offset = usize::from(bytes[0] & 15) * 4;
    let route = if bytes[offset] == 8 {
        IcmpRoute::response(
            address,
            u16::from_be_bytes([bytes[offset + 4], bytes[offset + 5]]),
            u16::from_be_bytes([bytes[offset + 6], bytes[offset + 7]]),
        )
    } else {
        IcmpRoute::request(address)
    };
    Some((route, offset + 8..offset + 8 + payload.len()))
}

// A private table keeps cleanup from modifying any existing firewall rules.
struct ReplyFilter {
    table: String,
}
impl ReplyFilter {
    fn apply(rules: &str) -> Result<()> {
        let mut child = Command::new("nft")
            .args(["-f", "-"])
            .stdin(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        child.stdin.take().unwrap().write_all(rules.as_bytes())?;
        let output = child.wait_with_output()?;
        if !output.status.success() {
            anyhow::bail!(
                "Failed to update ICMP firewall rules ({}): {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Ok(())
    }

    fn install(id: u16) -> Result<Self> {
        let table = format!("covert_icmp_{}_{}", std::process::id(), fastrand::u32(..));
        // Keep the locally originated request-ID rule and add destination/ID pairs learned after
        // authentication. Unrelated ping replies retain their normal behavior.
        Self::apply(&format!(
            "add table ip {table}\n\
             add set ip {table} reply_peers {{ typeof ip daddr . icmp id; }}\n\
             add chain ip {table} output {{ type filter hook output priority 0; policy accept; }}\n\
             add rule ip {table} output icmp type echo-reply icmp id {id} meta mark != {SOCKET_MARK} drop\n\
             add rule ip {table} output icmp type echo-reply ip daddr . icmp id @reply_peers meta mark != {SOCKET_MARK} drop\n"
        ))?;
        Ok(Self { table })
    }

    fn update_route<'a>(
        &self,
        previous: Option<(Ipv4Addr, u16)>,
        next: Option<(Ipv4Addr, u16)>,
        other_routes: impl Iterator<Item = &'a IcmpRoute>,
    ) -> Result<()> {
        if previous == next {
            return Ok(());
        }
        let others: Vec<_> = other_routes.filter_map(IcmpRoute::reply_key).collect();
        let mut rules = String::new();
        if let Some((address, id)) = next
            && !others.contains(&(address, id))
        {
            rules.push_str(&format!(
                "add element ip {} reply_peers {{ {address} . {id} }}\n",
                self.table
            ));
        }
        if let Some((address, id)) = previous
            && !others.contains(&(address, id))
        {
            rules.push_str(&format!(
                "delete element ip {} reply_peers {{ {address} . {id} }}\n",
                self.table
            ));
        }
        if !rules.is_empty() {
            Self::apply(&rules)?;
        }
        Ok(())
    }
}
impl Drop for ReplyFilter {
    fn drop(&mut self) {
        match Command::new("nft")
            .args(["delete", "table", "ip", &self.table])
            .output()
        {
            Ok(output) if output.status.success() => {}
            other => error!(?other, table = %self.table, "Failed to remove ICMP firewall table"),
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
        // Echo-request IDs belong to the sender and can be rewritten by NAT.
        // Peer selection/authentication happens before learning the reply route.
        || (u16::from_be_bytes([icmp[4], icmp[5]]) != id
            && icmp[0] != 8)
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
