#![allow(dead_code)]

use bytes::BytesMut;
use dashmap::DashMap;
use futures::{SinkExt, StreamExt, channel::mpsc};
use serde::Deserialize;
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    io,
    io::Write,
    mem::MaybeUninit,
    net::{Ipv4Addr, SocketAddrV4},
    process::{Command, Stdio},
    sync::Arc,
};
use tokio::{io::unix::AsyncFd, task::JoinSet};
use tokio_util::codec::Encoder;
use tracing::error;

use crate::{
    Result,
    codec::{self, Codec, Packet, PacketLayout},
    config::Config,
    transport::{Endpoint, PacketSender, State, maintain_peers, process_packet},
};

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct IcmpListenerConfig {
    #[serde(default = "default_icmp_id")]
    id: u16,
}

fn default_icmp_id() -> u16 {
    1339
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct IcmpTransportPeerConfig {
    endpoint: Option<IcmpRoute>,
}

type IcmpRoute = Ipv4Addr;
const SOCKET_MARK: u32 = 0x434f5654;

pub async fn create_icmp_endpoint(
    state: &Arc<State>,
    config: &Arc<Config>,
    listener: &IcmpListenerConfig,
) -> Result<Endpoint<impl PacketSender<IcmpRoute> + use<>, IcmpRoute>> {
    let routing = Arc::new(
        config
            .peers
            .iter()
            .filter_map(|p| p.transport.unwrap_icmp().endpoint.map(|e| (p.peer_id, e)))
            .collect::<DashMap<_, _>>(),
    );

    let icmp = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))?;
    let addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, listener.id);
    icmp.bind(&addr.into())?;
    icmp.set_mark(SOCKET_MARK)?;
    icmp.set_nonblocking(true)?;

    // The descriptor remains owned exclusively by this AsyncFd until it is dropped.
    let sock = Arc::new(unsafe { AsyncFd::register(icmp).map_err(|err| err.into_parts().1)? });
    let firewall = ReplyFilter::install(listener.id)?;

    let (sender, recv) = mpsc::channel::<(Packet, IcmpRoute)>(512);
    let outgoing = sender.clone().sink_map_err(Into::into);
    let maintenance_sender = sender.clone().sink_map_err(Into::into);
    let state = state.clone();
    let config = config.clone();
    let task_routing = routing.clone();
    let id = listener.id;
    tokio::spawn(async move {
        let _firewall = firewall;
        let mut tasks = JoinSet::new();
        tasks.spawn(sender_task(recv, sock.clone(), id));
        tasks.spawn(maintain_peers(
            state.clone(),
            config.clone(),
            task_routing.clone(),
            maintenance_sender,
        ));
        tokio::select! {
            _ = receiver_task(state, config, task_routing, outgoing, sock, id) => {},
            _ = tasks.join_next() => {},
        }
    });

    Ok(Endpoint {
        sender: sender.sink_map_err(Into::into),
        routing,
    })
}

async fn sender_task(
    mut recv: mpsc::Receiver<(Packet, IcmpRoute)>,
    sock: Arc<AsyncFd<Socket>>,
    id: u16,
) {
    let mut codec = Codec::new(PacketLayout::default());
    let mut sequence = 0_u16;
    let mut buf = BytesMut::new();
    while let Some((packet, dst)) = recv.next().await {
        let addr = SocketAddrV4::new(dst, 0);

        buf.clear();
        buf.resize(8, 0);
        if let Err(err) = codec.encode(packet, &mut buf) {
            error!("Failed to encode a packet: {err}");
            continue;
        }
        let header = etherparse::Icmpv4Header::with_checksum(
            etherparse::Icmpv4Type::EchoRequest(etherparse::IcmpEchoHeader { id, seq: sequence }),
            &buf[8..],
        );
        buf[..8].copy_from_slice(&header.to_bytes());
        sequence = sequence.wrapping_add(1);
        let addr = addr.into();
        let result = sock
            .async_io(tokio::io::Interest::WRITABLE, |socket| {
                socket.send_to(&buf, &addr)
            })
            .await;
        match result {
            Ok(sent) if sent == buf.len() => {}
            Ok(sent) => error!(%dst, sent, expected = buf.len(), "Incomplete ICMP datagram send"),
            Err(err) => error!(%dst, "Failed to send ICMP datagram: {err}"),
        }
    }
}

// A private table keeps cleanup from modifying any existing firewall rules.
struct ReplyFilter(String);
impl ReplyFilter {
    fn install(id: u16) -> io::Result<Self> {
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
            return Err(io::Error::other(format!(
                "Failed to install ICMP rule: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
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
fn echo_payload(bytes: &[u8], id: u16) -> Option<(Ipv4Addr, &[u8])> {
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
    if !matches!(icmp[0], 0 | 8) || icmp[1] != 0 || u16::from_be_bytes([icmp[4], icmp[5]]) != id {
        return None;
    }
    let (header, payload) = etherparse::Icmpv4Header::from_slice(icmp).ok()?;
    if header.checksum != header.icmp_type.calc_checksum(payload) {
        return None;
    }
    Some((
        Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]),
        payload,
    ))
}

async fn receiver_task<S: PacketSender<IcmpRoute>>(
    state: Arc<State>,
    config: Arc<Config>,
    routing: Arc<DashMap<uuid::Uuid, IcmpRoute>>,
    mut sender: S,
    sock: Arc<AsyncFd<Socket>>,
    id: u16,
) {
    let mut bytes = vec![MaybeUninit::<u8>::uninit(); 65535];
    loop {
        let result = tokio::select! {
            _ = state.tun_in_tx.closed() => break,
            result = sock.async_io(tokio::io::Interest::READABLE, |socket| socket.recv(&mut bytes)) => result,
        };
        let len = match result {
            Ok(len) => len,
            Err(err) => {
                error!("ICMP receive failed: {err}");
                break;
            }
        };
        // recv initialized exactly the returned number of bytes.
        let received = unsafe { std::slice::from_raw_parts(bytes.as_ptr().cast::<u8>(), len) };
        let Some((route, payload)) = echo_payload(received, id) else {
            continue;
        };
        let mut payload = BytesMut::from(payload);
        let Some(Ok(packet)) = codec::parse(&mut payload, &PacketLayout::default()) else {
            continue;
        };
        if !payload.is_empty() {
            continue;
        }
        match process_packet(&state, &config, packet, route, &routing, &mut sender).await {
            Ok(true) => {}
            Ok(false) => break,
            Err(err) => error!("Failed to process ICMP packet: {err}"),
        }
    }
}

mod tests;
