use crate::{
    Result,
    codec::{self, Codec, Packet, PacketLayout},
    config::Config,
    transport::{Endpoint, PacketSender, State, maintain_peers, process_packet},
};
use bytes::BytesMut;
use dashmap::DashMap;
use futures::{SinkExt, StreamExt, channel::mpsc};
use serde::Deserialize;
use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};
use tokio::{net::UdpSocket, task::JoinSet};
use tokio_util::udp::UdpFramed;
use tracing::{error, trace};
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

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct UdpTransportPeerConfig {
    endpoint: Option<SocketAddr>,
}

#[cfg(test)]
type UdpPacketSender = UdpFramed<Codec, Arc<UdpSocket>>;
type UdpRoute = SocketAddr;

pub async fn create_udp_endpoint(
    state: &Arc<State>,
    config: &Arc<Config>,
    listener: &UdpListenerConfig,
) -> Result<Endpoint<impl PacketSender<UdpRoute> + use<>, UdpRoute>> {
    let addr = (Ipv4Addr::UNSPECIFIED, listener.port);
    let socket = Arc::new(UdpSocket::bind(addr).await?);

    let routing = Arc::new(
        config
            .peers
            .iter()
            .filter_map(|p| p.transport.udp()?.endpoint.map(|e| (p.peer_id, e)))
            .collect::<DashMap<_, _>>(),
    );
    let (sender, recv) = mpsc::channel(512);
    tokio::spawn(socket_listener_task(
        state.clone(),
        socket.clone(),
        config.clone(),
        routing.clone(),
        recv,
        sender.clone().sink_map_err(Into::into),
    ));

    Ok(Endpoint {
        routing,
        sender: sender.sink_map_err(Into::into),
    })
}

async fn socket_listener_task<S: PacketSender<UdpRoute> + Clone + Send + 'static>(
    state: Arc<State>,
    socket: Arc<UdpSocket>,
    config: Arc<Config>,
    routing: Arc<DashMap<Uuid, SocketAddr>>,
    recv: mpsc::Receiver<(Packet, UdpRoute)>,
    mut sender: S,
) {
    let mut framed = UdpFramed::new(socket.clone(), Codec::new(config.layout));

    // Dropping the receive task also stops its independent maintenance task.
    let mut maintenance = JoinSet::new();
    maintenance.spawn(sender_task(socket.clone(), config.layout, recv));
    maintenance.spawn(maintain_peers(
        state.clone(),
        config.clone(),
        routing.clone(),
        sender.clone(),
    ));
    loop {
        tokio::select! {
            _ = state.tun_in_tx.closed() => break,
            result = maintenance.join_next() => {
                error!(?result, "UDP worker exited; stopping endpoint");
                break;
            }
            result = framed.next() => {
                match result {
                    Some(Ok((packet, addr))) => {
                        trace!(?addr, "Received a packet on udp socket");

                        match process_packet(&state, &config, packet, addr, &routing, &mut sender).await {
                            Ok(true) => {},
                            Ok(false) => break,
                            Err(err) => error!("Failed to process incoming packet: {err}"),
                        }
                    }
                    Some(Err(err)) => {
                        // UdpFramed retains a datagram when decode_eof returns an error.
                        // Discard it so the next poll can receive a new datagram.
                        framed.read_buffer_mut().clear();
                        error!("Failed to parse the packet on udp socket: {err}");
                    }
                    None => break,
                }
            }
        }
    }
}

const BATCH_SIZE: usize = 64;

struct Datagram {
    bytes: BytesMut,
    address: SocketAddr,
}

async fn sender_task(
    socket: Arc<UdpSocket>,
    layout: PacketLayout,
    mut recv: mpsc::Receiver<(Packet, UdpRoute)>,
) {
    // Keep the encoding buffers across batches to avoid reallocating per packet.
    let mut batch: Vec<_> = (0..BATCH_SIZE)
        .map(|_| Datagram {
            bytes: BytesMut::new(),
            address: SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
        })
        .collect();
    while let Some(first) = recv.next().await {
        let mut item = Some(first);
        let mut count = 0;
        while let Some((packet, address)) = item {
            let datagram = &mut batch[count];
            datagram.bytes.clear();
            match codec::append(&mut datagram.bytes, packet, &layout) {
                Ok(()) => {
                    datagram.address = address;
                    count += 1;
                }
                Err(err) => error!(%address, "Failed to encode UDP packet: {err}"),
            }
            if count == BATCH_SIZE {
                break;
            }
            // Drain only ready packets: a single datagram never waits for a batch timer.
            item = recv.try_recv().ok();
        }
        let mut sent = 0;
        while sent < count {
            let result = socket
                .async_io(tokio::io::Interest::WRITABLE, || {
                    try_send_batch(&socket, &batch[sent..count])
                })
                .await;
            match result {
                Ok(0) => {
                    error!("UDP batch send made no progress; stopping sender");
                    return;
                }
                Ok(n) => {
                    sent += n;
                    trace!(packets = n, "Sent UDP batch");
                }
                Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(err) => {
                    // sendmmsg reports an error only when no datagram was sent.
                    // Discard the failing head so one invalid destination/oversized
                    // datagram cannot block unrelated peers behind it.
                    error!(address = %batch[sent].address, "Failed to send UDP datagram: {err}");
                    sent += 1;
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn try_send_batch(socket: &UdpSocket, batch: &[Datagram]) -> io::Result<usize> {
    use std::os::fd::AsRawFd;
    if batch.is_empty() {
        return Ok(0);
    }
    debug_assert!(batch.len() <= BATCH_SIZE);
    let addresses: Vec<_> = batch
        .iter()
        .map(|datagram| socket2::SockAddr::from(datagram.address))
        .collect();
    let mut vectors: Vec<_> = batch
        .iter()
        .map(|datagram| libc::iovec {
            // sendmmsg reads these buffers; its C API uses a mutable void pointer.
            iov_base: datagram.bytes.as_ptr().cast_mut().cast(),
            iov_len: datagram.bytes.len(),
        })
        .collect();
    let mut messages: Vec<libc::mmsghdr> = batch
        .iter()
        .enumerate()
        .map(|(index, _)| {
            // An all-zero msghdr has no control data and is fully initialized below.
            let mut message: libc::mmsghdr = unsafe { std::mem::zeroed() };
            message.msg_hdr.msg_name = addresses[index].as_ptr().cast_mut().cast();
            message.msg_hdr.msg_namelen = addresses[index].len();
            message.msg_hdr.msg_iov = &mut vectors[index];
            message.msg_hdr.msg_iovlen = 1;
            message
        })
        .collect();
    // All address, iovec, and payload allocations remain alive and stationary
    // until this nonblocking syscall returns. The kernel only writes messages.
    let sent = unsafe {
        libc::sendmmsg(
            socket.as_raw_fd(),
            messages.as_mut_ptr(),
            messages.len() as _,
            libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
        )
    };
    if sent < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(sent as usize)
    }
}

#[cfg(not(target_os = "linux"))]
fn try_send_batch(socket: &UdpSocket, batch: &[Datagram]) -> io::Result<usize> {
    use std::os::fd::AsRawFd;
    let Some(datagram) = batch.first() else {
        return Ok(0);
    };
    let address = socket2::SockAddr::from(datagram.address);
    // Match the Linux readiness/error behavior with a single nonblocking datagram.
    let sent = unsafe {
        libc::sendto(
            socket.as_raw_fd(),
            datagram.bytes.as_ptr().cast(),
            datagram.bytes.len(),
            libc::MSG_DONTWAIT,
            address.as_ptr(),
            address.len(),
        )
    };
    if sent < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(1)
    }
}

#[cfg(test)]
mod tests;
