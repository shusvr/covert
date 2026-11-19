use crate::network;
use anyhow::Result;
use covert::{
    codec::{Packet, PacketLayout},
    config::{Config, ListenerConfig, Peer, PeerTransport},
    transport::{Adapter, Endpoint, UdpListenerConfig, encode_datagram},
};
use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Mutex,
};
use tokio::net::UdpSocket;
use tracing::trace;

#[derive(Default)]
pub struct UdpAdapter {
    quic: bool,
    pending: Mutex<Vec<(SocketAddr, Packet)>>,
}
impl Adapter for UdpAdapter {
    type Route = SocketAddr;
    fn supports_peer(&self, peer: &Peer) -> bool {
        match peer.transport {
            PeerTransport::Udp { .. } => !self.quic,
            PeerTransport::Quic { .. } => self.quic,
            PeerTransport::None => true,
            _ => false,
        }
    }
    fn peer_route(&self, peer: &Peer) -> Option<SocketAddr> {
        match &peer.transport {
            PeerTransport::Udp { udp } | PeerTransport::Quic { quic: udp } => udp.endpoint,
            _ => None,
        }
    }
    fn deliver(&self, route: SocketAddr, packet: Packet) {
        self.pending.lock().unwrap().push((route, packet));
    }
}

pub struct Udp {
    socket: UdpSocket,
    layout: PacketLayout,
    listener: ListenerConfig,
}
impl Udp {
    pub async fn bind(
        config: &Config,
        listener: &UdpListenerConfig,
    ) -> Result<(Self, Endpoint<UdpAdapter>)> {
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, listener.port)).await?;
        let adapter = UdpAdapter {
            quic: matches!(config.interface.listener, ListenerConfig::Quic { .. }),
            ..UdpAdapter::default()
        };
        let endpoint = Endpoint::new(adapter, config.clone())?;
        Ok((
            Self {
                socket,
                layout: config.layout,
                listener: config.interface.listener.clone(),
            },
            endpoint,
        ))
    }
}
impl network::Socket for Udp {
    type Adapter = UdpAdapter;
    #[cfg(target_os = "linux")]
    const RECEIVE_BATCH: usize = batch::BATCH_SIZE;

    async fn receive(&self, received: &mut network::ReceiveBatch<SocketAddr>) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            self.socket
                .async_io(tokio::io::Interest::READABLE, || {
                    batch::receive(self.socket.as_raw_fd(), received)
                })
                .await?;
        }
        #[cfg(not(target_os = "linux"))]
        {
            let (len, address) = self.socket.recv_from(&mut received.buffer).await?;
            received.packets.push((address, 0..len));
        }
        Ok(())
    }
    async fn flush(&self, adapter: &UdpAdapter) -> Result<()> {
        let pending = std::mem::take(&mut *adapter.pending.lock().unwrap());
        let mut packets = Vec::with_capacity(pending.len());
        for (address, packet) in pending {
            match encode_datagram(packet, &self.listener, &self.layout) {
                Ok(bytes) => packets.push((address, bytes)),
                Err(covert::Error::PacketOverflow) => {
                    trace!(%address, "Discarding oversized outbound datagram");
                }
                Err(err) => return Err(err.into()),
            }
        }
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            let mut sent = 0;
            while sent < packets.len() {
                let remaining = &packets[sent..packets.len().min(sent + batch::BATCH_SIZE)];
                match self
                    .socket
                    .async_io(tokio::io::Interest::WRITABLE, || {
                        batch::send(self.socket.as_raw_fd(), remaining)
                    })
                    .await
                {
                    // sendmmsg may send only a prefix. Retry precisely the tail.
                    Ok(count) => sent += count,
                    Err(err) => {
                        // A bad destination must not discard later valid datagrams.
                        trace!(address = %packets[sent].0, %err, "Failed to send UDP datagram");
                        sent += 1;
                    }
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        for (address, bytes) in packets {
            if let Err(err) = self.socket.send_to(&bytes, address).await {
                trace!(%address, %err, "Failed to send UDP datagram");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;

#[cfg(target_os = "linux")]
mod batch;
