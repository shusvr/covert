use crate::network;
use anyhow::Result;
use covert::{
    codec::{Packet, PacketLayout},
    config::{Config, Peer, PeerTransport},
    transport::{Adapter, Endpoint, UdpListenerConfig},
};
use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Mutex,
};
use tokio::net::UdpSocket;
use tracing::trace;

#[derive(Default)]
pub struct UdpAdapter {
    pending: Mutex<Vec<(SocketAddr, Packet)>>,
}
impl Adapter for UdpAdapter {
    type Route = SocketAddr;
    fn supports_peer(&self, peer: &Peer) -> bool {
        matches!(
            peer.transport,
            PeerTransport::Udp { .. } | PeerTransport::None
        )
    }
    fn peer_route(&self, peer: &Peer) -> Option<SocketAddr> {
        match &peer.transport {
            PeerTransport::Udp { udp } => udp.endpoint,
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
}
impl Udp {
    pub async fn bind(
        config: &Config,
        listener: &UdpListenerConfig,
    ) -> Result<(Self, Endpoint<UdpAdapter>)> {
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, listener.port)).await?;
        let endpoint = Endpoint::new(UdpAdapter::default(), config.clone())?;
        Ok((
            Self {
                socket,
                layout: config.layout,
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
        let packets = pending
            .into_iter()
            .map(|(address, packet)| packet.to_bytes(&self.layout).map(|bytes| (address, bytes)))
            .collect::<covert::Result<Vec<_>>>()?;
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
