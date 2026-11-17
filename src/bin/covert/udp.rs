use crate::network;
use anyhow::Result;
use covert::{
    codec::{Packet, PacketLayout},
    config::{Config, Peer, PeerTransport},
    transport::{Adapter, Endpoint, UdpListenerConfig},
};
use std::{
    net::{Ipv4Addr, SocketAddr},
    ops::Range,
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
        let endpoint = Endpoint::new(UdpAdapter::default(), config.clone())
            .map_err(anyhow::Error::from_boxed)?;
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
    async fn receive(&self, buffer: &mut [u8]) -> Result<Option<(SocketAddr, Range<usize>)>> {
        let (len, address) = self.socket.recv_from(buffer).await?;
        Ok(Some((address, 0..len)))
    }
    async fn flush(&self, adapter: &UdpAdapter) -> Result<()> {
        let pending = std::mem::take(&mut *adapter.pending.lock().unwrap());
        for (address, packet) in pending {
            let bytes = packet.to_bytes(&self.layout)?;
            if let Err(err) = self.socket.send_to(&bytes, address).await {
                trace!(%address, %err, "Failed to send UDP datagram");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
