use crate::{
    codec::{self, Packet},
    config::{Config, Peer},
    state::State,
    tunnel::{DecodedInitiation, Tunnel},
};
use etherparse::IpSlice;
use std::{collections::HashMap, time::Instant};
use tracing::error;
use uuid::Uuid;

mod config;
pub use crate::state::{PeerStatus, StatusSnapshot};
pub use config::*;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync + 'static>>;

pub trait Adapter {
    type Route: Clone;
    fn peer_route(&self, peer: &Peer) -> Option<Self::Route>;

    fn supports_peer(&self, _peer: &Peer) -> bool {
        true
    }

    fn deliver(&self, route: Self::Route, packet: Packet);

    /// Reject transport-specific route/type combinations before processing.
    fn accepts(
        &self,
        _previous: Option<&Self::Route>,
        _incoming: &Self::Route,
        _packet: &Packet,
    ) -> bool {
        true
    }

    /// Apply transport side effects before committing an authenticated route.
    /// Other routes exclude the peer being updated, so shared resources can be retained.
    fn route_changed<'a>(
        &self,
        _previous: Option<&Self::Route>,
        _next: &Self::Route,
        _other_routes: impl Iterator<Item = &'a Self::Route>,
    ) -> Result<()>
    where
        Self::Route: 'a,
    {
        Ok(())
    }
}

pub struct Endpoint<A: Adapter> {
    adapter: A,
    config: Config,
    state: State,
    peers: HashMap<Uuid, PeerTunnel<A::Route>>,
}

impl<A: Adapter> Endpoint<A> {
    pub fn new(adapter: A, config: Config) -> Result<Self> {
        let mut state = State::new();
        for peer in &config.peers {
            state.peer_statistics.entry(peer.id).or_default();
        }
        Ok(Self {
            peers: config
                .peers
                .iter()
                .filter(|peer| adapter.supports_peer(peer))
                .map(|p| PeerTunnel::new(&config, p, adapter.peer_route(p)).map(|x| (p.id, x)))
                .collect::<Result<HashMap<_, _>>>()?,
            config,
            adapter,
            state,
        })
    }

    /// Write an IP packet that has arrive from tun for processing
    pub fn tun_write(&mut self, packet: &[u8]) -> Result<()> {
        let dst = IpSlice::from_slice(&packet)?.destination_addr();

        for p in self.config.peers.iter() {
            if p.allowed_ips.iter().any(|n| n.contains(&dst)) {
                let Some(pt) = self.peers.get_mut(&p.id) else {
                    continue;
                };
                pt.transmit(&mut self.state, packet);

                if let Err(err) = pt.advance(&mut self.state) {
                    error!("Failed to advance peer tunnel: {err}");
                    continue;
                }

                while let Some((route, packet)) =
                    pt.address.as_ref().zip(pt.tunnel.read_outbound_packet())
                {
                    self.adapter.deliver(route.clone(), packet);
                }
            }
        }

        Ok(())
    }

    /// Read a packet that is destined for the TUN
    pub fn tun_read(&mut self) -> impl Iterator<Item = Vec<u8>> {
        self.peers
            .values_mut()
            .flat_map(|pt| std::iter::from_fn(|| pt.delivered(&self.state)))
    }

    /// Write a packet that came from outside
    pub fn out_write(&mut self, route: A::Route, mut buf: &[u8]) {
        while let Some(res) = codec::parse_slice(buf, &self.config.layout) {
            match res {
                Ok((packet, len)) => {
                    if let Err(err) = self.process_incoming(route.clone(), packet) {
                        error!("Failed to process incoming packet: {err}")
                    }

                    buf = &buf[len..];
                }
                Err(err) => {
                    error!("Failed to parse incoming packet: {err}");
                    break;
                }
            }
        }
    }

    /// Process exactly one complete datagram; reject truncation, trailing bytes,
    /// and concatenated frames before touching any tunnel state.
    pub fn out_write_datagram(&mut self, route: A::Route, buf: &[u8]) {
        if let Err(err) = self.process_datagram(route, buf) {
            tracing::trace!(%err, "Discarding invalid datagram");
        }
    }

    /// Process one datagram, reporting whether it was authenticated and accepted.
    pub fn process_datagram(&mut self, route: A::Route, buf: &[u8]) -> Result<bool> {
        match codec::parse_slice(buf, &self.config.layout) {
            Some(Ok((packet, consumed))) if consumed == buf.len() => {
                self.process_incoming(route, packet)
            }
            _ => Err("Malformed datagram".into()),
        }
    }

    pub fn advance(&mut self) {
        for pt in self.peers.values_mut() {
            if let Err(err) = pt.advance(&mut self.state) {
                error!("Failed to advance peer tunnel: {err}");
                continue;
            }

            while let Some((route, packet)) =
                pt.address.as_ref().zip(pt.tunnel.read_outbound_packet())
            {
                self.adapter.deliver(route.clone(), packet);
            }
        }
    }

    pub fn adapter(&self) -> &A {
        &self.adapter
    }

    pub fn status(&self) -> StatusSnapshot {
        self.state.status(&self.config)
    }

    fn process_incoming(&mut self, route: A::Route, packet: Packet) -> Result<bool> {
        if let Some((peer_id, inv)) = self.identify(&packet)? {
            let pt = self.peers.get_mut(&peer_id).unwrap();
            if !self.adapter.accepts(pt.address.as_ref(), &route, &packet) {
                return Ok(false);
            }
            let accepted = if let Some(decoded) = inv {
                pt.tunnel.accept_initiation(decoded)?
            } else {
                pt.tunnel.process_incoming_packet_accepted(packet)?
            };
            if accepted {
                self.adapter.route_changed(
                    self.peers[&peer_id].address.as_ref(),
                    &route,
                    self.peers
                        .iter()
                        .filter(|(id, _)| **id != peer_id)
                        .filter_map(|(_, peer)| peer.address.as_ref()),
                )?;
                self.peers.get_mut(&peer_id).unwrap().address = Some(route);
            }
            let pt = self.peers.get_mut(&peer_id).unwrap();
            pt.advance(&mut self.state)?;

            while let Some((route, packet)) =
                pt.address.as_ref().zip(pt.tunnel.read_outbound_packet())
            {
                self.adapter.deliver(route.clone(), packet);
            }
            return Ok(accepted);
        }

        Ok(false)
    }

    fn identify(&self, packet: &Packet) -> Result<Option<(Uuid, Option<DecodedInitiation>)>> {
        let receiver_idx = match packet {
            Packet::Initiating(initiation) => {
                let decoded = DecodedInitiation::decode(
                    &self.config.interface.private_key.0,
                    initiation.clone(),
                )?;
                return Ok(self
                    .config
                    .peers
                    .iter()
                    .find(|peer| {
                        *peer.public_key.0 == decoded.public_key
                            && self.peers.contains_key(&peer.id)
                    })
                    .map(|peer| (peer.id, Some(decoded))));
            }
            Packet::Reply(reply) => reply.receiver_idx,
            Packet::Data(data) => data.receiver_idx,
        };
        Ok(self
            .peers
            .iter()
            .find(|(_, peer)| peer.tunnel.local_index() == Some(receiver_idx))
            .map(|(&id, _)| (id, None)))
    }
}

pub(super) struct PeerTunnel<R> {
    peer_id: Uuid,
    tunnel: Tunnel,
    address: Option<R>,
    established: Option<Instant>,
}

impl<R> PeerTunnel<R> {
    fn new(config: &Config, peer: &Peer, address: Option<R>) -> Result<Self> {
        let mut tunnel = Tunnel::new(
            config.layout,
            *config.interface.private_key.0,
            peer.liveness
                .unpack_with_fallback(&config.interface.liveness),
            *peer.public_key.0,
            peer.pre_shared_key.as_ref().map(|key| *key.0),
        );
        if address.is_some() {
            tunnel.initiate()?;
        }

        Ok(Self {
            peer_id: peer.id,
            tunnel,
            address,
            established: None,
        })
    }

    fn advance(&mut self, state: &mut State) -> Result<()> {
        self.tunnel.process_new_packets(true)?;
        let established = self.tunnel.established_at();
        if established.is_some() && established != self.established {
            state.record_established(self.peer_id);
        }
        self.established = established;
        state.connected.insert(self.peer_id, self.tunnel.is_live());
        Ok(())
    }

    fn delivered(&mut self, state: &State) -> Option<Vec<u8>> {
        let packet = self.tunnel.read_packet()?;
        if packet.is_empty() {
            return None;
        }

        state.record_peer_received(self.peer_id, packet.len() as u64);
        Some(packet)
    }

    fn transmit(&mut self, state: &State, packet: &[u8]) {
        state.record_peer_sent(&self.peer_id, packet.len() as u64);
        self.tunnel.push_packet(packet);
    }
}

#[cfg(test)]
mod tests;
