//! Covert packet framing, independent of sockets and session state.
use super::quic;
use crate::{
    Error, Result,
    codec::{self, Packet, PacketLayout},
    config::ListenerConfig,
};
use bytes::{Bytes, BytesMut};

pub(crate) use quic::DATA_OVERHEAD as QUIC_DATA_OVERHEAD;

#[derive(Clone, Copy)]
enum Format {
    Raw,
    Quic,
}

/// Encodes and decodes Covert payloads carried by UDP or ICMP.
#[derive(Clone, Copy)]
pub struct DatagramCodec {
    layout: PacketLayout,
    format: Format,
}

impl DatagramCodec {
    pub fn new(listener: &ListenerConfig, layout: PacketLayout) -> Self {
        match listener {
            ListenerConfig::Udp { .. } | ListenerConfig::Icmp { .. } => Self::raw(layout),
            ListenerConfig::Quic { .. } => Self {
                layout,
                format: Format::Quic,
            },
        }
    }

    /// The Covert payload format shared by plain UDP and ICMP.
    pub fn raw(layout: PacketLayout) -> Self {
        Self {
            layout,
            format: Format::Raw,
        }
    }

    pub fn encode(&self, packet: Packet) -> Result<Bytes> {
        match self.format {
            Format::Raw => packet.to_bytes(&self.layout),
            Format::Quic => quic::encode(packet, &self.layout),
        }
    }

    /// Append a payload to an existing buffer, such as after an ICMP header.
    pub fn append(&self, buffer: &mut BytesMut, packet: Packet) -> Result<()> {
        match self.format {
            Format::Raw => codec::append(buffer, packet, &self.layout),
            Format::Quic => {
                buffer.extend_from_slice(&self.encode(packet)?);
                Ok(())
            }
        }
    }

    /// Parse exactly one datagram, rejecting trailing or incomplete frames.
    pub fn decode(&self, bytes: &[u8]) -> Result<Packet> {
        match self.format {
            Format::Raw => match self.decode_raw_prefix(bytes) {
                Some(Ok((packet, consumed))) if consumed == bytes.len() => Ok(packet),
                _ => Err(Error::MalformedDatagram),
            },
            Format::Quic => quic::decode(bytes, &self.layout),
        }
    }

    pub(super) fn supports_concatenation(&self) -> bool {
        matches!(self.format, Format::Raw)
    }

    pub(super) fn decode_raw_prefix(&self, bytes: &[u8]) -> Option<Result<(Packet, usize)>> {
        debug_assert!(self.supports_concatenation());
        codec::parse_slice(bytes, &self.layout)
    }
}

/// Serialize an outbound packet for the selected interface transport.
pub fn encode_datagram(
    packet: Packet,
    listener: &ListenerConfig,
    layout: &PacketLayout,
) -> Result<Bytes> {
    DatagramCodec::new(listener, *layout).encode(packet)
}
