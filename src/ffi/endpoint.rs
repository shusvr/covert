//! Fixed-remote client endpoint: the host owns sockets and transport framing.
use super::*;
use crate::codec::{Packet, PacketLayout};
use crate::config::DEFAULT_FWMARK;
use crate::{
    config::{Config, Interface, ListenerConfig, LivenessOptions, Peer, PeerTransport},
    transport::{Adapter, Endpoint, UdpListenerConfig, encode_datagram},
};
use std::{collections::VecDeque, sync::Mutex};

struct Frames {
    outbound: Mutex<VecDeque<Packet>>,
    echo_reply_client: bool,
}
impl Adapter for Frames {
    type Route = ();
    fn peer_route(&self, _: &Peer) -> Option<()> {
        Some(())
    }
    fn deliver(&self, _: (), packet: Packet) {
        self.outbound.lock().unwrap().push_back(packet);
    }
    fn accepts(&self, _: Option<&()>, _: &(), packet: &Packet) -> bool {
        !self.echo_reply_client || !matches!(packet, Packet::Initiating(_))
    }
}

/// Opaque single-peer endpoint, independent of Android, sockets and JNI.
pub struct ClientEndpoint {
    endpoint: Endpoint<Frames>,
    layout: PacketLayout,
    listener: ListenerConfig,
}
#[repr(C)]
pub struct EndpointStatus {
    pub sent: u64,
    pub received: u64,
    pub first_established_at: u64,
    pub last_established_at: u64,
    pub connected: u8,
}
free_handle!(covert_endpoint_free, ClientEndpoint);

/// mode: 0 = UDP, 1 = initiating-only ICMP EchoReply, 2 = QUIC-shaped UDP.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn covert_endpoint_client_new(
    layout: *const PacketLayout,
    secret: *const u8,
    public: *const u8,
    shared: *const u8,
    liveness: *const TunnelLiveness,
    mode: u32,
    out: *mut *mut ClientEndpoint,
) -> i32 {
    guard(|| {
        let out = unsafe { get_mut(out)? };
        *out = ptr::null_mut();
        if mode > 2 {
            return Err(Error::InvalidArgument("invalid FFI argument"));
        }
        let live = unsafe { get(liveness)? };
        // Config uses u32 seconds; reject truncation at this boundary.
        let liveness = LivenessOptions {
            timeout: Some(
                live.timeout
                    .try_into()
                    .map_err(|_| Error::InvalidArgument("invalid FFI argument"))?,
            ),
            max_age: Some(
                live.max_age
                    .try_into()
                    .map_err(|_| Error::InvalidArgument("invalid FFI argument"))?,
            ),
            keepalive: Some(live.ka_delay),
            keepalive_jitter: Some(live.ka_jitter),
        };
        let layout = *unsafe { get(layout)? };
        layout
            .check()
            .map_err(|_| Error::InvalidArgument("invalid FFI argument"))?;
        let config = Config {
            dev_name: String::new(),
            layout,
            interface: Interface {
                addresses: vec![],
                mtu: 1400,
                private_key: unsafe { key(secret)? }.into(),
                hooks: Default::default(),
                liveness,
                listener: if mode == 2 {
                    ListenerConfig::Quic {
                        quic: UdpListenerConfig { port: 0 },
                    }
                } else {
                    ListenerConfig::Udp {
                        udp: UdpListenerConfig { port: 0 },
                    }
                },
                fwmark: DEFAULT_FWMARK,
                table: false,
            },
            peers: vec![Peer {
                id: uuid::Uuid::new_v4(),
                public_key: unsafe { key(public)? }.into(),
                pre_shared_key: unsafe { psk(shared)? }.map(Into::into),
                allowed_ips: vec!["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()],
                transport: PeerTransport::None,
                liveness: Default::default(),
                metric: 600,
            }],
        };
        *out = Box::into_raw(Box::new(from_engine(config, mode == 1)?));
        Ok(())
    })
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn covert_endpoint_advance(endpoint: *mut ClientEndpoint) -> i32 {
    guard(|| {
        unsafe { get_mut(endpoint)? }.endpoint.advance();
        Ok(())
    })
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn covert_endpoint_tun_write(
    endpoint: *mut ClientEndpoint,
    data: *const u8,
    len: usize,
) -> i32 {
    guard(|| {
        unsafe { get_mut(endpoint)? }
            .endpoint
            .tun_write(unsafe { bytes(data, len)? })
            .map_err(|_| Error::InvalidArgument("invalid FFI argument"))
    })
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn covert_endpoint_out_write(
    endpoint: *mut ClientEndpoint,
    data: *const u8,
    len: usize,
) -> i32 {
    guard(|| {
        match unsafe { get_mut(endpoint)? }
            .endpoint
            .process_datagram((), unsafe { bytes(data, len)? })?
        {
            true => Ok(()),
            false => Err(Error::Empty),
        }
    })
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn covert_endpoint_read_outbound(
    endpoint: *mut ClientEndpoint,
    out: *mut Buffer,
) -> i32 {
    guard(|| {
        let out = unsafe { get_mut(out)? };
        let client = unsafe { get_mut(endpoint)? };
        let packet = client
            .endpoint
            .adapter()
            .outbound
            .lock()
            .unwrap()
            .pop_front()
            .ok_or(Error::Empty)?;
        output(
            out,
            encode_datagram(packet, &client.listener, &client.layout)?.to_vec(),
        );
        Ok(())
    })
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn covert_endpoint_tun_read(
    endpoint: *mut ClientEndpoint,
    out: *mut Buffer,
) -> i32 {
    guard(|| {
        let out = unsafe { get_mut(out)? };
        let packet = unsafe { get_mut(endpoint)? }
            .endpoint
            .tun_read()
            .next()
            .ok_or(Error::Empty)?;
        output(out, packet);
        Ok(())
    })
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn covert_endpoint_status(
    endpoint: *const ClientEndpoint,
    out: *mut EndpointStatus,
) -> i32 {
    guard(|| {
        let out = unsafe { get_mut(out)? };
        let status = unsafe { get(endpoint)? }.endpoint.status();
        let peer = &status.peers[0];
        *out = EndpointStatus {
            sent: peer.sent,
            received: peer.received,
            first_established_at: peer.first_established_at.unwrap_or(0),
            last_established_at: peer.last_established_at.unwrap_or(0),
            connected: u8::from(peer.status == "connected"),
        };
        Ok(())
    })
}

fn from_engine(config: Config, echo_reply_client: bool) -> Result<ClientEndpoint> {
    let layout = config.layout;
    let listener = config.interface.listener.clone();
    let adapter = Frames {
        outbound: Mutex::new(VecDeque::new()),
        echo_reply_client,
    };
    let endpoint = Endpoint::new(adapter, config)?;
    Ok(ClientEndpoint {
        endpoint,
        layout,
        listener,
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn covert_endpoint_from_config(
    config: *const ConfigHandle,
    out: *mut *mut ClientEndpoint,
    error: *mut Buffer,
) -> i32 {
    guard(|| {
        let out = unsafe { get_mut(out)? };
        *out = ptr::null_mut();
        let config = unsafe { get(config)? };
        if config.peers.len() != 1 {
            return super::config::report(error, "Client endpoints require exactly one peer");
        }
        if super::config::validate(config).is_err() {
            return super::config::report(error, "Invalid packet layout or interface MTU");
        }
        let echo_reply_client = match config.interface.listener {
            ListenerConfig::Udp { .. } | ListenerConfig::Quic { .. } => false,
            ListenerConfig::Icmp { ref icmp }
                if icmp.mode == crate::transport::IcmpMode::EchoReply =>
            {
                true
            }
            _ => {
                return super::config::report(
                    error,
                    "Client endpoints support only ICMP EchoReply mode",
                );
            }
        };
        *out = Box::into_raw(Box::new(from_engine(config.clone(), echo_reply_client)?));
        Ok(())
    })
}
