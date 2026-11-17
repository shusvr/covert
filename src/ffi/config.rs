//! C handles are the library's actual Config; no second configuration model.
use super::*;
pub use crate::config::Config as ConfigHandle;
use crate::{
    codec::PacketLayout,
    config::{Interface, ListenerConfig, LivenessOptions, Peer, PeerTransport},
    transport::{
        IcmpListenerConfig, IcmpMode, IcmpTransportPeerConfig, UdpListenerConfig,
        UdpTransportPeerConfig,
    },
};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
};
use ipnet::IpNet;
use std::net::IpAddr;
use zeroize::Zeroizing;

pub const INTERFACE: usize = usize::MAX;
free_handle!(covert_config_free, ConfigHandle);
pub(super) fn report(error: *mut Buffer, message: &str) -> Result {
    if !error.is_null() {
        output(unsafe { get_mut(error)? }, message.as_bytes().to_vec());
    }
    Err(INVALID)
}
fn key_text(text: &str) -> Result<Key> {
    let clean = Zeroizing::new(
        text.chars()
            .filter(|c| !c.is_ascii_whitespace())
            .collect::<String>(),
    );
    let decoded = Zeroizing::new(
        STANDARD
            .decode(&*clean)
            .or_else(|_| STANDARD_NO_PAD.decode(&*clean))
            .map_err(|_| INVALID)?,
    );
    decoded.as_slice().try_into().map_err(|_| INVALID)
}
fn nets(text: &str) -> Result<Vec<IpNet>> {
    text.split(|c: char| c == ',' || c.is_whitespace())
        .filter(|s| !s.is_empty())
        .map(|s| {
            if s.contains('/') {
                s.parse().map_err(|_| INVALID)
            } else {
                let ip: IpAddr = s.parse().map_err(|_| INVALID)?;
                IpNet::new(ip, if ip.is_ipv4() { 32 } else { 128 }).map_err(|_| INVALID)
            }
        })
        .collect()
}
fn peer(config: &ConfigHandle, index: usize) -> Result<&Peer> {
    config.peers.get(index).ok_or(INVALID)
}
fn peer_mut(config: &mut ConfigHandle, index: usize) -> Result<&mut Peer> {
    config.peers.get_mut(index).ok_or(INVALID)
}
fn liveness(config: &ConfigHandle, index: usize) -> Result<&LivenessOptions> {
    if index == INTERFACE {
        Ok(&config.interface.liveness)
    } else {
        Ok(&peer(config, index)?.liveness)
    }
}
fn liveness_mut(config: &mut ConfigHandle, index: usize) -> Result<&mut LivenessOptions> {
    if index == INTERFACE {
        Ok(&mut config.interface.liveness)
    } else {
        Ok(&mut peer_mut(config, index)?.liveness)
    }
}
pub(super) fn validate(config: &ConfigHandle) -> Result {
    config.layout.check().map_err(|_| INVALID)?;
    if config.interface.mtu == 0 {
        return Err(INVALID);
    }
    Ok(())
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn covert_config_new(out: *mut *mut ConfigHandle) -> i32 {
    guard(|| {
        let out = unsafe { get_mut(out)? };
        *out = ptr::null_mut();
        *out = Box::into_raw(Box::new(ConfigHandle {
            dev_name: String::new(),
            layout: Default::default(),
            interface: Interface {
                addresses: vec![],
                mtu: 1450,
                private_key: [0; 32].into(),
                liveness: Default::default(),
                hooks: Default::default(),
                listener: ListenerConfig::Udp {
                    udp: UdpListenerConfig { port: 40676 },
                },
            },
            peers: vec![],
        }));
        Ok(())
    })
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn covert_config_add_peer(config: *mut ConfigHandle, out: *mut usize) -> i32 {
    guard(|| {
        let out = unsafe { get_mut(out)? };
        let config = unsafe { get_mut(config)? };
        *out = config.peers.len();
        config.peers.push(Peer {
            id: uuid::Uuid::new_v4(),
            public_key: [0; 32].into(),
            pre_shared_key: None,
            allowed_ips: vec![],
            transport: PeerTransport::None,
            liveness: Default::default(),
        });
        Ok(())
    })
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn covert_config_remove_peer(config: *mut ConfigHandle, index: usize) -> i32 {
    guard(|| {
        let config = unsafe { get_mut(config)? };
        if index >= config.peers.len() {
            return Err(INVALID);
        }
        config.peers.remove(index);
        Ok(())
    })
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn covert_config_peer_count(
    config: *const ConfigHandle,
    out: *mut usize,
) -> i32 {
    guard(|| {
        *unsafe { get_mut(out)? } = unsafe { get(config)? }.peers.len();
        Ok(())
    })
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn covert_config_set_string(
    config: *mut ConfigHandle,
    index: usize,
    field: u32,
    data: *const u8,
    len: usize,
) -> i32 {
    guard(|| {
        let config = unsafe { get_mut(config)? };
        let text = std::str::from_utf8(unsafe { bytes(data, len)? })
            .map_err(|_| INVALID)?
            .trim();
        match (index, field) {
            (INTERFACE, 0) => {
                let layout: PacketLayout = if text.is_empty() {
                    Default::default()
                } else {
                    text.parse().map_err(|_| INVALID)?
                };
                layout.check().map_err(|_| INVALID)?;
                config.layout = layout;
            }
            (INTERFACE, 1) => config.dev_name = text.to_owned(),
            (INTERFACE, 2) => config.interface.private_key = key_text(text)?.into(),
            (INTERFACE, 3) => config.interface.addresses = nets(text)?,
            (index, 4) => peer_mut(config, index)?.public_key = key_text(text)?.into(),
            (index, 5) => {
                peer_mut(config, index)?.pre_shared_key = if text.is_empty() {
                    None
                } else {
                    Some(key_text(text)?.into())
                }
            }
            (index, 6) => peer_mut(config, index)?.allowed_ips = nets(text)?,
            (index, 7) => {
                let transport = if text.is_empty() {
                    PeerTransport::None
                } else {
                    match peer(config, index)?.transport {
                        PeerTransport::Udp { .. } => PeerTransport::Udp {
                            udp: UdpTransportPeerConfig {
                                endpoint: Some(text.parse().map_err(|_| INVALID)?),
                            },
                        },
                        PeerTransport::Icmp { .. } => PeerTransport::Icmp {
                            icmp: IcmpTransportPeerConfig {
                                endpoint: Some(text.parse().map_err(|_| INVALID)?),
                            },
                        },
                        PeerTransport::None => match config.interface.listener {
                            ListenerConfig::Udp { .. } => PeerTransport::Udp {
                                udp: UdpTransportPeerConfig {
                                    endpoint: Some(text.parse().map_err(|_| INVALID)?),
                                },
                            },
                            ListenerConfig::Icmp { .. } => PeerTransport::Icmp {
                                icmp: IcmpTransportPeerConfig {
                                    endpoint: Some(text.parse().map_err(|_| INVALID)?),
                                },
                            },
                        },
                    }
                };
                peer_mut(config, index)?.transport = transport;
            }
            (index, 8) => peer_mut(config, index)?.id = text.parse().map_err(|_| INVALID)?,
            _ => return Err(INVALID),
        };
        Ok(())
    })
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn covert_config_get_string(
    config: *const ConfigHandle,
    index: usize,
    field: u32,
    out: *mut Buffer,
) -> i32 {
    guard(|| {
        let out = unsafe { get_mut(out)? };
        let config = unsafe { get(config)? };
        let value = match (index, field) {
            (INTERFACE, 0) => config.layout.to_string(),
            (INTERFACE, 1) => config.dev_name.clone(),
            (INTERFACE, 2) => STANDARD.encode(&*config.interface.private_key.0),
            (INTERFACE, 3) => config
                .interface
                .addresses
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(","),
            (index, 4) => STANDARD.encode(&*peer(config, index)?.public_key.0),
            (index, 5) => {
                STANDARD.encode(&*peer(config, index)?.pre_shared_key.as_ref().ok_or(EMPTY)?.0)
            }
            (index, 6) => peer(config, index)?
                .allowed_ips
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(","),
            (index, 7) => match &peer(config, index)?.transport {
                PeerTransport::Udp { udp } => udp.endpoint.ok_or(EMPTY)?.to_string(),
                PeerTransport::Icmp { icmp } => icmp.endpoint.ok_or(EMPTY)?.to_string(),
                PeerTransport::None => return Err(EMPTY),
            },
            (index, 8) => peer(config, index)?.id.to_string(),
            _ => return Err(INVALID),
        };
        output(out, value.into_bytes());
        Ok(())
    })
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn covert_config_set_u32(
    config: *mut ConfigHandle,
    index: usize,
    field: u32,
    value: u32,
) -> i32 {
    guard(|| {
        let config = unsafe { get_mut(config)? };
        match (index, field) {
            (INTERFACE, 16) => {
                let mtu = value.try_into().map_err(|_| INVALID)?;
                if mtu == 0 {
                    return Err(INVALID);
                }
                config.interface.mtu = mtu
            }
            (INTERFACE, 17) => {
                config.interface.listener = match value {
                    0 => ListenerConfig::Udp {
                        udp: UdpListenerConfig { port: 40676 },
                    },
                    1 => ListenerConfig::Icmp {
                        icmp: IcmpListenerConfig {
                            mode: IcmpMode::EchoReply,
                        },
                    },
                    _ => return Err(INVALID),
                }
            }
            (index, 17) => {
                peer_mut(config, index)?.transport = match value {
                    0 => PeerTransport::Udp {
                        udp: UdpTransportPeerConfig { endpoint: None },
                    },
                    1 => PeerTransport::Icmp {
                        icmp: IcmpTransportPeerConfig { endpoint: None },
                    },
                    2 => PeerTransport::None,
                    _ => return Err(INVALID),
                }
            }
            (INTERFACE, 18) => match &mut config.interface.listener {
                ListenerConfig::Udp { udp } => udp.port = value.try_into().map_err(|_| INVALID)?,
                _ => return Err(INVALID),
            },
            (INTERFACE, 19) => match &mut config.interface.listener {
                ListenerConfig::Icmp { icmp } => {
                    icmp.mode = match value {
                        0 => IcmpMode::EchoReply,
                        1 => IcmpMode::OnlyEcho,
                        _ => return Err(INVALID),
                    }
                }
                _ => return Err(INVALID),
            },
            (index, 20..=23) => {
                let live = liveness_mut(config, index)?;
                *match field {
                    20 => &mut live.timeout,
                    21 => &mut live.max_age,
                    22 => &mut live.keepalive,
                    _ => &mut live.keepalive_jitter,
                } = Some(value)
            }
            _ => return Err(INVALID),
        };
        Ok(())
    })
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn covert_config_get_u32(
    config: *const ConfigHandle,
    index: usize,
    field: u32,
    out: *mut u32,
) -> i32 {
    guard(|| {
        let out = unsafe { get_mut(out)? };
        let config = unsafe { get(config)? };
        let value = match (index, field) {
            (INTERFACE, 16) => u32::from(config.interface.mtu),
            (INTERFACE, 17) => match config.interface.listener {
                ListenerConfig::Udp { .. } => 0,
                ListenerConfig::Icmp { .. } => 1,
            },
            (index, 17) => match peer(config, index)?.transport {
                PeerTransport::Udp { .. } => 0,
                PeerTransport::Icmp { .. } => 1,
                PeerTransport::None => 2,
            },
            (INTERFACE, 18) => match &config.interface.listener {
                ListenerConfig::Udp { udp } => u32::from(udp.port),
                _ => return Err(INVALID),
            },
            (INTERFACE, 19) => match &config.interface.listener {
                ListenerConfig::Icmp { icmp } => match icmp.mode {
                    IcmpMode::EchoReply => 0,
                    IcmpMode::OnlyEcho => 1,
                },
                _ => return Err(INVALID),
            },
            (index, 20..=23) => {
                let live = liveness(config, index)?;
                match field {
                    20 => live.timeout,
                    21 => live.max_age,
                    22 => live.keepalive,
                    _ => live.keepalive_jitter,
                }
                .ok_or(EMPTY)?
            }
            _ => return Err(INVALID),
        };
        *out = value;
        Ok(())
    })
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn covert_config_clear_u32(
    config: *mut ConfigHandle,
    index: usize,
    field: u32,
) -> i32 {
    guard(|| {
        let live = liveness_mut(unsafe { get_mut(config)? }, index)?;
        *match field {
            20 => &mut live.timeout,
            21 => &mut live.max_age,
            22 => &mut live.keepalive,
            23 => &mut live.keepalive_jitter,
            _ => return Err(INVALID),
        } = None;
        Ok(())
    })
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn covert_config_validate(
    config: *const ConfigHandle,
    error: *mut Buffer,
) -> i32 {
    guard(|| {
        if validate(unsafe { get(config)? }).is_err() {
            report(error, "Invalid packet layout or interface MTU")
        } else {
            Ok(())
        }
    })
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn covert_config_public_key(
    config: *const ConfigHandle,
    out: *mut Buffer,
) -> i32 {
    guard(|| {
        let out = unsafe { get_mut(out)? };
        let config = unsafe { get(config)? };
        let key = crate::crypto::to_sk(&config.interface.private_key.0);
        let public = key.compute_public_key().map_err(|_| FAILED)?;
        output(out, STANDARD.encode(public.as_ref()).into_bytes());
        Ok(())
    })
}
