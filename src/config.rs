use crate::{
    codec::PacketLayout,
    transport::{
        dns::{DnsListenerConfig, DnsTransportPeerConfig},
        icmp::{IcmpListenerConfig, IcmpTransportPeerConfig},
        ntp::{NtpListenerConfig, NtpTransportPeerConfig},
        udp::{UdpListenerConfig, UdpTransportPeerConfig},
        webrtc::{WebrtcListenerConfig, WebrtcTransportPeerConfig},
    },
};
use base64::prelude::*;
use ipnet::IpNet;
use serde::{Deserialize, Deserializer};
use std::{
    fmt::{Debug, Display},
    net::IpAddr,
    str::FromStr,
};
use uuid::Uuid;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Config {
    #[serde(skip, default)]
    pub dev_name: String,
    #[serde(deserialize_with = "de_packet_layout", default)]
    pub layout: PacketLayout,
    pub interface: Interface,
    #[serde(rename = "Peer", default)]
    pub peers: Vec<Peer>,
}

fn de_packet_layout<'de, D: Deserializer<'de>>(de: D) -> Result<PacketLayout, D::Error> {
    let s = String::deserialize(de)?;
    PacketLayout::from_str(&s).map_err(|err| serde::de::Error::custom(err))
}

const DEFAULT_TIMEOUT: u32 = 28;
const DEFAULT_MAX_AGE: u32 = 300;
const DEFAULT_KEEPALIVE_DELAY: u32 = 10;
const DEFAULT_KEEPALIVE_JITTER: u32 = 3;

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct LivenessOptions {
    #[serde(default)]
    pub timeout: Option<u32>,
    pub keepalive: Option<u32>,
    pub keepalive_jitter: Option<u32>,
    pub max_age: Option<u32>,
}

#[derive(Debug, Clone, Copy)]
pub struct Liveness {
    pub timeout: u64,
    pub max_age: u64,
    pub ka_delay: u32,
    pub ka_jitter: u32,
}

impl Liveness {
    pub fn next_ka(&self) -> u64 {
        ((self.ka_delay as f64 + (self.ka_jitter as f64 * (fastrand::f64() * 2.0 - 1.0))) * 1000.0)
            .max(1000.0) as u64
    }
}

impl LivenessOptions {
    pub fn unpack_with_fallback(&self, fallback: &LivenessOptions) -> Liveness {
        Liveness {
            timeout: self.timeout.or(fallback.timeout).unwrap_or(DEFAULT_TIMEOUT) as u64,
            max_age: self.max_age.or(fallback.max_age).unwrap_or(DEFAULT_MAX_AGE) as u64,
            ka_delay: self
                .keepalive
                .or(fallback.keepalive)
                .unwrap_or(DEFAULT_KEEPALIVE_DELAY),
            ka_jitter: self
                .keepalive_jitter
                .or(fallback.keepalive_jitter)
                .unwrap_or(DEFAULT_KEEPALIVE_JITTER),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Interface {
    #[serde(alias = "Address", deserialize_with = "deserialize_addrs")]
    pub addresses: Vec<IpNet>,
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    pub private_key: PrivKey,

    #[serde(flatten)]
    pub liveness: LivenessOptions,
    pub listener: ListenerConfig,
    #[serde(flatten)]
    pub hooks: InterfaceHooks,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct InterfaceHooks {
    #[serde(default, deserialize_with = "deserialize_hooks")]
    pub pre_up: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_hooks")]
    pub post_up: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_hooks")]
    pub pre_down: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_hooks")]
    pub post_down: Vec<String>,
}

fn deserialize_hooks<'de, D: Deserializer<'de>>(de: D) -> Result<Vec<String>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Hooks {
        One(String),
        Many(Vec<String>),
    }
    Ok(match Hooks::deserialize(de)? {
        Hooks::One(command) => vec![command],
        Hooks::Many(commands) => commands,
    })
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Peer {
    #[serde(default = "random_uuid")]
    pub id: Uuid,
    pub public_key: PubKey,
    pub pre_shared_key: Option<PrivKey>,
    #[serde(rename = "AllowedIPs", deserialize_with = "deserialize_addrs")]
    pub allowed_ips: Vec<IpNet>,
    #[serde(default)]
    pub transport: PeerTransport,
    #[serde(flatten)]
    pub liveness: LivenessOptions,
}

macro_rules! make_listen_peer_cfgs {
    ($($var:ident, $lower:ident, $listen:ident, $peer:ident);* $(;)?) => {
        #[derive(Debug, Clone, Deserialize)]
        #[serde(rename_all = "PascalCase")]
        pub enum ListenerConfig {
            $($var { $lower: $listen }),*
        }

        impl ListenerConfig {
            pub fn tag(&self) -> &'static str {
                match self {$(
                    Self::$var { .. } => stringify!($lower)
                ),*}
            }
        }

        #[derive(Debug, Clone, Deserialize, Default)]
        #[serde(rename_all = "PascalCase")]
        pub enum PeerTransport {
            $($var { $lower: $peer }),*,
            #[default]
            None,
        }

        impl PeerTransport {
            pub fn tag(&self) -> &'static str {
                match self {
                    $( Self::$var { .. } => stringify!($lower) ),*,
                    Self::None {} => "none",
                }
            }

            $(
                pub fn $lower(&self) -> Option<&$peer> {
                    match self {
                        Self::$var { $lower } => Some($lower),
                        _ => None,
                    }
                }
            )*
        }
    };
}

make_listen_peer_cfgs!(
    Udp, udp, UdpListenerConfig, UdpTransportPeerConfig;
    Icmp, icmp, IcmpListenerConfig, IcmpTransportPeerConfig;
    Ntp, ntp, NtpListenerConfig, NtpTransportPeerConfig;
    Dns, dns, DnsListenerConfig, DnsTransportPeerConfig;
    Webrtc, webrtc, WebrtcListenerConfig, WebrtcTransportPeerConfig;
);

impl ListenerConfig {
    /// Largest inner IP packet fitting a 1500-byte IPv4 path with this layout.
    /// None means the transport fragments packets; zero means even minimum
    /// data framing/padding cannot fit, regardless of the configured TUN MTU.
    pub fn suggested_mtu(&self, layout: &PacketLayout) -> Option<usize> {
        let budget = match self {
            Self::Udp { .. } | Self::Icmp { .. } => 1500 - 28,
            // IPv4/UDP + NTP header, then a four-byte-aligned extension
            // containing its header and the Covert payload length (8 bytes).
            Self::Ntp { .. } => ((1500 - 28 - 48) & !3usize) - 8,
            Self::Dns { .. } | Self::Webrtc { .. } => return None,
        };
        if layout.odp > budget {
            return Some(0);
        }
        Some(budget.saturating_sub(layout.odd).saturating_sub(16))
    }
}

fn deserialize_addrs<'de, D>(deserializer: D) -> Result<Vec<IpNet>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let out = match InnerAddresses::deserialize(deserializer)? {
        InnerAddresses::One(one) => vec![one.into_net()],
        InnerAddresses::Many(many) => many.into_iter().map(|x| x.into_net()).collect(),
    };

    // [has default, has not default] * 2
    let mut seen: [[bool; 2]; 2] = Default::default();
    for net in &out {
        seen[net.addr().is_ipv6() as usize][(net.prefix_len() != 0) as usize] = true;
    }

    for (family, [default, specific]) in ["ipv4", "ipv6"].into_iter().zip(seen) {
        if default && specific {
            return Err(serde::de::Error::custom(format!(
                "{family} default route cannot be mixed with non default {family} networks"
            )));
        }
    }

    Ok(out)
}

#[derive(Deserialize)]
#[serde(untagged)]
pub enum InnerAddress {
    Bare(IpAddr),
    Net(IpNet),
}

impl InnerAddress {
    pub fn into_net(self) -> IpNet {
        match self {
            InnerAddress::Bare(bare) => IpNet::new(bare, 32 + bare.is_ipv6() as u8 * 96).unwrap(),
            InnerAddress::Net(net) => net,
        }
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
pub enum InnerAddresses {
    One(InnerAddress),
    Many(Vec<InnerAddress>),
}

pub type PubKey = Key<false>;
pub type PrivKey = Key<true>;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Key<const PRIV: bool>(pub [u8; 32]);

impl<const PRIV: bool> From<[u8; 32]> for Key<PRIV> {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl<'de, const PRIV: bool> Deserialize<'de> for Key<PRIV> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let arr = BASE64_STANDARD
            .decode(&String::deserialize(deserializer)?)
            .map_err(|err| serde::de::Error::custom(err))?;
        let bytes = arr
            .try_into()
            .map_err(|_| serde::de::Error::custom("key length must be 32 bytes"))?;
        Ok(Self(bytes))
    }
}

impl<const PRIV: bool> Display for Key<PRIV> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if PRIV && cfg!(not(debug_assertions)) {
            write!(f, "<REDACTED>")
        } else {
            let b64 = BASE64_STANDARD.encode(&self.0);
            write!(f, "{b64}")
        }
    }
}

impl<const PRIV: bool> Debug for Key<PRIV> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut d = f.debug_tuple("Key");

        if PRIV && cfg!(not(debug_assertions)) {
            d.field(&"<REDACTED>").finish()
        } else {
            let b64 = BASE64_STANDARD.encode(&self.0);
            d.field(&b64).finish()
        }
    }
}

fn default_mtu() -> u16 {
    1450
}

fn random_uuid() -> Uuid {
    Uuid::new_v4()
}
