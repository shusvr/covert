use crate::Result;
use crate::{
    codec::PacketLayout,
    transport::{
        IcmpListenerConfig, IcmpTransportPeerConfig, UdpListenerConfig, UdpTransportPeerConfig,
    },
};
use base64::prelude::*;
use ipnet::IpNet;
use serde::{Deserialize, Deserializer, Serialize};
use std::{
    fmt::{Debug, Display},
    net::IpAddr,
    str::FromStr,
    time::Duration,
};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Config {
    #[serde(skip, default)]
    pub dev_name: String,
    #[serde(
        deserialize_with = "de_packet_layout",
        serialize_with = "ser_packet_layout",
        default
    )]
    #[serde(skip_serializing_if = "PacketLayout::is_default")]
    pub layout: PacketLayout,
    pub interface: Interface,
    #[serde(rename = "Peer", default)]
    pub peers: Vec<Peer>,
}

impl Config {
    pub fn to_json(&self, pretty: bool) -> Result<String> {
        if pretty {
            Ok(serde_json::to_string_pretty(self)?)
        } else {
            Ok(serde_json::to_string(self)?)
        }
    }

    pub fn from_json(&self, json: &str) -> Result<Self> {
        let conf = serde_json::from_str::<Self>(json)?;
        conf.layout.check()?;
        Ok(conf)
    }

    pub fn to_query(&self) -> Result<String> {
        Ok(serde_qs::to_string(self)?)
    }

    pub fn from_query(query: &str) -> Result<Self> {
        let conf = serde_qs::from_str::<Self>(query)?;
        conf.layout.check()?;
        Ok(conf)
    }
}

fn ser_packet_layout<S: serde::Serializer>(
    layout: &PacketLayout,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&layout.to_string())
}

fn de_packet_layout<'de, D: Deserializer<'de>>(de: D) -> Result<PacketLayout, D::Error> {
    let s = String::deserialize(de)?;
    PacketLayout::from_str(&s).map_err(|err| serde::de::Error::custom(err))
}

const DEFAULT_TIMEOUT: u32 = 28;
const DEFAULT_MAX_AGE: u32 = 300;
const DEFAULT_KEEPALIVE_DELAY: u32 = 10;
const DEFAULT_KEEPALIVE_JITTER: u32 = 3;

#[derive(Debug, Clone, Copy)]
pub struct Liveness {
    pub timeout: u64,
    pub max_age: u64,
    pub ka_delay: u32,
    pub ka_jitter: u32,
}

impl Liveness {
    pub fn has_expired(&self, since_established: Duration, since_last_seen: Duration) -> bool {
        (since_established > Duration::from_secs(self.max_age) && self.max_age != 0)
            || (since_last_seen > Duration::from_secs(self.timeout) && self.timeout != 0)
    }

    pub fn next_ka(&self) -> u64 {
        ((self.ka_delay as f64 + (self.ka_jitter as f64 * (fastrand::f64() * 2.0 - 1.0))) * 1000.0)
            .max(1000.0) as u64
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default, rename_all = "PascalCase")]
pub struct LivenessOptions {
    #[serde(
        skip_serializing_if = "Option::is_none",
        deserialize_with = "de_optional_u32"
    )]
    pub timeout: Option<u32>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        deserialize_with = "de_optional_u32"
    )]
    pub keepalive: Option<u32>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        deserialize_with = "de_optional_u32"
    )]
    pub keepalive_jitter: Option<u32>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        deserialize_with = "de_optional_u32"
    )]
    pub max_age: Option<u32>,
}

// Flattened fields arrive as strings when deserializing query parameters.
fn de_optional_u32<'de, D: Deserializer<'de>>(de: D) -> Result<Option<u32>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Number {
        Integer(u32),
        Text(String),
    }
    Option::<Number>::deserialize(de)?
        .map(|number| match number {
            Number::Integer(value) => Ok(value),
            Number::Text(value) => value.parse().map_err(serde::de::Error::custom),
        })
        .transpose()
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

pub const DEFAULT_FWMARK: u16 = 0xDEAD;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Interface {
    #[serde(alias = "Address", deserialize_with = "deserialize_addrs")]
    pub addresses: Vec<IpNet>,
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    #[serde(skip, default = "default_fwmark")]
    pub fwmark: u16,
    #[serde(skip_serializing, default = "default_on")]
    pub table: bool,
    pub private_key: PrivKey,

    #[serde(flatten)]
    pub liveness: LivenessOptions,
    pub listener: ListenerConfig,
    #[serde(flatten, skip_serializing)]
    pub hooks: InterfaceHooks,
}

fn default_on() -> bool {
    true
}

fn default_fwmark() -> u16 {
    DEFAULT_FWMARK
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Peer {
    #[serde(skip_serializing, default = "random_uuid")]
    pub id: Uuid,
    pub public_key: PubKey,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pre_shared_key: Option<PrivKey>,
    #[serde(rename = "AllowedIPs", deserialize_with = "deserialize_addrs")]
    pub allowed_ips: Vec<IpNet>,
    #[serde(skip_serializing_if = "PeerTransport::is_none", default)]
    pub transport: PeerTransport,
    #[serde(flatten)]
    pub liveness: LivenessOptions,
}

macro_rules! make_listen_peer_cfgs {
    ($($var:ident, $lower:ident, $str:literal, $listen:ident, $peer:ident);* $(;)?) => {
        #[derive(Debug, Clone, Serialize, Deserialize)]
        #[serde(untagged)]
        pub enum ListenerConfig {
            $($var {
                #[serde(rename = $str)]
                $lower: $listen
            }),*
        }

        impl ListenerConfig {
            pub fn tag(&self) -> &'static str {
                match self {$(
                    Self::$var { .. } => stringify!($lower)
                ),*}
            }
        }

        #[derive(Debug, Clone, Serialize, Deserialize, Default)]
        #[serde(untagged)]
        pub enum PeerTransport {
            $($var {
                #[serde(rename = $str)]
                $lower: $peer
            }),*,
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
        }
    };
}

impl PeerTransport {
    fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }
}

make_listen_peer_cfgs!(
    Udp, udp, "Udp", UdpListenerConfig, UdpTransportPeerConfig;
    Icmp, icmp, "Icmp", IcmpListenerConfig, IcmpTransportPeerConfig;
);

impl ListenerConfig {
    /// Largest inner IP packet fitting a 1500-byte IPv4 path with this layout.
    /// Zero means even minimum
    /// data framing/padding cannot fit, regardless of the configured TUN MTU.
    pub fn suggested_mtu(&self, layout: &PacketLayout) -> Option<usize> {
        let budget = match self {
            Self::Udp { .. } | Self::Icmp { .. } => 1500 - 28,
        };
        if usize::from(layout.odp) > budget {
            return Some(0);
        }
        Some(
            budget
                .saturating_sub(usize::from(layout.odd))
                .saturating_sub(16),
        )
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

#[derive(Clone, PartialEq, Eq)]
pub struct Key<const PRIV: bool>(pub zeroize::Zeroizing<[u8; 32]>);

impl<const PRIV: bool> Serialize for Key<PRIV> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        zeroize::Zeroizing::new(BASE64_STANDARD.encode(&self.0)).serialize(serializer)
    }
}

impl<const PRIV: bool> From<[u8; 32]> for Key<PRIV> {
    fn from(bytes: [u8; 32]) -> Self {
        Self(zeroize::Zeroizing::new(bytes))
    }
}

impl<'de, const PRIV: bool> Deserialize<'de> for Key<PRIV> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let encoded = zeroize::Zeroizing::new(String::deserialize(deserializer)?);
        let arr = zeroize::Zeroizing::new(
            BASE64_STANDARD
                .decode(encoded.as_bytes())
                .map_err(|err| serde::de::Error::custom(err))?,
        );
        let bytes: [u8; 32] = arr
            .as_slice()
            .try_into()
            .map_err(|_| serde::de::Error::custom("key length must be 32 bytes"))?;
        Ok(Self::from(bytes))
    }
}

impl<const PRIV: bool> Display for Key<PRIV> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if PRIV && cfg!(not(debug_assertions)) {
            write!(f, "<REDACTED>")
        } else {
            let b64 = BASE64_STANDARD.encode(&*self.0);
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
            let b64 = BASE64_STANDARD.encode(&*self.0);
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
