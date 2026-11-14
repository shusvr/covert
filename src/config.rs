use crate::{
    codec::PacketLayout,
    transport::{
        icmp::{IcmpListenerConfig, IcmpTransportPeerConfig},
        udp::{UdpListenerConfig, UdpTransportPeerConfig},
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

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Interface {
    #[serde(alias = "Address", deserialize_with = "deserialize_addrs")]
    pub addresses: Vec<IpNet>,
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    pub private_key: PrivKey,

    pub listener: ListenerConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Peer {
    #[serde(skip, default = "random_uuid")]
    pub peer_id: Uuid,
    pub public_key: PubKey,
    pub pre_shared_key: Option<PrivKey>,
    #[serde(rename = "AllowedIPs", deserialize_with = "deserialize_addrs")]
    pub allowed_ips: Vec<IpNet>,
    pub transport: PeerTransport,
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

        #[derive(Debug, Clone, Deserialize)]
        #[serde(rename_all = "PascalCase")]
        pub enum PeerTransport {
            $($var { $lower: $peer }),*
        }

        impl PeerTransport {
            pub fn tag(&self) -> &'static str {
                match self {$(
                    Self::$var { .. } => stringify!($lower)
                ),*}
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
);

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
