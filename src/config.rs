use base64::prelude::*;
use covert::transport::udp::{UdpTransportConfig, UdpTransportPeerConfig};
use ipnet::IpNet;
use serde::Deserialize;
use std::{collections::HashMap, fmt::Debug, net::IpAddr};
use uuid::Uuid;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Config {
    pub interface: Interface,
    #[serde(rename = "Peer", default)]
    pub peers: Vec<Peer>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Interface {
    #[serde(alias = "Address", deserialize_with = "deserialize_addrs")]
    pub addresses: Vec<IpNet>,
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    pub private_key: PrivKey,

    pub transport: Transport,
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

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum Transport {
    Udp {
        udp: UdpTransportConfig,
    },
    Other {
        id: String,
        #[serde(flatten)]
        values: HashMap<String, toml::Value>,
    },
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum PeerTransport {
    Udp {
        udp: UdpTransportPeerConfig,
    },
    Other {
        id: String,
        #[serde(flatten)]
        values: HashMap<String, toml::Value>,
    },
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

#[cfg(debug_assertions)]
impl<const PRIV: bool> Debug for Key<PRIV> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let b64 = BASE64_STANDARD.encode(&self.0);
        f.debug_tuple("Key").field(&b64).finish()
    }
}

#[cfg(not(debug_assertions))]
impl Debug for Key<false> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let b64 = BASE64_STANDARD.encode(&self.0);
        f.debug_tuple("Key").field(&b64).finish()
    }
}

#[cfg(not(debug_assertions))]
impl Debug for Key<true> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Key").field(&"<REDACTED>").finish()
    }
}

fn default_mtu() -> u16 {
    1450
}

fn random_uuid() -> Uuid {
    Uuid::new_v4()
}
