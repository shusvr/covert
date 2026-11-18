use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, SocketAddr};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, PartialEq, Eq)]
pub enum IcmpMode {
    #[default]
    EchoReply,
    OnlyEcho,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct IcmpListenerConfig {
    #[serde(default)]
    pub mode: IcmpMode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct IcmpTransportPeerConfig {
    pub endpoint: Option<Ipv4Addr>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct UdpListenerConfig {
    #[serde(default = "default_listen_port", deserialize_with = "deserialize_port")]
    pub port: u16,
}

fn default_listen_port() -> u16 {
    40676
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct UdpTransportPeerConfig {
    pub endpoint: Option<SocketAddr>,
}

// Untagged transport enums buffer query values as strings rather than numbers.
fn deserialize_port<'de, D: serde::Deserializer<'de>>(de: D) -> Result<u16, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Port {
        Number(u16),
        Text(String),
    }
    match Port::deserialize(de)? {
        Port::Number(port) => Ok(port),
        Port::Text(port) => port.parse().map_err(serde::de::Error::custom),
    }
}
