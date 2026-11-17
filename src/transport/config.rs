use serde::Deserialize;
use std::net::{Ipv4Addr, SocketAddr};

#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq, Eq)]
pub enum IcmpMode {
    #[default]
    EchoReply,
    OnlyEcho,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct IcmpListenerConfig {
    #[serde(default)]
    pub mode: IcmpMode,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct IcmpTransportPeerConfig {
    pub endpoint: Option<Ipv4Addr>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct UdpListenerConfig {
    #[serde(default = "default_listen_port")]
    pub port: u16,
}

fn default_listen_port() -> u16 {
    40676
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct UdpTransportPeerConfig {
    pub endpoint: Option<SocketAddr>,
}
