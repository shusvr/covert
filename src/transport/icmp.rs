#![allow(dead_code)]

use serde::Deserialize;
use std::net::IpAddr;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct IcmpListenerConfig {
    #[serde(default = "default_icmp_id")]
    id: u16,
}

fn default_icmp_id() -> u16 {
    1339
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct IcmpTransportPeerConfig {
    endpoint: Option<IpAddr>,
}
