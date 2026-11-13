#![allow(dead_code, unused_variables)]

use crate::{
    Result,
    config::{Config, ListenerConfig},
};

pub mod icmp;
pub mod udp;

pub trait Listener {}

pub async fn create_listener(config: &Config) -> Result<()> {
    match &config.interface.listener {
        ListenerConfig::Udp { udp } => {
            let listener = udp::create_udp_listener(config, udp).await?;
        }
        ListenerConfig::Icmp { icmp } => todo!(),
        ListenerConfig::Other { id, values } => todo!(),
    }

    Ok(())
}
