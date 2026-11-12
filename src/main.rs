#![allow(dead_code)]

use anyhow::{Context, Result, bail};
use base64::prelude::*;
use bytes::Bytes;
use clap::{Parser, Subcommand};
use covert::crypto::{pk_to_bytes, random_sk, sk_to_bytes};
use std::{fs, path::PathBuf, sync::Arc};
use tokio::sync::mpsc;
use tracing::{debug, error};

use crate::config::{PeerTransport, Transport};

mod config;

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the tunnel with a TOML configuration file.
    Run { config: PathBuf },
    /// Generate a base64-encoded X25519 private and public key pair.
    Genkey,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    _ = dotenvy::dotenv();
    tracing_subscriber::fmt::init();

    match cli.command {
        Command::Run { config } => run(config).await,
        Command::Genkey => {
            let private_key = random_sk().context("failed to generate private key")?;
            let public_key = private_key
                .compute_public_key()
                .context("failed to derive public key")?;
            println!(
                "Private key: {}",
                BASE64_STANDARD.encode(sk_to_bytes(&private_key))
            );
            println!(
                "Public key: {}",
                BASE64_STANDARD.encode(pk_to_bytes(&public_key))
            );
            Ok(())
        }
    }
}

async fn run(conf_path: PathBuf) -> Result<()> {
    let file_name = conf_path
        .file_name()
        .unwrap()
        .to_str()
        .context("file name must be utf8")?;
    if !file_name.ends_with(".toml") {
        bail!("Config file name must end in .toml");
    } else if file_name.len() > 21 {
        bail!("Config file name must be at most 21 characters long")
    } else if file_name
        .strip_suffix(".toml")
        .unwrap()
        .contains(|c| !matches!(c, 'a'..='z' | 'A'..='Z' | '0'..='9' | '_' | '=' | '+' | '.' | '-'))
    {
        bail!("Config file name must be [a-zA-Z0-9_=+.-]")
    }

    if !conf_path.is_file() {
        bail!("Config is not a valid file or doesn't exit");
    }

    let conf_text = fs::read_to_string(&conf_path).context("failed to read the file")?;
    let config: Arc<config::Config> = toml::from_str::<config::Config>(&conf_text)
        .context("invalid config")?
        .into();
    debug!(path=?conf_path, "Config: {config:#?}");

    for p in &config.peers {
        let matches = match (&config.interface.transport, &p.transport) {
            (Transport::Udp { .. }, PeerTransport::Udp { .. }) => true,
            (Transport::Other { id, .. }, PeerTransport::Other { id: peer, .. }) => id == peer,
            _ => false,
        };

        if !matches {
            bail!("One of the peers' transport doesn't match the interface transport");
        }
    }

    let mut builder = tun::DeviceBuilder::new()
        .mtu(config.interface.mtu)
        .name(file_name.strip_suffix(".toml").unwrap())
        .layer(tun::Layer::L3)
        .enable(true);

    for net in &config.interface.addresses {
        match net {
            ipnet::IpNet::V4(addr) => builder = builder.ipv4(addr.addr(), addr.prefix_len(), None),
            ipnet::IpNet::V6(addr) => builder = builder.ipv6(addr.addr(), addr.prefix_len()),
        }
    }

    let tun = builder
        .build_async()
        .context("failed to create a tun device")?;

    const CHAN_LEN: usize = 512;

    let (_tun_out_tx, mut tun_out_rx) = mpsc::channel::<Bytes>(CHAN_LEN);
    let (tun_in_tx, _tun_in_rx) = mpsc::channel::<Bytes>(CHAN_LEN);

    let mut tun_buf = vec![0; config.interface.mtu as usize];
    loop {
        tokio::select! {
            result = tun.recv(&mut tun_buf) => match result {
                Ok(len) => {
                    debug!(len, "Received packet on tun");
                    let packet = Bytes::copy_from_slice(&tun_buf[..len]);
                    tun_in_tx.send(packet).await?;
                }
                Err(err) => error!("Failed to receive on tun: {err}"),
            },
            // wack
            opt = tun_out_rx.recv() => if let Some(packet) = opt {
                tun.send(&packet).await?;
            } else {
                break Ok(())
            }
        }
    }
}
