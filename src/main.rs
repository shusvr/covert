#![allow(dead_code)]

use anyhow::{Context, Result, bail};
use base64::prelude::*;
use bytes::Bytes;
use clap::{Parser, Subcommand};
use covert::{
    config::{ArcConfig, Config, PeerTransport, Transport},
    crypto::{pk_to_bytes, random_sk, sk_to_bytes},
};
use etherparse::{NetHeaders, PacketHeaders};
use std::{
    fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
};
use tokio::sync::mpsc;
use tracing::{debug, error};

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

fn read_config(path: &Path) -> anyhow::Result<ArcConfig> {
    let file_name = path
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

    if !path.is_file() {
        bail!("Config is not a valid file or doesn't exit");
    }

    let conf_text = fs::read_to_string(&path).context("failed to read the file")?;
    let mut config = toml::from_str::<Config>(&conf_text).context("invalid config")?;
    config.dev_name = file_name.strip_suffix(".toml").unwrap().to_owned();
    debug!(?path, "Config: {config:#?}");

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

    Ok(config.into())
}

async fn run(conf_path: PathBuf) -> Result<()> {
    let config = read_config(&conf_path)?;
    let mut builder = tun::DeviceBuilder::new()
        .mtu(config.interface.mtu)
        .name(&config.dev_name)
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

    let (tun_out_tx, tun_out_rx) = mpsc::channel::<Bytes>(CHAN_LEN);
    let (tun_in_tx, mut tun_in_rx) = mpsc::channel::<Bytes>(CHAN_LEN);

    tokio::spawn(reader_task(config.clone(), tun_out_rx));

    let mut tun_buf = vec![0; config.interface.mtu as usize];
    loop {
        tokio::select! {
            result = tun.recv(&mut tun_buf) => match result {
                Ok(len) => {
                    debug!(len, "Received packet on tun");
                    let packet = Bytes::copy_from_slice(&tun_buf[..len]);
                    tun_out_tx.send(packet).await?;
                }
                Err(err) => error!("Failed to receive on tun: {err}"),
            },
            // wack
            opt = tun_in_rx.recv() => if let Some(packet) = opt {
                debug!(len=packet.len(), "Received packet to tun");

                tun.send(&packet).await?;
            } else {
                break Ok(())
            }
        }
    }
}

async fn process_tun_packet(config: &Config, packet: Bytes) -> Result<()> {
    let parsed = PacketHeaders::from_ip_slice(&packet)?;
    let net = parsed.net.unwrap();
    let dst = match net {
        NetHeaders::Ipv4(ipv4, _) => IpAddr::V4(Ipv4Addr::from_octets(ipv4.destination)),
        NetHeaders::Ipv6(ipv6, _) => IpAddr::V6(Ipv6Addr::from_octets(ipv6.destination)),
        _ => unreachable!(),
    };

    for p in config.peers.iter() {
        if p.allowed_ips.iter().any(|x| x.contains(&dst)) {
            // todo send packet to peer
        }
    }

    Ok(())
}

async fn reader_task(config: ArcConfig, mut tun_out_rx: mpsc::Receiver<Bytes>) {
    loop {
        let Some(packet) = tun_out_rx.recv().await else {
            debug!("tun_out_rx was closed, exiting reader task");
            break;
        };

        let len = packet.len();
        if let Err(err) = process_tun_packet(&config, packet).await {
            error!(packet_len = len, "process_tun_packet error: {err}");
        }
    }
}
