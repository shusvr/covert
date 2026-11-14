#![allow(dead_code)]

use anyhow::{Context, Result, bail};
use base64::prelude::*;
use clap::{Parser, Subcommand};
use covert::{
    codec::PacketLayout,
    config::{Config, ListenerConfig, PeerTransport},
    crypto::{pk_to_bytes, random_sk, sk_to_bytes, to_sk},
    transport::{Endpoint, PacketSender, State},
};
use etherparse::{NetHeaders, PacketHeaders};
use std::{
    fs,
    io::{self, Read},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::sync::mpsc;
use tracing::{Level, debug, error, trace};

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// Increase logging verbosity (-v for debug, -vv for trace).
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the tunnel with a TOML configuration file.
    Run {
        /// Capacity of the internal message channel.
        #[arg(short, long)]
        chanlen: Option<u16>,

        config: PathBuf,
    },
    /// Generate a base64-encoded X25519 private and public key pair.
    Genkey,
    /// Derive a base64-encoded public key from a private key or stdin.
    Pubkey {
        /// Base64-encoded private key; read stdin when omitted.
        private_key: Option<String>,
    },
    /// Generate a random packet layout
    Genlayout,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let log_level = match cli.verbose {
        0 => Level::INFO,
        1 => Level::DEBUG,
        _ => Level::TRACE,
    };
    tracing_subscriber::fmt().with_max_level(log_level).init();

    match cli.command {
        Command::Run { config, chanlen } => run(config, chanlen).await,
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
        Command::Genlayout => {
            let layout = PacketLayout::random().to_string();
            println!("{layout}");
            Ok(())
        }
        Command::Pubkey { private_key } => {
            let private_key = match private_key {
                Some(key) => key,
                None => {
                    let mut key = String::new();
                    io::stdin()
                        .read_to_string(&mut key)
                        .context("failed to read private key from stdin")?;
                    key
                }
            };
            let decoded = BASE64_STANDARD
                .decode(private_key.trim())
                .context("private key must be valid base64")?;
            let key: covert::Key = decoded
                .try_into()
                .map_err(|_| anyhow::anyhow!("private key must be 32 bytes"))?;
            let public_key = to_sk(&key)
                .compute_public_key()
                .context("failed to derive public key")?;
            println!("{}", BASE64_STANDARD.encode(pk_to_bytes(&public_key)));
            Ok(())
        }
    }
}

fn read_config(path: &Path) -> anyhow::Result<Arc<Config>> {
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
        let matches = match (&config.interface.listener, &p.transport) {
            (ListenerConfig::Udp { .. }, PeerTransport::Udp { .. }) => true,
            (ListenerConfig::Icmp { .. }, PeerTransport::Icmp { .. }) => true,
            _ => false,
        };

        if !matches {
            bail!("One of the peers' transport doesn't match the interface transport");
        }
    }

    Ok(config.into())
}

async fn run(conf_path: PathBuf, chanlen: Option<u16>) -> Result<()> {
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

    let chanlen = chanlen.unwrap_or(512) as usize;
    let (tun_in_tx, tun_in_rx) = mpsc::channel::<Vec<u8>>(chanlen);

    let state = Arc::new(State::new(tun_in_tx));
    match &config.interface.listener {
        ListenerConfig::Udp { udp } => {
            let endpoint =
                covert::transport::udp::create_udp_endpoint(&state, &config, udp).await?;
            run_endpoint(tun, state, config, endpoint, tun_in_rx).await
        }
        ListenerConfig::Icmp { icmp } => {
            let endpoint =
                covert::transport::icmp::create_icmp_endpoint(&state, &config, icmp).await?;
            run_endpoint(tun, state, config, endpoint, tun_in_rx).await
        }
    }
}

async fn run_endpoint<S: PacketSender<R>, R: Clone>(
    tun: tun::AsyncDevice,
    state: Arc<State>,
    config: Arc<Config>,
    mut listener: Endpoint<S, R>,
    mut tun_in_rx: mpsc::Receiver<Vec<u8>>,
) -> Result<()> {
    let mut tun_buf = vec![0; config.interface.mtu as usize];
    loop {
        tokio::select! {
            result = tun.recv(&mut tun_buf) => match result {
                Ok(len) => {
                    trace!(len, "Received packet on tun");

                    if let Err(err) = process_tun_packet(&state, &config, &mut listener, &tun_buf[..len]).await {
                        error!("Failed to process tun packet: {err}");
                    }
                }
                Err(err) => error!("Failed to receive on tun: {err}"),
            },
            // wack
            opt = tun_in_rx.recv() => if let Some(packet) = opt {
                trace!(len=packet.len(), "Received packet to tun");

                tun.send(&packet).await?;
            } else {
                break Ok(())
            }
        }
    }
}

async fn process_tun_packet<S: PacketSender<R>, R: Clone>(
    state: &State,
    config: &Config,
    listener: &mut Endpoint<S, R>,
    packet: &[u8],
) -> Result<()> {
    let parsed = PacketHeaders::from_ip_slice(&packet)?;
    let net = parsed.net.unwrap();
    let dst = match net {
        NetHeaders::Ipv4(ipv4, _) => IpAddr::V4(Ipv4Addr::from_octets(ipv4.destination)),
        NetHeaders::Ipv6(ipv6, _) => IpAddr::V6(Ipv6Addr::from_octets(ipv6.destination)),
        _ => unreachable!(),
    };

    for p in config.peers.iter() {
        if p.allowed_ips.iter().any(|x| x.contains(&dst)) {
            if let Err(err) = listener.trasmit(state, config, p.peer_id, packet).await {
                error!("Failed to transmit: {err}");
            }
        }
    }

    Ok(())
}
