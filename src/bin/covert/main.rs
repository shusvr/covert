use crate::{
    config::{Config, ListenerConfig},
    transport::{State, TransportEndpoint},
};
use anyhow::{Context, Result, bail};
use base64::prelude::*;
use clap::{Parser, Subcommand};
use covert::{
    codec::{self, PacketLayout},
    crypto::{self, pk_to_bytes, random_sk, sk_to_bytes, to_sk},
    sans,
};
use etherparse::IpSlice;
use std::{
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::sync::mpsc;
use tracing::{Level, error, info, trace, warn};

mod config;
mod rpc;
mod transport;
mod tun_io;

#[derive(Parser)]
#[command(version = env!("COVERT_VERSION"), about)]
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

        /// Stream JSON status on a Unix socket; omit PATH to use the runtime directory.
        /// Place CONFIG before a bare -r to avoid ambiguity with the optional PATH.
        #[arg(short = 'r', long, num_args = 0..=1, value_name = "PATH")]
        rpc: Option<Option<PathBuf>>,

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
    /// Generate a random UUID v4.
    Genuuid,
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
        Command::Run {
            config,
            chanlen,
            rpc,
        } => run(config, chanlen, rpc).await,
        Command::Genkey => {
            let private_key = random_sk().context("failed to generate private key")?;
            let public_key = private_key
                .compute_public_key()
                .context("failed to derive public key")?;
            let private_bytes = zeroize::Zeroizing::new(sk_to_bytes(&private_key));
            let encoded_private =
                zeroize::Zeroizing::new(BASE64_STANDARD.encode(private_bytes.as_slice()));
            println!("Private key: {}", encoded_private.as_str());
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
        Command::Genuuid => {
            println!("{}", uuid::Uuid::new_v4());
            Ok(())
        }
        Command::Pubkey { private_key } => {
            let private_key = match private_key {
                Some(key) => zeroize::Zeroizing::new(key),
                None => {
                    let mut key = zeroize::Zeroizing::new(String::new());
                    io::stdin()
                        .read_to_string(&mut key)
                        .context("failed to read private key from stdin")?;
                    key
                }
            };
            let decoded = zeroize::Zeroizing::new(
                BASE64_STANDARD
                    .decode(private_key.trim())
                    .context("private key must be valid base64")?,
            );
            let key = zeroize::Zeroizing::new(
                <crypto::Key>::try_from(decoded.as_slice())
                    .map_err(|_| anyhow::anyhow!("private key must be 32 bytes"))?,
            );
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

    let conf_text =
        zeroize::Zeroizing::new(fs::read_to_string(&path).context("failed to read the file")?);
    let mut config = toml::from_str::<Config>(&conf_text).context("invalid config")?;
    config.dev_name = file_name.strip_suffix(".toml").unwrap().to_owned();
    trace!(?path, "Config: {config:#?}");

    let listener_tag = config.interface.listener.tag();

    if let Some(suggested_mtu) = config.interface.listener.suggested_mtu(&config.layout) {
        if suggested_mtu == 0 {
            warn!(
                transport = listener_tag,
                path_mtu = 1500,
                "Packet layout framing or minimum padding cannot fit a 1500-byte IPv4 path, even with a smaller TUN MTU"
            );
        } else if usize::from(config.interface.mtu) > suggested_mtu {
            warn!(
                transport = listener_tag,
                mtu = config.interface.mtu,
                suggested_mtu,
                path_mtu = 1500,
                "Configured TUN MTU exceeds the suggested MTU for this packet layout; encapsulated packets may exceed 1500 bytes"
            );
        }
    }

    let mut mismatch = false;
    for p in &config.peers {
        let peer_tag = p.transport.tag();

        info!(peer_id=?p.id, transport=peer_tag, %p.public_key, psk=?&p.pre_shared_key.is_some(), "Peer");
        let liveness = p.liveness.unpack_with_fallback(&config.interface.liveness);
        let twice_keepalive = (u64::from(liveness.ka_delay) + u64::from(liveness.ka_jitter)) * 2;
        if liveness.timeout != 0 && liveness.timeout < twice_keepalive {
            warn!(
                peer_id = ?p.id,
                keepalive = liveness.ka_delay,
                keepalive_jitter = liveness.ka_jitter,
                timeout = liveness.timeout,
                "Peer timeout is less than twice the maximum configured keepalive interval"
            );
        }
        if listener_tag != peer_tag && peer_tag != "none" {
            mismatch = true;
        }
    }

    if mismatch {
        warn!("One of the peers' transport doesn't match the interface transport");
    }

    Ok(config.into())
}

async fn run(
    conf_path: PathBuf,
    chanlen: Option<u16>,
    rpc_path: Option<Option<PathBuf>>,
) -> Result<()> {
    let config = read_config(&conf_path)?;
    let rpc = match rpc_path {
        None => None,
        Some(path) => {
            let path = match path {
                Some(path) => path,
                None => rpc::default_path(&config.dev_name)?,
            };
            let server = rpc::Server::bind(&path)
                .with_context(|| format!("failed to bind RPC socket {}", path.display()))?;
            info!(path = %path.display(), "RPC socket listening");
            Some(server)
        }
    };
    run_hooks("PreUp", &config.interface.hooks.pre_up, &config.dev_name).await?;
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

    #[cfg(target_os = "linux")]
    let builder = builder.offload(true);
    let tun = builder
        .build_async()
        .context("failed to create a tun device")?;

    #[cfg(target_os = "linux")]
    tracing::debug!(
        tcp_gso = tun.tcp_gso(),
        udp_gso = tun.udp_gso(),
        "TUN offloading enabled"
    );

    let result = async {
        run_hooks("PostUp", &config.interface.hooks.post_up, &config.dev_name).await?;
        tokio::select! {
            result = serve(&tun, &config, chanlen, rpc.as_ref()) => result,
            result = shutdown_signal() => result,
        }
    }
    .await;
    let pre_down = run_hooks(
        "PreDown",
        &config.interface.hooks.pre_down,
        &config.dev_name,
    )
    .await;
    drop(tun);
    let post_down = run_hooks(
        "PostDown",
        &config.interface.hooks.post_down,
        &config.dev_name,
    )
    .await;
    // Always attempt both cleanup phases, preserving the original failure.
    for outcome in [&result, &pre_down, &post_down] {
        if let Err(err) = outcome {
            error!("Interface lifecycle: {err:#}");
        }
    }
    result.and(pre_down).and(post_down)
}

async fn run_hooks(phase: &str, commands: &[String], iface: &str) -> Result<()> {
    for command in commands {
        let command = command.replace("%i", iface);
        info!(phase, %command, "Running interface hook");
        let status = tokio::process::Command::new("sh")
            .arg("-c")
            .arg(&command)
            .status()
            .await
            .with_context(|| format!("failed to execute {phase} hook"))?;
        if !status.success() {
            bail!("{phase} hook failed ({status}): {command}");
        }
    }
    Ok(())
}

async fn shutdown_signal() -> Result<()> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;
    tokio::select! {
        _ = interrupt.recv() => {},
        _ = terminate.recv() => {},
    }
    Ok(())
}

async fn serve(
    tun: &tun::AsyncDevice,
    config: &Arc<Config>,
    chanlen: Option<u16>,
    rpc: Option<&rpc::Server>,
) -> Result<()> {
    let chanlen = chanlen.unwrap_or(512) as usize;
    let (tun_in_tx, tun_in_rx) = mpsc::channel::<Vec<u8>>(chanlen);

    let state = Arc::new(State::new(tun_in_tx));
    let rpc_state = state.clone();
    let endpoint = async {
        match &config.interface.listener {
            ListenerConfig::Udp { udp } => {
                let endpoint = transport::udp::create_udp_endpoint(&state, &config, udp).await?;
                run_endpoint(tun, state, config.clone(), endpoint, tun_in_rx).await
            }
            ListenerConfig::Icmp { icmp } => {
                let endpoint = transport::icmp::create_icmp_endpoint(&state, &config, icmp).await?;
                run_endpoint(tun, state, config.clone(), endpoint, tun_in_rx).await
            }
        }
    };
    if let Some(server) = rpc {
        tokio::select! {
            result = endpoint => result,
            result = server.serve(rpc_state, config.clone()) => {
                result.context("RPC listener failed")
            }
        }
    } else {
        endpoint.await
    }
}

async fn run_endpoint(
    tun: &tun::AsyncDevice,
    state: Arc<State>,
    config: Arc<Config>,
    mut listener: impl TransportEndpoint,
    mut tun_in_rx: mpsc::Receiver<Vec<u8>>,
) -> Result<()> {
    let mut reader = tun_io::Reader::new(config.interface.mtu);
    let mut writer = tun_io::Writer::default();
    loop {
        tokio::select! {
            result = reader.recv(tun) => match result {
                Ok(count) => {
                    trace!(packets = count, "Received TUN batch");
                    for index in 0..count {
                        let packet = reader.packet(index);
                        if let Err(err) = process_tun_packet(&state, &config, &mut listener, packet).await {
                            error!("Failed to process tun packet: {err}");
                        }
                    }
                }
                Err(err) => error!("Failed to receive on tun: {err}"),
            },
            opt = tun_in_rx.recv() => if let Some(packet) = opt {
                trace!(len=packet.len(), "Received packet to tun");

                writer.send(tun, packet, &mut tun_in_rx).await?;
            } else {
                break Ok(())
            }
        }
    }
}

async fn process_tun_packet(
    state: &State,
    config: &Config,
    listener: &mut impl TransportEndpoint,
    packet: &[u8],
) -> Result<()> {
    let dst = IpSlice::from_slice(packet)?.destination_addr();

    for p in config.peers.iter() {
        if p.allowed_ips.iter().any(|x| x.contains(&dst)) {
            if let Err(err) = listener.trasmit(state, config, p.id, packet).await {
                error!("Failed to transmit: {err}");
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn tun_routing_only_requires_valid_ip_headers() {
        struct Capture(Vec<(uuid::Uuid, Vec<u8>)>);
        impl TransportEndpoint for Capture {
            async fn trasmit(
                &mut self,
                _state: &State,
                _config: &Config,
                peer_id: uuid::Uuid,
                packet: &[u8],
            ) -> Result<()> {
                self.0.push((peer_id, packet.to_vec()));
                Ok(())
            }
        }
        let mut config: Config = toml::from_str(include_str!("../../../config.toml")).unwrap();
        config.peers[0].allowed_ips = vec![
            "192.0.2.2/32".parse().unwrap(),
            "2001:db8::2/128".parse().unwrap(),
        ];
        let (tx, _rx) = mpsc::channel(1);
        let state = State::new(tx);
        let mut capture = Capture(Vec::new());
        // Both packets claim UDP but contain no UDP header. Routing must only
        // inspect the IP destination and leave the transport payload untouched.
        let ipv4 = etherparse::Ipv4Header::new(
            0,
            64,
            etherparse::IpNumber::UDP,
            [192, 0, 2, 1],
            [192, 0, 2, 2],
        )
        .unwrap()
        .to_bytes()
        .to_vec();
        let ipv6 = etherparse::Ipv6Header {
            next_header: etherparse::IpNumber::UDP,
            hop_limit: 64,
            source: "2001:db8::1"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets(),
            destination: "2001:db8::2"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets(),
            ..Default::default()
        }
        .to_bytes()
        .to_vec();
        for packet in [&ipv4, &ipv6] {
            process_tun_packet(&state, &config, &mut capture, packet)
                .await
                .unwrap();
            assert_eq!(
                capture.0.last().unwrap(),
                &(config.peers[0].id, packet.clone())
            );
        }
        let mut unmatched = ipv4.clone();
        unmatched[19] = 3;
        process_tun_packet(&state, &config, &mut capture, &unmatched)
            .await
            .unwrap();
        for packet in [&[][..], &[0xf0][..], &ipv4[..19], &ipv6[..39]] {
            assert!(
                process_tun_packet(&state, &config, &mut capture, packet)
                    .await
                    .is_err()
            );
        }
        assert_eq!(capture.0.len(), 2);
    }

    #[test]
    fn rpc_flag_accepts_missing_or_explicit_path() {
        for (args, expected) in [
            (vec!["covert", "run", "co1.toml"], None),
            (vec!["covert", "run", "co1.toml", "-r"], Some(None)),
            (vec!["covert", "run", "co1.toml", "--rpc"], Some(None)),
            (
                vec!["covert", "run", "co1.toml", "-r", "./rpc.sock"],
                Some(Some(PathBuf::from("./rpc.sock"))),
            ),
            (
                vec!["covert", "run", "-r", "./rpc.sock", "co1.toml"],
                Some(Some(PathBuf::from("./rpc.sock"))),
            ),
        ] {
            let Command::Run { rpc, config, .. } = Cli::try_parse_from(args).unwrap().command
            else {
                panic!("expected run");
            };
            assert_eq!(rpc, expected);
            assert_eq!(config, PathBuf::from("co1.toml"));
        }
    }

    #[test]
    fn suggested_mtu_accounts_for_transport_layout_and_padding() {
        for (listener, expected) in [
            ("Udp = { udp = {} }", Some(1438)),
            ("Icmp = { icmp = {} }", Some(1438)),
            ("Icmp = { icmp = { Mode = \"OnlyEcho\" } }", Some(1438)),
        ] {
            let listener: ListenerConfig = toml::from_str(listener).unwrap();
            let mut layout = PacketLayout::default();
            assert_eq!(listener.suggested_mtu(&layout), expected);
            layout.odd += 20;
            assert_eq!(
                listener.suggested_mtu(&layout),
                expected.map(|mtu| mtu - 20)
            );
            layout.odp = 1500;
            assert_eq!(listener.suggested_mtu(&layout), expected.map(|_| 0));
            layout.odp = 0;
            layout.odd = usize::MAX;
            assert_eq!(listener.suggested_mtu(&layout), expected.map(|_| 0));
        }
    }

    #[tokio::test]
    async fn hooks_expand_interface_run_in_order_and_stop_on_failure() {
        let path = std::env::temp_dir().join(format!("covert-hooks-{}", uuid::Uuid::new_v4()));
        let commands = vec![
            format!("printf '%i first\\n' > '{}'", path.display()),
            format!("printf '%i second\\n' >> '{}'", path.display()),
            "exit 7".to_owned(),
            format!("printf 'unexpected' >> '{}'", path.display()),
        ];
        let result = run_hooks("PostUp", &commands, "vpn-test").await;
        let contents = fs::read_to_string(&path).unwrap();
        fs::remove_file(path).unwrap();
        assert_eq!(contents, "vpn-test first\nvpn-test second\n");
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("PostUp hook failed")
        );
    }

    #[test]
    fn hooks_accept_single_commands_arrays_and_defaults() {
        let reference = include_str!("../../../config.toml");
        let default: Config = toml::from_str(reference).unwrap();
        assert!(default.interface.hooks.pre_up.is_empty());
        let configured = reference.replace(
            "[Interface]",
            r#"[Interface]
PreUp = "echo %i"
PostUp = ["first", "second"]
PreDown = []
PostDown = "done"
"#,
        );
        let config: Config = toml::from_str(&configured).unwrap();
        assert_eq!(config.interface.hooks.pre_up, ["echo %i"]);
        assert_eq!(config.interface.hooks.post_up, ["first", "second"]);
        assert!(config.interface.hooks.pre_down.is_empty());
        assert_eq!(config.interface.hooks.post_down, ["done"]);
    }
}
