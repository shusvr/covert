use anyhow::{Context, Result, bail};
use base64::prelude::*;
use clap::{Parser, Subcommand};
use covert::{
    codec::PacketLayout,
    config::{Config, ListenerConfig},
    crypto::{self, pk_to_bytes, random_sk, sk_to_bytes, to_sk},
    transport::Endpoint,
};
use std::{
    fs,
    io::{self, IsTerminal, Read},
    net::IpAddr,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::sync::{mpsc, watch};
use tracing::{Level, error, info, trace, warn};

mod icmp;
mod network;
mod rpc;
mod tun_io;
mod udp;

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
    /// Adds new peer, overriding config in place
    Addpeer {
        config: PathBuf,
        /// Public server IP used by the generated client.
        #[arg(short, long)]
        endpoint: IpAddr,
        /// Ip for new peer, must be in the interface subnet.
        #[arg(long)]
        ip: Option<IpAddr>,
        /// Generate pre shared key
        #[arg(long)]
        psk: bool,
        /// Output file path; write to stdout when omitted.
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Output in json format
        #[arg(short, long, conflicts_with = "query")]
        json: bool,
        /// Output in query format
        #[arg(short, long, conflicts_with = "json")]
        query: bool,
    },
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
        Command::Addpeer {
            endpoint,
            ip,
            psk,
            config,
            output,
            json,
            query,
        } => add_peer(&config, endpoint, output, ip, psk, json, query),
    }
}

fn add_peer(
    config: &Path,
    endpoint: IpAddr,
    output: Option<PathBuf>,
    ip: Option<IpAddr>,
    psk: bool,
    json: bool,
    query: bool,
) -> anyhow::Result<()> {
    use covert::config::{InterfaceHooks, LivenessOptions, Peer, PeerTransport};
    use std::io::Write;

    if fs::symlink_metadata(config)?.file_type().is_symlink() {
        bail!("config must be a regular file, not a symlink");
    }
    let original = zeroize::Zeroizing::new(fs::read_to_string(config)?);
    let server: Config = toml_edit::de::from_str(&original).context("invalid server config")?;
    let mut document = original.parse::<toml_edit::DocumentMut>()?;
    let address = choose_peer_ip(&server, ip)?;
    let host = ipnet::IpNet::new(address, if address.is_ipv4() { 32 } else { 128 })?;
    let private = random_sk().context("failed to generate peer key")?;
    let public = pk_to_bytes(&private.compute_public_key()?);
    let shared = if psk {
        Some(sk_to_bytes(&random_sk()?).into())
    } else {
        None
    };
    let peer = Peer {
        id: uuid::Uuid::new_v4(),
        public_key: public.into(),
        pre_shared_key: shared.clone(),
        allowed_ips: vec![host],
        transport: PeerTransport::None,
        liveness: LivenessOptions::default(),
        metric: 600,
    };
    let encoded = toml_edit::ser::to_string(&peer)?;
    let table = encoded.parse::<toml_edit::DocumentMut>()?.into_table();
    if document.get("Peer").is_none() {
        document["Peer"] = toml_edit::Item::ArrayOfTables(toml_edit::ArrayOfTables::new());
    }
    if let Some(peers) = document["Peer"].as_array_of_tables_mut() {
        peers.push(table);
    } else if let Some(peers) = document["Peer"].as_array_mut() {
        peers.push(table.into_inline_table());
    } else {
        bail!("Peer must be an array of tables");
    }

    let mut client = server.clone();
    client.interface.private_key = sk_to_bytes(&private).into();
    client.interface.addresses = vec![host];
    client.interface.hooks = InterfaceHooks::default();
    client.peers = vec![Peer {
        id: uuid::Uuid::new_v4(),
        public_key: pk_to_bytes(&to_sk(&server.interface.private_key.0).compute_public_key()?)
            .into(),
        pre_shared_key: shared,
        allowed_ips: vec![
            if address.is_ipv4() {
                "0.0.0.0/0"
            } else {
                "::/0"
            }
            .parse()?,
        ],
        transport: match &server.interface.listener {
            ListenerConfig::Udp { udp } => PeerTransport::Udp {
                udp: covert::transport::UdpTransportPeerConfig {
                    endpoint: Some(std::net::SocketAddr::new(endpoint, udp.port)),
                },
            },
            ListenerConfig::Quic { quic } => PeerTransport::Quic {
                quic: covert::transport::UdpTransportPeerConfig {
                    endpoint: Some(std::net::SocketAddr::new(endpoint, quic.port)),
                },
            },
            ListenerConfig::Icmp { .. } => PeerTransport::Icmp {
                icmp: covert::transport::IcmpTransportPeerConfig {
                    endpoint: Some(match endpoint {
                        IpAddr::V4(ip) => ip,
                        IpAddr::V6(_) => bail!("ICMP requires an IPv4 server endpoint"),
                    }),
                },
            },
        },
        liveness: LivenessOptions::default(),
        metric: 600,
    }];
    let exported = zeroize::Zeroizing::new(if json {
        client.to_json(std::io::stdout().is_terminal())?
    } else if query {
        "covert:/?".to_owned() + &client.to_query()?
    } else {
        toml_edit::ser::to_string_pretty(&client)?
    });
    // Validate the edited document before changing either file.
    let updated = zeroize::Zeroizing::new(document.to_string());
    let _: Config = toml_edit::de::from_str(&updated)?;
    let mut output_file = if let Some(path) = &output {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        Some(options.open(path).context("output must be a new file")?)
    } else {
        None
    };
    let result = (|| -> Result<()> {
        if let Some(file) = &mut output_file {
            writeln!(file, "{}", exported.as_str())?;
            file.sync_all()?;
        }
        replace_config(config, &original, &updated)?;
        Ok(())
    })();
    if result.is_err() {
        if let Some(path) = &output {
            let _ = fs::remove_file(path);
        }
    }
    result?;
    if output.is_none() {
        println!("{}", exported.as_str());
    }
    Ok(())
}

fn choose_peer_ip(config: &Config, requested: Option<IpAddr>) -> Result<IpAddr> {
    let occupied = |ip: IpAddr| {
        config
            .interface
            .addresses
            .iter()
            .any(|net| net.addr() == ip)
            || config
                .peers
                .iter()
                .any(|peer| peer.allowed_ips.iter().any(|net| net.contains(&ip)))
    };
    let usable = |ip: IpAddr| {
        config.interface.addresses.iter().any(|net| {
            net.contains(&ip)
                && (net.prefix_len() > 30
                    || !ip.is_ipv4()
                    || (ip != net.network() && ip != net.broadcast()))
        })
    };
    if let Some(ip) = requested {
        if !usable(ip) {
            bail!("peer IP must be a usable address in an interface subnet");
        }
        if occupied(ip) {
            bail!("peer IP is already assigned or covered by an existing peer");
        }
        return Ok(ip);
    }
    for subnet in &config.interface.addresses {
        let Some(mut candidate) = subnet.hosts().next() else {
            continue;
        };
        while subnet.contains(&candidate) && usable(candidate) {
            if !occupied(candidate) {
                return Ok(candidate);
            }
            // Skip entire occupied ranges, including large IPv6 prefixes.
            let end = config
                .peers
                .iter()
                .flat_map(|peer| &peer.allowed_ips)
                .filter(|net| net.contains(&candidate))
                .map(|net| net.broadcast())
                .max()
                .unwrap_or(candidate);
            candidate = match end {
                IpAddr::V4(ip) => match u32::from(ip).checked_add(1) {
                    Some(next) => std::net::Ipv4Addr::from(next).into(),
                    None => break,
                },
                IpAddr::V6(ip) => match u128::from(ip).checked_add(1) {
                    Some(next) => std::net::Ipv6Addr::from(next).into(),
                    None => break,
                },
            };
        }
    }
    bail!("no available peer IP in the interface subnets; specify --ip or expand the subnet")
}

fn replace_config(path: &Path, original: &str, updated: &str) -> Result<()> {
    use std::io::Write;
    let temporary = path.with_file_name(format!(".covert-{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| -> Result<()> {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        file.write_all(updated.as_bytes())?;
        file.set_permissions(fs::metadata(path)?.permissions())?;
        file.sync_all()?;
        if fs::read_to_string(path)? != original {
            bail!("config changed while adding peer; retry");
        }
        fs::rename(&temporary, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
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
    let mut config = toml_edit::de::from_str::<Config>(&conf_text).context("invalid config")?;
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
    let capacity = usize::from(chanlen.unwrap_or(512)).max(1);
    match &config.interface.listener {
        ListenerConfig::Udp { udp } | ListenerConfig::Quic { quic: udp } => {
            let (socket, endpoint) = udp::Udp::bind(config, udp).await?;
            run_endpoint(tun, config, socket, endpoint, capacity, rpc).await
        }
        ListenerConfig::Icmp { icmp } => {
            let (socket, endpoint) = icmp::Icmp::bind(config, icmp)?;
            run_endpoint(tun, config, socket, endpoint, capacity, rpc).await
        }
    }
}

async fn run_endpoint<S: network::Socket>(
    tun: &tun::AsyncDevice,
    config: &Config,
    socket: S,
    endpoint: Endpoint<S::Adapter>,
    capacity: usize,
    rpc: Option<&rpc::Server>,
) -> Result<()> {
    let (out_tx, out_rx) = mpsc::channel(capacity);
    let (in_tx, mut in_rx) = mpsc::channel(capacity);
    let (status_tx, status_rx) = watch::channel(endpoint.status());
    let mut reader = tun_io::Reader::new(config.interface.mtu);
    let mut writer = tun_io::Writer::default();
    // Read and write independently: a full queue in one direction must not
    // prevent the opposite direction from draining its queue.
    let read = async {
        loop {
            let count = reader.recv(tun).await?;
            trace!(packets = count, "Received TUN batch");
            for index in 0..count {
                out_tx
                    .send(reader.packet(index).to_vec())
                    .await
                    .context("Socket worker stopped")?;
            }
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    };
    let write = async {
        while let Some(packet) = in_rx.recv().await {
            writer.send(tun, packet, &mut in_rx).await?;
        }
        Ok::<(), anyhow::Error>(())
    };
    let rpc = async {
        match rpc {
            Some(server) => server.serve(status_rx).await,
            None => std::future::pending().await,
        }
    };
    tokio::select! {
        result = network::run(socket, endpoint, out_rx, in_tx, status_tx) => result,
        result = read => result,
        result = write => result,
        result = rpc => result.context("RPC listener failed"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct PeerFiles(PathBuf);
    impl PeerFiles {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("covert-addpeer-{}", uuid::Uuid::new_v4()));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for PeerFiles {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn addpeer_roundtrips_formats_preserves_server_and_pairs_keys() {
        for (json, query) in [(false, false), (true, false), (false, true)] {
            let files = PeerFiles::new();
            let path = files.0.join("server.toml");
            let output = files.0.join("client");
            let mut server: Config =
                toml_edit::de::from_str(include_str!("../../../config.toml")).unwrap();
            server.interface.addresses = vec!["10.42.0.1/24".parse().unwrap()];
            server.peers.clear();
            server.interface.hooks.post_up = vec!["echo keep".into()];
            let text = format!(
                "# preserve this comment\n{}\n[Interface.Custom]\nKeep = 'yes'\n",
                toml_edit::ser::to_string_pretty(&server).unwrap()
            );
            fs::write(&path, &text).unwrap();
            add_peer(
                &path,
                "203.0.113.1".parse().unwrap(),
                Some(output.clone()),
                None,
                true,
                json,
                query,
            )
            .unwrap();
            let edited = fs::read_to_string(&path).unwrap();
            assert!(edited.starts_with("# preserve this comment\n"));
            assert!(edited.contains("Keep = 'yes'"));
            let updated: Config = toml_edit::de::from_str(&edited).unwrap();
            assert_eq!(updated.peers.len(), 1);
            assert_eq!(updated.peers[0].allowed_ips[0].to_string(), "10.42.0.2/32");
            assert_eq!(
                *updated.interface.private_key.0,
                *server.interface.private_key.0
            );
            let exported = fs::read_to_string(&output).unwrap();
            let client: Config = if json {
                serde_json::from_str(&exported).unwrap()
            } else if query {
                serde_qs::from_str(exported.trim()).unwrap()
            } else {
                toml_edit::de::from_str(&exported).unwrap()
            };
            assert_eq!(
                client.interface.addresses[0],
                updated.peers[0].allowed_ips[0]
            );
            assert_eq!(
                pk_to_bytes(
                    &to_sk(&client.interface.private_key.0)
                        .compute_public_key()
                        .unwrap()
                ),
                *updated.peers[0].public_key.0
            );
            assert_eq!(
                *client.peers[0].pre_shared_key.as_ref().unwrap().0,
                *updated.peers[0].pre_shared_key.as_ref().unwrap().0
            );
            assert!(client.interface.hooks.post_up.is_empty());
            match client.peers[0].transport {
                covert::config::PeerTransport::Udp { ref udp } => assert_eq!(
                    udp.endpoint.unwrap().ip(),
                    "203.0.113.1".parse::<IpAddr>().unwrap()
                ),
                _ => panic!("expected UDP"),
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(
                    fs::metadata(output).unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
        }
    }

    #[test]
    fn addpeer_ip_allocation_skips_ranges_and_rejects_unusable_addresses() {
        let mut config: Config =
            toml_edit::de::from_str(include_str!("../../../config.toml")).unwrap();
        config.interface.addresses = vec!["10.42.0.1/24".parse().unwrap()];
        config.peers.truncate(1);
        config.peers[0].allowed_ips = vec!["10.42.0.0/25".parse().unwrap()];
        assert_eq!(
            choose_peer_ip(&config, None).unwrap().to_string(),
            "10.42.0.128"
        );
        for ip in [
            "10.42.0.0",
            "10.42.0.1",
            "10.42.0.2",
            "10.42.0.255",
            "10.43.0.2",
            "::1",
        ] {
            assert!(choose_peer_ip(&config, Some(ip.parse().unwrap())).is_err());
        }
        config.interface.addresses = vec!["fd00::1/64".parse().unwrap()];
        config.peers[0].allowed_ips = vec!["fd00::/65".parse().unwrap()];
        assert_eq!(
            choose_peer_ip(&config, None).unwrap().to_string(),
            "fd00::8000:0:0:0"
        );
        config.peers[0].allowed_ips = vec!["::/0".parse().unwrap()];
        assert!(choose_peer_ip(&config, None).is_err());
    }

    #[test]
    fn addpeer_appends_to_existing_tables_and_supports_icmp_without_psk() {
        let files = PeerFiles::new();
        let path = files.0.join("server.toml");
        let output = files.0.join("client.json");
        let text = format!(
            "[Interface]\nAddress = '10.42.0.1/24'\nPrivateKey = '{}'\nPostUp = 'echo server-only'\n[Interface.Listener.Icmp.icmp]\nMode = 'EchoReply'\n\n# original peer\n[[Peer]]\nPublicKey = '{}'\nAllowedIPs = '10.42.0.2/32' # retain\n",
            BASE64_STANDARD.encode([1; 32]),
            BASE64_STANDARD.encode([2; 32])
        );
        fs::write(&path, &text).unwrap();
        assert!(
            add_peer(
                &path,
                "::1".parse().unwrap(),
                Some(output.clone()),
                None,
                false,
                true,
                false
            )
            .is_err()
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), text);
        assert!(!output.exists());
        add_peer(
            &path,
            "203.0.113.1".parse().unwrap(),
            Some(output.clone()),
            Some("10.42.0.3".parse().unwrap()),
            false,
            true,
            false,
        )
        .unwrap();
        let edited = fs::read_to_string(path).unwrap();
        assert!(edited.starts_with(&text));
        let server: Config = toml_edit::de::from_str(&edited).unwrap();
        assert_eq!(server.peers.len(), 2);
        let client: Config = serde_json::from_str(&fs::read_to_string(output).unwrap()).unwrap();
        assert!(client.peers[0].pre_shared_key.is_none());
        assert!(client.interface.hooks.post_up.is_empty());
        assert!(matches!(
            client.peers[0].transport,
            covert::config::PeerTransport::Icmp { .. }
        ));
    }

    #[test]
    fn addpeer_flags_require_endpoint_and_reject_conflicting_formats() {
        assert!(Cli::try_parse_from(["covert", "addpeer", "server.toml"]).is_err());
        assert!(
            Cli::try_parse_from([
                "covert",
                "addpeer",
                "server.toml",
                "--endpoint",
                "203.0.113.1",
                "--psk",
                "--json",
                "--output",
                "client.json"
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "covert",
                "addpeer",
                "server.toml",
                "--endpoint",
                "203.0.113.1",
                "--json",
                "--query"
            ])
            .is_err()
        );
    }

    #[test]
    fn addpeer_failures_do_not_change_server_or_overwrite_output() {
        let files = PeerFiles::new();
        let path = files.0.join("server.toml");
        let output = files.0.join("client");
        let original = include_str!("../../../config.toml");
        fs::write(&path, original).unwrap();
        fs::write(&output, "keep").unwrap();
        assert!(
            add_peer(
                &path,
                "203.0.113.1".parse().unwrap(),
                Some(output.clone()),
                None,
                false,
                false,
                false
            )
            .is_err()
        );
        assert_eq!(fs::read_to_string(path).unwrap(), original);
        assert_eq!(fs::read_to_string(output).unwrap(), "keep");
    }

    #[test]
    fn tun_routing_only_requires_valid_ip_headers() {
        use covert::{codec::Packet, config::Peer, transport::Adapter};
        struct Capture;
        impl Adapter for Capture {
            type Route = ();
            fn peer_route(&self, _: &Peer) -> Option<()> {
                None
            }
            fn deliver(&self, _: (), _: Packet) {}
        }
        let mut config: Config =
            toml_edit::de::from_str(include_str!("../../../config.toml")).unwrap();
        config.peers[0].allowed_ips = vec![
            "192.0.2.2/32".parse().unwrap(),
            "2001:db8::2/128".parse().unwrap(),
        ];
        let mut endpoint = Endpoint::new(Capture, config).unwrap();
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
            endpoint.tun_write(packet).unwrap();
        }
        assert_eq!(
            endpoint.status().peers[0].sent,
            (ipv4.len() + ipv6.len()) as u64
        );
        let mut unmatched = ipv4.clone();
        unmatched[19] = 3;
        endpoint.tun_write(&unmatched).unwrap();
        assert_eq!(
            endpoint.status().peers[0].sent,
            (ipv4.len() + ipv6.len()) as u64
        );
        for packet in [&[][..], &[0xf0][..], &ipv4[..19], &ipv6[..39]] {
            assert!(endpoint.tun_write(packet).is_err());
        }
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
            let listener: ListenerConfig = toml_edit::de::from_str(listener).unwrap();
            let mut layout = PacketLayout::default();
            assert_eq!(listener.suggested_mtu(&layout), expected);
            layout.odd += 20;
            assert_eq!(
                listener.suggested_mtu(&layout),
                expected.map(|mtu| mtu - 20)
            );
            layout.odp = 1500;
            assert_eq!(listener.suggested_mtu(&layout), expected.map(|_| 0));
            layout.odp = u16::MAX;
            assert_eq!(listener.suggested_mtu(&layout), expected.map(|_| 0));
            layout.odp = 0;
            layout.odd = u8::MAX;
            assert_eq!(
                listener.suggested_mtu(&layout),
                Some(1472 - usize::from(u8::MAX) - 16)
            );
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
        let default: Config = toml_edit::de::from_str(reference).unwrap();
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
        let config: Config = toml_edit::de::from_str(&configured).unwrap();
        assert_eq!(config.interface.hooks.pre_up, ["echo %i"]);
        assert_eq!(config.interface.hooks.post_up, ["first", "second"]);
        assert!(config.interface.hooks.pre_down.is_empty());
        assert_eq!(config.interface.hooks.post_down, ["done"]);
    }
}
