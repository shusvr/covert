use anyhow::{Context, Result, bail};
use covert::{
    config::{Config, InterfaceHooks, ListenerConfig, LivenessOptions, Peer, PeerTransport},
    crypto::{pk_to_bytes, random_sk, sk_to_bytes, to_sk},
};
use std::{
    fs,
    io::{IsTerminal, Write},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
};

pub(super) fn add_peer(
    config: &Path,
    endpoint: IpAddr,
    output: Option<PathBuf>,
    ip: Option<IpAddr>,
    psk: bool,
    no_initiate: bool,
    json: bool,
    query: bool,
) -> anyhow::Result<()> {
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
        liveness: LivenessOptions {
            max_age: no_initiate.then_some(0),
            timeout: no_initiate.then_some(0),
            ..LivenessOptions::default()
        },
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
                    endpoint: Some(SocketAddr::new(endpoint, udp.port)),
                },
            },
            ListenerConfig::Quic { quic } => PeerTransport::Quic {
                quic: covert::transport::UdpTransportPeerConfig {
                    endpoint: Some(SocketAddr::new(endpoint, quic.port)),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Cli, Command};
    use base64::prelude::*;
    use clap::Parser;

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
                false,
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
    fn addpeer_flags_allow_endpoint_discovery_and_reject_conflicting_formats() {
        let cli = Cli::try_parse_from(["covert", "addpeer", "server.toml"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Addpeer { endpoint: None, .. }
        ));
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
                false,
                false
            )
            .is_err()
        );
        assert_eq!(fs::read_to_string(path).unwrap(), original);
        assert_eq!(fs::read_to_string(output).unwrap(), "keep");
    }
}
