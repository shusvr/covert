//! Read-only Unix-socket status stream. Each line is one complete JSON snapshot.
use anyhow::{Context, Result};
use covert::transport::StatusSnapshot;
use std::{
    fs,
    os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::{
    io::AsyncWriteExt,
    net::{UnixListener, UnixStream},
    sync::watch,
    task::JoinSet,
    time::{MissedTickBehavior, interval, timeout},
};

pub struct Server {
    listener: UnixListener,
    _path: SocketPath,
}
struct SocketPath {
    path: PathBuf,
    device: u64,
    inode: u64,
}
impl Drop for SocketPath {
    fn drop(&mut self) {
        // Never unlink another process's replacement or a symlink at this path.
        if let Ok(metadata) = fs::symlink_metadata(&self.path) {
            if metadata.file_type().is_socket()
                && metadata.dev() == self.device
                && metadata.ino() == self.inode
            {
                if let Err(err) = fs::remove_file(&self.path) {
                    tracing::error!(path = %self.path.display(), %err, "Failed to remove RPC socket");
                }
            }
        }
    }
}

pub fn default_path(device: &str) -> Result<PathBuf> {
    let directory =
        dirs::runtime_dir().context("runtime directory is unavailable; specify --rpc PATH")?;
    Ok(directory.join(format!("covert.{device}.sock")))
}

impl Server {
    pub fn bind(path: &Path) -> Result<Self> {
        // No mkdir, stale-socket removal, or fallback directory: bind must fail
        // for an existing path or an unusable parent directory.
        let listener = UnixListener::bind(path)?;
        let metadata = fs::symlink_metadata(path)?;
        let guard = SocketPath {
            path: path.to_owned(),
            device: metadata.dev(),
            inode: metadata.ino(),
        };
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        Ok(Self {
            listener,
            _path: guard,
        })
    }

    pub async fn serve(&self, status: watch::Receiver<StatusSnapshot>) -> Result<()> {
        let mut clients = JoinSet::new();
        loop {
            tokio::select! {
                accepted = self.listener.accept() => {
                    let (stream, _) = accepted?;
                    let status = status.clone();
                    clients.spawn(async move {
                        if let Err(err) = stream_status(stream, status).await {
                            tracing::trace!(%err, "RPC client disconnected");
                        }
                    });
                }
                result = clients.join_next(), if !clients.is_empty() => {
                    if let Some(Err(err)) = result { tracing::error!(%err, "RPC client task failed"); }
                }
            }
        }
    }
}

async fn stream_status(
    mut stream: UnixStream,
    status: watch::Receiver<StatusSnapshot>,
) -> Result<()> {
    let mut ticks = interval(Duration::from_secs(1));
    ticks.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        ticks.tick().await;
        let mut line =
            serde_json::to_vec(&*status.borrow()).context("Failed to serialize RPC status")?;
        line.push(b'\n');
        timeout(Duration::from_secs(5), stream.write_all(&line))
            .await
            .context("RPC client is not reading")?
            .context("Failed to write RPC status")?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use covert::{
        codec::Packet,
        config::Config,
        config::Peer,
        transport::{Adapter, Endpoint},
    };
    use std::sync::Arc;
    use tokio::io::{AsyncBufReadExt, BufReader};

    struct Directory(PathBuf);
    impl Directory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("covert-rpc-{}", uuid::Uuid::new_v4()));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[tokio::test]
    async fn binding_refuses_existing_paths_and_never_creates_directories() {
        let dir = Directory::new();
        let path = dir.0.join("status.sock");
        let server = Server::bind(&path).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(Server::bind(&path).is_err());
        assert!(path.exists());
        drop(server);
        assert!(!path.exists());
        fs::write(&path, "keep me").unwrap();
        assert!(Server::bind(&path).is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), "keep me");
        let missing = dir.0.join("missing");
        assert!(Server::bind(&missing.join("status.sock")).is_err());
        assert!(!missing.exists());
        let path = dir.0.join("replaced.sock");
        let server = Server::bind(&path).unwrap();
        fs::remove_file(&path).unwrap();
        fs::write(&path, "replacement").unwrap();
        drop(server);
        assert_eq!(fs::read_to_string(&path).unwrap(), "replacement");
    }

    #[tokio::test]
    async fn streams_immediate_and_periodic_json_to_multiple_clients() {
        let dir = Directory::new();
        let path = dir.0.join("status.sock");
        let config: Config = toml::from_str(include_str!("../../../config.toml")).unwrap();
        struct Capture;
        impl Adapter for Capture {
            type Route = ();
            fn peer_route(&self, _: &Peer) -> Option<()> {
                None
            }
            fn deliver(&self, _: (), _: Packet) {}
        }
        let endpoint = Endpoint::new(Capture, config).unwrap();
        let (status_tx, status) = watch::channel(endpoint.status());
        let server = Arc::new(Server::bind(&path).unwrap());
        let task_server = server.clone();
        let task = tokio::spawn(async move { task_server.serve(status).await });
        let mut a = BufReader::new(UnixStream::connect(&path).await.unwrap()).lines();
        let mut b = BufReader::new(UnixStream::connect(&path).await.unwrap()).lines();
        let first = timeout(Duration::from_secs(2), a.next_line())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let first: serde_json::Value = serde_json::from_str(&first).unwrap();
        assert!(uuid::Uuid::parse_str(first["session"].as_str().unwrap()).is_ok());
        assert_eq!(first["peers"][0]["status"], "disconnected");
        assert_eq!(first["peers"][0]["transport"], "udp");
        assert_eq!(first["peers"][0]["sent"], 0);
        assert_eq!(first["peers"][0]["received"], 0);
        assert!(first["peers"][0]["first_established_at"].is_null());
        assert!(!first.to_string().contains("private_key"));
        for client in [&mut a, &mut b] {
            let line = timeout(Duration::from_secs(2), client.next_line())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            let next: serde_json::Value = serde_json::from_str(&line).unwrap();
            assert_eq!(next, first);
        }
        let mut updated = endpoint.status();
        updated.peers[0].sent = 123;
        status_tx.send_replace(updated);
        for client in [&mut a, &mut b] {
            timeout(Duration::from_secs(3), async {
                loop {
                    let line = client.next_line().await.unwrap().unwrap();
                    let next: serde_json::Value = serde_json::from_str(&line).unwrap();
                    if next["peers"][0]["sent"] == 123 {
                        assert_eq!(next["session"], first["session"]);
                        break;
                    }
                }
            })
            .await
            .unwrap();
        }
        task.abort();
        let _ = task.await;
        drop(server);
        assert!(!path.exists());
    }

    #[test]
    fn default_socket_uses_runtime_directory_directly() {
        match dirs::runtime_dir() {
            Some(dir) => assert_eq!(default_path("co1").unwrap(), dir.join("covert.co1.sock")),
            None => assert!(
                default_path("co1")
                    .unwrap_err()
                    .to_string()
                    .contains("runtime directory is unavailable")
            ),
        }
    }
}
