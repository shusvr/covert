#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("Wire: {0}")]
    Codec(#[from] covert::codec::Error),
    #[error("Tunnel: {0}")]
    Tunnel(#[from] covert::sans::Error),
    #[error("{transport} endpoint stopped")]
    EndpointStopped { transport: &'static str },
    #[error("TUN receiver closed")]
    TunReceiverClosed,
    #[cfg(not(target_os = "linux"))]
    #[error("Incomplete TUN write: wrote {written} of {expected} bytes")]
    IncompleteTunWrite { written: usize, expected: usize },
    #[error("Failed to install ICMP firewall rule ({status}): {stderr}")]
    IcmpFirewallSetup {
        status: std::process::ExitStatus,
        stderr: String,
    },
}

pub type Result<T = ()> = std::result::Result<T, Error>;
