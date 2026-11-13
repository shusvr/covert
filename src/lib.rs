use aws_lc_rs::error::Unspecified;
use thiserror::Error;

pub type Key = [u8; 32];
pub type SealedKey = [u8; 48];
pub type Timestamp = i64;
pub type SealedTimestamp = [u8; 24];
pub type Nonce = [u8; 12];

pub mod codec;
pub mod config;
pub mod crypto;
pub mod transport;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Io: {0}")]
    Io(#[from] std::io::Error),
    #[error("Wire: {0}")]
    Codec(#[from] codec::Error),
    #[error("Unspecified crypto error")]
    Crypto,
}

impl From<Unspecified> for Error {
    fn from(_: Unspecified) -> Self {
        Self::Crypto
    }
}

pub(crate) type Result<T = (), E = Error> = std::result::Result<T, E>;
