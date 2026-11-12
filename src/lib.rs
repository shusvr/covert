pub type Key = [u8; 32];
pub type SealedKey = [u8; 48];
pub type Timestamp = i64;
pub type SealedTimestamp = [u8; 24];
pub type Nonce = [u8; 12];

pub mod config;
pub mod crypto;
pub mod transport;
pub mod wire;
