//! Errors shared by every Rust API in the library.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Received unexpected packet type {0}")]
    UnexpectedTy(u8),
    #[error("Tried encoding a packet that is too large")]
    PacketOverflow,
    #[error("Invalid packet layout({0})")]
    InvalidLayout(&'static str),
    #[error("Failed to parse layout: {0}")]
    LayoutParseErr(#[from] serde_urlencoded::de::Error),
    #[error("Layout param `{0}` doesn't exist")]
    UnkownLayoutParam(String),
    #[error("Layout params `{0}` and `{1}` will cause overlap")]
    LayoutFieldsOverlap(String, String),
    #[error("Io: {0}")]
    Io(#[from] std::io::Error),
    #[error("Cryptographic operation failed")]
    Crypto(#[from] aws_lc_rs::error::Unspecified),
    #[error("Invalid IP packet: {0}")]
    IpPacket(#[from] etherparse::err::ip::SliceError),
    #[error("Malformed datagram")]
    MalformedDatagram,
    #[error("Invalid argument: {0}")]
    InvalidArgument(&'static str),
    #[error("No item available")]
    Empty,
    #[error("Adapter: {0}")]
    Adapter(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
}

impl Error {
    /// Preserve an external transport adapter's error as the source.
    pub fn adapter(error: impl Into<Box<dyn std::error::Error + Send + Sync + 'static>>) -> Self {
        Self::Adapter(error.into())
    }
}

pub type Result<T = ()> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error as _;

    #[test]
    fn crypto_and_layout_apis_return_the_shared_error() {
        let random: Result<_> = crate::crypto::random_sk();
        assert!(random.is_ok());
        let invalid: Result<crate::codec::PacketLayout> = "unknown_field=1".parse();
        let error = invalid.unwrap_err();
        assert!(matches!(error, Error::LayoutParseErr(_)));
        assert!(error.source().is_some());
        let failed: Result<_> = crate::crypto::initiate(&[1; 32], &[0; 32], 0, 1);
        let error = failed.unwrap_err();
        assert!(matches!(error, Error::Crypto(_)));
        assert!(error.source().is_some());
    }

    #[test]
    fn transport_ip_errors_and_adapter_sources_are_preserved() {
        let error: Error = etherparse::IpSlice::from_slice(&[]).unwrap_err().into();
        assert!(matches!(error, Error::IpPacket(_)));
        assert!(error.source().is_some());
        let error = Error::adapter(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "adapter denied",
        ));
        let source = error
            .source()
            .unwrap()
            .downcast_ref::<std::io::Error>()
            .unwrap();
        assert_eq!(source.kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn error_supports_send_sync_and_io_conversion() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Error>();
        let error: Error = std::io::Error::from(std::io::ErrorKind::BrokenPipe).into();
        assert!(matches!(error, Error::Io(_)));
        assert!(error.source().unwrap().is::<std::io::Error>());
    }
}
