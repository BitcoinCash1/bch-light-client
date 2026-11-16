//! The error type of the client's API.

use std::fmt;

/// What kind of failure an [`Error`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorKind {
    /// No peer could be reached or none answered; retrying later may work.
    Unavailable,
    /// A peer sent data that breaks the rules: a bad header, a filter that
    /// does not match its block, a block that does not match its header.
    InvalidData,
    /// The thing asked for does not exist on the chain or in the mempool.
    NotFound,
    /// The peers' filters cannot answer this yet, such as a lookup by
    /// transaction ID alone before the filters have transaction keys.
    Unsupported,
    /// A transaction was refused by the network.
    Rejected,
    /// The request is malformed.
    InvalidInput,
    /// The client is shutting down.
    Stopped,
    /// Reading or writing the client's own files failed.
    Storage,
}

/// An error of the light client.
#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    message: String,
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl Error {
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            source: None,
        }
    }

    pub(crate) fn with_source(
        kind: ErrorKind,
        message: impl Into<String>,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self {
            kind,
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }

    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// Whether trying again later may succeed.
    pub fn is_retryable(&self) -> bool {
        matches!(self.kind, ErrorKind::Unavailable)
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.source {
            Some(source) => write!(f, "{}: {}", self.message, source),
            None => f.write_str(&self.message),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_ref()
            .map(|s| s.as_ref() as &(dyn std::error::Error + 'static))
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::with_source(ErrorKind::Storage, "storage", e)
    }
}

impl From<crate::p2p::peer::PeerError> for Error {
    fn from(e: crate::p2p::peer::PeerError) -> Self {
        Error::with_source(ErrorKind::Unavailable, "peer request failed", e)
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
