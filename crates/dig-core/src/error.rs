//! Error types for dig-core

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Result type alias for dig operations
pub type Result<T> = std::result::Result<T, DigError>;

/// Comprehensive error type for DNS operations
#[derive(Error, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum DigError {
    #[error("DNS query failed: {0}")]
    QueryFailed(String),

    #[error("Connection timeout after {0}ms")]
    Timeout(u64),

    #[error("Failed to parse domain name: {0}")]
    InvalidDomain(String),

    #[error("Failed to parse IP address: {0}")]
    InvalidIpAddress(String),

    #[error("DNS server returned error: {0}")]
    ServerError(String),

    #[error("No DNS servers configured")]
    NoServersConfigured,

    #[error("Record type not supported: {0}")]
    UnsupportedRecordType(String),

    #[error("DNSSEC validation failed: {0}")]
    DnssecValidationFailed(String),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Protocol error: {0}")]
    ProtocolError(String),

    #[error("No records found for {0}")]
    NoRecordsFound(String),

    #[error("Trace failed: {0}")]
    TraceFailed(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),
}

impl DigError {
    /// Get the exit code for this error
    pub fn exit_code(&self) -> i32 {
        match self {
            DigError::NoRecordsFound(_) => 1,
            DigError::Timeout(_) => 2,
            DigError::QueryFailed(_) => 3,
            DigError::ServerError(_) => 4,
            DigError::DnssecValidationFailed(_) => 5,
            _ => 10,
        }
    }
}

impl From<std::io::Error> for DigError {
    fn from(err: std::io::Error) -> Self {
        DigError::NetworkError(err.to_string())
    }
}

impl From<crate::tsig::TsigError> for DigError {
    fn from(err: crate::tsig::TsigError) -> Self {
        DigError::ConfigError(format!("TSIG error: {}", err))
    }
}

impl From<crate::edns::EdnsError> for DigError {
    fn from(err: crate::edns::EdnsError) -> Self {
        DigError::ConfigError(format!("EDNS error: {}", err))
    }
}
