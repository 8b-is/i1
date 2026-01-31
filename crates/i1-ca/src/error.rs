//! Error types for i1-ca.

use thiserror::Error;

/// Errors that can occur in CA operations.
#[derive(Debug, Error)]
pub enum CaError {
    /// Key generation failed.
    #[error("Key generation failed: {0}")]
    KeyGeneration(String),

    /// Certificate signing failed.
    #[error("Certificate signing failed: {0}")]
    Signing(String),

    /// Certificate parsing failed.
    #[error("Certificate parsing failed: {0}")]
    Parsing(String),

    /// Invalid certificate chain.
    #[error("Invalid certificate chain: {0}")]
    InvalidChain(String),

    /// Certificate has been revoked.
    #[error("Certificate revoked: {0}")]
    Revoked(String),

    /// Certificate has expired.
    #[error("Certificate expired")]
    Expired,

    /// Certificate not yet valid.
    #[error("Certificate not yet valid")]
    NotYetValid,

    /// IO error.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// PEM encoding/decoding error.
    #[error("PEM error: {0}")]
    Pem(String),

    /// Certificate generation error from rcgen.
    #[error("Certificate generation error: {0}")]
    RcGen(String),
}

impl From<rcgen::Error> for CaError {
    fn from(e: rcgen::Error) -> Self {
        CaError::RcGen(e.to_string())
    }
}
