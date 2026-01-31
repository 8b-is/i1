//! Error types for i1-honeypot.

use thiserror::Error;

/// Errors that can occur in honeypot operations.
#[derive(Debug, Error)]
pub enum HoneypotError {
    /// Serialization error.
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Invalid configuration.
    #[error("Invalid honeypot configuration: {0}")]
    InvalidConfig(String),

    /// Document generation error.
    #[error("Failed to generate document: {0}")]
    DocumentGeneration(String),

    /// IO error.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}
