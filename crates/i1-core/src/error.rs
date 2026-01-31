use thiserror::Error;

/// Result type alias for i1 operations
pub type Result<T> = std::result::Result<T, I1Error>;

/// Errors that can occur when using i1
#[derive(Error, Debug)]
pub enum I1Error {
    /// Authentication failed - invalid or missing API key
    #[error("authentication failed: invalid API key")]
    Unauthorized,

    /// Rate limit exceeded
    #[error("rate limit exceeded, retry after {retry_after:?} seconds")]
    RateLimited {
        /// Seconds to wait before retrying
        retry_after: Option<u64>,
    },

    /// Insufficient query or scan credits
    #[error("insufficient credits: {required} required, {available} available")]
    InsufficientCredits {
        /// Credits required for the operation
        required: u32,
        /// Credits currently available
        available: u32,
    },

    /// Resource not found
    #[error("resource not found: {resource}")]
    NotFound {
        /// Description of the resource that wasn't found
        resource: String,
    },

    /// Provider API returned an error response
    #[error("{provider} API error ({code}): {message}")]
    Provider {
        /// Provider name
        provider: String,
        /// HTTP status code
        code: u16,
        /// Error message from the API
        message: String,
    },

    /// HTTP request failed
    #[error("HTTP request failed: {0}")]
    Http(String),

    /// Request timed out
    #[error("request timed out after {0} seconds")]
    Timeout(u64),

    /// Connection failed
    #[error("connection failed: {0}")]
    Connection(String),

    /// JSON parsing/serialization error
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Invalid IP address format
    #[error("invalid IP address: {0}")]
    InvalidIp(String),

    /// Invalid query syntax
    #[error("invalid query syntax: {0}")]
    InvalidQuery(String),

    /// Invalid URL
    #[error("invalid URL: {0}")]
    InvalidUrl(String),

    /// Configuration error
    #[error("configuration error: {0}")]
    Config(String),

    /// Port scan failed
    #[error("port scan failed: {0}")]
    Scan(String),

    /// WHOIS lookup failed
    #[error("WHOIS lookup failed: {0}")]
    Whois(String),

    /// DNS resolution failed
    #[error("DNS resolution failed: {0}")]
    Dns(String),

    /// Traceroute failed
    #[error("traceroute failed: {0}")]
    Trace(String),

    /// Provider not configured
    #[error("provider '{0}' is not configured")]
    ProviderNotConfigured(String),

    /// No providers available
    #[error("no providers available for this operation")]
    NoProviders,

    /// Generic internal error
    #[error("internal error: {0}")]
    Internal(String),
}

impl I1Error {
    /// Returns true if the error is retryable
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::RateLimited { .. } | Self::Timeout(_) | Self::Connection(_)
        )
    }

    /// Returns true if the error is due to authentication
    #[must_use]
    pub const fn is_auth_error(&self) -> bool {
        matches!(self, Self::Unauthorized)
    }

    /// Returns the HTTP status code if this is a provider error
    #[must_use]
    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::Unauthorized => Some(401),
            Self::RateLimited { .. } => Some(429),
            Self::NotFound { .. } => Some(404),
            Self::Provider { code, .. } => Some(*code),
            _ => None,
        }
    }

    /// Create a provider error
    pub fn provider(provider: impl Into<String>, code: u16, message: impl Into<String>) -> Self {
        Self::Provider {
            provider: provider.into(),
            code,
            message: message.into(),
        }
    }
}
