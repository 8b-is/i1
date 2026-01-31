//! Authentication schemes for different providers.

use serde::{Deserialize, Serialize};

/// Authentication configuration for a provider
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuthConfig {
    /// API key passed as query parameter (Shodan style)
    ApiKeyQuery { key: String, param_name: String },

    /// API key passed in header (X-API-Key style)
    ApiKeyHeader { key: String, header_name: String },

    /// Basic authentication (Censys style)
    Basic { username: String, password: String },

    /// Bearer token (`GreyNoise` style)
    Bearer { token: String },

    /// No authentication (public endpoints)
    None,
}

impl AuthConfig {
    /// Create Shodan-style auth (?key=xxx)
    pub fn shodan(key: impl Into<String>) -> Self {
        Self::ApiKeyQuery {
            key: key.into(),
            param_name: "key".to_string(),
        }
    }

    /// Create Censys-style auth (Basic auth)
    pub fn censys(api_id: impl Into<String>, api_secret: impl Into<String>) -> Self {
        Self::Basic {
            username: api_id.into(),
            password: api_secret.into(),
        }
    }

    /// Create Criminal IP style auth (X-Key header)
    pub fn criminalip(key: impl Into<String>) -> Self {
        Self::ApiKeyHeader {
            key: key.into(),
            header_name: "x-api-key".to_string(),
        }
    }

    /// Create GreyNoise-style auth (Bearer token)
    pub fn greynoise(token: impl Into<String>) -> Self {
        Self::Bearer {
            token: token.into(),
        }
    }

    /// Create i1.is native auth
    pub fn i1_native(token: impl Into<String>) -> Self {
        Self::Bearer {
            token: token.into(),
        }
    }
}

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Requests per second
    pub requests_per_second: f64,
    /// Burst size
    pub burst_size: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_second: 1.0,
            burst_size: 5,
        }
    }
}

impl RateLimitConfig {
    /// Shodan free tier limits
    pub const fn shodan_free() -> Self {
        Self {
            requests_per_second: 1.0,
            burst_size: 1,
        }
    }

    /// Shodan paid tier limits
    pub const fn shodan_paid() -> Self {
        Self {
            requests_per_second: 10.0,
            burst_size: 10,
        }
    }

    /// Censys limits
    pub const fn censys() -> Self {
        Self {
            requests_per_second: 0.4, // 120 per 5 min
            burst_size: 5,
        }
    }

    /// Criminal IP limits
    pub const fn criminalip() -> Self {
        Self {
            requests_per_second: 2.0,
            burst_size: 10,
        }
    }

    /// i1.is native (generous for our own infra)
    pub const fn i1_native() -> Self {
        Self {
            requests_per_second: 100.0,
            burst_size: 50,
        }
    }
}
