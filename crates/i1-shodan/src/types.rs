//! Shodan-specific types.

use serde::{Deserialize, Serialize};

/// Shodan account information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShodanAccount {
    /// Query credits remaining
    pub query_credits: Option<i64>,
    /// Scan credits remaining
    pub scan_credits: Option<i64>,
    /// Account plan
    pub plan: Option<String>,
    /// Whether the account has HTTPS access
    pub https: Option<bool>,
    /// Whether the account has unlocked access
    pub unlocked: Option<bool>,
    /// Telnet access
    pub telnet: Option<bool>,
}

/// Shodan API info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShodanApiInfo {
    /// Query credits remaining
    pub query_credits: i64,
    /// Scan credits remaining
    pub scan_credits: i64,
    /// Monitored IPs
    pub monitored_ips: Option<i64>,
    /// Plan name
    pub plan: String,
    /// Whether the account has HTTPS access
    pub https: bool,
    /// Whether the account has unlocked access
    pub unlocked: bool,
}
