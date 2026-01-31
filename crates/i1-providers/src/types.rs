//! Common types shared across providers.

use serde::{Deserialize, Serialize};

/// Provider identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProviderId {
    Shodan,
    Censys,
    CriminalIp,
    GreyNoise,
    Native,
}

impl ProviderId {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Shodan => "shodan",
            Self::Censys => "censys",
            Self::CriminalIp => "criminalip",
            Self::GreyNoise => "greynoise",
            Self::Native => "native",
        }
    }

    pub const fn display_name(&self) -> &'static str {
        match self {
            Self::Shodan => "Shodan",
            Self::Censys => "Censys",
            Self::CriminalIp => "Criminal IP",
            Self::GreyNoise => "GreyNoise",
            Self::Native => "i1.is",
        }
    }
}

impl std::fmt::Display for ProviderId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

/// Result from multiple providers merged together
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergedHostInfo {
    pub ip: String,
    pub sources: Vec<ProviderId>,
    pub hostnames: Vec<String>,
    pub ports: Vec<PortInfo>,
    pub os: Option<String>,
    pub org: Option<String>,
    pub asn: Option<String>,
    pub country: Option<String>,
    pub city: Option<String>,
    pub vulns: Vec<String>,
    pub tags: Vec<String>,
    pub last_seen: Option<chrono::DateTime<chrono::Utc>>,
    /// Provider-specific raw data
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<serde_json::Value>,
}

/// Port information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortInfo {
    pub port: u16,
    pub protocol: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,
}

/// Classification of IP behavior (for GreyNoise-like data)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IpClassification {
    /// Known benign scanner/crawler
    Benign,
    /// Known malicious actor
    Malicious,
    /// Unknown/unclassified
    Unknown,
    /// Part of RIOT dataset (common business services)
    Riot,
}

/// Threat level assessment
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ThreatLevel {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl ThreatLevel {
    pub fn from_cvss(cvss: f32) -> Self {
        match cvss {
            x if x >= 9.0 => Self::Critical,
            x if x >= 7.0 => Self::High,
            x if x >= 4.0 => Self::Medium,
            x if x > 0.0 => Self::Low,
            _ => Self::None,
        }
    }
}
