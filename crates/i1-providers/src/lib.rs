//! # i1-providers
//!
//! Provider traits and common types for i1 threat intelligence.
//!
//! This crate defines the core traits that all providers (Shodan, Censys,
//! Criminal IP, i1 Native, etc.) must implement.

use std::net::IpAddr;

use async_trait::async_trait;
use i1_core::{HostInfo, Result};
use serde::{Deserialize, Serialize};

pub mod auth;
pub mod types;

pub use auth::*;
pub use types::*;

/// Core provider trait - all providers must implement this.
#[async_trait]
pub trait Provider: Send + Sync {
    /// Provider name (e.g., "shodan", "censys", "criminalip")
    fn name(&self) -> &'static str;

    /// Provider display name for UI
    fn display_name(&self) -> &'static str;

    /// Base URL for the provider's API
    fn base_url(&self) -> &str;

    /// Check if the provider is configured and ready
    fn is_configured(&self) -> bool;

    /// Test connectivity to the provider
    async fn health_check(&self) -> Result<ProviderHealth>;
}

/// Host lookup capability
#[async_trait]
pub trait HostLookup: Provider {
    /// Look up information about an IP address
    async fn lookup_host(&self, ip: &str) -> Result<HostInfo>;

    /// Look up multiple IPs (batch operation if supported)
    async fn lookup_hosts(&self, ips: &[&str]) -> Result<Vec<HostInfo>> {
        let mut results = Vec::with_capacity(ips.len());
        for ip in ips {
            results.push(self.lookup_host(ip).await?);
        }
        Ok(results)
    }
}

/// Search capability
#[async_trait]
pub trait SearchProvider: Provider {
    /// Search for hosts matching a query
    async fn search(&self, query: &str, page: Option<u32>) -> Result<SearchResults>;

    /// Count results without fetching (saves API credits)
    async fn count(&self, query: &str) -> Result<u64>;

    /// Get available search filters/facets
    async fn filters(&self) -> Result<Vec<String>> {
        Ok(vec![])
    }
}

/// DNS lookup capability
#[async_trait]
pub trait DnsProvider: Provider {
    /// Resolve hostname to IPs
    async fn resolve(&self, hostname: &str) -> Result<Vec<IpAddr>>;

    /// Reverse DNS lookup
    async fn reverse(&self, ip: &str) -> Result<Vec<String>>;

    /// Get domain information (subdomains, records, etc.)
    async fn domain_info(&self, domain: &str) -> Result<DomainInfo>;
}

/// WHOIS lookup capability
#[async_trait]
pub trait WhoisProvider: Provider {
    /// WHOIS lookup for IP or domain
    async fn whois(&self, target: &str) -> Result<WhoisInfo>;
}

/// Vulnerability/CVE lookup capability
#[async_trait]
pub trait VulnProvider: Provider {
    /// Get CVEs associated with an IP
    async fn vulns_for_ip(&self, ip: &str) -> Result<Vec<VulnInfo>>;

    /// Search for hosts with a specific CVE
    async fn hosts_with_cve(&self, cve: &str) -> Result<SearchResults>;
}

/// Provider health status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderHealth {
    pub provider: String,
    pub status: HealthStatus,
    pub latency_ms: Option<u64>,
    pub credits_remaining: Option<i64>,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
    Unconfigured,
}

/// Unified search results across providers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResults {
    pub provider: String,
    pub total: u64,
    pub page: u32,
    pub results: Vec<HostInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub facets: Option<serde_json::Value>,
}

/// Domain information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainInfo {
    pub domain: String,
    pub subdomains: Vec<String>,
    pub records: Vec<DnsRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registrar: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<chrono::DateTime<chrono::Utc>>,
}

/// DNS record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    pub record_type: String,
    pub name: String,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u32>,
}

/// WHOIS information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhoisInfo {
    pub target: String,
    pub raw: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registrar: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cidr: Option<String>,
}

/// Vulnerability information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnInfo {
    pub cve: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cvss: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub references: Option<Vec<String>>,
    pub verified: bool,
}
