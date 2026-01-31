//! # i1-native
//!
//! i1.is native provider - caching layer and standard lookups.
//!
//! This crate provides:
//! - Caching layer for all other providers
//! - Direct WHOIS lookups
//! - DNS resolution
//! - The i1.is API backend
//!
//! # Example
//!
//! ```rust,ignore
//! use i1_native::NativeProvider;
//! use i1_providers::{Provider, HostLookup, WhoisProvider};
//!
//! let provider = NativeProvider::new("your-i1-token");
//!
//! // Check cache first, then query i1.is backend
//! let host = provider.lookup_host("8.8.8.8").await?;
//!
//! // Direct WHOIS lookup (no external API needed)
//! let whois = provider.whois("8.8.8.8").await?;
//! ```

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use i1_core::{GeoLocation, HostInfo, I1Error, Result};
use i1_providers::{
    AuthConfig, DnsProvider, DnsRecord, DomainInfo, HealthStatus, HostLookup, Provider,
    ProviderHealth, SearchProvider, SearchResults, WhoisInfo, WhoisProvider,
};
use reqwest::Client;
use serde::Deserialize;
use tracing::{debug, instrument};

const DEFAULT_BASE_URL: &str = "https://api.i1.is/v1";

/// i1.is native provider
pub struct NativeProvider {
    inner: Arc<NativeInner>,
}

struct NativeInner {
    http: Client,
    token: Option<String>,
    base_url: String,
}

impl NativeProvider {
    /// Create a new native provider (unauthenticated - limited access)
    pub fn anonymous() -> Self {
        Self {
            inner: Arc::new(NativeInner {
                http: Client::new(),
                token: None,
                base_url: DEFAULT_BASE_URL.to_string(),
            }),
        }
    }

    /// Create a new native provider with i1.is token
    pub fn new(token: impl Into<String>) -> Self {
        Self {
            inner: Arc::new(NativeInner {
                http: Client::new(),
                token: Some(token.into()),
                base_url: DEFAULT_BASE_URL.to_string(),
            }),
        }
    }

    /// Create with custom base URL (for self-hosted)
    pub fn with_url(token: impl Into<String>, base_url: impl Into<String>) -> Self {
        Self {
            inner: Arc::new(NativeInner {
                http: Client::new(),
                token: Some(token.into()),
                base_url: base_url.into(),
            }),
        }
    }

    /// Get authentication config
    pub fn auth_config(&self) -> AuthConfig {
        match &self.inner.token {
            Some(token) => AuthConfig::i1_native(token),
            None => AuthConfig::None,
        }
    }

    /// Make a GET request to the i1.is API
    #[instrument(skip(self), fields(provider = "native"))]
    async fn get<T: serde::de::DeserializeOwned>(&self, endpoint: &str) -> Result<T> {
        let url = format!("{}{}", self.inner.base_url, endpoint);
        debug!(url = %url, "i1.is API request");

        let mut request = self.inner.http.get(&url);
        if let Some(token) = &self.inner.token {
            request = request.bearer_auth(token);
        }

        let response = request
            .send()
            .await
            .map_err(|e| I1Error::Http(e.to_string()))?;

        let status = response.status();
        if !status.is_success() {
            let code = status.as_u16();
            let message = response.text().await.unwrap_or_default();

            return match code {
                401 | 403 => Err(I1Error::Unauthorized),
                429 => Err(I1Error::RateLimited { retry_after: None }),
                404 => Err(I1Error::NotFound {
                    resource: endpoint.to_string(),
                }),
                _ => Err(I1Error::provider("i1.is", code, message)),
            };
        }

        response
            .json()
            .await
            .map_err(|e| I1Error::Http(e.to_string()))
    }

    /// Perform a direct WHOIS lookup (local, no API)
    #[instrument(skip(self), fields(provider = "native"))]
    async fn whois_local(&self, target: &str) -> Result<WhoisInfo> {
        // Use whois-rs for local lookups
        let raw = tokio::task::spawn_blocking({
            let target = target.to_string();
            move || {
                let whois = whois_rs::WhoIs::from_string(&target)?;
                let options = whois_rs::WhoIsLookupOptions::from_string(&target)?;
                whois.lookup(options)
            }
        })
        .await
        .map_err(|e| I1Error::Internal(e.to_string()))?
        .map_err(|e| I1Error::Whois(e.to_string()))?;

        // Parse some common fields from the raw response
        let mut org = None;
        let mut country = None;
        let mut asn = None;
        let mut cidr = None;
        let mut registrar = None;

        for line in raw.lines() {
            let line_lower = line.to_lowercase();
            if line_lower.starts_with("orgname:") || line_lower.starts_with("org-name:") {
                org = Some(line.split(':').nth(1).unwrap_or("").trim().to_string());
            } else if line_lower.starts_with("country:") {
                country = Some(line.split(':').nth(1).unwrap_or("").trim().to_string());
            } else if line_lower.starts_with("originas:") || line_lower.starts_with("origin:") {
                asn = Some(line.split(':').nth(1).unwrap_or("").trim().to_string());
            } else if line_lower.starts_with("cidr:") || line_lower.starts_with("inetnum:") {
                cidr = Some(line.split(':').nth(1).unwrap_or("").trim().to_string());
            } else if line_lower.starts_with("registrar:") {
                registrar = Some(line.split(':').nth(1).unwrap_or("").trim().to_string());
            }
        }

        Ok(WhoisInfo {
            target: target.to_string(),
            raw,
            registrar,
            org,
            country,
            asn,
            cidr,
        })
    }

    /// Perform a DNS resolution (local)
    #[instrument(skip(self), fields(provider = "native"))]
    async fn dns_resolve_local(&self, hostname: &str) -> Result<Vec<IpAddr>> {
        // Use tokio's built-in DNS for simplicity
        let addrs = tokio::net::lookup_host(format!("{hostname}:0"))
            .await
            .map_err(|e| I1Error::Dns(e.to_string()))?;

        Ok(addrs.map(|addr| addr.ip()).collect())
    }

    /// Perform reverse DNS (local)
    #[instrument(skip(self), fields(provider = "native"))]
    async fn dns_reverse_local(&self, ip: &str) -> Result<Vec<String>> {
        let _ip_addr: IpAddr = ip.parse().map_err(|_| I1Error::InvalidIp(ip.to_string()))?;
        // TODO: Implement proper reverse DNS when hickory-resolver API stabilizes
        // For now, return empty - the i1.is API will handle reverse DNS
        Ok(vec![])
    }
}

impl Clone for NativeProvider {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

#[async_trait]
impl Provider for NativeProvider {
    fn name(&self) -> &'static str {
        "native"
    }

    fn display_name(&self) -> &'static str {
        "i1.is"
    }

    fn base_url(&self) -> &str {
        &self.inner.base_url
    }

    fn is_configured(&self) -> bool {
        // Native provider works even without token (limited access)
        true
    }

    async fn health_check(&self) -> Result<ProviderHealth> {
        let start = Instant::now();

        // Check if i1.is API is reachable
        match self.get::<serde_json::Value>("/health").await {
            Ok(_) => Ok(ProviderHealth {
                provider: "native".to_string(),
                status: HealthStatus::Healthy,
                latency_ms: Some(start.elapsed().as_millis() as u64),
                credits_remaining: None,
                message: None,
            }),
            Err(I1Error::NotFound { .. }) => {
                // API doesn't have /health, but it responded - that's healthy enough
                Ok(ProviderHealth {
                    provider: "native".to_string(),
                    status: HealthStatus::Healthy,
                    latency_ms: Some(start.elapsed().as_millis() as u64),
                    credits_remaining: None,
                    message: None,
                })
            }
            Err(e) => Ok(ProviderHealth {
                provider: "native".to_string(),
                status: HealthStatus::Degraded,
                latency_ms: Some(start.elapsed().as_millis() as u64),
                credits_remaining: None,
                message: Some(format!("API unreachable, local lookups available: {e}")),
            }),
        }
    }
}

#[async_trait]
impl HostLookup for NativeProvider {
    #[instrument(skip(self), fields(provider = "native"))]
    async fn lookup_host(&self, ip: &str) -> Result<HostInfo> {
        // Try i1.is cache first
        match self.get::<I1HostResponse>(&format!("/host/{ip}")).await {
            Ok(response) => Ok(response.data),
            Err(I1Error::NotFound { .. }) => {
                // Not in cache - return minimal info from local lookups
                let whois = self.whois_local(ip).await.ok();
                let hostnames = self.dns_reverse_local(ip).await.unwrap_or_default();

                Ok(HostInfo {
                    ip: ip.parse().ok(),
                    ip_str: ip.to_string(),
                    hostnames,
                    domains: vec![],
                    org: whois.as_ref().and_then(|w| w.org.clone()),
                    asn: whois.as_ref().and_then(|w| w.asn.clone()),
                    isp: None,
                    os: None,
                    ports: vec![],
                    vulns: vec![],
                    tags: vec!["uncached".to_string()],
                    location: GeoLocation {
                        country_code: whois.as_ref().and_then(|w| w.country.clone()),
                        ..Default::default()
                    },
                    data: vec![],
                    last_update: None,
                })
            }
            Err(e) => Err(e),
        }
    }
}

#[async_trait]
impl SearchProvider for NativeProvider {
    #[instrument(skip(self), fields(provider = "native"))]
    async fn search(&self, query: &str, page: Option<u32>) -> Result<SearchResults> {
        let page_num = page.unwrap_or(1);
        let response: I1SearchResponse = self
            .get(&format!("/search?q={query}&page={page_num}"))
            .await?;

        Ok(SearchResults {
            provider: "native".to_string(),
            total: response.total,
            page: page_num,
            results: response.results,
            facets: None,
        })
    }

    #[instrument(skip(self), fields(provider = "native"))]
    async fn count(&self, query: &str) -> Result<u64> {
        let response: I1CountResponse = self.get(&format!("/count?q={query}")).await?;
        Ok(response.count)
    }
}

#[async_trait]
impl DnsProvider for NativeProvider {
    async fn resolve(&self, hostname: &str) -> Result<Vec<IpAddr>> {
        self.dns_resolve_local(hostname).await
    }

    async fn reverse(&self, ip: &str) -> Result<Vec<String>> {
        self.dns_reverse_local(ip).await
    }

    async fn domain_info(&self, domain: &str) -> Result<DomainInfo> {
        // Try API first
        match self
            .get::<I1DomainResponse>(&format!("/domain/{domain}"))
            .await
        {
            Ok(response) => Ok(response.data),
            Err(I1Error::NotFound { .. }) => {
                // Fallback to basic DNS lookup
                let ips = self.dns_resolve_local(domain).await.unwrap_or_default();

                Ok(DomainInfo {
                    domain: domain.to_string(),
                    subdomains: vec![],
                    records: ips
                        .into_iter()
                        .map(|ip| DnsRecord {
                            record_type: if ip.is_ipv4() { "A" } else { "AAAA" }.to_string(),
                            name: domain.to_string(),
                            value: ip.to_string(),
                            ttl: None,
                        })
                        .collect(),
                    registrar: None,
                    created: None,
                    expires: None,
                })
            }
            Err(e) => Err(e),
        }
    }
}

#[async_trait]
impl WhoisProvider for NativeProvider {
    async fn whois(&self, target: &str) -> Result<WhoisInfo> {
        // Always use local WHOIS - it's fast and doesn't cost API credits
        self.whois_local(target).await
    }
}

// i1.is API response types
#[derive(Debug, Deserialize)]
struct I1HostResponse {
    data: HostInfo,
}

#[derive(Debug, Deserialize)]
struct I1SearchResponse {
    total: u64,
    results: Vec<HostInfo>,
}

#[derive(Debug, Deserialize)]
struct I1CountResponse {
    count: u64,
}

#[derive(Debug, Deserialize)]
struct I1DomainResponse {
    data: DomainInfo,
}
