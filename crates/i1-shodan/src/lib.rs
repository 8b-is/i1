//! # i1-shodan
//!
//! Shodan provider implementation for i1 threat intelligence.
//!
//! This crate provides access to the [Shodan.io](https://shodan.io) API,
//! implementing the i1 provider traits.
//!
//! # Example
//!
//! ```rust,ignore
//! use i1_shodan::ShodanProvider;
//! use i1_providers::{Provider, HostLookup};
//!
//! let provider = ShodanProvider::new("your-api-key");
//! let host = provider.lookup_host("8.8.8.8").await?;
//! println!("Organization: {:?}", host.org);
//! ```

use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use governor::{Quota, RateLimiter};
use i1_core::{HostInfo, I1Error, Result};
use i1_providers::{
    AuthConfig, DnsProvider, DomainInfo, HealthStatus, HostLookup, Provider, ProviderHealth,
    RateLimitConfig, SearchProvider, SearchResults,
};
use reqwest::Client;
use serde::de::DeserializeOwned;
use std::net::IpAddr;
use std::num::NonZeroU32;
use tracing::{debug, instrument};

mod types;
pub use types::*;

const DEFAULT_BASE_URL: &str = "https://api.shodan.io";

/// Shodan provider for i1
pub struct ShodanProvider {
    inner: Arc<ShodanInner>,
}

struct ShodanInner {
    http: Client,
    api_key: String,
    base_url: String,
    rate_limiter: RateLimiter<
        governor::state::NotKeyed,
        governor::state::InMemoryState,
        governor::clock::DefaultClock,
    >,
}

impl ShodanProvider {
    /// Create a new Shodan provider with the given API key
    pub fn new(api_key: impl Into<String>) -> Self {
        Self::with_config(api_key, RateLimitConfig::shodan_free())
    }

    /// Create with custom rate limit config
    pub fn with_config(api_key: impl Into<String>, rate_limit: RateLimitConfig) -> Self {
        let quota = Quota::per_second(
            NonZeroU32::new(rate_limit.requests_per_second.max(1.0) as u32)
                .unwrap_or(NonZeroU32::MIN),
        )
        .allow_burst(NonZeroU32::new(rate_limit.burst_size).unwrap_or(NonZeroU32::MIN));

        Self {
            inner: Arc::new(ShodanInner {
                http: Client::new(),
                api_key: api_key.into(),
                base_url: DEFAULT_BASE_URL.to_string(),
                rate_limiter: RateLimiter::direct(quota),
            }),
        }
    }

    /// Create with paid tier rate limits
    pub fn paid(api_key: impl Into<String>) -> Self {
        Self::with_config(api_key, RateLimitConfig::shodan_paid())
    }

    /// Get authentication config for this provider
    pub fn auth_config(&self) -> AuthConfig {
        AuthConfig::shodan(&self.inner.api_key)
    }

    /// Make a GET request to the Shodan API
    async fn get<T: DeserializeOwned>(&self, endpoint: &str) -> Result<T> {
        self.get_with_query(endpoint, &[]).await
    }

    /// Make a GET request with query parameters
    #[instrument(skip(self), fields(provider = "shodan"))]
    async fn get_with_query<T: DeserializeOwned>(
        &self,
        endpoint: &str,
        query: &[(&str, &str)],
    ) -> Result<T> {
        // Wait for rate limiter
        self.inner.rate_limiter.until_ready().await;

        let url = format!("{}{}", self.inner.base_url, endpoint);
        debug!(url = %url, "Shodan API request");

        let mut request = self
            .inner
            .http
            .get(&url)
            .query(&[("key", &self.inner.api_key)]);

        if !query.is_empty() {
            request = request.query(query);
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
                401 => Err(I1Error::Unauthorized),
                402 => Err(I1Error::InsufficientCredits {
                    required: 1,
                    available: 0,
                }),
                429 => Err(I1Error::RateLimited { retry_after: None }),
                404 => Err(I1Error::NotFound {
                    resource: endpoint.to_string(),
                }),
                _ => Err(I1Error::provider("shodan", code, message)),
            };
        }

        response
            .json()
            .await
            .map_err(|e| I1Error::Http(e.to_string()))
    }
}

impl Clone for ShodanProvider {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

#[async_trait]
impl Provider for ShodanProvider {
    fn name(&self) -> &'static str {
        "shodan"
    }

    fn display_name(&self) -> &'static str {
        "Shodan"
    }

    fn base_url(&self) -> &str {
        &self.inner.base_url
    }

    fn is_configured(&self) -> bool {
        !self.inner.api_key.is_empty()
    }

    async fn health_check(&self) -> Result<ProviderHealth> {
        let start = Instant::now();

        match self.get::<serde_json::Value>("/api-info").await {
            Ok(info) => {
                let credits = info
                    .get("query_credits")
                    .and_then(serde_json::Value::as_i64);

                Ok(ProviderHealth {
                    provider: "shodan".to_string(),
                    status: HealthStatus::Healthy,
                    latency_ms: Some(start.elapsed().as_millis() as u64),
                    credits_remaining: credits,
                    message: None,
                })
            }
            Err(I1Error::Unauthorized) => Ok(ProviderHealth {
                provider: "shodan".to_string(),
                status: HealthStatus::Unhealthy,
                latency_ms: Some(start.elapsed().as_millis() as u64),
                credits_remaining: None,
                message: Some("Invalid API key".to_string()),
            }),
            Err(e) => Ok(ProviderHealth {
                provider: "shodan".to_string(),
                status: HealthStatus::Unhealthy,
                latency_ms: Some(start.elapsed().as_millis() as u64),
                credits_remaining: None,
                message: Some(e.to_string()),
            }),
        }
    }
}

#[async_trait]
impl HostLookup for ShodanProvider {
    #[instrument(skip(self), fields(provider = "shodan"))]
    async fn lookup_host(&self, ip: &str) -> Result<HostInfo> {
        let endpoint = format!("/shodan/host/{ip}");
        self.get(&endpoint).await
    }
}

#[async_trait]
impl SearchProvider for ShodanProvider {
    #[instrument(skip(self), fields(provider = "shodan"))]
    async fn search(&self, query: &str, page: Option<u32>) -> Result<SearchResults> {
        let page_str = page.unwrap_or(1).to_string();
        let query_params: Vec<(&str, &str)> = vec![("query", query), ("page", &page_str)];

        let response: ShodanSearchResponse = self
            .get_with_query("/shodan/host/search", &query_params)
            .await?;

        // Aggregate matches by IP - search returns one match per service/port,
        // but we want one HostInfo per IP with all ports collected.
        let mut ip_map: std::collections::HashMap<String, HostInfo> =
            std::collections::HashMap::new();

        for m in response.matches {
            let port = m.port;
            let ip_key = m.ip_str.clone();
            let entry = ip_map
                .entry(ip_key)
                .or_insert_with(|| m.into_host_info());
            if !entry.ports.contains(&port) {
                entry.ports.push(port);
            }
        }

        let results: Vec<HostInfo> = ip_map.into_values().collect();

        Ok(SearchResults {
            provider: "shodan".to_string(),
            total: response.total,
            page: page.unwrap_or(1),
            results,
            facets: response.facets,
        })
    }

    #[instrument(skip(self), fields(provider = "shodan"))]
    async fn count(&self, query: &str) -> Result<u64> {
        let response: ShodanCountResponse = self
            .get_with_query("/shodan/host/count", &[("query", query)])
            .await?;

        Ok(response.total)
    }

    async fn filters(&self) -> Result<Vec<String>> {
        let response: Vec<String> = self.get("/shodan/host/search/filters").await?;
        Ok(response)
    }
}

#[async_trait]
impl DnsProvider for ShodanProvider {
    async fn resolve(&self, hostname: &str) -> Result<Vec<IpAddr>> {
        let response: ShodanDnsResolve = self
            .get_with_query("/dns/resolve", &[("hostnames", hostname)])
            .await?;

        Ok(response
            .0
            .values()
            .filter_map(|v| v.as_str())
            .filter_map(|s| s.parse().ok())
            .collect())
    }

    async fn reverse(&self, ip: &str) -> Result<Vec<String>> {
        let response: ShodanDnsReverse =
            self.get_with_query("/dns/reverse", &[("ips", ip)]).await?;

        Ok(response
            .0
            .values()
            .flat_map(|v| {
                v.as_array()
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|s| s.as_str().map(String::from))
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default()
            })
            .collect())
    }

    async fn domain_info(&self, domain: &str) -> Result<DomainInfo> {
        let response: ShodanDomainInfo = self.get(&format!("/dns/domain/{domain}")).await?;

        Ok(DomainInfo {
            domain: response.domain,
            subdomains: response.subdomains,
            records: response
                .data
                .into_iter()
                .map(|r| i1_providers::DnsRecord {
                    record_type: r.record_type,
                    name: r.subdomain.unwrap_or_default(),
                    value: r.value,
                    ttl: None,
                })
                .collect(),
            registrar: None,
            created: None,
            expires: None,
        })
    }
}

// Shodan-specific response types

/// Raw search match from Shodan's /shodan/host/search API.
/// This is different from the /shodan/host/{ip} response - search matches
/// are individual service banners with host info flattened in.
#[derive(Debug, serde::Deserialize)]
struct ShodanSearchMatch {
    #[serde(default)]
    ip_str: String,
    #[serde(default)]
    port: u16,
    #[serde(default)]
    org: Option<String>,
    #[serde(default)]
    isp: Option<String>,
    #[serde(default)]
    asn: Option<String>,
    #[serde(default)]
    hostnames: Vec<String>,
    #[serde(default)]
    domains: Vec<String>,
    #[serde(default)]
    os: Option<String>,
    #[serde(default)]
    product: Option<String>,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    transport: Option<String>,
    #[serde(default)]
    location: Option<ShodanSearchLocation>,
    #[serde(default)]
    data: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    vulns: Option<std::collections::HashMap<String, serde_json::Value>>,
    #[serde(default)]
    http: Option<serde_json::Value>,
    #[serde(default)]
    ssl: Option<serde_json::Value>,
    #[serde(default)]
    ssh: Option<serde_json::Value>,
    #[serde(default, rename = "_shodan")]
    shodan_module: Option<serde_json::Value>,
}

#[derive(Debug, serde::Deserialize)]
struct ShodanSearchLocation {
    #[serde(default)]
    country_code: Option<String>,
    #[serde(default)]
    country_name: Option<String>,
    #[serde(default)]
    city: Option<String>,
    #[serde(default)]
    region_code: Option<String>,
}

impl ShodanSearchMatch {
    fn into_host_info(self) -> HostInfo {
        let location = self.location.unwrap_or(ShodanSearchLocation {
            country_code: None,
            country_name: None,
            city: None,
            region_code: None,
        });

        HostInfo {
            ip: None,
            ip_str: self.ip_str,
            hostnames: self.hostnames,
            domains: self.domains,
            org: self.org,
            asn: self.asn,
            isp: self.isp,
            os: self.os,
            ports: vec![self.port],
            vulns: self
                .vulns
                .map(|v| v.keys().cloned().collect())
                .unwrap_or_default(),
            tags: self.tags,
            location: i1_core::GeoLocation {
                country_code: location.country_code,
                country_name: location.country_name,
                city: location.city,
                region_code: location.region_code,
                postal_code: None,
                latitude: None,
                longitude: None,
                area_code: None,
                dma_code: None,
            },
            data: Vec::new(),
            last_update: None,
        }
    }
}

#[derive(Debug, serde::Deserialize)]
struct ShodanSearchResponse {
    total: u64,
    matches: Vec<ShodanSearchMatch>,
    facets: Option<serde_json::Value>,
}

#[derive(Debug, serde::Deserialize)]
struct ShodanCountResponse {
    total: u64,
}

#[derive(Debug, serde::Deserialize)]
struct ShodanDnsResolve(std::collections::HashMap<String, serde_json::Value>);

#[derive(Debug, serde::Deserialize)]
struct ShodanDnsReverse(std::collections::HashMap<String, serde_json::Value>);

#[derive(Debug, serde::Deserialize)]
struct ShodanDomainInfo {
    domain: String,
    #[serde(default)]
    subdomains: Vec<String>,
    #[serde(default)]
    data: Vec<ShodanDnsRecord>,
}

#[derive(Debug, serde::Deserialize)]
struct ShodanDnsRecord {
    #[serde(rename = "type")]
    record_type: String,
    subdomain: Option<String>,
    value: String,
}
