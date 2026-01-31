//! # i1-criminalip
//!
//! Criminal IP provider implementation for i1 threat intelligence.
//!
//! This crate provides access to the [Criminal IP](https://www.criminalip.io) API,
//! implementing the i1 provider traits.
//!
//! # Example
//!
//! ```rust,ignore
//! use i1_criminalip::CriminalIpProvider;
//! use i1_providers::{Provider, HostLookup};
//!
//! let provider = CriminalIpProvider::new("your-api-key");
//! let host = provider.lookup_host("8.8.8.8").await?;
//! println!("Risk score: {:?}", host.tags);
//! ```

use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use governor::{Quota, RateLimiter};
use i1_core::{GeoLocation, HostInfo, I1Error, Result, Service};
use i1_providers::{
    AuthConfig, HealthStatus, HostLookup, Provider, ProviderHealth, RateLimitConfig,
    SearchProvider, SearchResults,
};
use reqwest::Client;
use serde::Deserialize;
use std::num::NonZeroU32;
use tracing::{debug, instrument};

const DEFAULT_BASE_URL: &str = "https://api.criminalip.io/v1";

/// Criminal IP provider for i1
pub struct CriminalIpProvider {
    inner: Arc<CriminalIpInner>,
}

struct CriminalIpInner {
    http: Client,
    api_key: String,
    base_url: String,
    rate_limiter: RateLimiter<
        governor::state::NotKeyed,
        governor::state::InMemoryState,
        governor::clock::DefaultClock,
    >,
}

impl CriminalIpProvider {
    /// Create a new Criminal IP provider with the given API key
    pub fn new(api_key: impl Into<String>) -> Self {
        Self::with_config(api_key, RateLimitConfig::criminalip())
    }

    /// Create with custom rate limit config
    pub fn with_config(api_key: impl Into<String>, rate_limit: RateLimitConfig) -> Self {
        let quota = Quota::per_second(
            NonZeroU32::new(rate_limit.requests_per_second.max(1.0) as u32)
                .unwrap_or(NonZeroU32::MIN),
        )
        .allow_burst(NonZeroU32::new(rate_limit.burst_size).unwrap_or(NonZeroU32::MIN));

        Self {
            inner: Arc::new(CriminalIpInner {
                http: Client::new(),
                api_key: api_key.into(),
                base_url: DEFAULT_BASE_URL.to_string(),
                rate_limiter: RateLimiter::direct(quota),
            }),
        }
    }

    /// Get authentication config for this provider
    pub fn auth_config(&self) -> AuthConfig {
        AuthConfig::criminalip(&self.inner.api_key)
    }

    /// Make a GET request to the Criminal IP API
    #[instrument(skip(self), fields(provider = "criminalip"))]
    async fn get<T: serde::de::DeserializeOwned>(&self, endpoint: &str) -> Result<T> {
        self.inner.rate_limiter.until_ready().await;

        let url = format!("{}{}", self.inner.base_url, endpoint);
        debug!(url = %url, "Criminal IP API request");

        let response = self
            .inner
            .http
            .get(&url)
            .header("x-api-key", &self.inner.api_key)
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
                _ => Err(I1Error::provider("criminalip", code, message)),
            };
        }

        response
            .json()
            .await
            .map_err(|e| I1Error::Http(e.to_string()))
    }

    /// Convert Criminal IP response to i1 `HostInfo`
    fn convert_host(host: CriminalIpHost) -> HostInfo {
        let services: Vec<Service> = host
            .port
            .into_iter()
            .map(|p| Service {
                port: p.open_port_no as u16,
                transport: i1_core::Transport::Tcp,
                product: p.app_name,
                version: p.app_version,
                cpe: vec![],
                data: p.banner,
                timestamp: None,
                shodan_module: None,
                http: None,
                ssl: None,
                ssh: None,
                vulns: std::collections::HashMap::new(),
                tags: vec![],
                devicetype: None,
                info: None,
                os: None,
            })
            .collect();

        let ports: Vec<u16> = services.iter().map(|s| s.port).collect();

        // Build tags from risk scores
        let mut tags = vec![];
        if let Some(score) = &host.score {
            if score.inbound > 50.0 {
                tags.push(format!("risk:inbound:{:.0}", score.inbound));
            }
            if score.outbound > 50.0 {
                tags.push(format!("risk:outbound:{:.0}", score.outbound));
            }
        }
        if host.is_vpn == Some(true) {
            tags.push("vpn".to_string());
        }
        if host.is_proxy == Some(true) {
            tags.push("proxy".to_string());
        }
        if host.is_tor == Some(true) {
            tags.push("tor".to_string());
        }
        if host.is_hosting == Some(true) {
            tags.push("hosting".to_string());
        }

        HostInfo {
            ip: host.ip.parse().ok(),
            ip_str: host.ip,
            hostnames: host.hostname.map(|h| vec![h]).unwrap_or_default(),
            domains: vec![],
            org: host.org_name,
            asn: host.as_no.map(|n| format!("AS{n}")),
            isp: host.isp,
            os: None,
            ports,
            vulns: host
                .vulnerability
                .map(|v| v.into_iter().map(|vuln| vuln.cve_id).collect())
                .unwrap_or_default(),
            tags,
            location: GeoLocation {
                country_code: host.country_code,
                country_name: host.country,
                city: host.city,
                latitude: host.latitude,
                longitude: host.longitude,
                ..Default::default()
            },
            data: services,
            last_update: None,
        }
    }
}

impl Clone for CriminalIpProvider {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

#[async_trait]
impl Provider for CriminalIpProvider {
    fn name(&self) -> &'static str {
        "criminalip"
    }

    fn display_name(&self) -> &'static str {
        "Criminal IP"
    }

    fn base_url(&self) -> &str {
        &self.inner.base_url
    }

    fn is_configured(&self) -> bool {
        !self.inner.api_key.is_empty()
    }

    async fn health_check(&self) -> Result<ProviderHealth> {
        let start = Instant::now();

        // Criminal IP doesn't have a dedicated health endpoint, use a simple IP lookup
        match self.get::<serde_json::Value>("/user/me").await {
            Ok(info) => {
                let credits = info
                    .get("data")
                    .and_then(|d| d.get("credit"))
                    .and_then(serde_json::Value::as_i64);

                Ok(ProviderHealth {
                    provider: "criminalip".to_string(),
                    status: HealthStatus::Healthy,
                    latency_ms: Some(start.elapsed().as_millis() as u64),
                    credits_remaining: credits,
                    message: None,
                })
            }
            Err(I1Error::Unauthorized) => Ok(ProviderHealth {
                provider: "criminalip".to_string(),
                status: HealthStatus::Unhealthy,
                latency_ms: Some(start.elapsed().as_millis() as u64),
                credits_remaining: None,
                message: Some("Invalid API key".to_string()),
            }),
            Err(e) => Ok(ProviderHealth {
                provider: "criminalip".to_string(),
                status: HealthStatus::Unhealthy,
                latency_ms: Some(start.elapsed().as_millis() as u64),
                credits_remaining: None,
                message: Some(e.to_string()),
            }),
        }
    }
}

#[async_trait]
impl HostLookup for CriminalIpProvider {
    #[instrument(skip(self), fields(provider = "criminalip"))]
    async fn lookup_host(&self, ip: &str) -> Result<HostInfo> {
        let response: CriminalIpResponse = self.get(&format!("/asset/ip/report?ip={ip}")).await?;

        if response.status != 200 {
            return Err(I1Error::provider(
                "criminalip",
                response.status as u16,
                response.message.unwrap_or_default(),
            ));
        }

        Ok(Self::convert_host(response.data))
    }
}

#[async_trait]
impl SearchProvider for CriminalIpProvider {
    #[instrument(skip(self), fields(provider = "criminalip"))]
    async fn search(&self, query: &str, page: Option<u32>) -> Result<SearchResults> {
        let offset = page.map_or(0, |p| (p - 1) * 10);
        let response: CriminalIpSearchResponse = self
            .get(&format!("/banner/search?query={query}&offset={offset}"))
            .await?;

        if response.status != 200 {
            return Err(I1Error::provider(
                "criminalip",
                response.status as u16,
                response.message.unwrap_or_default(),
            ));
        }

        let results: Vec<HostInfo> = response
            .data
            .result
            .into_iter()
            .map(|r| HostInfo {
                ip: r.ip_address.parse().ok(),
                ip_str: r.ip_address,
                hostnames: vec![],
                domains: vec![],
                org: r.org_name,
                asn: r.as_no.map(|n| format!("AS{n}")),
                isp: None,
                os: None,
                ports: vec![r.open_port_no as u16],
                vulns: vec![],
                tags: vec![],
                location: GeoLocation {
                    country_code: r.country_code,
                    country_name: r.country,
                    city: r.city,
                    ..Default::default()
                },
                data: vec![],
                last_update: None,
            })
            .collect();

        Ok(SearchResults {
            provider: "criminalip".to_string(),
            total: response.data.count as u64,
            page: page.unwrap_or(1),
            results,
            facets: None,
        })
    }

    #[instrument(skip(self), fields(provider = "criminalip"))]
    async fn count(&self, query: &str) -> Result<u64> {
        let response: CriminalIpSearchResponse = self
            .get(&format!("/banner/search?query={query}&offset=0"))
            .await?;

        if response.status != 200 {
            return Err(I1Error::provider(
                "criminalip",
                response.status as u16,
                response.message.unwrap_or_default(),
            ));
        }

        Ok(response.data.count as u64)
    }
}

// Criminal IP specific types
#[derive(Debug, Deserialize)]
struct CriminalIpResponse {
    status: i32,
    message: Option<String>,
    data: CriminalIpHost,
}

#[derive(Debug, Deserialize)]
struct CriminalIpHost {
    ip: String,
    #[serde(default)]
    hostname: Option<String>,
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    country_code: Option<String>,
    #[serde(default)]
    city: Option<String>,
    #[serde(default)]
    latitude: Option<f64>,
    #[serde(default)]
    longitude: Option<f64>,
    #[serde(default)]
    isp: Option<String>,
    #[serde(default)]
    org_name: Option<String>,
    #[serde(default)]
    as_no: Option<u32>,
    #[serde(default)]
    score: Option<CriminalIpScore>,
    #[serde(default)]
    is_vpn: Option<bool>,
    #[serde(default)]
    is_proxy: Option<bool>,
    #[serde(default)]
    is_tor: Option<bool>,
    #[serde(default)]
    is_hosting: Option<bool>,
    #[serde(default)]
    port: Vec<CriminalIpPort>,
    #[serde(default)]
    vulnerability: Option<Vec<CriminalIpVuln>>,
}

#[derive(Debug, Deserialize)]
struct CriminalIpScore {
    inbound: f64,
    outbound: f64,
}

#[derive(Debug, Deserialize)]
struct CriminalIpPort {
    open_port_no: i32,
    #[serde(default)]
    app_name: Option<String>,
    #[serde(default)]
    app_version: Option<String>,
    #[serde(default)]
    banner: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CriminalIpVuln {
    cve_id: String,
}

#[derive(Debug, Deserialize)]
struct CriminalIpSearchResponse {
    status: i32,
    message: Option<String>,
    data: CriminalIpSearchData,
}

#[derive(Debug, Deserialize)]
struct CriminalIpSearchData {
    count: i64,
    #[serde(default)]
    result: Vec<CriminalIpSearchResult>,
}

#[derive(Debug, Deserialize)]
struct CriminalIpSearchResult {
    ip_address: String,
    open_port_no: i32,
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    country_code: Option<String>,
    #[serde(default)]
    city: Option<String>,
    #[serde(default)]
    org_name: Option<String>,
    #[serde(default)]
    as_no: Option<u32>,
}
