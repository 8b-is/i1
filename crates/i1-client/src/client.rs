//! Unified i1 client that aggregates multiple providers.

use std::collections::HashMap;
use std::sync::Arc;

use i1_core::{HostInfo, I1Error, Result};
use i1_providers::{
    HealthStatus, HostLookup, Provider, ProviderHealth, SearchProvider, SearchResults,
};
use tracing::{debug, info, instrument};

/// Unified i1 client that can aggregate multiple providers
pub struct I1Client {
    inner: Arc<I1ClientInner>,
}

struct I1ClientInner {
    providers: HashMap<String, Arc<dyn ProviderBox>>,
    default_provider: Option<String>,
}

/// Trait object wrapper for providers
trait ProviderBox: Provider + HostLookup + SearchProvider + Send + Sync {}
impl<T: Provider + HostLookup + SearchProvider + Send + Sync> ProviderBox for T {}

impl I1Client {
    /// Create a builder for the unified client
    pub fn builder() -> I1ClientBuilder {
        I1ClientBuilder::new()
    }

    /// Get a reference to a specific provider by name
    pub fn provider(&self, name: &str) -> Option<&dyn Provider> {
        self.inner
            .providers
            .get(name)
            .map(|p| p.as_ref() as &dyn Provider)
    }

    /// List all configured provider names
    pub fn providers(&self) -> Vec<&str> {
        self.inner.providers.keys().map(String::as_str).collect()
    }

    /// Check health of all providers
    #[instrument(skip(self))]
    pub async fn health_check_all(&self) -> Vec<ProviderHealth> {
        let mut results = Vec::with_capacity(self.inner.providers.len());

        for (name, provider) in &self.inner.providers {
            debug!(provider = %name, "Checking provider health");
            match provider.health_check().await {
                Ok(health) => results.push(health),
                Err(e) => results.push(ProviderHealth {
                    provider: name.clone(),
                    status: HealthStatus::Unhealthy,
                    latency_ms: None,
                    credits_remaining: None,
                    message: Some(e.to_string()),
                }),
            }
        }

        results
    }

    /// Look up host using default provider
    #[instrument(skip(self))]
    pub async fn lookup_host(&self, ip: &str) -> Result<HostInfo> {
        let provider_name = self
            .inner
            .default_provider
            .as_deref()
            .ok_or(I1Error::NoProviders)?;

        self.lookup_host_with(ip, provider_name).await
    }

    /// Look up host using a specific provider
    #[instrument(skip(self))]
    pub async fn lookup_host_with(&self, ip: &str, provider: &str) -> Result<HostInfo> {
        let provider = self
            .inner
            .providers
            .get(provider)
            .ok_or_else(|| I1Error::ProviderNotConfigured(provider.to_string()))?;

        provider.lookup_host(ip).await
    }

    /// Look up host from all configured providers and merge results
    #[instrument(skip(self))]
    pub async fn lookup_host_all(&self, ip: &str) -> Result<Vec<(String, Result<HostInfo>)>> {
        let mut results = Vec::new();

        for (name, provider) in &self.inner.providers {
            info!(provider = %name, ip = %ip, "Looking up host");
            let result = provider.lookup_host(ip).await;
            results.push((name.clone(), result));
        }

        Ok(results)
    }

    /// Search using default provider
    #[instrument(skip(self))]
    pub async fn search(&self, query: &str, page: Option<u32>) -> Result<SearchResults> {
        let provider_name = self
            .inner
            .default_provider
            .as_deref()
            .ok_or(I1Error::NoProviders)?;

        self.search_with(query, page, provider_name).await
    }

    /// Search using a specific provider
    #[instrument(skip(self))]
    pub async fn search_with(
        &self,
        query: &str,
        page: Option<u32>,
        provider: &str,
    ) -> Result<SearchResults> {
        let provider = self
            .inner
            .providers
            .get(provider)
            .ok_or_else(|| I1Error::ProviderNotConfigured(provider.to_string()))?;

        provider.search(query, page).await
    }

    /// Count results using default provider
    #[instrument(skip(self))]
    pub async fn count(&self, query: &str) -> Result<u64> {
        let provider_name = self
            .inner
            .default_provider
            .as_deref()
            .ok_or(I1Error::NoProviders)?;

        self.count_with(query, provider_name).await
    }

    /// Count results using a specific provider
    #[instrument(skip(self))]
    pub async fn count_with(&self, query: &str, provider: &str) -> Result<u64> {
        let provider = self
            .inner
            .providers
            .get(provider)
            .ok_or_else(|| I1Error::ProviderNotConfigured(provider.to_string()))?;

        provider.count(query).await
    }
}

impl Clone for I1Client {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

/// Builder for the unified i1 client
pub struct I1ClientBuilder {
    providers: HashMap<String, Arc<dyn ProviderBox>>,
    default_provider: Option<String>,
}

impl I1ClientBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            providers: HashMap::new(),
            default_provider: None,
        }
    }

    /// Add a provider to the client
    pub fn with_provider<P>(mut self, provider: P) -> Self
    where
        P: Provider + HostLookup + SearchProvider + Send + Sync + 'static,
    {
        let name = provider.name().to_string();
        if self.default_provider.is_none() {
            self.default_provider = Some(name.clone());
        }
        self.providers.insert(name, Arc::new(provider));
        self
    }

    /// Set the default provider (must be added first)
    pub fn default_provider(mut self, name: impl Into<String>) -> Self {
        self.default_provider = Some(name.into());
        self
    }

    /// Build the client
    pub fn build(self) -> I1Client {
        I1Client {
            inner: Arc::new(I1ClientInner {
                providers: self.providers,
                default_provider: self.default_provider,
            }),
        }
    }
}

impl Default for I1ClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}
