//! # i1 - Unified Security Reconnaissance Toolkit
//!
//! Multi-provider threat intelligence made easy.
//!
//! # Quick Start
//!
//! ```rust,ignore
//! use i1::prelude::*;
//!
//! #[tokio::main]
//! async fn main() -> i1::Result<()> {
//!     // Single provider (Shodan)
//!     let shodan = ShodanProvider::new("your-shodan-key");
//!     let host = shodan.lookup_host("8.8.8.8").await?;
//!     println!("Organization: {:?}", host.org);
//!
//!     // Multi-provider client
//!     let client = I1Client::builder()
//!         .with_provider(ShodanProvider::new("shodan-key"))
//!         .with_provider(CensysProvider::new("censys-id", "censys-secret"))
//!         .build();
//!
//!     // Query all providers
//!     let results = client.lookup_host_all("8.8.8.8").await?;
//!     for (provider, result) in results {
//!         println!("{}: {:?}", provider, result.map(|h| h.org));
//!     }
//!
//!     Ok(())
//! }
//! ```
//!
//! # Providers
//!
//! - **Shodan** - `i1-shodan` - Internet-wide scanning data
//! - **Censys** - `i1-censys` - Certificate and host data
//! - **Criminal IP** - `i1-criminalip` - Threat intelligence
//! - **Native** - `i1-native` - i1.is caching layer + WHOIS/DNS
//!
//! # Features
//!
//! - `default` - Uses rustls TLS + Shodan provider
//! - `shodan` - Enable Shodan provider
//! - `censys` - Enable Censys provider
//! - `criminalip` - Enable Criminal IP provider
//! - `native` - Enable i1.is native provider
//! - `all-providers` - Enable all providers
//! - `recon` - Enable local reconnaissance tools
//! - `scanner` - Enable port scanning
//! - `whois` - Enable WHOIS lookups
//! - `full-recon` - Enable all local recon tools

#![doc(html_root_url = "https://docs.rs/i1/0.1.0")]

// Re-export core types
pub use i1_core::*;

// Re-export provider traits
pub use i1_providers::{
    DnsProvider, DomainInfo, HealthStatus, HostLookup, Provider, ProviderHealth, RateLimitConfig,
    SearchProvider, SearchResults, VulnInfo, VulnProvider, WhoisInfo, WhoisProvider,
};

// Re-export unified client
pub use i1_client::{I1Client, I1ClientBuilder};

// Re-export providers
#[cfg(feature = "shodan")]
pub use i1_shodan::ShodanProvider;

#[cfg(feature = "censys")]
pub use i1_censys::CensysProvider;

#[cfg(feature = "criminalip")]
pub use i1_criminalip::CriminalIpProvider;

#[cfg(feature = "native")]
pub use i1_native::NativeProvider;

// Re-export recon if enabled
#[cfg(feature = "recon")]
pub use i1_recon as recon;

// Re-export runtime for convenience
pub use async_trait::async_trait;
pub use serde;
pub use serde_json;
pub use tokio;

/// Prelude module for convenient imports
pub mod prelude {
    pub use crate::{I1Client, I1ClientBuilder, Result};
    pub use i1_providers::{
        DnsProvider, HostLookup, Provider, ProviderHealth, SearchProvider, WhoisProvider,
    };

    #[cfg(feature = "shodan")]
    pub use i1_shodan::ShodanProvider;

    #[cfg(feature = "censys")]
    pub use i1_censys::CensysProvider;

    #[cfg(feature = "criminalip")]
    pub use i1_criminalip::CriminalIpProvider;

    #[cfg(feature = "native")]
    pub use i1_native::NativeProvider;
}
