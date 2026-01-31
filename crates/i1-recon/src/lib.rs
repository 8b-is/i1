//! Local network reconnaissance tools for i1.
//!
//! This crate provides optional integrations with network security tools
//! that run locally without requiring external API calls.

#![doc(html_root_url = "https://docs.rs/i1-recon/0.1.0")]

mod error;

#[cfg(feature = "scanner")]
pub mod scanner;

#[cfg(feature = "whois")]
pub mod whois;

// Temporarily disabled due to API changes
// #[cfg(feature = "dns")]
// pub mod dns;

// #[cfg(feature = "trace")]
// pub mod trace;

pub mod enrichment;

pub use error::{ReconError, ReconResult};
