//! HTTP client infrastructure for i1 security reconnaissance.
//!
//! This crate provides the unified [`I1Client`] that can work with multiple
//! threat intelligence providers simultaneously.

#![doc(html_root_url = "https://docs.rs/i1-client/0.1.0")]

mod client;
mod config;

pub use client::{I1Client, I1ClientBuilder};
pub use config::*;
pub use i1_core::{I1Error, Result};
