//! Core types and traits for i1 security reconnaissance.
//!
//! This crate provides the foundational types used across the i1 library:
//!
//! - **Types**: Strongly-typed representations of threat intelligence data
//! - **Errors**: Comprehensive error handling with [`I1Error`]
//!
//! # Example
//!
//! ```rust,ignore
//! use i1_core::{HostInfo, I1Error, Result};
//!
//! fn process_host(host: HostInfo) -> Result<()> {
//!     println!("IP: {}", host.ip_str);
//!     println!("Ports: {:?}", host.ports);
//!     Ok(())
//! }
//! ```

#![doc(html_root_url = "https://docs.rs/i1-core/0.1.0")]

mod error;
pub mod types;

pub use error::{I1Error, Result};
pub use types::*;
