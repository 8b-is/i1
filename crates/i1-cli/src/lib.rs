//! # i1-cli
//!
//! Security operations CLI for i1.is - multi-provider threat intelligence.
//!
//! ## Features
//!
//! - **Multi-provider**: Shodan, Censys, Criminal IP, i1.is native
//! - **Host lookup**: IP reconnaissance from multiple sources
//! - **Search**: Query threat intelligence databases
//! - **Defend module**: Geo-blocking, IP banning, firewall rules
//! - **Multiple output formats**: Pretty tables, JSON, CSV

pub mod cli;
pub mod config;
pub mod defend;
pub mod output;

pub use cli::run;
