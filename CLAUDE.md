# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**i1** - Multi-provider security operations CLI for the i1.is platform. Aggregates threat intelligence from multiple sources (Shodan, Censys, Criminal IP) with local reconnaissance tools and defensive capabilities.

## Build Commands

```bash
# Build all crates
cargo build --workspace

# Build release
cargo build --release

# Run tests
cargo test --all

# Lint (strict - must pass before commits)
cargo clippy -- -D warnings

# Format
cargo fmt

# Run the CLI
cargo run -p i1-cli -- --help
./target/release/i1 --help
```

## Architecture

Cargo workspace with multi-provider architecture:

```
crates/
├── i1-core/        # Core types, errors, shared traits
├── i1-client/      # Unified client that aggregates providers
├── i1-providers/   # Provider traits (HostLookup, SearchProvider, etc.)
├── i1-shodan/      # Shodan API provider
├── i1-censys/      # Censys API provider
├── i1-criminalip/  # Criminal IP API provider
├── i1-native/      # i1.is native provider (WHOIS, DNS)
├── i1-recon/       # Local reconnaissance tools (scanner, enrichment)
├── i1/             # Facade crate, re-exports all public API
└── i1-cli/         # CLI binary
```

### Provider Traits (i1-providers)

```rust
#[async_trait]
pub trait Provider: Send + Sync {
    fn name(&self) -> &'static str;
    fn display_name(&self) -> &'static str;
    fn base_url(&self) -> &str;
    fn is_configured(&self) -> bool;
    async fn health_check(&self) -> Result<ProviderHealth>;
}

#[async_trait]
pub trait HostLookup: Provider {
    async fn lookup_host(&self, ip: &str) -> Result<HostInfo>;
}

#[async_trait]
pub trait SearchProvider: Provider {
    async fn search(&self, query: &str, page: Option<u32>) -> Result<SearchResults>;
    async fn count(&self, query: &str) -> Result<u64>;
}

#[async_trait]
pub trait DnsProvider: Provider {
    async fn resolve(&self, hostname: &str) -> Result<Vec<IpAddr>>;
    async fn reverse(&self, ip: &str) -> Result<Vec<String>>;
}
```

### Key Files

- `crates/i1-core/src/types/*.rs` - All shared API response types
- `crates/i1-core/src/error.rs` - I1Error enum
- `crates/i1-providers/src/lib.rs` - Provider traits
- `crates/i1-shodan/src/lib.rs` - Shodan implementation
- `crates/i1-censys/src/lib.rs` - Censys implementation
- `crates/i1-cli/src/cli/args.rs` - Clap command definitions
- `crates/i1-cli/src/cli/commands/*.rs` - Command implementations
- `crates/i1-cli/src/defend/mod.rs` - Firewall rule generation

## CLI (i1)

Security operations CLI with multi-provider support.

```bash
# Basic commands
i1 myip                         # Show your public IP
i1 host 8.8.8.8                 # Look up host (uses Shodan by default)
i1 search "apache port:80"      # Search database
i1 count "nginx"                # Count without credits
i1 dns resolve example.com      # DNS lookup

# Multi-provider
i1 host 8.8.8.8 --all           # Query all providers
i1 host 8.8.8.8 -p censys       # Use specific provider

# Defensive tools
i1 defend status                # Show blocking status
i1 defend geoblock add cn ru    # Block countries
i1 defend ban 1.2.3.4           # Ban IP
i1 defend export --format nft   # Generate firewall rules

# Configuration
i1 config show                  # Show current config
i1 config set shodan-key xxx    # Set Shodan API key
i1 config set censys-id xxx     # Set Censys API ID
i1 config set censys-secret xxx # Set Censys secret
i1 config set criminalip-key xx # Set Criminal IP key
```

## Environment Variables

```bash
# API keys (also settable via config)
SHODAN_API_KEY=xxx       # Shodan API key
I1_SHODAN_KEY=xxx        # Alternative for Shodan
I1_CENSYS_ID=xxx         # Censys API ID
I1_CENSYS_SECRET=xxx     # Censys API secret
I1_CRIMINALIP_KEY=xxx    # Criminal IP API key
```

## Authentication Methods

Each provider uses different authentication:

| Provider    | Auth Method | Configuration |
|-------------|-------------|---------------|
| Shodan      | API key in query param | `?key=xxx` |
| Censys      | HTTP Basic Auth | `username:password` |
| Criminal IP | API key header | `x-api-key: xxx` |
| Native      | None (local) | - |

## Testing

```bash
# Unit tests
cargo test --all

# Live API tests (requires API keys)
SHODAN_API_KEY=xxx cargo test --features live-tests
```

## Notes

- License: MIT OR Apache-2.0
- Min Rust: 1.75+ (async trait stabilization)
- Config stored at: `~/.config/i1/config.toml` (Linux) or platform equivalent
- Uses `reqwest` with rustls for HTTP, `tokio` for async runtime
- Rate limiting per-provider using `governor` crate
