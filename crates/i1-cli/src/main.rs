//! i1 - Security Operations CLI
//!
//! Multi-provider threat intelligence at your fingertips.

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    i1_cli::run().await
}
