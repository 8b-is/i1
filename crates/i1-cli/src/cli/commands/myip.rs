//! `i1 myip` - Show your public IP address.

use anyhow::Result;
use colored::Colorize;

use super::Context;
use crate::output::OutputFormat;

pub async fn execute(ctx: Context) -> Result<()> {
    // Use a simple HTTP request to get public IP (no API key needed)
    let client = reqwest::Client::new();
    let ip = client
        .get("https://api.ipify.org")
        .send()
        .await?
        .text()
        .await?;

    let ip = ip.trim();

    match ctx.output_format {
        OutputFormat::Json => {
            println!("{{\"ip\":\"{ip}\"}}");
        }
        OutputFormat::Csv => {
            println!("ip");
            println!("{ip}");
        }
        OutputFormat::Yaml => {
            println!("ip: {ip}");
        }
        OutputFormat::Pretty => {
            if ctx.no_color {
                println!("Your IP: {ip}");
            } else {
                println!("Your IP: {}", ip.cyan().bold());
            }
        }
    }

    Ok(())
}
