//! `i1 dns` - DNS lookups.

use anyhow::Result;
use colored::Colorize;

use super::Context;
use crate::cli::args::{DnsArgs, DnsCommands};
use crate::output::OutputFormat;
use i1_providers::DnsProvider;

pub async fn execute(ctx: Context, args: DnsArgs) -> Result<()> {
    let provider = ctx.shodan_provider()?;

    match args.command {
        DnsCommands::Resolve { hostname } => {
            let ips = provider.resolve(&hostname).await?;

            match ctx.output_format {
                OutputFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&ips)?);
                }
                OutputFormat::Yaml => {
                    println!("{}", serde_yaml::to_string(&ips)?);
                }
                OutputFormat::Csv => {
                    println!("hostname,ip");
                    for ip in &ips {
                        println!("{hostname},{ip}");
                    }
                }
                OutputFormat::Pretty => {
                    if ctx.no_color {
                        println!("{hostname}");
                    } else {
                        println!("{}", hostname.green());
                    }
                    for ip in &ips {
                        println!("  -> {ip}");
                    }
                }
            }
        }
        DnsCommands::Reverse { ip } => {
            let hostnames = provider.reverse(&ip).await?;

            match ctx.output_format {
                OutputFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&hostnames)?);
                }
                OutputFormat::Yaml => {
                    println!("{}", serde_yaml::to_string(&hostnames)?);
                }
                OutputFormat::Csv => {
                    println!("ip,hostname");
                    for hostname in &hostnames {
                        println!("{ip},{hostname}");
                    }
                }
                OutputFormat::Pretty => {
                    if ctx.no_color {
                        println!("{ip}");
                    } else {
                        println!("{}", ip.cyan());
                    }
                    if hostnames.is_empty() {
                        println!("  No PTR records found");
                    } else {
                        for hostname in &hostnames {
                            println!("  -> {hostname}");
                        }
                    }
                }
            }
        }
    }

    Ok(())
}
