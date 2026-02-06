# i1

**Security operations CLI** - Threat intel, automated defense, and community blocklist sharing. Built in Rust.

> Every script kiddie that hits your server trains your defense. Every ban gets shared with everyone. The more they attack, the stronger we all get.

---

## What It Does

```bash
# Instant threat lookup + one-key ban
i1 t 40.70.26.226

# Auto-hunt attackers in your logs
i1 defend patrol run --execute

# Sync blocks across your server fleet via SSH
i1 defend push -a

# Share your blocklist with the community
i1 defend community contribute --fail2ban
```

---

## Quick Start

**No API keys required.** Everything works out of the box using WHOIS, DNS, and local reconnaissance. Shodan/Censys/CriminalIP are optional for deeper intel.

```bash
# Build from source
git clone https://github.com/8b-is/i1
cd i1
cargo build --release

# Works immediately - no keys needed
./target/release/i1 myip
./target/release/i1 t 1.2.3.4
./target/release/i1 defend patrol run --dry-run

# Optional: add API keys for richer threat intel
./target/release/i1 config set shodan-key YOUR_KEY
./target/release/i1 config set censys-id YOUR_ID
./target/release/i1 config set criminalip-key YOUR_KEY
```

---

## Threat Response

Look up any IP and take action in one command:

```
$ i1 t 40.70.26.226

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🎯 THREAT RESPONSE: 40.70.26.226
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Organization: Microsoft Corporation
  ASN: AS8075
  ISP: Microsoft Corporation
  Location: Boydton, VA, United States
  Open Ports: 50000

  [b] Ban this IP
  [a] Ban entire ASN
  [x] Show iptables command
```

```bash
i1 t 1.2.3.4 --ban -y       # Lookup + auto-ban
i1 t 1.2.3.4 --ban -a -y    # Lookup + ban entire ASN
i1 t 1.2.3.4 -x             # Just show the iptables command
```

Works with no API keys (WHOIS + DNS). Add Shodan/Censys/CriminalIP keys for deeper intel.

---

## Automated Patrol

Scans your Docker compose logs (nginx, postfix) for attackers and bans them automatically. Built for mailcow but works with any nginx setup.

```bash
# Dry run first - see what it would catch
i1 defend patrol run --dry-run

# Scan and ban immediately
i1 defend patrol run --execute

# Scan the last 24 hours
i1 defend patrol run --window 1440 --execute

# Set up a cron job - auto-ban every 15 minutes
i1 defend patrol cron --interval 15

# Check what patrol has been doing
i1 defend patrol log
```

**What it catches:**
- Webshell scanners (`.php` probing with 404s)
- WordPress exploit bots (`wp-content`, `xmlrpc.php`)
- Path traversal attempts (`../`, `%00`)
- Config/credential hunters (`.env`, `.git`, `/phpmyadmin`)
- SMTP brute force (auth failures, rejects)

**What it won't touch:**
- Your own IP (detected via SSH session + public IP lookup)
- Docker internal traffic
- Whitelisted IPs
- Already-banned IPs (just logs that they're still trying)

---

## SSH Fleet Sync

Push your blocks to all your servers, or pull from a battle-tested one. Uses your `~/.ssh/config`.

```bash
# Push to all servers in SSH config
i1 defend push -a

# Push to specific hosts
i1 defend push -H web1,db1,mail2

# Preview what would be pushed
i1 defend push --dry-run

# Pull blocks from your hardened mail server to a new box
i1 defend pull mailserver

# Merge remote rules with local
i1 defend pull mailserver --merge
```

Your IP is automatically whitelisted on remote servers before any blocks are applied. No more locking yourself out.

---

## Community Threat Sharing

Crowdsourced blocklist. Everyone's fail2ban and i1 blocks feed into a shared list.

```bash
# Share your blocked IPs with the community
i1 defend community contribute --fail2ban

# Fetch the community blocklist
i1 defend community fetch

# Auto-sync via cron (every 6 hours)
i1 defend community subscribe --interval 6

# See community stats
i1 defend community stats
```

The more servers contributing, the better everyone's defense gets.

---

## Defense Management

```bash
# Status
i1 defend status               # Full status
i1 defend status --quick        # One-liner

# Ban/unban
i1 defend ban 1.2.3.4          # Block an IP
i1 defend ban 1.2.3.0/24       # Block a range
i1 defend ban AS12345 -a        # Block an ASN
i1 defend unban 1.2.3.4        # Remove a block

# Geo-blocking
i1 defend geoblock add cn ru ro # Block countries
i1 defend geoblock list         # Show blocked countries
i1 defend geoblock codes        # Country code reference

# Whitelist (never blocked)
i1 defend whitelist add 1.2.3.4
i1 defend whitelist show

# Export firewall rules
i1 defend export --format iptables
i1 defend export --format nftables
i1 defend export --format pf

# Emergency kill switch
i1 defend disable
```

---

## SSH Session Protection

i1 detects if you're connected via SSH and refuses to block your own IP:

```
$ i1 defend ban 173.71.155.73
🛡️ PROTECTED: Refusing to block 173.71.155.73 - that's your current SSH session!

This prevents you from locking yourself out.
```

Works in `ban`, `threat`, and `patrol` commands.

---

## Recon & Intel

```bash
i1 myip                         # Your public IP
i1 host 8.8.8.8                 # Host lookup (Shodan)
i1 host 8.8.8.8 --all           # Query all providers
i1 host 8.8.8.8 -p censys       # Specific provider
i1 search "apache port:80"      # Search Shodan
i1 dns resolve example.com      # DNS lookup
```

---

## Architecture

```
crates/
├── i1-core/        # Types, errors, shared foundations
├── i1-providers/   # Provider traits (HostLookup, Search, DNS)
├── i1-shodan/      # Shodan API
├── i1-censys/      # Censys API
├── i1-criminalip/  # Criminal IP API
├── i1-native/      # Local WHOIS, DNS
├── i1-client/      # Unified multi-provider client
├── i1-recon/       # Scanner, enrichment tools
├── i1/             # Facade crate
└── i1-cli/         # The `i1` binary
```

---

## License

MIT OR Apache-2.0

---

*Built by [8b.is](https://8b.is). Born from Iceland's spirit of independence.*
