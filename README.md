# i1.is

**Security that IS.**

> "A real hacker doesn't go after good people."

---

## Our Code

### 1. Protect the Vulnerable

Grandma shouldn't need a cybersecurity degree to check her email. The 80-year-old who pays a fake Microsoft bill isn't a fool - she's inexperienced with the worst side of humanity. We protect her.

### 2. Free at the Crisis

Even if you never pay us, we will help you when it matters. Your patterns teach us. Your data strengthens everyone. The network protects itself.

### 3. Honest Partners Only

We work with companies that show integrity:
- **Hetzner** forwarded a fake "law enforcement" request to us and said *"your call"*
- **Germany CERT** notified us about an unpatched PostgreSQL - actual help, not surveillance
- We don't work with companies that blame customers for their unpatched servers

### 4. Attackers Train Our Defense

Every script kiddie that hits our network teaches us their patterns. Every attack signature gets shared with everyone. The more they attack, the stronger we get.

### 5. AI Serves Humans

TAI lives with you. Claude is the uncle we call for hard problems. Neither replaces human judgment. Both amplify human capability.

---

## What We Build

```
i1.is/
├── /condom      → Browse safely from a disposable VM ($5/mo)
├── /honeypot    → Trap scammers with fake data that phones home
├── /lookup      → Threat intel from Shodan, Censys, Criminal IP
├── /defend      → Firewall rules that actually work
└── /api         → All of the above, programmable

tai.is/
└── /42          → Your local AI guardian (the answer to everything)
```

---

## Architecture

### The Stack

```
┌─────────────────────────────────────────────────────────────────┐
│                         YOUR MACHINE                            │
│                                                                 │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │ TAI (tai.is) - Local AI Guardian                        │   │
│   │   • Knows YOUR patterns                                 │   │
│   │   • Detects imposters/injection                         │   │
│   │   • Lightweight, runs on your hardware                  │   │
│   │   • Calls i1.is when needed                             │   │
│   └─────────────────────────────────────────────────────────┘   │
│                              │                                  │
└──────────────────────────────┼──────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                     i1.is - Security Ops                        │
│                                                                 │
│   ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐       │
│   │ /condom  │  │/honeypot │  │ /lookup  │  │ /defend  │       │
│   │ Browser  │  │  Traps   │  │  Intel   │  │ Firewall │       │
│   │Isolation │  │Generation│  │  APIs    │  │  Rules   │       │
│   └──────────┘  └──────────┘  └──────────┘  └──────────┘       │
│                              │                                  │
│   Pattern Database ◄─────────┴─────────► Signature Sharing     │
│                                                                 │
└──────────────────────────────┼──────────────────────────────────┘
                               │
                               ▼ (when needed)
┌─────────────────────────────────────────────────────────────────┐
│                    Claude (Uncle Claude)                        │
│                                                                 │
│   • Deep analysis of novel attacks                              │
│   • Pattern extraction from complex threats                     │
│   • The heavy lifting TAI can't do alone                        │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Condom Mode

Your $5/month buys a disposable VM at Hetzner that:
- Browses the sketchy links FOR you
- Mimics your user-agent and fingerprint
- Runs suspicious downloads in a sandbox
- Feeds malware FAKE data (honeypots)
- Burns and rebuilds fresh after each session

```
You click sketchy link
        │
        ▼
┌─────────────────────────────────────────┐
│  Hetzner VM (your condom)               │
│                                         │
│  • Opens link in isolated browser       │
│  • Downloads run in sandbox             │
│  • Malware finds fake CC, crypto seeds  │
│  • Every fake credential phones home    │
│                                         │
│  You see: safe stream of the results    │
│  Scammer gets: tracked and burned       │
└─────────────────────────────────────────┘
```

### Honeypot Kit

For every sandbox, we generate:
- **LUHN-valid credit cards** - Pass validation, trigger alerts when used
- **Crypto wallets** - Fake BTC/ETH with enticing balances
- **Trap documents** - PDFs that phone home to `i1.is/t/{id}`
- **Fake credentials** - Bank logins, email passwords, all tracked

```
Documents/
├── passwords.txt           ← Scammer thinks: "Jackpot!"
├── Financial/
│   └── cards.csv           ← LUHN-valid traps
├── crypto_backup.txt       ← Fake seeds we control
└── Taxes/
    └── Tax_Return_2025.pdf ← Opens = we know
```

### Pattern Intelligence

Every attack teaches us:

```
Attack hits user #1 ──► Pattern extracted ──┐
Attack hits user #2 ──► Pattern extracted ──┼──► Signature DB
Attack hits user #3 ──► Pattern extracted ──┘
                                            │
                                            ▼
                              ┌─────────────────────────┐
                              │ TAI: "Seen this 47,000  │
                              │ times. Auto-blocked."   │
                              └─────────────────────────┘

Novel attack ──► TAI: "New pattern..." ──► Uncle Claude analyzes
                                                    │
                                                    ▼
                                          New signature created
                                                    │
                                                    ▼
                                          Pushed to ALL users
```

---

## The CLI

```bash
# Your public IP
i1 myip

# Threat intel
i1 host 8.8.8.8              # Lookup from Shodan
i1 host 8.8.8.8 --all        # All providers
i1 search "apache port:80"   # Search
i1 dns resolve example.com   # DNS

# Defense
i1 defend status             # What's blocked?
i1 defend geoblock add cn ru # Block countries
i1 defend ban 1.2.3.4        # Ban IP
i1 defend export             # Generate firewall rules

# Config (multi-provider)
i1 config set shodan-key xxx
i1 config set censys-id xxx
i1 config set criminalip-key xxx
```

---

## Crate Structure

```
crates/
├── i1-core/           # Types, errors, shared foundations
├── i1-providers/      # Provider traits (HostLookup, Search, DNS)
├── i1-shodan/         # Shodan API
├── i1-censys/         # Censys API (Basic auth)
├── i1-criminalip/     # Criminal IP (x-api-key header)
├── i1-native/         # Local WHOIS, DNS
├── i1-client/         # Unified multi-provider client
├── i1-recon/          # Scanner, enrichment tools
├── i1-honeypot/       # Trap generation (cards, wallets, docs)
├── i1-condom/         # Browser isolation (planned)
├── i1-vm/             # Hetzner orchestration (planned)
├── i1/                # Facade - re-exports everything
└── i1-cli/            # The `i1` command
```

---

## Values We Code By

| Principle | Implementation |
|-----------|----------------|
| **Transparency** | Open source. Read every line. |
| **Privacy** | Your data stays yours. Patterns are anonymized. |
| **No false promises** | "10x safer minimum" - we can prove it |
| **Accessible** | $5/month. Free tier that actually works. |
| **Integrity** | We partner with Hetzner, not OVH. |

---

## For Hackers (The Real Ones)

If you're here to help:
- PRs welcome
- Security reports: security@i1.is
- We appreciate white hats

If you're here to attack good people:
- You're training our defense
- Every pattern you use becomes useless
- The FBI laptop delivery service is always hiring

---

## Quick Start

```bash
# Install
cargo install i1-cli

# Or build from source
git clone https://github.com/i1-is/i1
cd i1
cargo build --release
./target/release/i1 --help

# Set your API key
i1 config set shodan-key YOUR_KEY

# Try it
i1 myip
i1 host 8.8.8.8
```

---

## Credits

- **Iceland** (.is) - For the domain and the spirit of independence
- **Hetzner** - For showing what integrity looks like
- **The 6502** - For teaching a generation that you don't need permission to create

---

## License

MIT OR Apache-2.0

Use it. Fork it. Protect people with it.

---

*Born from Iceland's spirit. Built by those who said "fuck playing it safe."*

**i1.is** - Security that IS.
