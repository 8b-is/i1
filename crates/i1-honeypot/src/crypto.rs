//! Fake cryptocurrency wallet generation for honeypots.

use rand::Rng;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Supported cryptocurrency networks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CryptoNetwork {
    Bitcoin,
    Ethereum,
    Litecoin,
    Dogecoin,
}

impl CryptoNetwork {
    /// Address prefix for this network.
    fn prefix(&self) -> &str {
        match self {
            CryptoNetwork::Bitcoin => "1",      // Legacy P2PKH
            CryptoNetwork::Ethereum => "0x",
            CryptoNetwork::Litecoin => "L",
            CryptoNetwork::Dogecoin => "D",
        }
    }

    /// Address length (excluding prefix).
    fn address_length(&self) -> usize {
        match self {
            CryptoNetwork::Bitcoin => 33,   // 34 total with prefix
            CryptoNetwork::Ethereum => 40,  // 42 total with 0x
            CryptoNetwork::Litecoin => 33,
            CryptoNetwork::Dogecoin => 33,
        }
    }

    /// Valid characters for address generation.
    fn charset(&self) -> &str {
        match self {
            CryptoNetwork::Ethereum => "0123456789abcdef",
            _ => "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz", // Base58
        }
    }
}

impl std::fmt::Display for CryptoNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoNetwork::Bitcoin => write!(f, "Bitcoin"),
            CryptoNetwork::Ethereum => write!(f, "Ethereum"),
            CryptoNetwork::Litecoin => write!(f, "Litecoin"),
            CryptoNetwork::Dogecoin => write!(f, "Dogecoin"),
        }
    }
}

/// A honeypot cryptocurrency wallet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoneypotWallet {
    /// Unique identifier for tracking
    pub id: Uuid,
    /// Cryptocurrency network
    pub network: CryptoNetwork,
    /// Wallet address (looks valid but we control it)
    pub address: String,
    /// Fake private key (DO NOT USE - for honeypot display only)
    pub private_key: String,
    /// BIP-39 style seed phrase (fake)
    pub seed_phrase: String,
    /// Fake balance to make it enticing
    pub fake_balance: String,
}

impl HoneypotWallet {
    /// Generate a new honeypot wallet.
    pub fn generate(network: CryptoNetwork) -> Self {
        Self {
            id: Uuid::new_v4(),
            network,
            address: generate_address(network),
            private_key: generate_private_key(network),
            seed_phrase: generate_seed_phrase(),
            fake_balance: generate_fake_balance(network),
        }
    }
}

/// Generate a realistic-looking address.
fn generate_address(network: CryptoNetwork) -> String {
    let mut rng = rand::thread_rng();
    let charset: Vec<char> = network.charset().chars().collect();
    let length = network.address_length();

    let random_part: String = (0..length)
        .map(|_| charset[rng.gen_range(0..charset.len())])
        .collect();

    format!("{}{}", network.prefix(), random_part)
}

/// Generate a fake private key.
fn generate_private_key(network: CryptoNetwork) -> String {
    let mut rng = rand::thread_rng();

    match network {
        CryptoNetwork::Ethereum => {
            let hex: String = (0..64)
                .map(|_| format!("{:x}", rng.gen_range(0..16)))
                .collect();
            format!("0x{}", hex)
        }
        _ => {
            // WIF format for Bitcoin-like
            let charset: Vec<char> = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
                .chars()
                .collect();
            let key: String = (0..51)
                .map(|_| charset[rng.gen_range(0..charset.len())])
                .collect();
            format!("5{}", key)
        }
    }
}

/// Generate a BIP-39 style seed phrase (fake but looks real).
fn generate_seed_phrase() -> String {
    let mut rng = rand::thread_rng();

    // Common BIP-39 words (subset for generation)
    let words = [
        "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
        "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid",
        "acoustic", "acquire", "across", "act", "action", "actor", "actress", "actual",
        "adapt", "add", "addict", "address", "adjust", "admit", "adult", "advance",
        "advice", "aerobic", "affair", "afford", "afraid", "again", "age", "agent",
        "agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album",
        "alert", "alien", "almost", "alpha", "already", "also", "alter", "always",
        "amazing", "among", "amount", "anchor", "ancient", "anger", "angry", "animal",
        "ankle", "announce", "annual", "another", "answer", "antenna", "antique", "anxiety",
        "any", "apart", "apology", "appear", "apple", "approve", "april", "arch",
        "arctic", "area", "arena", "argue", "arm", "armed", "armor", "army",
        "around", "arrange", "arrest", "arrive", "arrow", "art", "artefact", "artist",
        "artwork", "ask", "aspect", "assault", "asset", "assist", "assume", "asthma",
        "atom", "attack", "attend", "auction", "audit", "august", "aunt", "author",
        "auto", "autumn", "average", "avocado", "avoid", "awake", "aware", "away",
        "awesome", "awful", "awkward", "axis", "baby", "bachelor", "bacon", "badge",
    ];

    // Generate 12 or 24 word phrase
    let count = if rng.gen_bool(0.5) { 12 } else { 24 };

    (0..count)
        .map(|_| words[rng.gen_range(0..words.len())])
        .collect::<Vec<_>>()
        .join(" ")
}

/// Generate an enticing fake balance.
fn generate_fake_balance(network: CryptoNetwork) -> String {
    let mut rng = rand::thread_rng();

    let (amount, symbol) = match network {
        CryptoNetwork::Bitcoin => (rng.gen_range(0.5..5.0), "BTC"),
        CryptoNetwork::Ethereum => (rng.gen_range(2.0..20.0), "ETH"),
        CryptoNetwork::Litecoin => (rng.gen_range(10.0..100.0), "LTC"),
        CryptoNetwork::Dogecoin => (rng.gen_range(10000.0..100000.0), "DOGE"),
    };

    format!("{:.4} {}", amount, symbol)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bitcoin_wallet() {
        let wallet = HoneypotWallet::generate(CryptoNetwork::Bitcoin);
        assert!(wallet.address.starts_with('1'));
        assert!(wallet.private_key.starts_with('5'));
        assert!(wallet.seed_phrase.split_whitespace().count() >= 12);
    }

    #[test]
    fn test_ethereum_wallet() {
        let wallet = HoneypotWallet::generate(CryptoNetwork::Ethereum);
        assert!(wallet.address.starts_with("0x"));
        assert!(wallet.private_key.starts_with("0x"));
        assert_eq!(wallet.address.len(), 42);
    }

    #[test]
    fn test_seed_phrase_length() {
        let wallet = HoneypotWallet::generate(CryptoNetwork::Bitcoin);
        let word_count = wallet.seed_phrase.split_whitespace().count();
        assert!(word_count == 12 || word_count == 24);
    }
}
