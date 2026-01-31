//! # i1-honeypot
//!
//! Honeypot generation for i1.is - creates convincing fake data that traps scammers.
//!
//! ## Features
//!
//! - LUHN-valid credit cards that trigger alerts when used
//! - Fake cryptocurrency wallets with trackable addresses
//! - Decoy credentials and password files
//! - Trap documents that phone home when opened
//!
//! ## Example
//!
//! ```rust,ignore
//! use i1_honeypot::{HoneypotKit, CardNetwork};
//!
//! let kit = HoneypotKit::new("user-123");
//! let card = kit.generate_card(CardNetwork::Visa);
//! // Card passes LUHN validation but is flagged in our database
//! // Any attempt to charge it = instant notification + scammer tracking
//! ```

mod card;
mod credentials;
mod crypto;
mod documents;
mod error;

pub use card::{CardNetwork, HoneypotCard, generate_luhn_valid};
pub use credentials::{CredentialType, HoneypotCredential};
pub use crypto::{CryptoNetwork, HoneypotWallet};
pub use documents::{DocumentType, TrapDocument};
pub use error::HoneypotError;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A complete honeypot kit for a user's sandbox environment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoneypotKit {
    /// Unique identifier for this kit
    pub id: Uuid,
    /// User this kit belongs to
    pub user_id: String,
    /// When this kit was generated
    pub created_at: DateTime<Utc>,
    /// Generated credit cards
    pub cards: Vec<HoneypotCard>,
    /// Generated credentials
    pub credentials: Vec<HoneypotCredential>,
    /// Generated crypto wallets
    pub wallets: Vec<HoneypotWallet>,
    /// Trap documents
    pub documents: Vec<TrapDocument>,
}

impl HoneypotKit {
    /// Create a new honeypot kit for a user.
    pub fn new(user_id: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            user_id: user_id.into(),
            created_at: Utc::now(),
            cards: Vec::new(),
            credentials: Vec::new(),
            wallets: Vec::new(),
            documents: Vec::new(),
        }
    }

    /// Generate a full kit with default honeypots.
    pub fn generate_default_kit(user_id: impl Into<String>) -> Self {
        let mut kit = Self::new(user_id);

        // Generate some credit cards
        kit.cards.push(HoneypotCard::generate(CardNetwork::Visa));
        kit.cards.push(HoneypotCard::generate(CardNetwork::Mastercard));
        kit.cards.push(HoneypotCard::generate(CardNetwork::Amex));

        // Generate credentials
        kit.credentials.push(HoneypotCredential::generate(CredentialType::BankLogin));
        kit.credentials.push(HoneypotCredential::generate(CredentialType::EmailLogin));
        kit.credentials.push(HoneypotCredential::generate(CredentialType::SocialMedia));

        // Generate crypto wallets
        kit.wallets.push(HoneypotWallet::generate(CryptoNetwork::Bitcoin));
        kit.wallets.push(HoneypotWallet::generate(CryptoNetwork::Ethereum));

        // Generate trap documents
        kit.documents.push(TrapDocument::generate(DocumentType::TaxReturn));
        kit.documents.push(TrapDocument::generate(DocumentType::BankStatement));

        kit
    }

    /// Add a custom credit card to the kit.
    pub fn add_card(&mut self, network: CardNetwork) -> &HoneypotCard {
        self.cards.push(HoneypotCard::generate(network));
        self.cards.last().unwrap()
    }

    /// Export kit as JSON for sandbox deployment.
    pub fn to_json(&self) -> Result<String, HoneypotError> {
        serde_json::to_string_pretty(self).map_err(HoneypotError::Serialization)
    }

    /// Create files that look like real user data.
    pub fn generate_filesystem_artifacts(&self) -> Vec<(String, String)> {
        let mut files = Vec::new();

        // passwords.txt - classic
        let passwords: Vec<String> = self
            .credentials
            .iter()
            .map(|c| format!("{}: {}", c.site, c.password))
            .collect();
        files.push((
            "Documents/passwords.txt".to_string(),
            passwords.join("\n"),
        ));

        // credit_cards.csv
        let mut csv = "name,number,exp,cvv\n".to_string();
        for card in &self.cards {
            csv.push_str(&format!(
                "{},{},{},{}\n",
                card.holder_name, card.number, card.expiry, card.cvv
            ));
        }
        files.push(("Documents/Financial/cards.csv".to_string(), csv));

        // crypto seeds
        let seeds: Vec<String> = self
            .wallets
            .iter()
            .map(|w| format!("{} seed: {}", w.network, w.seed_phrase))
            .collect();
        files.push((
            "Documents/crypto_backup.txt".to_string(),
            seeds.join("\n\n"),
        ));

        files
    }
}

/// Event triggered when a honeypot is accessed/used.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TripwireEvent {
    /// Which honeypot was triggered
    pub honeypot_id: Uuid,
    /// Type of honeypot
    pub honeypot_type: String,
    /// When it was triggered
    pub triggered_at: DateTime<Utc>,
    /// IP address of attacker (if available)
    pub source_ip: Option<String>,
    /// Additional context
    pub context: serde_json::Value,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_kit() {
        let kit = HoneypotKit::generate_default_kit("test-user");
        assert!(!kit.cards.is_empty());
        assert!(!kit.credentials.is_empty());
        assert!(!kit.wallets.is_empty());
    }

    #[test]
    fn test_filesystem_artifacts() {
        let kit = HoneypotKit::generate_default_kit("test-user");
        let files = kit.generate_filesystem_artifacts();
        assert!(!files.is_empty());

        // Should have passwords.txt
        assert!(files.iter().any(|(path, _)| path.contains("passwords")));
    }
}
