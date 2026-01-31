//! Fake credential generation for honeypots.

use rand::Rng;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Types of credentials to generate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CredentialType {
    BankLogin,
    EmailLogin,
    SocialMedia,
    CryptoExchange,
    Shopping,
    Streaming,
}

impl CredentialType {
    fn sites(&self) -> &[&str] {
        match self {
            CredentialType::BankLogin => &[
                "chase.com",
                "bankofamerica.com",
                "wellsfargo.com",
                "citibank.com",
            ],
            CredentialType::EmailLogin => &[
                "gmail.com",
                "outlook.com",
                "yahoo.com",
                "protonmail.com",
            ],
            CredentialType::SocialMedia => &[
                "facebook.com",
                "instagram.com",
                "twitter.com",
                "linkedin.com",
            ],
            CredentialType::CryptoExchange => &[
                "coinbase.com",
                "binance.com",
                "kraken.com",
                "gemini.com",
            ],
            CredentialType::Shopping => &[
                "amazon.com",
                "ebay.com",
                "walmart.com",
                "target.com",
            ],
            CredentialType::Streaming => &[
                "netflix.com",
                "hulu.com",
                "disneyplus.com",
                "hbomax.com",
            ],
        }
    }
}

impl std::fmt::Display for CredentialType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CredentialType::BankLogin => write!(f, "Bank"),
            CredentialType::EmailLogin => write!(f, "Email"),
            CredentialType::SocialMedia => write!(f, "Social"),
            CredentialType::CryptoExchange => write!(f, "Crypto"),
            CredentialType::Shopping => write!(f, "Shopping"),
            CredentialType::Streaming => write!(f, "Streaming"),
        }
    }
}

/// A honeypot credential that looks real but triggers alerts when used.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoneypotCredential {
    /// Unique identifier for tracking
    pub id: Uuid,
    /// Type of credential
    pub credential_type: CredentialType,
    /// Website/service
    pub site: String,
    /// Username/email
    pub username: String,
    /// Password
    pub password: String,
    /// Security questions (if applicable)
    pub security_questions: Vec<(String, String)>,
}

impl HoneypotCredential {
    /// Generate a new honeypot credential.
    pub fn generate(credential_type: CredentialType) -> Self {
        let mut rng = rand::thread_rng();
        let sites = credential_type.sites();
        let site = sites[rng.gen_range(0..sites.len())].to_string();

        let (username, password) = generate_username_password(&site);

        Self {
            id: Uuid::new_v4(),
            credential_type,
            site,
            username,
            password,
            security_questions: generate_security_questions(),
        }
    }
}

/// Generate a realistic username and password pair.
fn generate_username_password(site: &str) -> (String, String) {
    let mut rng = rand::thread_rng();

    let first_names = ["james", "mary", "john", "patricia", "robert", "jennifer"];
    let last_names = ["smith", "johnson", "williams", "brown", "jones"];

    let first = first_names[rng.gen_range(0..first_names.len())];
    let last = last_names[rng.gen_range(0..last_names.len())];
    let num = rng.gen_range(1..999);

    // Email-style username for most sites
    let username = if site.contains("gmail") || site.contains("outlook") || site.contains("yahoo") {
        format!("{}.{}{}@{}", first, last, num, site)
    } else {
        format!("{}{}{}", first, last, num)
    };

    // "Realistic" weak passwords that people actually use
    let password_patterns = [
        format!("{}{}!", first.chars().next().unwrap().to_uppercase().collect::<String>() + &first[1..], num),
        format!("{}{}#", last.chars().next().unwrap().to_uppercase().collect::<String>() + &last[1..], num),
        format!("{}@{}", first, num),
        format!("Password{}!", num),
        format!("Welcome{}#", num),
    ];

    let password = password_patterns[rng.gen_range(0..password_patterns.len())].clone();

    (username, password)
}

/// Generate security questions and answers.
fn generate_security_questions() -> Vec<(String, String)> {
    let mut rng = rand::thread_rng();

    let qa_pairs = [
        ("What is your mother's maiden name?", &["Smith", "Johnson", "Williams", "Davis"][..]),
        ("What was the name of your first pet?", &["Max", "Buddy", "Charlie", "Lucy"]),
        ("What city were you born in?", &["New York", "Los Angeles", "Chicago", "Houston"]),
        ("What is your favorite movie?", &["Star Wars", "Titanic", "The Godfather", "Forrest Gump"]),
        ("What was the make of your first car?", &["Toyota", "Honda", "Ford", "Chevrolet"]),
    ];

    qa_pairs
        .iter()
        .take(3)
        .map(|(q, answers)| {
            (
                q.to_string(),
                answers[rng.gen_range(0..answers.len())].to_string(),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_credential() {
        let cred = HoneypotCredential::generate(CredentialType::BankLogin);
        assert!(!cred.username.is_empty());
        assert!(!cred.password.is_empty());
        assert!(!cred.site.is_empty());
    }

    #[test]
    fn test_email_format() {
        let cred = HoneypotCredential::generate(CredentialType::EmailLogin);
        if cred.site.contains("gmail") {
            assert!(cred.username.contains('@'));
        }
    }
}
