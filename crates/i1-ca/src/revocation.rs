//! Certificate revocation handling.
//!
//! When an intermediate or end-entity cert is compromised,
//! we revoke it here. The root can revoke intermediates,
//! intermediates can revoke end-entities.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Reason for certificate revocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RevocationReason {
    /// Key was compromised
    KeyCompromise,
    /// CA was compromised
    CaCompromise,
    /// Affiliation changed
    AffiliationChanged,
    /// Certificate superseded by new one
    Superseded,
    /// Operations ceased
    CessationOfOperation,
    /// Certificate on hold (temporary)
    CertificateHold,
    /// Privilege withdrawn
    PrivilegeWithdrawn,
    /// Attribute authority compromised
    AaCompromise,
    /// Unspecified reason
    Unspecified,
}

impl std::fmt::Display for RevocationReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RevocationReason::KeyCompromise => write!(f, "Key Compromise"),
            RevocationReason::CaCompromise => write!(f, "CA Compromise"),
            RevocationReason::AffiliationChanged => write!(f, "Affiliation Changed"),
            RevocationReason::Superseded => write!(f, "Superseded"),
            RevocationReason::CessationOfOperation => write!(f, "Cessation of Operation"),
            RevocationReason::CertificateHold => write!(f, "Certificate Hold"),
            RevocationReason::PrivilegeWithdrawn => write!(f, "Privilege Withdrawn"),
            RevocationReason::AaCompromise => write!(f, "AA Compromise"),
            RevocationReason::Unspecified => write!(f, "Unspecified"),
        }
    }
}

/// Entry in the revocation list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationEntry {
    /// Certificate serial number
    pub serial: String,
    /// When it was revoked
    pub revoked_at: DateTime<Utc>,
    /// Why it was revoked
    pub reason: RevocationReason,
    /// Optional notes
    pub notes: Option<String>,
}

/// Certificate Revocation List.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RevocationList {
    /// Unique ID for this CRL
    pub id: Uuid,
    /// Issuer of this CRL
    pub issuer: String,
    /// When this CRL was generated
    pub this_update: DateTime<Utc>,
    /// When the next CRL will be published
    pub next_update: DateTime<Utc>,
    /// Revoked certificates
    pub entries: Vec<RevocationEntry>,
}

impl RevocationList {
    /// Create a new revocation list.
    pub fn new(issuer: impl Into<String>) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            issuer: issuer.into(),
            this_update: now,
            next_update: now + chrono::Duration::days(1), // Daily updates
            entries: Vec::new(),
        }
    }

    /// Add a revocation entry.
    pub fn revoke(&mut self, serial: impl Into<String>, reason: RevocationReason) {
        self.entries.push(RevocationEntry {
            serial: serial.into(),
            revoked_at: Utc::now(),
            reason,
            notes: None,
        });
    }

    /// Add a revocation with notes.
    pub fn revoke_with_notes(
        &mut self,
        serial: impl Into<String>,
        reason: RevocationReason,
        notes: impl Into<String>,
    ) {
        self.entries.push(RevocationEntry {
            serial: serial.into(),
            revoked_at: Utc::now(),
            reason,
            notes: Some(notes.into()),
        });
    }

    /// Check if a serial number is revoked.
    pub fn is_revoked(&self, serial: &str) -> bool {
        self.entries.iter().any(|e| e.serial == serial)
    }

    /// Get revocation entry if revoked.
    pub fn get_revocation(&self, serial: &str) -> Option<&RevocationEntry> {
        self.entries.iter().find(|e| e.serial == serial)
    }

    /// Export as JSON.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Load from JSON.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Get count of revoked certificates.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the CRL is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_revocation_list() {
        let mut crl = RevocationList::new("Test CA");

        assert!(crl.is_empty());

        crl.revoke("ABC123", RevocationReason::KeyCompromise);

        assert!(!crl.is_empty());
        assert!(crl.is_revoked("ABC123"));
        assert!(!crl.is_revoked("XYZ789"));
    }

    #[test]
    fn test_revocation_with_notes() {
        let mut crl = RevocationList::new("Test CA");

        crl.revoke_with_notes(
            "BADCERT",
            RevocationReason::CaCompromise,
            "Found being used by scammer",
        );

        let entry = crl.get_revocation("BADCERT").unwrap();
        assert_eq!(entry.reason, RevocationReason::CaCompromise);
        assert!(entry.notes.as_ref().unwrap().contains("scammer"));
    }

    #[test]
    fn test_json_roundtrip() {
        let mut crl = RevocationList::new("Test");
        crl.revoke("123", RevocationReason::Superseded);

        let json = crl.to_json().unwrap();
        let loaded = RevocationList::from_json(&json).unwrap();

        assert_eq!(loaded.entries.len(), 1);
        assert!(loaded.is_revoked("123"));
    }
}
