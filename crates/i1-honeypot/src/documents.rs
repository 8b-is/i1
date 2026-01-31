//! Trap document generation for honeypots.
//!
//! These documents look like sensitive files but contain tracking mechanisms.

use chrono::{Datelike, Utc};
use rand::Rng;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Types of trap documents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DocumentType {
    TaxReturn,
    BankStatement,
    PayStub,
    MedicalRecord,
    InsurancePolicy,
    Will,
    Passport,
    DriversLicense,
}

impl DocumentType {
    /// Suggested filename for this document type.
    fn filename(&self) -> String {
        let mut rng = rand::thread_rng();
        let year = Utc::now().year() - rng.gen_range(0..3);

        match self {
            DocumentType::TaxReturn => format!("Tax_Return_{}.pdf", year),
            DocumentType::BankStatement => format!("Bank_Statement_{:02}_{}.pdf", rng.gen_range(1..=12), year),
            DocumentType::PayStub => format!("PayStub_{:02}_{}.pdf", rng.gen_range(1..=12), year),
            DocumentType::MedicalRecord => format!("Medical_Records_{}.pdf", year),
            DocumentType::InsurancePolicy => format!("Insurance_Policy_{}.pdf", year),
            DocumentType::Will => "Last_Will_and_Testament.pdf".to_string(),
            DocumentType::Passport => "Passport_Scan.pdf".to_string(),
            DocumentType::DriversLicense => "Drivers_License_Copy.pdf".to_string(),
        }
    }

    /// Folder path suggestion.
    fn folder(&self) -> &str {
        match self {
            DocumentType::TaxReturn => "Documents/Taxes",
            DocumentType::BankStatement => "Documents/Financial",
            DocumentType::PayStub => "Documents/Work",
            DocumentType::MedicalRecord => "Documents/Medical",
            DocumentType::InsurancePolicy => "Documents/Insurance",
            DocumentType::Will => "Documents/Legal",
            DocumentType::Passport => "Documents/ID",
            DocumentType::DriversLicense => "Documents/ID",
        }
    }
}

impl std::fmt::Display for DocumentType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DocumentType::TaxReturn => write!(f, "Tax Return"),
            DocumentType::BankStatement => write!(f, "Bank Statement"),
            DocumentType::PayStub => write!(f, "Pay Stub"),
            DocumentType::MedicalRecord => write!(f, "Medical Record"),
            DocumentType::InsurancePolicy => write!(f, "Insurance Policy"),
            DocumentType::Will => write!(f, "Will"),
            DocumentType::Passport => write!(f, "Passport"),
            DocumentType::DriversLicense => write!(f, "Driver's License"),
        }
    }
}

/// A trap document that reports back when opened.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrapDocument {
    /// Unique identifier for tracking
    pub id: Uuid,
    /// Document type
    pub document_type: DocumentType,
    /// Filename
    pub filename: String,
    /// Full path suggestion
    pub full_path: String,
    /// Tracking URL embedded in the document
    pub tracking_url: String,
    /// Fake SSN in the document (for tracking if used)
    pub fake_ssn: Option<String>,
    /// Fake account number (for tracking if used)
    pub fake_account: Option<String>,
}

impl TrapDocument {
    /// Generate a new trap document.
    pub fn generate(document_type: DocumentType) -> Self {
        let id = Uuid::new_v4();
        let filename = document_type.filename();
        let folder = document_type.folder();

        // Tracking URL that will phone home when document is opened
        // (PDF can contain JavaScript or external resource requests)
        let tracking_url = format!("https://i1.is/t/{}", id);

        Self {
            id,
            document_type,
            filename: filename.clone(),
            full_path: format!("{}/{}", folder, filename),
            tracking_url,
            fake_ssn: Some(generate_fake_ssn()),
            fake_account: Some(generate_fake_account()),
        }
    }

    /// Generate document content (placeholder - would be PDF generation).
    pub fn generate_content(&self) -> Vec<u8> {
        // In a real implementation, this would generate a PDF with:
        // - Embedded tracking pixel/JavaScript
        // - The fake SSN/account numbers
        // - Realistic-looking content

        // For now, just return a placeholder
        let content = format!(
            "TRAP DOCUMENT\n\
            Type: {}\n\
            Tracking ID: {}\n\
            Tracking URL: {}\n\
            Fake SSN: {}\n\
            Fake Account: {}\n",
            self.document_type,
            self.id,
            self.tracking_url,
            self.fake_ssn.as_deref().unwrap_or("N/A"),
            self.fake_account.as_deref().unwrap_or("N/A")
        );

        content.into_bytes()
    }
}

/// Generate a fake but valid-format SSN.
fn generate_fake_ssn() -> String {
    let mut rng = rand::thread_rng();

    // Generate area number (001-899, excluding 666)
    let area = loop {
        let n = rng.gen_range(1..900);
        if n != 666 {
            break n;
        }
    };

    // Group number (01-99)
    let group = rng.gen_range(1..100);

    // Serial number (0001-9999)
    let serial = rng.gen_range(1..10000);

    format!("{:03}-{:02}-{:04}", area, group, serial)
}

/// Generate a fake bank account number.
fn generate_fake_account() -> String {
    let mut rng = rand::thread_rng();

    // Routing number (9 digits, valid format)
    let routing: String = (0..9).map(|_| rng.gen_range(0..10).to_string()).collect();

    // Account number (10-12 digits)
    let length = rng.gen_range(10..=12);
    let account: String = (0..length).map(|_| rng.gen_range(0..10).to_string()).collect();

    format!("Routing: {} Account: {}", routing, account)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_document() {
        let doc = TrapDocument::generate(DocumentType::TaxReturn);
        assert!(doc.filename.contains("Tax_Return"));
        assert!(doc.tracking_url.contains("i1.is"));
        assert!(doc.fake_ssn.is_some());
    }

    #[test]
    fn test_ssn_format() {
        let ssn = generate_fake_ssn();
        assert_eq!(ssn.len(), 11); // XXX-XX-XXXX
        assert_eq!(ssn.chars().filter(|c| *c == '-').count(), 2);
    }

    #[test]
    fn test_document_paths() {
        let doc = TrapDocument::generate(DocumentType::BankStatement);
        assert!(doc.full_path.contains("Financial"));
    }
}
