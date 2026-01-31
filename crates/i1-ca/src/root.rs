//! Root Certificate Authority - AIR-GAPPED ONLY.
//!
//! This module generates and manages the root CA.
//! The root private key should NEVER be on a networked machine.

use chrono::{Duration, Utc};
use rcgen::{BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose};
use std::path::Path;
use uuid::Uuid;

use crate::{CaError, CertificateInfo, CertificateType, KeyAlgorithm, ValidityPeriod};

/// Root Certificate Authority.
///
/// # Security
///
/// The root CA should be generated and stored on an air-gapped machine.
/// It should only be used to sign intermediate CAs.
pub struct RootCa {
    /// Key pair for signing
    key_pair: KeyPair,
    /// The signed certificate
    certificate: Certificate,
    /// Certificate info for tracking
    pub info: CertificateInfo,
    /// PEM-encoded certificate
    cert_pem: String,
    /// PEM-encoded private key (PROTECT THIS)
    key_pem: String,
}

impl RootCa {
    /// Generate a new root CA.
    pub fn generate(common_name: &str, _algorithm: KeyAlgorithm) -> Result<Self, CaError> {
        // Generate key pair
        let key_pair = KeyPair::generate()?;
        let key_pem = key_pair.serialize_pem();

        let mut params = CertificateParams::default();

        // Distinguished Name
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, common_name);
        dn.push(DnType::OrganizationName, "i1.is");
        dn.push(DnType::CountryName, "IS");
        params.distinguished_name = dn;

        // This is a CA
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);

        // Key usage for CA
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

        // Validity: 20 years
        let now = Utc::now();
        params.not_before = time::OffsetDateTime::now_utc();
        params.not_after = time::OffsetDateTime::now_utc()
            + time::Duration::days(ValidityPeriod::Root.days() as i64);

        // Serial number
        let serial = Uuid::new_v4();
        params.serial_number = Some((serial.as_u128() as u64).into());

        // Self-sign the certificate
        let certificate = params.self_signed(&key_pair)?;
        let cert_pem = certificate.pem();

        // Build info
        let info = CertificateInfo {
            id: Uuid::new_v4(),
            serial: format!("{:016x}", serial.as_u128() as u64),
            subject: common_name.to_string(),
            issuer: common_name.to_string(),
            not_before: now,
            not_after: now + Duration::days(ValidityPeriod::Root.days() as i64),
            cert_type: CertificateType::Root,
            revoked: false,
            revocation_reason: None,
        };

        Ok(Self {
            key_pair,
            certificate,
            info,
            cert_pem,
            key_pem,
        })
    }

    /// Get the PEM-encoded certificate.
    pub fn certificate_pem(&self) -> &str {
        &self.cert_pem
    }

    /// Get the PEM-encoded private key.
    pub fn private_key_pem(&self) -> &str {
        &self.key_pem
    }

    /// Save the root CA to files.
    pub fn save_to_files(
        &self,
        key_path: impl AsRef<Path>,
        cert_path: impl AsRef<Path>,
    ) -> Result<(), CaError> {
        std::fs::write(key_path, &self.key_pem)?;
        std::fs::write(cert_path, &self.cert_pem)?;
        Ok(())
    }

    /// Get the key pair for signing.
    pub fn key_pair(&self) -> &KeyPair {
        &self.key_pair
    }

    /// Get the certificate for signing intermediates.
    pub fn certificate(&self) -> &Certificate {
        &self.certificate
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_root_ca() {
        let root = RootCa::generate("Test Root CA", KeyAlgorithm::EcdsaP256).unwrap();

        assert!(root.certificate_pem().contains("BEGIN CERTIFICATE"));
        assert!(root.private_key_pem().contains("PRIVATE KEY"));
        assert_eq!(root.info.cert_type, CertificateType::Root);
        assert!(!root.info.revoked);
    }

    #[test]
    fn test_root_ca_self_signed() {
        let root = RootCa::generate("Test Root", KeyAlgorithm::EcdsaP256).unwrap();
        assert_eq!(root.info.subject, root.info.issuer);
    }
}
