/// Zone Signing — DNSSEC zone signing framework
///
/// Features:
/// - RSA-SHA256/SHA512 zone signing
/// - RRSIG record generation
/// - Key tag computation
/// - Signature validity period management

use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};
use crate::proto::{Record, RType, Builder};
use rsa::{RsaPrivateKey, Pkcs1v15Sign};
use rsa::traits::PublicKeyParts;
use sha2::{Sha256, Sha512, Digest};
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey};
use signature::RandomizedDigestSigner; // trait needed for sign_with_rng or just generic usage if any

/// Zone signing key (ZSK) or Key signing key (KSK)
#[derive(Debug, Clone)]
pub struct DnsKey {
    /// Key flags (256=ZSK, 257=KSK)
    pub flags: u16,
    /// Key protocol (must be 3 for DNSSEC)
    pub protocol: u8,
    /// Algorithm (5=RSA-SHA1, 8=RSA-SHA256, 10=RSA-SHA512)
    pub algorithm: u8,
    /// Private key bytes (PEM or raw format)
    pub private_key: Vec<u8>,
    /// Key name (e.g., "example.com.")
    pub key_name: String,
}

impl DnsKey {
    /// Check if this is a Key Signing Key (KSK)
    pub fn is_ksk(&self) -> bool {
        self.flags & 0x0001 != 0
    }

    /// Check if this is a Zone Signing Key (ZSK)
    pub fn is_zsk(&self) -> bool {
        !self.is_ksk()
    }

    /// Load key from PEM file
    /// Parses PEM format to extract private key data
    pub fn from_pem_file(path: &str) -> std::io::Result<Self> {
        let content = fs::read_to_string(path)?;

        // Try parsing to verify it's a valid key and get DER bytes
        // We support both PKCS#1 and PKCS#8 formats

        // Try PKCS#8
        let der = RsaPrivateKey::from_pkcs8_pem(&content)
            .map(|k| k.to_pkcs8_der().unwrap().as_bytes().to_vec())
            .or_else(|_| {
                // Try PKCS#1
                RsaPrivateKey::from_pkcs1_pem(&content)
                    .map(|k| k.to_pkcs1_der().expect("der").as_bytes().to_vec())
            });

        let key_bytes = der.map_err(|e| std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Failed to parse RSA key from {}: {}", path, e)
        ))?;

        Ok(Self {
            flags: 256, // Default to ZSK
            protocol: 3,
            algorithm: 8, // Default to RSA-SHA256
            private_key: key_bytes, // Store as DER
            key_name: path.to_string(),
        })
    }

    fn rsa_private_key(&self) -> std::io::Result<RsaPrivateKey> {
        RsaPrivateKey::from_pkcs8_der(&self.private_key)
            .or_else(|_| RsaPrivateKey::from_pkcs1_der(&self.private_key))
            .map_err(|e| std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Failed to parse private key DER: {}", e)
            ))
    }

    /// DNSKEY RDATA: flags, protocol, algorithm, then the RSA public key in
    /// RFC 3110 form (exponent length, exponent, modulus).
    pub fn dnskey_rdata(&self) -> std::io::Result<Vec<u8>> {
        let public_key = self.rsa_private_key()?.to_public_key();
        let exponent = public_key.e().to_bytes_be();
        let modulus = public_key.n().to_bytes_be();

        let mut rdata = Builder::new();
        rdata.u16(self.flags);
        rdata.u8(self.protocol);
        rdata.u8(self.algorithm);
        if exponent.len() <= 255 {
            rdata.u8(exponent.len() as u8);
        } else {
            rdata.u8(0);
            rdata.u16(exponent.len() as u16);
        }
        rdata.raw(&exponent);
        rdata.raw(&modulus);
        Ok(rdata.finish())
    }

    /// DNSKEY record published at the zone apex.
    pub fn dnskey_record(&self, ttl: u32) -> std::io::Result<Record> {
        Ok(Record {
            name: self.key_name.clone(),
            rtype: RType::DNSKEY,
            class: crate::proto::CLASS_IN,
            ttl,
            rdata: self.dnskey_rdata()?,
        })
    }

    /// Key tag over the DNSKEY RDATA (RFC 4034 Appendix B), as resolvers compute it.
    pub fn key_tag(&self) -> std::io::Result<u16> {
        Ok(compute_key_tag(&self.dnskey_rdata()?))
    }
}

/// DNSSEC zone signer
pub struct ZoneSigner {
    /// Zone signing key (ZSK)
    zsk: DnsKey,
    /// Key signing key (KSK) — optional
    ksk: Option<DnsKey>,
    /// Signature inception (UNIX timestamp)
    inception: u32,
    /// Signature expiration (UNIX timestamp)
    expiration: u32,
}

impl ZoneSigner {
    pub fn new(zsk: DnsKey, ksk: Option<DnsKey>) -> Self {
        // Set validity period: 30 days
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;

        Self {
            zsk,
            ksk,
            // Start an hour back so validators with a slightly slow clock accept it
            inception: now.saturating_sub(3600),
            // The server re-signs daily, long before this runs out
            expiration: now + (30 * 24 * 3600), // 30 days
        }
    }

    /// Sign an RRset and generate RRSIG record
    /// rrset: records to sign (must all have same name, class, type)
    /// zone_name: zone origin
    pub fn sign_rrset(
        &self,
        rrset: &[Record],
        zone_name: &str,
        key_tag: u16,
    ) -> std::io::Result<Record> {
        self.sign_rrset_with_key(&self.zsk, rrset, zone_name, key_tag)
    }

    /// Key signing key, used to sign the apex DNSKEY RRset.
    pub fn ksk(&self) -> Option<&DnsKey> {
        self.ksk.as_ref()
    }

    /// Sign an RRset with an explicit key (the KSK signs the DNSKEY RRset).
    pub fn sign_rrset_with_key(
        &self,
        key: &DnsKey,
        rrset: &[Record],
        zone_name: &str,
        key_tag: u16,
    ) -> std::io::Result<Record> {
        if rrset.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "empty rrset"
            ));
        }

        // Labels in the owner name, not counting the root or a leading wildcard (RFC 4034 §3.1.3)
        let owner = rrset[0].name.trim_end_matches('.');
        let labels = owner.split('.')
            .filter(|label| !label.is_empty())
            .count()
            .saturating_sub(if owner.starts_with("*.") { 1 } else { 0 }) as u8;

        let mut rrsig = crate::proto::Rrsig {
            type_covered:  u16::from(&rrset[0].rtype),
            algorithm:     key.algorithm,
            labels,
            orig_ttl:      rrset[0].ttl,
            sig_expiry:    self.expiration,
            sig_inception: self.inception,
            key_tag,
            signer_name:   zone_name.to_ascii_lowercase(),
            signature:     Vec::new(),
        };

        // Signed data is the RRSIG RDATA without the signature, followed by the
        // canonically ordered RRset (RFC 4034 §6.2) — the same bytes validators rebuild.
        let signed_data = crate::dnssec::build_signed_data(&rrsig, rrset);
        rrsig.signature = self.sign_data(key, &signed_data)?;

        // Build RRSIG record
        let mut rrsig_rdata = Builder::new();
        rrsig_rdata.u16(rrsig.type_covered);          // type covered
        rrsig_rdata.u8(rrsig.algorithm);              // algorithm
        rrsig_rdata.u8(rrsig.labels);                 // labels
        rrsig_rdata.u32(rrsig.orig_ttl);              // original TTL
        rrsig_rdata.u32(rrsig.sig_expiry);            // signature expiration
        rrsig_rdata.u32(rrsig.sig_inception);         // signature inception
        rrsig_rdata.u16(rrsig.key_tag);               // key tag
        rrsig_rdata.name(&rrsig.signer_name);         // signer's name
        rrsig_rdata.raw(&rrsig.signature);            // signature

        Ok(Record {
            name: rrset[0].name.clone(),
            rtype: RType::RRSIG,
            class: rrset[0].class,
            ttl: rrset[0].ttl,
            rdata: rrsig_rdata.finish(),
        })
    }

    /// Sign data with the given key
    /// Implements RSA signing using PKCS#1 v1.5 padding and SHA-256/512
    fn sign_data(&self, key: &DnsKey, data: &[u8]) -> std::io::Result<Vec<u8>> {
        let priv_key = key.rsa_private_key()?;

        // Sign the digest based on algorithm
        if key.algorithm == 8 {
            let mut hasher = Sha256::new();
            hasher.update(data);
            let digest = hasher.finalize();
            let padding = Pkcs1v15Sign::new::<Sha256>();
            priv_key.sign(padding, &digest)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("RSA signing failed: {}", e)))
        } else {
            let mut hasher = Sha512::new();
            hasher.update(data);
            let digest = hasher.finalize();
            let padding = Pkcs1v15Sign::new::<Sha512>();
            priv_key.sign(padding, &digest)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("RSA signing failed: {}", e)))
        }
    }
}

/// Zone signing configuration from TOML
#[derive(Debug, Clone)]
pub struct ZoneSigningConfig {
    /// Enable zone signing
    pub enabled: bool,
    /// Path to ZSK (zone signing key)
    pub zsk_path: Option<String>,
    /// Path to KSK (key signing key)
    pub ksk_path: Option<String>,
    /// Algorithm: 5=RSA-SHA1, 8=RSA-SHA256, 10=RSA-SHA512
    pub algorithm: u8,
    /// TTL for RRSIG records
    pub rrsig_ttl: u32,
}

impl Default for ZoneSigningConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            zsk_path: None,
            ksk_path: None,
            algorithm: 8, // RSA-SHA256
            rrsig_ttl: 86400,
        }
    }
}

/// Key tag calculation (RFC 4034 Appendix B)
pub fn compute_key_tag(dnskey_rdata: &[u8]) -> u16 {
    let mut ac: u32 = 0;
    for (i, &b) in dnskey_rdata.iter().enumerate() {
        ac += if i & 1 == 0 { (b as u32) << 8 } else { b as u32 };
    }
    ac += ac >> 16;
    (ac & 0xFFFF) as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_tag_computation() {
        // Example DNSKEY rdata
        let rdata = vec![
            0x01, 0x00, // flags (257 = KSK)
            0x03,       // protocol
            0x08,       // algorithm (RSA-SHA256)
            // ... public key bytes
        ];
        let tag = compute_key_tag(&rdata);
        assert!(tag > 0);
    }

    #[test]
    fn test_signed_rrset_validates() {
        let private_key = RsaPrivateKey::new(&mut rand::thread_rng(), 1024).unwrap();
        let key = DnsKey {
            flags: 256,
            protocol: 3,
            algorithm: 8,
            private_key: private_key.to_pkcs8_der().unwrap().as_bytes().to_vec(),
            key_name: "example.com".to_string(),
        };
        let record = Record {
            name: "www.example.com".to_string(),
            rtype: RType::A,
            class: crate::proto::CLASS_IN,
            ttl: 300,
            rdata: vec![203, 0, 113, 10],
        };
        let dnskey = key.dnskey_record(3600).unwrap();
        let key_tag = key.key_tag().unwrap();
        let signer = ZoneSigner::new(key, None);
        let rrsig = signer.sign_rrset(&[record.clone()], "example.com", key_tag).unwrap();

        assert_eq!(crate::proto::parse_rrsig(&rrsig.rdata).unwrap().labels, 3);
        assert!(matches!(
            crate::dnssec::Validator::validate_rrset(&[record], &[rrsig], &[dnskey]),
            crate::dnssec::ValidationResult::Secure
        ));
    }

    #[test]
    fn test_zone_signing_config() {
        let cfg = ZoneSigningConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.algorithm, 8); // RSA-SHA256
    }
}
