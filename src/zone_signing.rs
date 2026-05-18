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
            inception: now,
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
        if rrset.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "empty rrset"
            ));
        }

        // Canonical wire format of RRset
        let mut canonical = Vec::new();
        for r in rrset {
            canonical.extend(crate::proto::canonical_rr(r));
        }

        let signature = self.sign_data(&canonical)?;

        // Build RRSIG record
        let mut rrsig_rdata = Builder::new();
        rrsig_rdata.u16(u16::from(&rrset[0].rtype)); // type covered
        rrsig_rdata.u8(self.zsk.algorithm);           // algorithm
        rrsig_rdata.u8(1);                            // labels (zone apex)
        rrsig_rdata.u32(rrset[0].ttl);               // original TTL
        rrsig_rdata.u32(self.expiration);            // signature expiration
        rrsig_rdata.u32(self.inception);             // signature inception
        rrsig_rdata.u16(key_tag);                    // key tag
        rrsig_rdata.name(zone_name);                 // signer's name
        rrsig_rdata.raw(&signature);                 // signature

        Ok(Record {
            name: rrset[0].name.clone(),
            rtype: RType::RRSIG,
            class: rrset[0].class,
            ttl: rrset[0].ttl,
            rdata: rrsig_rdata.finish(),
        })
    }

    /// Sign data with the ZSK
    /// Implements RSA signing using PKCS#1 v1.5 padding and SHA-256/512
    fn sign_data(&self, data: &[u8]) -> std::io::Result<Vec<u8>> {
        // Try to parse private key from DER bytes
        // We attempt PKCS#8 first, then PKCS#1
        let priv_key = RsaPrivateKey::from_pkcs8_der(&self.zsk.private_key)
            .or_else(|_| RsaPrivateKey::from_pkcs1_der(&self.zsk.private_key))
            .map_err(|e| std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Failed to parse private key DER: {}", e)
            ))?;

        // Sign the digest based on algorithm
        if self.zsk.algorithm == 8 {
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
    fn test_zone_signing_config() {
        let cfg = ZoneSigningConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.algorithm, 8); // RSA-SHA256
    }
}
