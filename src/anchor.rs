/// DNSSEC trust anchors — the root KSKs published by IANA.
///
/// These DS records anchor the DNSSEC chain of trust. Any validation that
/// reaches the root must terminate by matching a DNSKEY against one of these
/// DS digests. Update when IANA performs a KSK rollover (currently KSK-2017
/// and the in-progress KSK-2024).

use crate::dnssec::ValidationResult;
use crate::proto::{Builder, Record, RType};

/// Hard-coded root trust anchors (IANA, https://data.iana.org/root-anchors/).
pub fn root_anchors() -> Vec<RootAnchor> {
    vec![
        // KSK-2017 — key tag 20326, algorithm 8 (RSASHA256), digest type 2 (SHA-256).
        RootAnchor {
            key_tag: 20326,
            algorithm: 8,
            digest_type: 2,
            digest_hex: "e06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d",
        },
        // KSK-2024 — key tag 38696, algorithm 8, SHA-256.
        RootAnchor {
            key_tag: 38696,
            algorithm: 8,
            digest_type: 2,
            digest_hex: "683d2d0acb8c9b712a1948b27f741219298d0a450d612c483af444a4c0fb2b16",
        },
    ]
}

#[derive(Debug, Clone)]
pub struct RootAnchor {
    pub key_tag:     u16,
    pub algorithm:   u8,
    pub digest_type: u8,
    pub digest_hex:  &'static str,
}

impl RootAnchor {
    /// Build a synthetic DS Record for the root zone matching this anchor.
    pub fn as_ds_record(&self) -> Record {
        let mut b = Builder::new();
        b.u16(self.key_tag);
        b.u8(self.algorithm);
        b.u8(self.digest_type);
        b.raw(&hex::decode(self.digest_hex).expect("static hex"));
        Record {
            name:  ".".to_string(),
            rtype: RType::DS,
            class: crate::proto::CLASS_IN,
            ttl:   172_800,
            rdata: b.finish(),
        }
    }
}

/// Validate that a root-zone DNSKEY RRset chains up to a pinned IANA anchor.
pub fn validate_root_dnskeys(dnskeys: &[Record]) -> ValidationResult {
    let ds_records: Vec<Record> = root_anchors().iter().map(|a| a.as_ds_record()).collect();
    crate::dnssec::Validator::validate_dnskey_with_ds(dnskeys, &ds_records)
}
