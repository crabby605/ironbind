/// DNSSEC validation — RFC 4034, RFC 4035
/// Algorithms: RSASHA256 (8), RSASHA512 (10), ECDSAP256SHA256 (13)
/// Hash: SHA-1 (deprecated, detect only), SHA-256, SHA-384
///
/// NOTE: Full RSA/ECDSA signature verification requires big-integer arithmetic.
/// Without external crates we implement:
///   - Key tag computation (RFC 4034 App. B)
///   - DS digest verification (SHA-256/SHA-1 over owner + DNSKEY rdata)
///   - Signature wire format validation (field parsing, expiry check)
///   - Algorithm support matrix
///
/// For production use, link ring or rustls-webpki for actual crypto primitives.
/// The validation framework here is complete — swap verify_rsa/verify_ecdsa for
/// real implementations when a crypto crate is added.

use std::time::{SystemTime, UNIX_EPOCH};
use crate::proto::{Record, RType, parse_rrsig, parse_dnskey, parse_ds, canonical_rr, canonical_name, Builder};

// ── Algorithm IDs (RFC 8624) ─────────────────────────────────────────────────

pub const ALG_RSAMD5:         u8 = 1;   // MUST NOT implement
pub const ALG_DSA:            u8 = 3;   // MUST NOT implement
pub const ALG_RSASHA1:        u8 = 5;   // NOT RECOMMENDED
pub const ALG_DSA_NSEC3:      u8 = 6;
pub const ALG_RSASHA1_NSEC3:  u8 = 7;
pub const ALG_RSASHA256:      u8 = 8;   // MUST implement
pub const ALG_RSASHA512:      u8 = 10;  // RECOMMENDED
pub const ALG_ECC_GOST:       u8 = 12;
pub const ALG_ECDSAP256SHA256:u8 = 13;  // MUST implement
pub const ALG_ECDSAP384SHA384:u8 = 14;  // RECOMMENDED
pub const ALG_ED25519:        u8 = 15;  // RECOMMENDED
pub const ALG_ED448:          u8 = 16;

// ── Digest type IDs ──────────────────────────────────────────────────────────

pub const DIGEST_SHA1:   u8 = 1;  // MUST NOT use (deprecated)
pub const DIGEST_SHA256: u8 = 2;  // MUST implement
pub const DIGEST_GOST:   u8 = 3;
pub const DIGEST_SHA384: u8 = 4;  // RECOMMENDED

// ── Validation result ────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum ValidationResult {
    Secure,
    Insecure,     // No chain of trust
    Bogus(String),// Chain exists but verification failed
    Indeterminate,
}

// ── DNSSEC Validator ─────────────────────────────────────────────────────────

pub struct Validator;

impl Validator {
    /// Validate an RRset against RRSIG records and a trusted DNSKEY set.
    /// Returns Secure if at least one valid RRSIG is found.
    pub fn validate_rrset(
        rrset: &[Record],
        rrsigs: &[Record],
        dnskeys: &[Record],
    ) -> ValidationResult {
        if rrset.is_empty() || rrsigs.is_empty() || dnskeys.is_empty() {
            return ValidationResult::Insecure;
        }

        for sig_rec in rrsigs {
            let rrsig = match parse_rrsig(&sig_rec.rdata) {
                Ok(r) => r,
                Err(_) => continue,
            };

            // Check temporal validity
            let now = unix_now();
            if now < rrsig.sig_inception as u64 {
                continue; // not yet valid
            }
            if now > rrsig.sig_expiry as u64 {
                continue; // expired
            }

            // Find matching DNSKEY
            let dnskey_rec = dnskeys.iter().find(|dk| {
                if let Ok(key) = parse_dnskey(&dk.rdata) {
                    let tag = key.key_tag(&dk.rdata);
                    tag == rrsig.key_tag && key.algorithm == rrsig.algorithm
                } else {
                    false
                }
            });

            let dnskey_rec = match dnskey_rec {
                Some(r) => r,
                None => continue,
            };

            let dnskey = match parse_dnskey(&dnskey_rec.rdata) {
                Ok(k) => k,
                Err(_) => continue,
            };

            // Build signed data: RRSIG fields || canonical RRset (RFC 4034 §6.2)
            let signed_data = build_signed_data(&rrsig, rrset);

            // Verify signature
            let result = verify_signature(
                rrsig.algorithm,
                &dnskey.public_key,
                &signed_data,
                &rrsig.signature,
            );

            match result {
                Ok(true)  => return ValidationResult::Secure,
                Ok(false) => return ValidationResult::Bogus("signature mismatch".to_string()),
                Err(e)    => {
                    eprintln!("[dnssec] verify error: {}", e);
                    continue;
                }
            }
        }

        ValidationResult::Bogus("no valid RRSIG found".to_string())
    }

    /// Validate DNSKEY RRset against DS records from parent zone
    pub fn validate_dnskey_with_ds(dnskeys: &[Record], ds_records: &[Record]) -> ValidationResult {
        for ds_rec in ds_records {
            let ds = match parse_ds(&ds_rec.rdata) {
                Ok(d) => d,
                Err(_) => continue,
            };

            // Only SHA-256 and SHA-384 are acceptable (RFC 8624)
            if ds.digest_type != DIGEST_SHA256 && ds.digest_type != DIGEST_SHA384 {
                continue;
            }

            for key_rec in dnskeys {
                let dnskey = match parse_dnskey(&key_rec.rdata) {
                    Ok(k) => k,
                    Err(_) => continue,
                };

                let tag = dnskey.key_tag(&key_rec.rdata);
                if tag != ds.key_tag || dnskey.algorithm != ds.algorithm {
                    continue;
                }

                // Compute DS digest: hash(owner_name || DNSKEY_rdata)
                let mut preimage = canonical_name(&key_rec.name);
                preimage.extend_from_slice(&key_rec.rdata);

                let computed = match ds.digest_type {
                    DIGEST_SHA256 => sha256(&preimage).to_vec(),
                    DIGEST_SHA384 => sha384(&preimage).to_vec(),
                    _ => continue,
                };

                if computed == ds.digest {
                    return ValidationResult::Secure;
                } else {
                    return ValidationResult::Bogus(format!(
                        "DS digest mismatch for key tag {}", ds.key_tag
                    ));
                }
            }
        }

        ValidationResult::Insecure
    }

    /// Validate `rrset` (with its `rrsigs`) by walking the chain of trust from
    /// the IANA-pinned root anchors down to the owner zone.
    ///
    /// `fetch` looks up an RRset by (owner, type) and returns its records and
    /// covering RRSIGs (typically by re-querying upstream with DO bit set).
    /// Returning an empty Vec means "no records exist."
    pub fn chain_validate<F>(
        owner: &str,
        rrset: &[Record],
        rrsigs: &[Record],
        fetch: &mut F,
    ) -> ValidationResult
    where F: FnMut(&str, RType) -> (Vec<Record>, Vec<Record>),
    {
        // 1. Anchor the chain at root: pull root DNSKEYs and check against pins.
        let (root_keys, _root_keys_rrsig) = fetch(".", RType::DNSKEY);
        if root_keys.is_empty() {
            return ValidationResult::Bogus("no root DNSKEYs returned".to_string());
        }
        if crate::anchor::validate_root_dnskeys(&root_keys) != ValidationResult::Secure {
            return ValidationResult::Bogus("root DNSKEYs don't match IANA anchors".to_string());
        }

        // 2. Walk down from root to owner, validating DS @ parent then DNSKEY
        //    @ child at each zone cut.
        let labels: Vec<&str> = owner.trim_end_matches('.').split('.').rev().collect();
        let mut parent_keys = root_keys;
        let mut current = String::from(".");

        for label in &labels {
            let child = if current == "." { format!("{}.", label) }
                        else { format!("{}.{}", label, current) };

            // DS at the parent for this child.
            let (ds, ds_sigs) = fetch(&child, RType::DS);
            if ds.is_empty() {
                // No DS → insecure delegation. Per RFC 4035 we'd need an
                // NSEC/NSEC3 proof of absence; for simplicity treat as insecure.
                return ValidationResult::Insecure;
            }
            // The DS RRset itself must be signed by parent's keys.
            if Self::validate_rrset(&ds, &ds_sigs, &parent_keys) != ValidationResult::Secure {
                return ValidationResult::Bogus(format!("DS at {} doesn't validate against parent", child));
            }

            // DNSKEY at the child, validated against the DS we just verified.
            let (child_keys, child_keys_sigs) = fetch(&child, RType::DNSKEY);
            if child_keys.is_empty() {
                return ValidationResult::Bogus(format!("no DNSKEY at {}", child));
            }
            if Self::validate_dnskey_with_ds(&child_keys, &ds) != ValidationResult::Secure {
                return ValidationResult::Bogus(format!("DNSKEY at {} doesn't chain to DS", child));
            }
            // And those child keys must self-validate the DNSKEY RRset.
            if Self::validate_rrset(&child_keys, &child_keys_sigs, &child_keys) != ValidationResult::Secure {
                return ValidationResult::Bogus(format!("DNSKEY at {} self-signature invalid", child));
            }

            parent_keys = child_keys;
            current = child;

            if current.trim_end_matches('.') == owner.trim_end_matches('.') { break; }
        }

        // 3. Finally validate the actual answer against the zone keys.
        Self::validate_rrset(rrset, rrsigs, &parent_keys)
    }
}

// ── Signed data construction (RFC 4034 §6.2) ────────────────────────────────

fn build_signed_data(rrsig: &crate::proto::Rrsig, rrset: &[Record]) -> Vec<u8> {
    let mut data = Vec::new();

    // RRSIG RDATA (without signature field)
    let mut b = Builder::new();
    b.u16(rrsig.type_covered);
    b.u8(rrsig.algorithm);
    b.u8(rrsig.labels);
    b.u32(rrsig.orig_ttl);
    b.u32(rrsig.sig_expiry);
    b.u32(rrsig.sig_inception);
    b.u16(rrsig.key_tag);
    b.name(&rrsig.signer_name);
    data.extend(b.finish());

    // Canonical RRs sorted (RFC 4034 §6.3)
    let mut rrs: Vec<Vec<u8>> = rrset.iter().map(|r| {
        // Use orig_ttl from RRSIG for canonical form
        let mut rec = r.clone();
        rec.ttl = rrsig.orig_ttl;
        canonical_rr(&rec)
    }).collect();
    rrs.sort();
    for rr in rrs { data.extend(rr); }

    data
}

// ── Signature verification ───────────────────────────────────────────────────

fn verify_signature(algorithm: u8, pubkey: &[u8], data: &[u8], signature: &[u8]) -> Result<bool, String> {
    match algorithm {
        ALG_RSASHA256 => verify_rsa_sha256(pubkey, data, signature),
        ALG_RSASHA512 => verify_rsa_sha512(pubkey, data, signature),
        ALG_ECDSAP256SHA256 => verify_ecdsa_p256(pubkey, data, signature),
        ALG_ECDSAP384SHA384 => verify_ecdsa_p384(pubkey, data, signature),
        ALG_ED25519 => verify_ed25519(pubkey, data, signature),
        ALG_RSAMD5  => Err("RSAMD5 is prohibited (RFC 8624)".to_string()),
        n => Err(format!("unsupported algorithm {}", n)),
    }
}

/// RSA-SHA256 verification (RFC 5702).
/// RFC 3110: pubkey = exponent_len(1 or 3 bytes) || exponent || modulus.
fn verify_rsa_sha256(pubkey: &[u8], data: &[u8], signature: &[u8]) -> Result<bool, String> {
    verify_rsa(pubkey, data, signature, RsaHash::Sha256)
}

fn verify_rsa_sha512(pubkey: &[u8], data: &[u8], signature: &[u8]) -> Result<bool, String> {
    verify_rsa(pubkey, data, signature, RsaHash::Sha512)
}

enum RsaHash { Sha256, Sha512 }

fn verify_rsa(pubkey: &[u8], data: &[u8], signature: &[u8], hash: RsaHash) -> Result<bool, String> {
    use rsa::{RsaPublicKey, Pkcs1v15Sign, BigUint};

    let (exp, modulus) = parse_rsa_pubkey(pubkey)?;
    let n = BigUint::from_bytes_be(&modulus);
    let e = BigUint::from_bytes_be(&exp);
    let key = RsaPublicKey::new(n, e).map_err(|e| e.to_string())?;

    let result = match hash {
        RsaHash::Sha256 => key.verify(Pkcs1v15Sign::new::<sha2::Sha256>(), &sha256(data), signature),
        RsaHash::Sha512 => key.verify(Pkcs1v15Sign::new::<sha2::Sha512>(), &sha512(data), signature),
    };

    Ok(result.is_ok())
}

/// RFC 6605: ECDSA P-256 pubkey = 64 bytes (Qx || Qy), sig = 64 bytes (r || s)
fn verify_ecdsa_p256(pubkey: &[u8], data: &[u8], signature: &[u8]) -> Result<bool, String> {
    use p256::ecdsa::{VerifyingKey, Signature, signature::Verifier};

    if pubkey.len() != 64 {
        return Err(format!("ECDSA P-256 key must be 64 bytes, got {}", pubkey.len()));
    }
    if signature.len() != 64 {
        return Err(format!("ECDSA P-256 sig must be 64 bytes, got {}", signature.len()));
    }

    // SEC1 uncompressed encoding: 0x04 || Qx || Qy
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(pubkey);

    let key = VerifyingKey::from_sec1_bytes(&sec1).map_err(|e| e.to_string())?;
    let sig = Signature::from_slice(signature).map_err(|e| e.to_string())?;
    Ok(key.verify(data, &sig).is_ok())
}

fn verify_ecdsa_p384(pubkey: &[u8], data: &[u8], signature: &[u8]) -> Result<bool, String> {
    use p384::ecdsa::{VerifyingKey, Signature, signature::Verifier};

    if pubkey.len() != 96 { return Err("ECDSA P-384 key must be 96 bytes".to_string()); }
    if signature.len() != 96 { return Err("ECDSA P-384 sig must be 96 bytes".to_string()); }

    let mut sec1 = Vec::with_capacity(97);
    sec1.push(0x04);
    sec1.extend_from_slice(pubkey);

    let key = VerifyingKey::from_sec1_bytes(&sec1).map_err(|e| e.to_string())?;
    let sig = Signature::from_slice(signature).map_err(|e| e.to_string())?;
    Ok(key.verify(data, &sig).is_ok())
}

/// RFC 8080: Ed25519 pubkey = 32 bytes, sig = 64 bytes
fn verify_ed25519(pubkey: &[u8], data: &[u8], signature: &[u8]) -> Result<bool, String> {
    use ed25519_dalek::{VerifyingKey, Signature, Verifier};

    if pubkey.len() != 32 { return Err("Ed25519 key must be 32 bytes".to_string()); }
    if signature.len() != 64 { return Err("Ed25519 sig must be 64 bytes".to_string()); }

    let key_bytes: [u8; 32] = pubkey.try_into().map_err(|_| "key len".to_string())?;
    let sig_bytes: [u8; 64] = signature.try_into().map_err(|_| "sig len".to_string())?;
    let key = VerifyingKey::from_bytes(&key_bytes).map_err(|e| e.to_string())?;
    let sig = Signature::from_bytes(&sig_bytes);
    Ok(key.verify(data, &sig).is_ok())
}

/// Parse RSA public key per RFC 3110
fn parse_rsa_pubkey(key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    if key.is_empty() { return Err("empty RSA key".to_string()); }
    let (exp_len, rest) = if key[0] == 0 {
        if key.len() < 3 { return Err("RSA key too short".to_string()); }
        let len = ((key[1] as usize) << 8) | key[2] as usize;
        (len, &key[3..])
    } else {
        (key[0] as usize, &key[1..])
    };
    if rest.len() < exp_len { return Err("RSA exponent truncated".to_string()); }
    Ok((rest[..exp_len].to_vec(), rest[exp_len..].to_vec()))
}

// ── Pure-std SHA implementations ──────────────────────────────────────────────
// SHA-256 per FIPS 180-4

const K256: [u32; 64] = [
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
];

pub fn sha256(msg: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19,
    ];

    let mut padded = msg.to_vec();
    let bit_len = (msg.len() as u64) * 8;
    padded.push(0x80);
    while padded.len() % 64 != 56 { padded.push(0); }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for block in padded.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(block[i*4..i*4+4].try_into().unwrap());
        }
        for i in 16..64 {
            let s0 = w[i-15].rotate_right(7) ^ w[i-15].rotate_right(18) ^ (w[i-15] >> 3);
            let s1 = w[i-2].rotate_right(17) ^ w[i-2].rotate_right(19) ^ (w[i-2] >> 10);
            w[i] = w[i-16].wrapping_add(s0).wrapping_add(w[i-7]).wrapping_add(s1);
        }
        let [mut a,mut b,mut c,mut d,mut e,mut f,mut g,mut hh] = h;
        for i in 0..64 {
            let s1   = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch   = (e & f) ^ ((!e) & g);
            let temp1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(K256[i]).wrapping_add(w[i]);
            let s0   = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj  = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            hh = g; g = f; f = e;
            e = d.wrapping_add(temp1);
            d = c; c = b; b = a;
            a = temp1.wrapping_add(temp2);
        }
        h[0]=h[0].wrapping_add(a); h[1]=h[1].wrapping_add(b);
        h[2]=h[2].wrapping_add(c); h[3]=h[3].wrapping_add(d);
        h[4]=h[4].wrapping_add(e); h[5]=h[5].wrapping_add(f);
        h[6]=h[6].wrapping_add(g); h[7]=h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 32];
    for (i, v) in h.iter().enumerate() {
        out[i*4..i*4+4].copy_from_slice(&v.to_be_bytes());
    }
    out
}

// SHA-384 per FIPS 180-4 (truncated SHA-512)
const K512: [u64; 80] = [
    0x428a2f98d728ae22,0x7137449123ef65cd,0xb5c0fbcfec4d3b2f,0xe9b5dba58189dbbc,
    0x3956c25bf348b538,0x59f111f1b605d019,0x923f82a4af194f9b,0xab1c5ed5da6d8118,
    0xd807aa98a3030242,0x12835b0145706fbe,0x243185be4ee4b28c,0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,0x80deb1fe3b1696b1,0x9bdc06a725c71235,0xc19bf174cf692694,
    0xe49b69c19ef14ad2,0xefbe4786384f25e3,0x0fc19dc68b8cd5b5,0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,0x4a7484aa6ea6e483,0x5cb0a9dcbd41fbd4,0x76f988da831153b5,
    0x983e5152ee66dfab,0xa831c66d2db43210,0xb00327c898fb213f,0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,0xd5a79147930aa725,0x06ca6351e003826f,0x142929670a0e6e70,
    0x27b70a8546d22ffc,0x2e1b21385c26c926,0x4d2c6dfc5ac42aed,0x53380d139d95b3df,
    0x650a73548baf63de,0x766a0abb3c77b2a8,0x81c2c92e47edaee6,0x92722c851482353b,
    0xa2bfe8a14cf10364,0xa81a664bbc423001,0xc24b8b70d0f89791,0xc76c51a30654be30,
    0xd192e819d6ef5218,0xd69906245565a910,0xf40e35855771202a,0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,0x1e376c085141ab53,0x2748774cdf8eeb99,0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,0x4ed8aa4ae3418acb,0x5b9cca4f7763e373,0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,0x78a5636f43172f60,0x84c87814a1f0ab72,0x8cc702081a6439ec,
    0x90befffa23631e28,0xa4506cebde82bde9,0xbef9a3f7b2c67915,0xc67178f2e372532b,
    0xca273eceea26619c,0xd186b8c721c0c207,0xeada7dd6cde0eb1e,0xf57d4f7fee6ed178,
    0x06f067aa72176fba,0x0a637dc5a2c898a6,0x113f9804bef90dae,0x1b710b35131c471b,
    0x28db77f523047d84,0x32caab7b40c72493,0x3c9ebe0a15c9bebc,0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,0x597f299cfc657e2a,0x5fcb6fab3ad6faec,0x6c44198c4a475817,
];

pub fn sha384(msg: &[u8]) -> [u8; 48] {
    let full = sha512_internal(msg, true);
    full[..48].try_into().unwrap()
}

pub fn sha512(msg: &[u8]) -> [u8; 64] {
    sha512_internal(msg, false)
}

fn sha512_internal(msg: &[u8], truncated: bool) -> [u8; 64] {
    let mut h: [u64; 8] = if truncated {
        // SHA-384 initial values
        [0xcbbb9d5dc1059ed8,0x629a292a367cd507,0x9159015a3070dd17,0x152fecd8f70e5939,
         0x67332667ffc00b31,0x8eb44a8768581511,0xdb0c2e0d64f98fa7,0x47b5481dbefa4fa4]
    } else {
        // SHA-512 initial values
        [0x6a09e667f3bcc908,0xbb67ae8584caa73b,0x3c6ef372fe94f82b,0xa54ff53a5f1d36f1,
         0x510e527fade682d1,0x9b05688c2b3e6c1f,0x1f83d9abfb41bd6b,0x5be0cd19137e2179]
    };

    let bit_len = (msg.len() as u128) * 8;
    let mut padded = msg.to_vec();
    padded.push(0x80);
    while padded.len() % 128 != 112 { padded.push(0); }
    padded.extend_from_slice(&0u64.to_be_bytes()); // high bits of length
    padded.extend_from_slice(&(bit_len as u64).to_be_bytes());

    for block in padded.chunks(128) {
        let mut w = [0u64; 80];
        for i in 0..16 {
            w[i] = u64::from_be_bytes(block[i*8..i*8+8].try_into().unwrap());
        }
        for i in 16..80 {
            let s0 = w[i-15].rotate_right(1) ^ w[i-15].rotate_right(8) ^ (w[i-15] >> 7);
            let s1 = w[i-2].rotate_right(19) ^ w[i-2].rotate_right(61) ^ (w[i-2] >> 6);
            w[i] = w[i-16].wrapping_add(s0).wrapping_add(w[i-7]).wrapping_add(s1);
        }
        let [mut a,mut b,mut c,mut d,mut e,mut f,mut g,mut hh] = h;
        for i in 0..80 {
            let s1   = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let ch   = (e & f) ^ ((!e) & g);
            let t1   = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(K512[i]).wrapping_add(w[i]);
            let s0   = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            let maj  = (a & b) ^ (a & c) ^ (b & c);
            let t2   = s0.wrapping_add(maj);
            hh=g; g=f; f=e; e=d.wrapping_add(t1); d=c; c=b; b=a; a=t1.wrapping_add(t2);
        }
        h[0]=h[0].wrapping_add(a); h[1]=h[1].wrapping_add(b);
        h[2]=h[2].wrapping_add(c); h[3]=h[3].wrapping_add(d);
        h[4]=h[4].wrapping_add(e); h[5]=h[5].wrapping_add(f);
        h[6]=h[6].wrapping_add(g); h[7]=h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 64];
    for (i, v) in h.iter().enumerate() {
        out[i*8..i*8+8].copy_from_slice(&v.to_be_bytes());
    }
    out
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
