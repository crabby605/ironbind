/// TSIG — Transaction Signature for DNS (RFC 8945)
///
/// Implements HMAC-SHA256 TSIG signing and verification of DNS messages.
/// The TSIG RR is appended to the additional section of a message and covers
/// the entire wire-format packet (with the TSIG RR itself excluded).

use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::proto::{Builder, Parser, CLASS_ANY};

type HmacSha256 = Hmac<Sha256>;

pub const ALG_HMAC_SHA256: &str = "hmac-sha256.";

/// A named TSIG key.
#[derive(Debug, Clone)]
pub struct TsigKey {
    pub name:      String,   // e.g. "transfer-key."
    pub algorithm: String,   // e.g. "hmac-sha256."
    pub secret:    Vec<u8>,  // raw HMAC secret
}

/// A keyring keyed by TSIG key name (lowercased, trailing-dot normalized).
#[derive(Debug, Default, Clone)]
pub struct TsigKeyring {
    keys: HashMap<String, TsigKey>,
}

impl TsigKeyring {
    pub fn new() -> Self { Self::default() }

    pub fn insert(&mut self, key: TsigKey) {
        self.keys.insert(canonical(&key.name), key);
    }

    pub fn get(&self, name: &str) -> Option<&TsigKey> {
        self.keys.get(&canonical(name))
    }

    pub fn is_empty(&self) -> bool { self.keys.is_empty() }
}

/// Parsed TSIG record contents (RFC 8945 §4.2).
#[derive(Debug, Clone)]
pub struct TsigRdata {
    pub algorithm:   String,
    pub time_signed: u64, // 48-bit
    pub fudge:       u16,
    pub mac:         Vec<u8>,
    pub orig_id:     u16,
    pub error:       u16,
    pub other:       Vec<u8>,
}

/// Append a TSIG RR signing `message` (which must have its ARCOUNT already
/// reflecting the TSIG to follow). Returns the full signed message bytes.
pub fn sign_message(message: &[u8], key: &TsigKey) -> Vec<u8> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let fudge: u16 = 300;

    // Build the MAC preimage: message || RR canonical fields excluding MAC.
    let mut to_sign = Vec::with_capacity(message.len() + 128);
    to_sign.extend_from_slice(message);
    extend_tsig_variables(&mut to_sign, &key.name, &key.algorithm, now, fudge, 0, &[]);

    let mut mac = HmacSha256::new_from_slice(&key.secret).expect("hmac key");
    mac.update(&to_sign);
    let mac_bytes = mac.finalize().into_bytes().to_vec();

    // Now build the TSIG RR and append to message.
    let mut out = message.to_vec();
    let orig_id = u16::from_be_bytes([message[0], message[1]]);
    append_tsig_rr(&mut out, &key.name, &key.algorithm, now, fudge, &mac_bytes, orig_id);
    // Bump ARCOUNT
    let arcount = u16::from_be_bytes([out[10], out[11]]).wrapping_add(1);
    out[10..12].copy_from_slice(&arcount.to_be_bytes());
    out
}

/// Verify a TSIG-signed message. Returns Ok(()) if the MAC validates with a
/// key from the keyring within the fudge window.
pub fn verify_message(message: &[u8], keyring: &TsigKeyring) -> Result<(), String> {
    let (tsig_name, tsig, tsig_rr_offset, arcount) = extract_tsig(message)?;
    let key = keyring.get(&tsig_name).ok_or_else(|| format!("unknown TSIG key {}", tsig_name))?;

    if !canonical(&tsig.algorithm).starts_with("hmac-sha256") {
        return Err(format!("unsupported TSIG algorithm {}", tsig.algorithm));
    }

    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    if (tsig.time_signed as i64 - now as i64).abs() > tsig.fudge as i64 {
        return Err("TSIG time outside fudge window".to_string());
    }

    // Reconstruct preimage: message bytes up to the TSIG RR with ARCOUNT
    // decremented and the original ID restored, then TSIG variables.
    let mut preimage = Vec::with_capacity(tsig_rr_offset + 128);
    preimage.extend_from_slice(&message[..tsig_rr_offset]);
    // Original ID
    preimage[0..2].copy_from_slice(&tsig.orig_id.to_be_bytes());
    // ARCOUNT - 1
    let new_ar = arcount.saturating_sub(1);
    preimage[10..12].copy_from_slice(&new_ar.to_be_bytes());
    extend_tsig_variables(&mut preimage, &tsig_name, &tsig.algorithm, tsig.time_signed, tsig.fudge, tsig.error, &tsig.other);

    let mut mac = HmacSha256::new_from_slice(&key.secret).map_err(|e| e.to_string())?;
    mac.update(&preimage);
    mac.verify_slice(&tsig.mac).map_err(|_| "TSIG MAC mismatch".to_string())
}

fn extract_tsig(message: &[u8]) -> Result<(String, TsigRdata, usize, u16), String> {
    if message.len() < 12 { return Err("message too short".to_string()); }
    let arcount = u16::from_be_bytes([message[10], message[11]]);
    if arcount == 0 { return Err("no additional records".to_string()); }

    // Walk all sections to land just before the last RR (assumed to be TSIG per RFC).
    let qd = u16::from_be_bytes([message[4], message[5]]);
    let an = u16::from_be_bytes([message[6], message[7]]);
    let ns = u16::from_be_bytes([message[8], message[9]]);
    let mut p = Parser::new(message);
    p.pos = 12;
    for _ in 0..qd { let _ = p.name().map_err(|e| e.to_string())?; p.pos += 4; }
    for _ in 0..(an + ns + arcount - 1) { skip_rr(&mut p)?; }

    let tsig_offset = p.pos;
    let name = p.name().map_err(|e| e.to_string())?;
    let rtype = p.u16().map_err(|e| e.to_string())?;
    if rtype != 250 { return Err("last RR is not TSIG".to_string()); }
    let _class = p.u16().map_err(|e| e.to_string())?;
    let _ttl = p.u32().map_err(|e| e.to_string())?;
    let rdlen = p.u16().map_err(|e| e.to_string())? as usize;
    let rdata_start = p.pos;

    let algorithm = p.name().map_err(|e| e.to_string())?;
    // 48-bit time
    let t1 = p.u16().map_err(|e| e.to_string())? as u64;
    let t2 = p.u32().map_err(|e| e.to_string())? as u64;
    let time_signed = (t1 << 32) | t2;
    let fudge = p.u16().map_err(|e| e.to_string())?;
    let mac_len = p.u16().map_err(|e| e.to_string())? as usize;
    let mac_bytes = p.bytes(mac_len).map_err(|e| e.to_string())?;
    let orig_id = p.u16().map_err(|e| e.to_string())?;
    let error = p.u16().map_err(|e| e.to_string())?;
    let other_len = p.u16().map_err(|e| e.to_string())? as usize;
    let other = p.bytes(other_len).map_err(|e| e.to_string())?;
    let _ = (rdlen, rdata_start);

    Ok((name, TsigRdata {
        algorithm, time_signed, fudge, mac: mac_bytes, orig_id, error, other,
    }, tsig_offset, arcount))
}

fn skip_rr(p: &mut Parser) -> Result<(), String> {
    let _ = p.name().map_err(|e| e.to_string())?;
    let _ = p.u16().map_err(|e| e.to_string())?;
    let _ = p.u16().map_err(|e| e.to_string())?;
    let _ = p.u32().map_err(|e| e.to_string())?;
    let rdlen = p.u16().map_err(|e| e.to_string())? as usize;
    p.pos += rdlen;
    Ok(())
}

/// RFC 8945 §5.3.2: the variables hashed for MAC computation.
fn extend_tsig_variables(
    buf: &mut Vec<u8>,
    key_name: &str,
    algorithm: &str,
    time_signed: u64,
    fudge: u16,
    error: u16,
    other: &[u8],
) {
    let mut b = Builder::new();
    b.name(key_name);
    b.u16(CLASS_ANY);
    b.u32(0); // TTL
    b.name(algorithm);
    // 48-bit time
    b.u16(((time_signed >> 32) & 0xFFFF) as u16);
    b.u32((time_signed & 0xFFFF_FFFF) as u32);
    b.u16(fudge);
    b.u16(error);
    b.u16(other.len() as u16);
    b.raw(other);
    buf.extend(b.finish());
}

fn append_tsig_rr(
    out: &mut Vec<u8>,
    key_name: &str,
    algorithm: &str,
    time_signed: u64,
    fudge: u16,
    mac: &[u8],
    orig_id: u16,
) {
    let mut b = Builder::new();
    b.name(key_name);
    b.u16(250); // TYPE TSIG
    b.u16(CLASS_ANY);
    b.u32(0); // TTL
    // rdlen written after building rdata
    let mut rd = Builder::new();
    rd.name(algorithm);
    rd.u16(((time_signed >> 32) & 0xFFFF) as u16);
    rd.u32((time_signed & 0xFFFF_FFFF) as u32);
    rd.u16(fudge);
    rd.u16(mac.len() as u16);
    rd.raw(mac);
    rd.u16(orig_id);
    rd.u16(0); // error
    rd.u16(0); // other len
    let rdata = rd.finish();
    b.u16(rdata.len() as u16);
    b.raw(&rdata);
    out.extend(b.finish());
}

fn canonical(name: &str) -> String {
    let n = name.to_ascii_lowercase();
    if n.ends_with('.') { n } else { format!("{}.", n) }
}
