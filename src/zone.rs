/// Authoritative zone — RFC 1035 zone file parser + in-memory store
use std::{
    collections::{BTreeMap, HashMap},
    fs,
    net::{Ipv4Addr, Ipv6Addr},
    str::FromStr,
};
use crate::proto::{Builder, RType, Record, canonical_name};

// ── Zone store ───────────────────────────────────────────────────────────────

pub struct Zone {
    pub origin: String,
    /// (fqdn_lower, rtype_u16) → rrset
    rrsets: HashMap<(String, u16), Vec<Record>>,
    /// All known names (for NSEC)
    names:  BTreeMap<String, ()>,
}

impl Zone {
    pub fn new(origin: &str) -> Self {
        Self {
            origin: origin.trim_end_matches('.').to_ascii_lowercase(),
            rrsets: HashMap::new(),
            names:  BTreeMap::new(),
        }
    }

    pub fn add(&mut self, r: Record) {
        let key = (r.name.to_ascii_lowercase(), u16::from(&r.rtype));
        self.names.insert(r.name.to_ascii_lowercase(), ());
        self.rrsets.entry(key).or_default().push(r);
    }

    pub fn lookup(&self, name: &str, qtype: &RType) -> Option<&Vec<Record>> {
        let key = (name.to_ascii_lowercase(), u16::from(qtype));
        self.rrsets.get(&key)
    }

    pub fn name_exists(&self, name: &str) -> bool {
        self.names.contains_key(&name.to_ascii_lowercase())
    }

    pub fn is_authoritative_for(&self, name: &str) -> bool {
        let n = name.to_ascii_lowercase();
        n == self.origin || n.ends_with(&format!(".{}", self.origin))
    }

    /// Get SOA record for this zone
    pub fn soa(&self) -> Option<&Vec<Record>> {
        self.lookup(&self.origin.clone(), &RType::SOA)
    }

    /// Iterate every RRset in the zone.
    pub fn iter_rrsets(&self) -> impl Iterator<Item = &Vec<Record>> {
        self.rrsets.values()
    }

    /// All records of a given type for NSEC chain building
    pub fn all_names_sorted(&self) -> Vec<String> {
        self.names.keys().cloned().collect()
    }

    /// NSEC next name for a given name (RFC 4034 §4)
    pub fn nsec_next(&self, name: &str) -> Option<String> {
        let lower = name.to_ascii_lowercase();
        let mut found = false;
        for k in self.names.keys() {
            if found { return Some(k.clone()); }
            if k == &lower { found = true; }
        }
        // Wrap around to first name (last NSEC points to zone apex)
        self.names.keys().next().cloned()
    }

    /// Return the lexicographic predecessor / successor pair (RFC 4034 §6.1)
    /// surrounding `qname`, used to build NSEC denial-of-existence records.
    pub fn nsec_covering(&self, qname: &str) -> Option<(String, String)> {
        let lower = qname.to_ascii_lowercase();
        let names: Vec<&String> = self.names.keys().collect();
        if names.is_empty() { return None; }
        let mut prev = names.last().copied()?.clone();
        for n in &names {
            if n.as_str() > lower.as_str() {
                return Some((prev, (*n).clone()));
            }
            prev = (*n).clone();
        }
        // qname is after all names → wrap to first.
        Some((prev, names.first().copied()?.clone()))
    }

    /// Build the NSEC bitmap of types that exist at `owner` (RFC 4034 §4.1.2).
    pub fn nsec_record(&self, owner: &str, next: &str) -> Option<Record> {
        use crate::proto::Builder;
        let lower = owner.to_ascii_lowercase();
        let types: Vec<u16> = self.rrsets.iter()
            .filter(|((n, _), _)| n == &lower)
            .map(|((_, t), _)| *t)
            .collect();
        if types.is_empty() && owner != &self.origin { return None; }
        let mut b = Builder::new();
        b.name(next);
        b.raw(&encode_nsec_bitmap(&types));
        Some(Record {
            name:  owner.to_string(),
            rtype: RType::NSEC,
            class: crate::proto::CLASS_IN,
            ttl:   3600,
            rdata: b.finish(),
        })
    }
}

/// RFC 4034 §4.1.2 type-bitmap encoding: windowed bitmap of present RR types.
fn encode_nsec_bitmap(types: &[u16]) -> Vec<u8> {
    use std::collections::BTreeMap;
    let mut windows: BTreeMap<u8, [u8; 32]> = BTreeMap::new();
    for &t in types {
        let win = (t >> 8) as u8;
        let bit = (t & 0xFF) as usize;
        let entry = windows.entry(win).or_insert([0u8; 32]);
        entry[bit / 8] |= 0x80 >> (bit % 8);
    }
    let mut out = Vec::new();
    for (win, bits) in windows {
        let used = bits.iter().rposition(|&b| b != 0).map(|i| i + 1).unwrap_or(0);
        if used == 0 { continue; }
        out.push(win);
        out.push(used as u8);
        out.extend_from_slice(&bits[..used]);
    }
    out
}

impl Zone {
    /// Parse the zone's NSEC3PARAM (if any) from the apex.
    pub fn nsec3_params(&self) -> Option<Nsec3Params> {
        let rec = self.lookup(&self.origin.clone(), &RType::NSEC3PARAM)?.first()?;
        Nsec3Params::parse(&rec.rdata)
    }

    /// Build a covering NSEC3 record for `qname`: returns the NSEC3 RR whose
    /// hashed owner immediately precedes hash(qname) in the chain.
    pub fn nsec3_covering(&self, qname: &str) -> Option<Record> {
        let params = self.nsec3_params()?;
        let target_hash = params.hash_name(qname);

        // Collect every NSEC3 RR in the zone, owner is base32hex(hash).origin.
        let mut entries: Vec<(String, Record)> = Vec::new();
        for rrset in self.iter_rrsets() {
            for r in rrset {
                if r.rtype == RType::NSEC3 {
                    let label = r.name.split('.').next().unwrap_or("").to_ascii_uppercase();
                    entries.push((label, r.clone()));
                }
            }
        }
        if entries.is_empty() { return None; }
        entries.sort_by(|a, b| a.0.cmp(&b.0));

        // Walk the sorted chain looking for the NSEC3 that covers target_hash.
        let target_label = base32hex_encode(&target_hash);
        let mut prev = &entries[entries.len() - 1];
        for entry in &entries {
            if entry.0 > target_label { return Some(prev.1.clone()); }
            prev = entry;
        }
        // qname's hash sorts after every entry → wrap.
        Some(prev.1.clone())
    }
}

/// NSEC3PARAM contents (RFC 5155 §4).
#[derive(Debug, Clone)]
pub struct Nsec3Params {
    pub algorithm:  u8,
    pub flags:      u8,
    pub iterations: u16,
    pub salt:       Vec<u8>,
}

impl Nsec3Params {
    pub fn parse(rdata: &[u8]) -> Option<Self> {
        if rdata.len() < 5 { return None; }
        let salt_len = rdata[4] as usize;
        if rdata.len() < 5 + salt_len { return None; }
        Some(Self {
            algorithm:  rdata[0],
            flags:      rdata[1],
            iterations: u16::from_be_bytes([rdata[2], rdata[3]]),
            salt:       rdata[5..5 + salt_len].to_vec(),
        })
    }

    /// RFC 5155 §5: hashed owner = H( name_wire || salt ), iterated.
    pub fn hash_name(&self, name: &str) -> Vec<u8> {
        use sha1::{Digest, Sha1};
        let wire = crate::proto::canonical_name(name);
        let mut hash = {
            let mut h = Sha1::new();
            h.update(&wire);
            h.update(&self.salt);
            h.finalize().to_vec()
        };
        for _ in 0..self.iterations {
            let mut h = Sha1::new();
            h.update(&hash);
            h.update(&self.salt);
            hash = h.finalize().to_vec();
        }
        hash
    }
}

/// Base32hex encoding (RFC 4648 §7) — used for NSEC3 owner names.
fn base32hex_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUV";
    let mut out = String::with_capacity((input.len() * 8 + 4) / 5);
    let mut buf: u32 = 0;
    let mut bits = 0u32;
    for &b in input {
        buf = (buf << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buf >> bits) & 0x1f) as usize;
            out.push(ALPHABET[idx] as char);
        }
    }
    if bits > 0 {
        let idx = ((buf << (5 - bits)) & 0x1f) as usize;
        out.push(ALPHABET[idx] as char);
    }
    out
}

impl Zone {
    // ── Zone file parser ─────────────────────────────────────────────────────

    /// Parse RFC 1035 zone file. Supports:
    ///   $ORIGIN, $TTL directives
    ///   A, AAAA, CNAME, NS, MX, TXT, PTR, SOA, SRV, DNSKEY, DS, RRSIG
    pub fn load_file(&mut self, path: &str) -> std::io::Result<()> {
        let content = fs::read_to_string(path)?;
        let mut default_ttl: u32 = 3600;
        let mut origin = self.origin.clone();
        let mut last_name = origin.clone();

        for raw_line in content.lines() {
            // Strip inline comments
            let line = match raw_line.find(';') {
                Some(i) => &raw_line[..i],
                None    => raw_line,
            };
            let line = line.trim();
            if line.is_empty() { continue; }

            // Directives
            if line.starts_with("$ORIGIN") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if let Some(o) = parts.get(1) {
                    origin = o.trim_end_matches('.').to_ascii_lowercase();
                    self.origin = origin.clone();
                }
                continue;
            }
            if line.starts_with("$TTL") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if let Some(t) = parts.get(1) {
                    default_ttl = parse_ttl(t);
                }
                continue;
            }

            // RR line: [name] [ttl] [class] type rdata...
            let tokens: Vec<&str> = line.split_whitespace().collect();
            if tokens.len() < 2 { continue; }

            let mut idx = 0;

            // Name field — blank means reuse last_name
            let name = if tokens[0].starts_with(|c: char| c.is_alphanumeric() || c == '_' || c == '*' || c == '@') && !is_type(tokens[0]) {
                idx = 1;
                let n = tokens[0];
                let fqdn = if n == "@" {
                    origin.clone()
                } else if n.ends_with('.') {
                    n.trim_end_matches('.').to_ascii_lowercase()
                } else {
                    format!("{}.{}", n.to_ascii_lowercase(), origin)
                };
                last_name = fqdn.clone();
                fqdn
            } else {
                last_name.clone()
            };

            // Optional TTL
            let ttl = if let Some(t) = tokens.get(idx) {
                if let Ok(n) = t.parse::<u32>() { idx += 1; n }
                else if t.ends_with(|c: char| matches!(c, 'h'|'H'|'m'|'M'|'d'|'D'|'w'|'W'|'s'|'S')) {
                    idx += 1; parse_ttl(t)
                } else { default_ttl }
            } else { default_ttl };

            // Optional class (IN/ANY — skip)
            if let Some(cls) = tokens.get(idx) {
                if matches!(cls.to_uppercase().as_str(), "IN" | "ANY" | "CH" | "HS") {
                    idx += 1;
                }
            }

            // Type
            let rtype_str = match tokens.get(idx) {
                Some(t) => { idx += 1; t.to_uppercase() }
                None => continue,
            };

            let rdata_tokens = &tokens[idx..];
            if rdata_tokens.is_empty() { continue; }

            let rdata = match build_rdata(&rtype_str, rdata_tokens, &origin) {
                Some(r) => r,
                None => {
                    eprintln!("[zone] unsupported/parse error: {} {} {:?}", name, rtype_str, rdata_tokens);
                    continue;
                }
            };

            let rtype = str_to_rtype(&rtype_str);
            self.add(Record { name, rtype, class: 1, ttl, rdata });
        }

        eprintln!("[zone] loaded {} rrsets from {}", self.rrsets.len(), path);
        Ok(())
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn is_type(s: &str) -> bool {
    matches!(s.to_uppercase().as_str(),
        "A"|"AAAA"|"NS"|"CNAME"|"SOA"|"PTR"|"MX"|"TXT"|
        "SRV"|"NAPTR"|"DS"|"DNSKEY"|"RRSIG"|"NSEC"|"NSEC3"|"CAA")
}

fn parse_ttl(s: &str) -> u32 {
    let (num, mult): (&str, u32) = match s.chars().last() {
        Some('s') | Some('S') => (&s[..s.len()-1], 1),
        Some('m') | Some('M') => (&s[..s.len()-1], 60),
        Some('h') | Some('H') => (&s[..s.len()-1], 3600),
        Some('d') | Some('D') => (&s[..s.len()-1], 86400),
        Some('w') | Some('W') => (&s[..s.len()-1], 604800),
        _ => (s, 1),
    };
    num.parse::<u32>().unwrap_or(3600) * mult
}

fn str_to_rtype(s: &str) -> RType {
    match s {
        "A"      => RType::A,
        "AAAA"   => RType::AAAA,
        "NS"     => RType::NS,
        "CNAME"  => RType::CNAME,
        "SOA"    => RType::SOA,
        "PTR"    => RType::PTR,
        "MX"     => RType::MX,
        "TXT"    => RType::TXT,
        "SRV"    => RType::SRV,
        "DS"     => RType::DS,
        "DNSKEY" => RType::DNSKEY,
        "RRSIG"  => RType::RRSIG,
        "NSEC"   => RType::NSEC,
        _        => RType::Unknown(0),
    }
}

fn fqdn(name: &str, origin: &str) -> String {
    let n = name.trim_end_matches('.');
    if n == "@" { return origin.to_string(); }
    if name.ends_with('.') {
        n.to_ascii_lowercase()
    } else {
        format!("{}.{}", n.to_ascii_lowercase(), origin)
    }
}

fn encode_name(name: &str) -> Vec<u8> {
    canonical_name(name)
}

fn build_rdata(rtype: &str, tokens: &[&str], origin: &str) -> Option<Vec<u8>> {
    match rtype {
        "A" => {
            let ip = Ipv4Addr::from_str(tokens[0]).ok()?;
            Some(ip.octets().to_vec())
        }
        "AAAA" => {
            let ip = Ipv6Addr::from_str(tokens[0]).ok()?;
            Some(ip.octets().to_vec())
        }
        "NS" | "CNAME" | "PTR" => {
            Some(encode_name(&fqdn(tokens[0], origin)))
        }
        "MX" => {
            let pref: u16 = tokens[0].parse().ok()?;
            let mut b = Builder::new();
            b.u16(pref);
            b.name(&fqdn(tokens[1], origin));
            Some(b.finish())
        }
        "SOA" => {
            // mname rname serial refresh retry expire minimum
            if tokens.len() < 7 { return None; }
            let mut b = Builder::new();
            b.name(&fqdn(tokens[0], origin));
            b.name(&fqdn(tokens[1], origin));
            b.u32(tokens[2].parse().ok()?);
            b.u32(parse_ttl(tokens[3]));
            b.u32(parse_ttl(tokens[4]));
            b.u32(parse_ttl(tokens[5]));
            b.u32(parse_ttl(tokens[6]));
            Some(b.finish())
        }
        "TXT" => {
            // Join all tokens, strip quotes
            let joined = tokens.join(" ");
            let text = joined.trim_matches('"');
            // Each string segment ≤255 bytes
            let bytes = text.as_bytes();
            let mut out = Vec::new();
            for chunk in bytes.chunks(255) {
                out.push(chunk.len() as u8);
                out.extend_from_slice(chunk);
            }
            Some(out)
        }
        "SRV" => {
            // priority weight port target
            if tokens.len() < 4 { return None; }
            let mut b = Builder::new();
            b.u16(tokens[0].parse().ok()?);
            b.u16(tokens[1].parse().ok()?);
            b.u16(tokens[2].parse().ok()?);
            b.name(&fqdn(tokens[3], origin));
            Some(b.finish())
        }
        "DS" => {
            // key-tag algorithm digest-type digest-hex
            if tokens.len() < 4 { return None; }
            let mut b = Builder::new();
            b.u16(tokens[0].parse().ok()?);
            b.u8(tokens[1].parse().ok()?);
            b.u8(tokens[2].parse().ok()?);
            let digest = hex_decode(tokens[3])?;
            b.raw(&digest);
            Some(b.finish())
        }
        "DNSKEY" => {
            // flags protocol algorithm pubkey-base64
            if tokens.len() < 4 { return None; }
            let mut b = Builder::new();
            b.u16(tokens[0].parse().ok()?);
            b.u8(tokens[1].parse().ok()?);
            b.u8(tokens[2].parse().ok()?);
            let key = base64_decode(&tokens[3..].join(""))?;
            b.raw(&key);
            Some(b.finish())
        }
        _ => None,
    }
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.replace(' ', "");
    if s.len() % 2 != 0 { return None; }
    (0..s.len()).step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i+2], 16).ok())
        .collect()
}

/// Minimal base64 decoder (no deps)
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    let val = |c: u8| -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            b'=' => Some(0),
            _ => None,
        }
    };
    let bytes = s.as_bytes();
    if bytes.len() % 4 != 0 { return None; }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let a = val(chunk[0])?;
        let b = val(chunk[1])?;
        let c = val(chunk[2])?;
        let d = val(chunk[3])?;
        let n = ((a as u32) << 18) | ((b as u32) << 12) | ((c as u32) << 6) | (d as u32);
        out.push((n >> 16) as u8);
        if chunk[2] != b'=' { out.push((n >> 8) as u8); }
        if chunk[3] != b'=' { out.push(n as u8); }
    }
    Some(out)
}
