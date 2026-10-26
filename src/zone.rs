/// Authoritative zone — RFC 1035 zone file parser + in-memory store
use std::{
    cmp::Ordering,
    collections::{BTreeMap, HashMap},
    fs,
    net::{Ipv4Addr, Ipv6Addr},
    str::FromStr,
};
use crate::proto::{Builder, RType, Record, canonical_name};

pub struct Zone {
    pub origin: String,
    /// (fqdn_lower, rtype_u16) → rrset
    rrsets: HashMap<(String, u16), Vec<Record>>,
    /// All known names (for NSEC)
    names:  BTreeMap<String, ()>,
    /// NSEC chain owners in canonical order; empty for an unsigned zone
    nsec_owners: Vec<String>,
}

impl Zone {
    pub fn new(origin: &str) -> Self {
        Self {
            origin: origin.trim_end_matches('.').to_ascii_lowercase(),
            rrsets: HashMap::new(),
            names:  BTreeMap::new(),
            nsec_owners: Vec::new(),
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

    /// True for names that own records and for empty non-terminals
    /// (e.g. `_tcp.example.com` when only `_http._tcp.example.com` exists),
    /// which must answer NODATA rather than NXDOMAIN (RFC 8020).
    pub fn name_exists(&self, name: &str) -> bool {
        let lower = name.to_ascii_lowercase();
        let descendant_suffix = format!(".{}", lower);
        self.names.contains_key(&lower)
            || self.names.keys().any(|existing| existing.ends_with(&descendant_suffix))
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

    /// Build the NSEC chain (RFC 4034 §4) over every owner name, in canonical
    /// order, so it can be signed with the rest of the zone. Each NSEC lists the
    /// types at its owner plus the RRSIG and NSEC records signing adds.
    pub fn build_nsec_chain(&mut self, ttl: u32) {
        let mut owners: Vec<String> = self.names.keys().cloned().collect();
        owners.sort_by(|a, b| canonical_order(a, b));
        for (index, owner) in owners.iter().enumerate() {
            let next = &owners[(index + 1) % owners.len()];
            let mut types: Vec<u16> = self.rrsets.keys()
                .filter(|(name, _)| name == owner)
                .map(|(_, rtype)| *rtype)
                .collect();
            types.extend([u16::from(&RType::RRSIG), u16::from(&RType::NSEC)]);
            let mut rdata = Builder::new();
            rdata.name(next);
            rdata.raw(&encode_nsec_bitmap(&types));
            self.add(Record {
                name:  owner.clone(),
                rtype: RType::NSEC,
                class: crate::proto::CLASS_IN,
                ttl,
                rdata: rdata.finish(),
            });
        }
        self.nsec_owners = owners;
    }

    /// True once the zone carries a signed NSEC chain.
    pub fn is_signed(&self) -> bool {
        !self.nsec_owners.is_empty()
    }

    /// Owner of the NSEC that proves `name` does not exist: the last owner that
    /// sorts before it canonically, wrapping to the final owner (RFC 4034 §6.1).
    pub fn nsec_covering_owner(&self, name: &str) -> Option<&str> {
        let position = self.nsec_owners.partition_point(|owner| canonical_order(owner, name) == Ordering::Less);
        let index = if position == 0 { self.nsec_owners.len().checked_sub(1)? } else { position - 1 };
        self.nsec_owners.get(index).map(String::as_str)
    }

    /// Longest ancestor of `name` that exists in the zone (RFC 4592 §3.3.1).
    pub fn closest_encloser(&self, name: &str) -> String {
        let mut candidate = name.to_ascii_lowercase();
        while candidate != self.origin {
            match candidate.split_once('.') {
                Some((_, parent)) => candidate = parent.to_string(),
                None => return self.origin.clone(),
            }
            if self.name_exists(&candidate) { return candidate; }
        }
        candidate
    }
}

/// DNSSEC canonical name order (RFC 4034 §6.1): compare labels from the root
/// down, each as lowercase bytes, with a missing label sorting first.
pub fn canonical_order(a: &str, b: &str) -> Ordering {
    let labels = |name: &str| -> Vec<Vec<u8>> {
        name.trim_end_matches('.')
            .rsplit('.')
            .filter(|label| !label.is_empty())
            .map(|label| label.to_ascii_lowercase().into_bytes())
            .collect()
    };
    labels(a).cmp(&labels(b))
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

    /// Parse RFC 1035 zone file. Supports:
    ///   $ORIGIN, $TTL directives
    ///   A, AAAA, CNAME, NS, MX, TXT, PTR, SOA, SRV, DNSKEY, DS, RRSIG
    pub fn load_file(&mut self, path: &str) -> std::io::Result<()> {
        let content = fs::read_to_string(path)?;
        let mut default_ttl: u32 = 3600;
        let mut origin = self.origin.clone();
        let mut last_name = origin.clone();

        // A record wrapped in parentheses (RFC 1035 §5.1) spans several lines,
        // so lines are buffered until every opening parenthesis is closed.
        let mut pending_record = String::new();
        let mut open_parentheses: i32 = 0;

        for raw_line in content.lines() {
            // Strip inline comments, but keep ';' that sits inside a quoted string
            let without_comment = strip_zone_comment(raw_line);
            if pending_record.is_empty() && without_comment.trim().is_empty() { continue; }

            pending_record.push_str(without_comment);
            pending_record.push(' ');
            open_parentheses += parenthesis_balance(without_comment);
            if open_parentheses > 0 { continue; }
            open_parentheses = 0;

            let record_text = std::mem::take(&mut pending_record);
            // An owner field left blank (line starts with whitespace) reuses the previous owner
            let owner_is_blank = record_text.starts_with(char::is_whitespace);
            let line = record_text.trim();
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
            // Unsupported directives such as $INCLUDE must not be read as owner names
            if line.starts_with('$') {
                eprintln!("[zone] unsupported directive: {}", line);
                continue;
            }

            // RR line: [name] [ttl] [class] type rdata...
            let owned_tokens = tokenize_zone_line(line);
            let tokens: Vec<&str> = owned_tokens.iter().map(String::as_str).collect();
            if tokens.len() < 2 { continue; }

            let mut idx = 0;

            // Name field — blank means reuse last_name
            let name = if !owner_is_blank && !is_type(tokens[0]) && !is_class(tokens[0]) {
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
                if is_class(cls) {
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

/// Cut a zone file line at its ';' comment, ignoring any ';' inside a quoted string.
fn strip_zone_comment(line: &str) -> &str {
    let mut inside_quotes = false;
    let mut escaped = false;
    for (index, character) in line.char_indices() {
        match character {
            _ if escaped => escaped = false,
            '\\' => escaped = true,
            '"' => inside_quotes = !inside_quotes,
            ';' if !inside_quotes => return &line[..index],
            _ => {}
        }
    }
    line
}

/// Opening minus closing parentheses outside quoted strings.
fn parenthesis_balance(line: &str) -> i32 {
    let mut inside_quotes = false;
    let mut escaped = false;
    let mut balance = 0;
    for character in line.chars() {
        match character {
            _ if escaped => escaped = false,
            '\\' => escaped = true,
            '"' => inside_quotes = !inside_quotes,
            '(' if !inside_quotes => balance += 1,
            ')' if !inside_quotes => balance -= 1,
            _ => {}
        }
    }
    balance
}

/// Split a record into fields on whitespace. A quoted string stays one field
/// (quotes included) and grouping parentheses are dropped.
fn tokenize_zone_line(line: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current_token = String::new();
    let mut inside_quotes = false;
    let mut escaped = false;
    for character in line.chars() {
        if escaped {
            current_token.push(character);
            escaped = false;
            continue;
        }
        match character {
            '\\' => { current_token.push(character); escaped = true; }
            '"' => { current_token.push(character); inside_quotes = !inside_quotes; }
            '(' | ')' if !inside_quotes => {
                if !current_token.is_empty() { tokens.push(std::mem::take(&mut current_token)); }
            }
            _ if character.is_whitespace() && !inside_quotes => {
                if !current_token.is_empty() { tokens.push(std::mem::take(&mut current_token)); }
            }
            _ => current_token.push(character),
        }
    }
    if !current_token.is_empty() { tokens.push(current_token); }
    tokens
}

fn is_class(s: &str) -> bool {
    matches!(s.to_uppercase().as_str(), "IN" | "ANY" | "CH" | "HS")
}

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
            // Every field is its own character-string; quotes are stripped
            let mut out = Vec::new();
            for token in tokens {
                let text = token.strip_prefix('"')
                    .and_then(|rest| rest.strip_suffix('"'))
                    .unwrap_or(token);
                let bytes = text.as_bytes();
                if bytes.is_empty() { out.push(0); }
                // Each string segment ≤255 bytes
                for chunk in bytes.chunks(255) {
                    out.push(chunk.len() as u8);
                    out.extend_from_slice(chunk);
                }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parses_multi_line_soa_and_quoted_semicolons() {
        let zone_text = r#"$ORIGIN example.com.
$TTL 3600
@   IN  SOA   ns1.example.com. admin.example.com. (
                2024010101  ; serial
                3600        ; refresh
                900         ; retry
                604800      ; expire
                300 )       ; minimum
_dmarc      IN  TXT   "v=DMARC1; p=reject" ; trailing comment
www         IN  A     203.0.113.10
            300 IN  AAAA  2001:db8::1
_http._tcp  IN  SRV   10 0 80 www.example.com.
"#;
        let path = std::env::temp_dir().join(format!("ironbind-test-{}.zone", std::process::id()));
        std::fs::write(&path, zone_text).unwrap();
        let mut zone = Zone::new("example.com");
        zone.load_file(path.to_str().unwrap()).unwrap();
        let _ = std::fs::remove_file(&path);

        let soa = zone.soa().expect("multi-line SOA should load");
        assert_eq!(crate::cache::soa_minimum_ttl(&soa[0].rdata), 300);

        let txt = zone.lookup("_dmarc.example.com", &RType::TXT).unwrap();
        assert_eq!(&txt[0].rdata[1..], b"v=DMARC1; p=reject");

        // A line starting with whitespace belongs to the previous owner, even with a leading TTL
        let aaaa = zone.lookup("www.example.com", &RType::AAAA).unwrap();
        assert_eq!(aaaa[0].ttl, 300);

        // Empty non-terminal exists (NODATA, not NXDOMAIN)
        assert!(zone.name_exists("_tcp.example.com"));
        assert!(!zone.name_exists("missing.example.com"));
    }
}
