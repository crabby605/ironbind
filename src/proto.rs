/// DNS wire format parsing and serialization
///
/// Implements RFC standards:
/// - RFC 1035: DNS format and DNS protocol
/// - RFC 2535: DNSSEC Keys and Signatures
/// - RFC 4034: DNSSEC Algorithms and Digest Types
/// - RFC 6891: EDNS0 Extension Mechanism
///
/// This module handles:
/// - Converting between wire format (bytes) and Rust structures
/// - DNS name compression (RFC 1035 §4.1.4)
/// - EDNS0 OPT pseudo-records (RFC 6891)
/// - DNSSEC record parsing (RRSIG, DNSKEY, DS)

use std::io;

/// DNS Resource Record Types
///
/// Represents all standard RR types. Additional types can be stored as Unknown(u16).
/// Maps to IANA DNS TYPE registry values.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RType {
    A,              // IPv4 address (type 1)
    NS,             // Nameserver (type 2)
    CNAME,          // Canonical name / alias (type 5)
    SOA,            // Start of Authority (type 6)
    PTR,            // Pointer / reverse DNS (type 12)
    MX,             // Mail exchange (type 15)
    TXT,            // Text record (type 16)
    AAAA,           // IPv6 address (type 28)
    SRV,            // Service record (type 33)
    NAPTR,          // Naming Authority Pointer (type 35)
    OPT,            // EDNS0 pseudo-RR (type 41) — not a real record, used for options
    DS,             // DNSSEC Delegation Signer (type 43)
    RRSIG,          // DNSSEC Signature (type 46)
    NSEC,           // DNSSEC Next Secure (type 47)
    DNSKEY,         // DNSSEC Public Key (type 48)
    NSEC3,          // DNSSEC NSEC3 (type 50)
    NSEC3PARAM,     // DNSSEC NSEC3 parameters (type 51)
    TSIG,           // Transaction Signature (type 250, RFC 8945)
    IXFR,           // Incremental zone transfer (type 251, RFC 1995)
    AXFR,           // Full zone transfer (type 252, RFC 5936)
    ANY,            // Wildcard query (type 255)
    Unknown(u16),   // Any other type stored as numeric value
}

impl From<u16> for RType {
    fn from(n: u16) -> Self {
        match n {
            1   => Self::A,
            2   => Self::NS,
            5   => Self::CNAME,
            6   => Self::SOA,
            12  => Self::PTR,
            15  => Self::MX,
            16  => Self::TXT,
            28  => Self::AAAA,
            33  => Self::SRV,
            35  => Self::NAPTR,
            41  => Self::OPT,
            43  => Self::DS,
            46  => Self::RRSIG,
            47  => Self::NSEC,
            48  => Self::DNSKEY,
            50  => Self::NSEC3,
            51  => Self::NSEC3PARAM,
            250 => Self::TSIG,
            251 => Self::IXFR,
            252 => Self::AXFR,
            255 => Self::ANY,
            n   => Self::Unknown(n),
        }
    }
}

impl From<&RType> for u16 {
    fn from(r: &RType) -> u16 {
        match r {
            RType::A           => 1,
            RType::NS          => 2,
            RType::CNAME       => 5,
            RType::SOA         => 6,
            RType::PTR         => 12,
            RType::MX          => 15,
            RType::TXT         => 16,
            RType::AAAA        => 28,
            RType::SRV         => 33,
            RType::NAPTR       => 35,
            RType::OPT         => 41,
            RType::DS          => 43,
            RType::RRSIG       => 46,
            RType::NSEC        => 47,
            RType::DNSKEY      => 48,
            RType::NSEC3       => 50,
            RType::NSEC3PARAM  => 51,
            RType::TSIG        => 250,
            RType::IXFR        => 251,
            RType::AXFR        => 252,
            RType::ANY         => 255,
            RType::Unknown(n)  => *n,
        }
    }
}

// ── DNS Classes ──────────────────────────────────────────────────────────────

pub const CLASS_IN:   u16 = 1;
pub const CLASS_ANY:  u16 = 255;
pub const CLASS_NONE: u16 = 254;

// ── RCODE values ─────────────────────────────────────────────────────────────

pub const RCODE_NOERROR:  u8 = 0;
pub const RCODE_FORMERR:  u8 = 1;
pub const RCODE_SERVFAIL: u8 = 2;
pub const RCODE_NXDOMAIN: u8 = 3;
pub const RCODE_NOTIMP:   u8 = 4;
pub const RCODE_REFUSED:  u8 = 5;

// ── Packet structures ────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Question {
    pub name:   String,
    pub qtype:  RType,
    pub qclass: u16,
}

#[derive(Debug, Clone)]
pub struct Record {
    pub name:  String,
    pub rtype: RType,
    pub class: u16,
    pub ttl:   u32,
    pub rdata: Vec<u8>,
}

/// Parsed RRSIG fields (RFC 4034 §3.1)
#[derive(Debug, Clone)]
pub struct Rrsig {
    pub type_covered:  u16,
    pub algorithm:     u8,
    pub labels:        u8,
    pub orig_ttl:      u32,
    pub sig_expiry:    u32,
    pub sig_inception: u32,
    pub key_tag:       u16,
    pub signer_name:   String,
    pub signature:     Vec<u8>,
}

/// Parsed DNSKEY fields (RFC 4034 §2.1)
#[derive(Debug, Clone)]
pub struct Dnskey {
    pub flags:     u16,  // bit 7 = ZSK, bit 8 = SEP (KSK)
    pub protocol:  u8,   // must be 3
    pub algorithm: u8,
    pub public_key: Vec<u8>,
}

impl Dnskey {
    pub fn is_zone_key(&self) -> bool { self.flags & 0x0100 != 0 }
    pub fn is_sep(&self)      -> bool { self.flags & 0x0001 != 0 }
    /// Compute key tag per RFC 4034 Appendix B
    pub fn key_tag(&self, raw_rdata: &[u8]) -> u16 {
        let mut ac: u32 = 0;
        for (i, &b) in raw_rdata.iter().enumerate() {
            ac += if i & 1 == 0 { (b as u32) << 8 } else { b as u32 };
        }
        ac += ac >> 16;
        (ac & 0xFFFF) as u16
    }
}

/// Parsed DS fields (RFC 4034 §5.1)
#[derive(Debug, Clone)]
pub struct Ds {
    pub key_tag:    u16,
    pub algorithm:  u8,
    pub digest_type: u8,
    pub digest:     Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Packet {
    pub id:         u16,        // Query/Response ID (echoed in response)
    pub flags:      u16,        // DNS flags: QR|OPCODE|AA|TC|RD|RA|...|RCODE
                                // QR (bit 15): 0=query, 1=response
                                // OPCODE (bits 14-11): 0=standard query, 3=inverse, 4=status
                                // AA (bit 10): authoritative answer flag
                                // TC (bit 9): truncated flag (message was truncated)
                                // RD (bit 8): recursion desired (client requests recursive lookup)
                                // RA (bit 7): recursion available (server supports recursion)
                                // RCODE (bits 3-0): response code (0=ok, 3=NXDOMAIN, 2=SERVFAIL, etc)
    pub questions:  Vec<Question>,  // Questions section (usually 1 question)
    pub answers:    Vec<Record>,    // Answer section (RRs that answer the question)
    pub authority:  Vec<Record>,    // Authority section (RRs pointing to authority)
    pub additional: Vec<Record>,    // Additional section (RRs with useful info)
    /// EDNS0 payload size from OPT record (0 = no EDNS seen, max UDP size otherwise)
    pub edns_udp_size: u16,
    /// EDNS0 DO (DNSSEC OK) bit — signals client supports DNSSEC
    pub dnssec_ok: bool,
}

impl Packet {
    pub fn new_response(id: u16, req_flags: u16) -> Self {
        // QR=1, copy RD from request, RA=1
        let flags = 0x8000 | (req_flags & 0x0100) | 0x0080;
        Packet {
            id, flags,
            questions: vec![],
            answers: vec![],
            authority: vec![],
            additional: vec![],
            edns_udp_size: 0,
            dnssec_ok: false,
        }
    }

    pub fn is_query(&self)    -> bool { self.flags & 0x8000 == 0 }
    pub fn is_response(&self) -> bool { self.flags & 0x8000 != 0 }
    pub fn rd(&self)          -> bool { self.flags & 0x0100 != 0 }
    pub fn truncated(&self)   -> bool { self.flags & 0x0200 != 0 }

    pub fn set_aa(&mut self)    { self.flags |=  0x0400; }
    pub fn set_tc(&mut self)    { self.flags |=  0x0200; }
    pub fn clear_tc(&mut self)  { self.flags &= !0x0200; }
    pub fn set_ra(&mut self)    { self.flags |=  0x0080; }

    pub fn rcode(&self) -> u8 { (self.flags & 0x000F) as u8 }
    pub fn set_rcode(&mut self, c: u8) {
        self.flags = (self.flags & 0xFFF0) | (c as u16 & 0xF);
    }

    pub fn opcode(&self) -> u8 { ((self.flags >> 11) & 0xF) as u8 }
}

// ── Parser: Wire Format → Rust Structures ─────────────────────────────────────
//
// Converts raw DNS wire format (bytes) into Rust structures.
// Handles:
// - DNS name compression (RFC 1035 §4.1.4): names use pointers to avoid repetition
// - Name decompression: restores compressed names in rdata (SOA, MX, CNAME, etc)
// - Variable-length data: domain names, RDATA sections
// - Little-endian (big-endian) encoding for u16/u32
//

pub struct Parser<'a> {
    pub buf: &'a [u8],   // Full packet buffer (needed for pointer dereferencing)
    pub pos: usize,      // Current read position in buffer
}

impl<'a> Parser<'a> {
    pub fn new(buf: &'a [u8]) -> Self { Self { buf, pos: 0 } }

    pub fn peek(&self) -> io::Result<u8> {
        self.buf.get(self.pos).copied()
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "eof"))
    }
    pub fn u8(&mut self) -> io::Result<u8> {
        let b = self.peek()?; self.pos += 1; Ok(b)
    }
    pub fn u16(&mut self) -> io::Result<u16> {
        Ok((self.u8()? as u16) << 8 | self.u8()? as u16)
    }
    pub fn u32(&mut self) -> io::Result<u32> {
        Ok((self.u16()? as u32) << 16 | self.u16()? as u32)
    }
    pub fn bytes(&mut self, n: usize) -> io::Result<Vec<u8>> {
        if self.pos + n > self.buf.len() {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "eof reading bytes"));
        }
        let v = self.buf[self.pos..self.pos + n].to_vec();
        self.pos += n;
        Ok(v)
    }
    pub fn remaining(&self) -> usize { self.buf.len().saturating_sub(self.pos) }

    /// RFC 1035 §4.1.4 — DNS name parsing with label compression support
    ///
    /// Names are stored as length-prefixed labels separated by 0x00 terminator.
    /// Compression uses pointers: if high 2 bits = 11, remaining 14 bits point
    /// to another name location in the packet (to avoid repetition).
    ///
    /// Examples:
    /// - "example.com." → 7 "example" 3 "com" 0
    /// - "www.example.com." where "example.com" is at offset 42 → 3 "www" [0xC0, 0x2A]
    pub fn name(&mut self) -> io::Result<String> {
        let mut parts: Vec<String> = Vec::new();
        let mut pos = self.pos;
        let mut jumped = false;
        let mut jumps  = 0u8;

        loop {
            if pos >= self.buf.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "name out of bounds"));
            }
            let b = self.buf[pos];
            if b == 0 {
                if !jumped { self.pos = pos + 1; }
                break;
            } else if b & 0xC0 == 0xC0 {
                if pos + 1 >= self.buf.len() {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "ptr oob"));
                }
                if !jumped { self.pos = pos + 2; }
                let offset = (((b & 0x3F) as usize) << 8) | self.buf[pos + 1] as usize;
                pos = offset;
                jumped = true;
                jumps += 1;
                if jumps > 20 {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "pointer loop"));
                }
            } else {
                let len = b as usize;
                pos += 1;
                let end = pos + len;
                if end > self.buf.len() {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "label oob"));
                }
                parts.push(
                    std::str::from_utf8(&self.buf[pos..end])
                        .unwrap_or("?")
                        .to_ascii_lowercase(),
                );
                pos = end;
            }
        }
        Ok(if parts.is_empty() { ".".to_string() } else { parts.join(".") })
    }

    fn record(&mut self) -> io::Result<Record> {
        let name   = self.name()?;
        let rtype  = RType::from(self.u16()?);
        let class  = self.u16()?;
        let ttl    = self.u32()?;
        let rdlen  = self.u16()? as usize;
        let rdata_offset = self.pos;          // offset of rdata within full packet
        let rdata_raw = self.bytes(rdlen)?;
        // Decompress any pointer-compressed names inside rdata
        let rdata = decompress_rdata(self.buf, &rtype, &rdata_raw, rdata_offset);
        Ok(Record { name, rtype, class, ttl, rdata })
    }

    pub fn parse(&mut self) -> io::Result<Packet> {
        let id      = self.u16()?;
        let flags   = self.u16()?;
        let qdcount = self.u16()?;
        let ancount = self.u16()?;
        let nscount = self.u16()?;
        let arcount = self.u16()?;

        let mut questions = Vec::with_capacity(qdcount as usize);
        for _ in 0..qdcount {
            questions.push(Question {
                name:   self.name()?,
                qtype:  RType::from(self.u16()?),
                qclass: self.u16()?,
            });
        }

        let answers   = (0..ancount).map(|_| self.record()).collect::<io::Result<Vec<_>>>()?;
        let authority = (0..nscount).map(|_| self.record()).collect::<io::Result<Vec<_>>>()?;
        let additional_raw = (0..arcount).map(|_| self.record()).collect::<io::Result<Vec<_>>>()?;

        // Extract EDNS0 OPT from additional
        let mut edns_udp_size = 0u16;
        let mut dnssec_ok = false;
        let mut additional = Vec::new();
        for rec in additional_raw {
            if rec.rtype == RType::OPT {
                edns_udp_size = rec.class; // OPT CLASS = requestor UDP payload size
                dnssec_ok = rec.ttl & 0x8000 != 0; // DO bit in TTL field
            } else {
                additional.push(rec);
            }
        }

        Ok(Packet { id, flags, questions, answers, authority, additional, edns_udp_size, dnssec_ok })
    }
}

// ── RRSIG / DNSKEY / DS parsers ──────────────────────────────────────────────

pub fn parse_rrsig(rdata: &[u8]) -> io::Result<Rrsig> {
    let mut p = Parser::new(rdata);
    let type_covered  = p.u16()?;
    let algorithm     = p.u8()?;
    let labels        = p.u8()?;
    let orig_ttl      = p.u32()?;
    let sig_expiry    = p.u32()?;
    let sig_inception = p.u32()?;
    let key_tag       = p.u16()?;
    let signer_name   = p.name()?;
    let signature     = p.bytes(p.remaining())?;
    Ok(Rrsig { type_covered, algorithm, labels, orig_ttl, sig_expiry, sig_inception, key_tag, signer_name, signature })
}

pub fn parse_dnskey(rdata: &[u8]) -> io::Result<Dnskey> {
    let mut p = Parser::new(rdata);
    let flags     = p.u16()?;
    let protocol  = p.u8()?;
    let algorithm = p.u8()?;
    let public_key = p.bytes(p.remaining())?;
    Ok(Dnskey { flags, protocol, algorithm, public_key })
}

pub fn parse_ds(rdata: &[u8]) -> io::Result<Ds> {
    let mut p = Parser::new(rdata);
    let key_tag      = p.u16()?;
    let algorithm    = p.u8()?;
    let digest_type  = p.u8()?;
    let digest       = p.bytes(p.remaining())?;
    Ok(Ds { key_tag, algorithm, digest_type, digest })
}

// ── Serializer: Rust Structures → Wire Format ──────────────────────────────────
//
// Converts Rust structures into raw DNS wire format (bytes).
// Handles:
// - Efficient name compression: stores name offsets to reuse common suffixes
// - Proper big-endian (network) byte order for all integers
// - EDNS0 OPT record injection (if enabled)
//

pub struct Builder {
    buf: Vec<u8>,
}

impl Builder {
    pub fn new() -> Self { Self { buf: Vec::with_capacity(512) } }

    pub fn u8(&mut self, v: u8)   { self.buf.push(v); }
    pub fn u16(&mut self, v: u16) { self.buf.extend_from_slice(&v.to_be_bytes()); }
    pub fn u32(&mut self, v: u32) { self.buf.extend_from_slice(&v.to_be_bytes()); }
    pub fn raw(&mut self, v: &[u8]) { self.buf.extend_from_slice(v); }

    pub fn name(&mut self, name: &str) {
        if name == "." || name.is_empty() {
            self.u8(0);
            return;
        }
        for label in name.trim_end_matches('.').split('.') {
            if label.is_empty() { continue; }
            self.u8(label.len() as u8);
            self.raw(label.as_bytes());
        }
        self.u8(0);
    }

    pub fn question(&mut self, q: &Question) {
        self.name(&q.name);
        self.u16(u16::from(&q.qtype));
        self.u16(q.qclass);
    }

    pub fn record(&mut self, r: &Record) {
        self.name(&r.name);
        self.u16(u16::from(&r.rtype));
        self.u16(r.class);
        self.u32(r.ttl);
        self.u16(r.rdata.len() as u16);
        self.raw(&r.rdata);
    }

    /// Append EDNS0 OPT record
    pub fn opt(&mut self, udp_size: u16, dnssec_ok: bool) {
        self.u8(0);          // name = root
        self.u16(41);        // TYPE = OPT
        self.u16(udp_size);  // CLASS = requestor UDP size
        // TTL: extended RCODE (0) + version (0) + DO bit + Z
        let ttl: u32 = if dnssec_ok { 0x8000 } else { 0 };
        self.u32(ttl);
        self.u16(0);         // RDLEN = 0 (no options)
    }

    pub fn finish(self) -> Vec<u8> { self.buf }
}

pub fn serialize(pkt: &Packet, include_edns: bool) -> Vec<u8> {
    let mut b = Builder::new();
    let ar_extra = if include_edns && pkt.edns_udp_size > 0 { 1 } else { 0 };

    b.u16(pkt.id);
    b.u16(pkt.flags);
    b.u16(pkt.questions.len()  as u16);
    b.u16(pkt.answers.len()    as u16);
    b.u16(pkt.authority.len()  as u16);
    b.u16((pkt.additional.len() + ar_extra) as u16);

    for q in &pkt.questions  { b.question(q); }
    for r in &pkt.answers    { b.record(r);   }
    for r in &pkt.authority  { b.record(r);   }
    for r in &pkt.additional { b.record(r);   }

    if include_edns && pkt.edns_udp_size > 0 {
        b.opt(pkt.edns_udp_size, pkt.dnssec_ok);
    }

    b.finish()
}

/// Encode a DNS name into canonical wire format (no compression) for DNSSEC signing
pub fn canonical_name(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let lower = name.to_ascii_lowercase();
    let trimmed = lower.trim_end_matches('.');
    if trimmed.is_empty() {
        out.push(0);
        return out;
    }
    for label in trimmed.split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}

/// Decompress rdata that contains DNS names (SOA, MX, NS, CNAME, PTR, SRV).
/// Names in rdata may use pointer compression relative to the FULL packet buffer.
/// We must expand them to uncompressed wire format before storing/forwarding.
/// `pkt_buf` = full original packet bytes, `rtype` = record type, `rdata` = raw rdata slice.
pub fn decompress_rdata(pkt_buf: &[u8], rtype: &RType, rdata: &[u8], rdata_offset: usize) -> Vec<u8> {
    // For these types, rdata contains one or more DNS names that may be compressed
    match rtype {
        RType::NS | RType::CNAME | RType::PTR => {
            // rdata is a single name
            let mut p = Parser::new(pkt_buf);
            p.pos = rdata_offset;
            match p.name() {
                Ok(name) => canonical_name(&name),
                Err(_)   => rdata.to_vec(),
            }
        }
        RType::MX => {
            // u16 preference + name
            if rdata.len() < 2 { return rdata.to_vec(); }
            let pref = u16::from_be_bytes([rdata[0], rdata[1]]);
            let mut p = Parser::new(pkt_buf);
            p.pos = rdata_offset + 2;
            match p.name() {
                Ok(name) => {
                    let mut b = Builder::new();
                    b.u16(pref);
                    b.name(&name);
                    b.finish()
                }
                Err(_) => rdata.to_vec(),
            }
        }
        RType::SOA => {
            // mname + rname + 5x u32
            let mut p = Parser::new(pkt_buf);
            p.pos = rdata_offset;
            let mname = match p.name() { Ok(n) => n, Err(_) => return rdata.to_vec() };
            let rname = match p.name() { Ok(n) => n, Err(_) => return rdata.to_vec() };
            // Read remaining 5 u32s from original rdata using offset
            let consumed = p.pos - rdata_offset;
            if consumed + 20 > rdata.len() + 20 { // allow exact fit
                // read from packet position
            }
            let serial  = match p.u32() { Ok(v) => v, Err(_) => return rdata.to_vec() };
            let refresh = match p.u32() { Ok(v) => v, Err(_) => return rdata.to_vec() };
            let retry   = match p.u32() { Ok(v) => v, Err(_) => return rdata.to_vec() };
            let expire  = match p.u32() { Ok(v) => v, Err(_) => return rdata.to_vec() };
            let minimum = match p.u32() { Ok(v) => v, Err(_) => return rdata.to_vec() };

            let mut b = Builder::new();
            b.name(&mname);
            b.name(&rname);
            b.u32(serial);
            b.u32(refresh);
            b.u32(retry);
            b.u32(expire);
            b.u32(minimum);
            b.finish()
        }
        RType::SRV => {
            // u16 priority + u16 weight + u16 port + name
            if rdata.len() < 6 { return rdata.to_vec(); }
            let priority = u16::from_be_bytes([rdata[0], rdata[1]]);
            let weight   = u16::from_be_bytes([rdata[2], rdata[3]]);
            let port     = u16::from_be_bytes([rdata[4], rdata[5]]);
            let mut p = Parser::new(pkt_buf);
            p.pos = rdata_offset + 6;
            match p.name() {
                Ok(name) => {
                    let mut b = Builder::new();
                    b.u16(priority);
                    b.u16(weight);
                    b.u16(port);
                    b.name(&name);
                    b.finish()
                }
                Err(_) => rdata.to_vec(),
            }
        }
        // All other types: rdata contains no names (A, AAAA, TXT, DS, DNSKEY, RRSIG...)
        _ => rdata.to_vec(),
    }
}

/// Canonical RR wire format for DNSSEC signature verification (RFC 4034 §6.2)
pub fn canonical_rr(r: &Record) -> Vec<u8> {
    let mut b = Builder::new();
    b.name(&r.name.to_ascii_lowercase());
    b.u16(u16::from(&r.rtype));
    b.u16(r.class);
    b.u32(r.ttl);
    b.u16(r.rdata.len() as u16);
    b.raw(&r.rdata);
    b.finish()
}