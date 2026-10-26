/// Iterative DNS Resolver — RFC 1034 §5.3.3 compliant
///
/// Implements two-stage resolution:
/// 1. Forwarder path: tries system resolvers from /etc/resolv.conf (fast)
/// 2. Iterative path: walks DNS tree from root if forwarders unavailable
///
/// Iterative resolution process:
/// - Start at root nameserver (from IANA root hints hardcoded)
/// - Query for requested name + type
/// - If answer received: done, return answer
/// - If referral received: extract NS names and IPs from authority section
/// - If NS names have glue records (A/AAAA in additional): use those IPs
/// - Otherwise: recursively resolve NS names to get IPs
/// - Follow up to 20 referrals max (prevent loops)
/// - Handle CNAME chains (max depth)
/// - Automatic TCP failover when TC bit set
///
/// Thread-safe: can be called concurrently from multiple query threads
use std::{
    collections::HashSet,
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket},
    str::FromStr,
    time::{Duration, Instant},
};
use crate::proto::{Packet, Parser, Question, Record, RType, serialize, CLASS_IN};

const ROOT_SERVERS: &[(&str, &str)] = &[
    ("a.root-servers.net", "198.41.0.4"),
    ("b.root-servers.net", "199.9.14.201"),
    ("c.root-servers.net", "192.33.4.12"),
    ("d.root-servers.net", "199.7.91.13"),
    ("e.root-servers.net", "192.203.230.10"),
    ("f.root-servers.net", "192.5.5.241"),
    ("g.root-servers.net", "192.112.36.4"),
    ("h.root-servers.net", "198.97.190.53"),
    ("i.root-servers.net", "192.36.148.17"),
    ("j.root-servers.net", "192.58.128.30"),
    ("k.root-servers.net", "193.0.14.129"),
    ("l.root-servers.net", "199.7.83.42"),
    ("m.root-servers.net", "202.12.27.33"),
];

const TIMEOUT_MS:   u64 = 2000;
const MAX_REFERRALS: usize = 20;
/// Nested lookups for glueless NS names. Without a limit, nameservers that point
/// at each other recurse until the stack overflows, which no panic handler can catch.
const MAX_NS_LOOKUP_DEPTH: usize = 4;
const DNS_PORT: u16 = 53;

#[derive(Debug, Clone)]
pub struct ResolverConfig {
    /// Forwarders from /etc/resolv.conf (used as first attempt before iterating)
    /// These are upstream DNS servers that handle recursive queries
    pub forwarders: Vec<SocketAddr>,
    /// Whether to attempt forwarders before falling back to iterative resolution
    pub use_forwarders: bool,
    /// UDP query timeout in milliseconds (default: 2000ms)
    pub timeout_ms: u64,
    /// Log each recursive step (mirrors `log_queries` in config.toml)
    pub log_queries: bool,
}

impl ResolverConfig {
    pub fn from_resolv_conf() -> Self {
        let forwarders = parse_resolv_conf().unwrap_or_default();
        eprintln!("[resolver] forwarders from /etc/resolv.conf: {:?}", forwarders);
        Self {
            use_forwarders: !forwarders.is_empty(),
            forwarders,
            timeout_ms: TIMEOUT_MS,
            log_queries: false,
        }
    }
}

fn parse_resolv_conf() -> Option<Vec<SocketAddr>> {
    let content = fs::read_to_string("/etc/resolv.conf").ok()?;
    let addrs: Vec<SocketAddr> = content
        .lines()
        .filter(|l| l.trim_start().starts_with("nameserver"))
        .filter_map(|l| {
            let ip_str = l.split_whitespace().nth(1)?;
            let ip = IpAddr::from_str(ip_str).ok()?;
            Some(SocketAddr::new(ip, DNS_PORT))
        })
        .collect();
    if addrs.is_empty() { None } else { Some(addrs) }
}

#[derive(Debug)]
pub enum ResolveResult {
    Answer(Packet),
    NxDomain(Packet),
    ServFail(String),
}

pub struct Resolver {
    pub config: ResolverConfig,
}

impl Resolver {
    pub fn new(config: ResolverConfig) -> Self { Self { config } }

    /// Fetch an RRset together with its covering RRSIGs from a forwarder.
    /// Used by the chain-of-trust validator to pull DNSKEY/DS at each cut.
    pub fn fetch_with_rrsig(&self, name: &str, qtype: &RType) -> (Vec<Record>, Vec<Record>) {
        let q = build_query_dnssec(name, qtype);
        for fwd in &self.config.forwarders {
            if let Ok(pkt) = udp_exchange(&q, fwd, self.config.timeout_ms) {
                let records: Vec<Record> = pkt.answers.iter()
                    .filter(|r| r.rtype == *qtype)
                    .cloned()
                    .collect();
                let rrsigs: Vec<Record> = pkt.answers.iter()
                    .filter(|r| r.rtype == RType::RRSIG)
                    .cloned()
                    .collect();
                return (records, rrsigs);
            }
        }
        (Vec::new(), Vec::new())
    }

    /// Resolve name + qtype. Returns the final answer packet.
    pub fn resolve(&self, name: &str, qtype: &RType) -> ResolveResult {
        // 1. Try forwarders first (fast path — uses /etc/resolv.conf)
        if self.config.use_forwarders {
            let q = build_query(name, qtype, true);
            for fwd in &self.config.forwarders {
                match udp_exchange(&q, fwd, self.config.timeout_ms) {
                    Ok(pkt) => {
                        if pkt.rcode() == crate::proto::RCODE_SERVFAIL { continue; }
                        return if pkt.rcode() == crate::proto::RCODE_NXDOMAIN {
                            ResolveResult::NxDomain(pkt)
                        } else {
                            ResolveResult::Answer(pkt)
                        };
                    }
                    Err(_) => continue,
                }
            }
            // forwarders all failed — fall through to iterative
            if self.config.log_queries { eprintln!("[resolver] all forwarders failed, falling back to iterative"); }
        }

        // 2. Iterative resolution from root
        self.iterative_resolve(name, qtype, 0)
    }

    fn iterative_resolve(&self, name: &str, qtype: &RType, depth: usize) -> ResolveResult {
        if depth > MAX_NS_LOOKUP_DEPTH {
            return ResolveResult::ServFail(format!("NS lookup depth exceeded for {}", name));
        }

        // Start from a random root server
        let mut nameservers: Vec<IpAddr> = ROOT_SERVERS.iter()
            .filter_map(|(_, ip)| ip.parse().ok())
            .collect();
        // The zone the current nameservers are authoritative for. Anything they
        // return outside it is out of bailiwick and ignored (cache poisoning defence).
        let mut current_zone = String::from(".");

        let mut referral_count = 0;
        let mut visited: HashSet<String> = HashSet::new();
        let mut cname_chain: Vec<String> = Vec::new();
        let mut current_name = name.to_string();

        loop {
            if referral_count >= MAX_REFERRALS {
                return ResolveResult::ServFail(format!(
                    "max referrals ({}) exceeded for {}", MAX_REFERRALS, name
                ));
            }

            let q = build_query(&current_name, qtype, false);

            // Try each nameserver in the current set
            let mut resp: Option<Packet> = None;
            'ns_loop: for ns_ip in &nameservers {
                let addr = SocketAddr::new(*ns_ip, DNS_PORT);
                let key = format!("{}-{}", current_name, addr);
                if visited.contains(&key) { continue; }
                visited.insert(key);

                match udp_exchange(&q, &addr, self.config.timeout_ms) {
                    Ok(pkt) => {
                        resp = Some(pkt);
                        break 'ns_loop;
                    }
                    Err(e) => {
                        if self.config.log_queries { eprintln!("[iter] {} → {}: {}", current_name, addr, e); }
                        continue;
                    }
                }
            }

            let pkt = match resp {
                Some(p) => p,
                None => return ResolveResult::ServFail(
                    format!("all nameservers failed for {}", current_name)
                ),
            };

            let mut pkt = pkt;
            pkt.answers.retain(|r| in_bailiwick(&r.name, &current_zone));
            pkt.authority.retain(|r| in_bailiwick(&r.name, &current_zone));
            pkt.additional.retain(|r| r.rtype == RType::OPT || in_bailiwick(&r.name, &current_zone));

            // NXDOMAIN
            if pkt.rcode() == crate::proto::RCODE_NXDOMAIN {
                return ResolveResult::NxDomain(pkt);
            }

            // Got answers
            if !pkt.answers.is_empty() {
                // Check for CNAME chain
                let cname = pkt.answers.iter().find(|r| r.rtype == RType::CNAME);
                if let Some(cn) = cname {
                    if qtype != &RType::CNAME {
                        let target = parse_name_from_rdata(&cn.rdata);
                        if target.is_empty() || cname_chain.contains(&target) {
                            return ResolveResult::ServFail("CNAME loop".to_string());
                        }
                        if self.config.log_queries { eprintln!("[iter] CNAME {} → {}", current_name, target); }
                        cname_chain.push(current_name.clone());
                        current_name = target;
                        // Restart from root for CNAME target
                        nameservers = ROOT_SERVERS.iter()
                            .filter_map(|(_, ip)| ip.parse().ok())
                            .collect();
                        current_zone = String::from(".");
                        referral_count += 1;
                        continue;
                    }
                }
                return ResolveResult::Answer(pkt);
            }

            // Referral — authority section has NS records
            if !pkt.authority.is_empty() {
                // A referral must delegate to a zone below the one we asked about,
                // and that zone must contain the name being resolved.
                let delegation = pkt.authority.iter()
                    .find(|r| r.rtype == RType::NS)
                    .map(|r| r.name.to_ascii_lowercase());
                let Some(delegated_zone) = delegation.filter(|zone| {
                    zone != &current_zone && in_bailiwick(&current_name, zone)
                }) else {
                    return ResolveResult::ServFail(format!("bogus referral for {}", current_name));
                };

                let ns_names: Vec<String> = pkt.authority.iter()
                    .filter(|r| r.rtype == RType::NS && r.name.eq_ignore_ascii_case(&delegated_zone))
                    .map(|r| parse_name_from_rdata(&r.rdata))
                    .filter(|n| !n.is_empty())
                    .collect();

                if ns_names.is_empty() {
                    return ResolveResult::ServFail("empty referral".to_string());
                }

                // Check glue records in additional section (already limited to the current zone)
                let mut next_ns: Vec<IpAddr> = Vec::new();
                for ns in &ns_names {
                    for add in &pkt.additional {
                        if add.name.to_ascii_lowercase() == ns.to_ascii_lowercase() {
                            match add.rtype {
                                RType::A if add.rdata.len() == 4 => {
                                    let ip = Ipv4Addr::new(
                                        add.rdata[0], add.rdata[1],
                                        add.rdata[2], add.rdata[3],
                                    );
                                    next_ns.push(IpAddr::V4(ip));
                                }
                                _ => {}
                            }
                        }
                    }
                }

                // No glue — resolve NS names directly
                if next_ns.is_empty() {
                    for ns in &ns_names {
                        match self.iterative_resolve(ns, &RType::A, depth + 1) {
                            ResolveResult::Answer(p) => {
                                for r in &p.answers {
                                    if r.rtype == RType::A && r.rdata.len() == 4 {
                                        let ip = Ipv4Addr::new(
                                            r.rdata[0], r.rdata[1],
                                            r.rdata[2], r.rdata[3],
                                        );
                                        next_ns.push(IpAddr::V4(ip));
                                    }
                                }
                            }
                            _ => {}
                        }
                        if !next_ns.is_empty() { break; }
                    }
                }

                if next_ns.is_empty() {
                    return ResolveResult::ServFail(format!(
                        "could not resolve any NS for referral: {:?}", ns_names
                    ));
                }

                if self.config.log_queries { eprintln!("[iter] referral for {} → {:?}", current_name, &ns_names[..1]); }
                nameservers = next_ns;
                current_zone = delegated_zone;
                referral_count += 1;
                continue;
            }

            // No answers, no authority — NODATA or broken server
            return ResolveResult::Answer(pkt);
        }
    }
}

/// Build a recursive query with EDNS0 + DO bit set, used for DNSSEC fetches.
fn build_query_dnssec(name: &str, qtype: &RType) -> Vec<u8> {
    // Unpredictable ID: together with the random source port this is what a spoofer has to guess
    let id: u16 = rand::random();
    let pkt = Packet {
        id,
        flags: 0x0100, // RD
        questions: vec![Question { name: name.to_string(), qtype: qtype.clone(), qclass: CLASS_IN }],
        answers: vec![], authority: vec![], additional: vec![],
        edns_udp_size: 4096,
        dnssec_ok: true,
    };
    serialize(&pkt, true)
}

fn build_query(name: &str, qtype: &RType, recurse: bool) -> Vec<u8> {
    // Unpredictable ID: together with the random source port this is what a spoofer has to guess
    let id: u16 = rand::random();

    let flags: u16 = if recurse { 0x0100 } else { 0x0000 }; // RD bit

    let pkt = Packet {
        id,
        flags,
        questions: vec![Question {
            name: name.to_string(),
            qtype: qtype.clone(),
            qclass: CLASS_IN,
        }],
        answers: vec![],
        authority: vec![],
        additional: vec![],
        edns_udp_size: 4096,
        dnssec_ok: false,
    };

    // Add EDNS0 OPT
    let mut raw = serialize(&pkt, true);
    raw
}

fn udp_exchange(query: &[u8], addr: &SocketAddr, timeout_ms: u64) -> std::io::Result<Packet> {
    // A fresh socket per query gets a random ephemeral source port from the OS.
    // Connecting it makes the kernel drop datagrams from any other address.
    let local = if addr.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
    let sock = UdpSocket::bind(local)?;
    sock.connect(addr)?;
    sock.send(query)?;

    let expected = Parser::new(query).parse()?;
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    let mut buf = vec![0u8; 4096];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "no matching reply"));
        }
        sock.set_read_timeout(Some(remaining))?;
        let len = sock.recv(&mut buf)?;

        // Ignore anything that isn't the reply to this exact query: a spoofed
        // packet has to match the ID and question as well as the port.
        let Ok(pkt) = Parser::new(&buf[..len]).parse() else { continue };
        if !answers_query(&expected, &pkt) { continue; }

        // TC bit set — retry over TCP
        if pkt.truncated() {
            return tcp_exchange(query, addr, timeout_ms);
        }
        return Ok(pkt);
    }
}

fn tcp_exchange(query: &[u8], addr: &SocketAddr, timeout_ms: u64) -> std::io::Result<Packet> {
    use std::net::TcpStream;
    use std::io::{Read, Write};

    let mut stream = TcpStream::connect_timeout(addr, Duration::from_millis(timeout_ms))?;
    stream.set_read_timeout(Some(Duration::from_millis(timeout_ms)))?;

    let len = (query.len() as u16).to_be_bytes();
    stream.write_all(&len)?;
    stream.write_all(query)?;

    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf)?;
    let rlen = u16::from_be_bytes(len_buf) as usize;

    let mut buf = vec![0u8; rlen];
    stream.read_exact(&mut buf)?;

    let pkt = Parser::new(&buf).parse()?;
    let expected = Parser::new(query).parse()?;
    if !answers_query(&expected, &pkt) {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "reply does not match query"));
    }
    Ok(pkt)
}

/// True when `reply` is a response with the same ID and question as `query`.
fn answers_query(query: &Packet, reply: &Packet) -> bool {
    let (Some(asked), Some(answered)) = (query.questions.first(), reply.questions.first()) else { return false };
    reply.is_response()
        && reply.id == query.id
        && answered.name.eq_ignore_ascii_case(&asked.name)
        && answered.qtype == asked.qtype
        && answered.qclass == asked.qclass
}

/// True when `name` is `zone` or below it ("." contains everything).
fn in_bailiwick(name: &str, zone: &str) -> bool {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    let zone = zone.trim_end_matches('.').to_ascii_lowercase();
    zone.is_empty() || name == zone || name.ends_with(&format!(".{}", zone))
}

/// Decode a DNS-wire-encoded name from rdata (no compression — NS/CNAME rdata)
fn parse_name_from_rdata(rdata: &[u8]) -> String {
    Parser::new(rdata).name().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(id: u16, flags: u16, name: &str, qtype: RType) -> Packet {
        Packet {
            id, flags,
            questions: vec![Question { name: name.to_string(), qtype, qclass: CLASS_IN }],
            answers: vec![], authority: vec![], additional: vec![],
            edns_udp_size: 0, dnssec_ok: false,
        }
    }

    #[test]
    fn test_reply_must_match_query() {
        let query = packet(4242, 0x0100, "www.example.com", RType::A);
        assert!(answers_query(&query, &packet(4242, 0x8180, "WWW.example.com", RType::A)));
        assert!(!answers_query(&query, &packet(4243, 0x8180, "www.example.com", RType::A)), "wrong ID");
        assert!(!answers_query(&query, &packet(4242, 0x8180, "evil.example.com", RType::A)), "wrong name");
        assert!(!answers_query(&query, &packet(4242, 0x8180, "www.example.com", RType::AAAA)), "wrong type");
        assert!(!answers_query(&query, &packet(4242, 0x0100, "www.example.com", RType::A)), "not a response");
    }

    #[test]
    fn test_bailiwick() {
        assert!(in_bailiwick("www.example.com", "example.com"));
        assert!(in_bailiwick("example.com", "example.com"));
        assert!(in_bailiwick("anything.org", "."));
        assert!(!in_bailiwick("www.attacker.com", "example.com"));
        assert!(!in_bailiwick("badexample.com", "example.com"));
    }
}
