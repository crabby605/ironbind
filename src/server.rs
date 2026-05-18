/// DNS Server — RFC 1035 compliant UDP + TCP server
///
/// Implements:
/// - UDP server loop: handles concurrent queries with thread pool
/// - TCP server: supports long responses and RFC 1035 2-byte length prefix
/// - Query resolution pipeline:
///   1. Check if query is for an authoritative zone → return immediately
///   2. Check cache (positive and negative) → return if valid
///   3. If RD bit set, perform recursive resolution (delegate to resolver module)
///   4. If DNSSEC enabled and DO bit set, validate signatures
/// - Rate limiting: configurable queries/second per IP (prevents abuse)
/// - Thread-per-query model: simple but effective for moderate load
use std::{
    io::{Read, Write},
    net::{IpAddr, TcpListener, TcpStream, UdpSocket},
    sync::Arc,
    thread,
    time::Duration,
};

use crate::{
    axfr,
    cache::{Cache, CacheValue, NegativeKind, soa_minimum_ttl},
    config::ServerConfig,
    dnssec::{Validator, ValidationResult},
    metrics::Metrics,
    proto::{
        Packet, Parser, Question, RType, Record,
        RCODE_NOERROR, RCODE_NXDOMAIN, RCODE_SERVFAIL, RCODE_REFUSED, RCODE_NOTIMP,
        serialize,
    },
    ratelimit::RateLimiter,
    resolver::{Resolver, ResolveResult},
    signals,
    threadpool::ThreadPool,
    tsig::{TsigKeyring, sign_message, verify_message},
    zone::Zone,
    zone_manager::ZoneManager,
};
use std::sync::RwLock;
use std::time::Instant;

// ── Server state (shared across threads) ─────────────────────────────────────
//
// State is wrapped in Arc (atomic reference count) so each thread has a shared
// reference to the same zones, cache, resolver, and config without copying.

pub struct State {
    pub zones:        RwLock<Vec<Arc<Zone>>>,    // Authoritative zones, swappable on SIGHUP reload
    pub cache:        Arc<Cache>,                // Shared DNS cache (thread-safe)
    pub resolver:     Arc<Resolver>,             // Shared recursive resolver
    pub config:       Arc<ServerConfig>,         // Server configuration
    pub rate_limiter: Option<Arc<RateLimiter>>,  // Optional rate limiting per IP
    pub metrics:      Arc<Metrics>,              // Prometheus-compatible counters
    pub zone_manager: Arc<RwLock<ZoneManager>>,  // Hot-reloadable zone manager
    pub tsig_keys:    Arc<TsigKeyring>,          // Keyring for TSIG-protected operations
}

/// Public re-export so DoT/DoH modules can invoke the standard query pipeline.
/// Signs the response with TSIG when the request was signed with a known key.
pub fn handle_query_public(data: &[u8], state: &State, peer_ip: IpAddr) -> Option<Vec<u8>> {
    let resp = handle_query(data, state, peer_ip)?;
    Some(maybe_sign_response(data, resp, state))
}

fn maybe_sign_response(req: &[u8], resp: Vec<u8>, state: &State) -> Vec<u8> {
    if state.tsig_keys.is_empty() { return resp; }
    // Cheap check: does request have a TSIG RR?
    let req_pkt = match Parser::new(req).parse() {
        Ok(p) => p,
        Err(_) => return resp,
    };
    let signing_key_name = req_pkt.additional.iter()
        .find(|r| r.rtype == RType::TSIG)
        .map(|r| r.name.clone());
    let Some(name) = signing_key_name else { return resp; };
    let Some(key) = state.tsig_keys.get(&name) else { return resp; };
    sign_message(&resp, key)
}

// ── Entry point ───────────────────────────────────────────────────────────────
//
// Spawns:
// 1. Cache eviction thread: purges expired entries every 60 seconds
// 2. TCP listener thread: accepts TCP connections on configured address
// 3. Main loop: UDP listener on same address (blocking recv_from)
//
// Each query gets a new thread via thread::spawn for isolation and concurrency.

pub fn run(state: Arc<State>) {
    let addr = state.config.bind_addr();

    // Cache eviction thread
    {
        let cache = Arc::clone(&state.cache);
        thread::spawn(move || loop {
            thread::sleep(Duration::from_secs(60));
            cache.evict_expired();
        });
    }

    // SIGHUP reload watcher: polls the flag set by the signal handler
    {
        let state = Arc::clone(&state);
        thread::spawn(move || loop {
            thread::sleep(Duration::from_secs(1));
            if signals::should_reload() {
                eprintln!("[signals] SIGHUP received, reloading zones");
                let mut mgr = state.zone_manager.write().unwrap();
                mgr.reload_all();
                let reloaded: Vec<Arc<Zone>> = mgr.get_zones();
                if !reloaded.is_empty() {
                    *state.zones.write().unwrap() = reloaded;
                }
            }
        });
    }

    // Metrics HTTP endpoint (Prometheus scrape target)
    if state.config.metrics_port > 0 {
        let metrics = Arc::clone(&state.metrics);
        let port = state.config.metrics_port;
        thread::spawn(move || metrics_server(port, metrics));
    }

    // Bounded worker pool — all UDP/TCP/DoT/DoH queries dispatch here.
    let pool = Arc::new(ThreadPool::new(state.config.worker_threads.max(1)));

    // Optional DoT/DoH listeners
    if let Some(dot) = &state.config.dot {
        let state = Arc::clone(&state);
        let pool = Arc::clone(&pool);
        let bind = dot.bind.clone();
        let cert = dot.cert_path.clone();
        let key = dot.key_path.clone();
        thread::spawn(move || crate::dot::run(bind, cert, key, state, pool));
    }
    if let Some(doh) = &state.config.doh {
        let state = Arc::clone(&state);
        let pool = Arc::clone(&pool);
        let bind = doh.bind.clone();
        let cert = doh.cert_path.clone();
        let key = doh.key_path.clone();
        thread::spawn(move || crate::doh::run(bind, cert, key, state, pool));
    }

    // TCP listener thread
    {
        let state = Arc::clone(&state);
        let addr  = addr.clone();
        let pool  = Arc::clone(&pool);
        thread::spawn(move || {
            let listener = TcpListener::bind(&addr).expect("TCP bind failed");
            eprintln!("[tcp] listening on {}", addr);
            for stream in listener.incoming() {
                match stream {
                    Ok(s) => {
                        let st = Arc::clone(&state);
                        pool.submit(move || handle_tcp(s, st));
                    }
                    Err(e) => eprintln!("[tcp] accept: {}", e),
                }
            }
        });
    }

    // UDP main loop
    let sock = UdpSocket::bind(&addr).expect("UDP bind failed");
    eprintln!("[udp] listening on {}", addr);

    loop {
        let mut buf = vec![0u8; 4096];
        match sock.recv_from(&mut buf) {
            Ok((len, peer)) => {
                let data = buf[..len].to_vec();
                let st   = Arc::clone(&state);
                let sock = sock.try_clone().expect("socket clone");
                pool.submit(move || {
                    st.metrics.record_udp_query();
                    let resp = handle_query_public(&data, &st, peer.ip());
                    if let Some(r) = resp {
                        // UDP max — truncate if over limit
                        let max = if st.config.dnssec_validate { 4096 } else { 512 };
                        let r = if r.len() > max {
                            build_truncated(&data)
                        } else {
                            r
                        };
                        let _ = sock.send_to(&r, peer);
                    }
                });
            }
            Err(e) => eprintln!("[udp] recv: {}", e),
        }
    }
}

// ── Query handler ─────────────────────────────────────────────────────────────
//
// Resolution flow for each query:
// 1. Rate limit check: if too many queries from this IP, drop silently (RFC 5358)
// 2. Parse DNS packet from wire format
// 3. Validate OPCODE (must be 0 for standard queries)
// 4. Authoritative lookup: check each zone if name belongs to it
// 5. Cache lookup: check positive and negative caches
// 6. Recursive resolution: if RD bit set, delegate to resolver
// 7. DNSSEC validation: if enabled and DO bit set, validate signatures
// 8. Serialize response back to wire format
//
// Returns: Some(bytes) to send response, None to drop query

fn handle_query(data: &[u8], state: &State, peer_ip: IpAddr) -> Option<Vec<u8>> {
    let start = Instant::now();
    state.metrics.record_query();

    // Rate limit check
    if let Some(rl) = &state.rate_limiter {
        if !rl.check(peer_ip) {
            eprintln!("[ratelimit] dropped query from {}", peer_ip);
            return None; // drop silently (RFC 5358 recommendation)
        }
    }

    // Enforce TSIG on every query when configured. AXFR/IXFR have their own
    // mandatory check in maybe_zone_transfer.
    if state.config.tsig_require_all && !state.tsig_keys.is_empty() {
        if let Err(e) = verify_message(data, &state.tsig_keys) {
            eprintln!("[tsig] rejecting query from {}: {}", peer_ip, e);
            let id = if data.len() >= 2 { u16::from_be_bytes([data[0], data[1]]) } else { 0 };
            let mut r = Packet::new_response(id, 0);
            r.set_rcode(RCODE_REFUSED);
            return Some(serialize(&r, false));
        }
    }

    let pkt = match Parser::new(data).parse() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[parse] {} {}", peer_ip, e);
            return Some(formerr_response(data));
        }
    };

    // Only handle standard queries (OPCODE=0)
    if pkt.opcode() != 0 {
        return Some(error_response(&pkt, RCODE_NOTIMP));
    }

    if pkt.is_response() { return None; }

    let q = match pkt.questions.first() {
        Some(q) => q.clone(),
        None    => return Some(error_response(&pkt, RCODE_NOERROR)),
    };

    log_query(&q, &peer_ip);

    // Build response
    let mut resp = Packet::new_response(pkt.id, pkt.flags);
    resp.questions = pkt.questions.clone();
    resp.edns_udp_size = if pkt.edns_udp_size > 0 { pkt.edns_udp_size } else { 0 };
    resp.dnssec_ok = pkt.dnssec_ok;

    // ── 1. Authoritative zone lookup ─────────────────────────────────────────
    let zones_snapshot: Vec<Arc<Zone>> = state.zones.read().unwrap().clone();
    for zone in &zones_snapshot {
        if !zone.is_authoritative_for(&q.name) { continue; }

        resp.set_aa();

        if let Some(records) = zone.lookup(&q.name, &q.qtype) {
            resp.answers = records.clone();
            // Add DNSSEC records if DO bit set
            if pkt.dnssec_ok {
                if let Some(rrsigs) = zone.lookup(&q.name, &RType::RRSIG) {
                    resp.answers.extend(rrsigs.iter()
                        .filter(|r| {
                            if let Ok(sig) = crate::proto::parse_rrsig(&r.rdata) {
                                sig.type_covered == u16::from(&q.qtype)
                            } else { false }
                        })
                        .cloned());
                }
            }
            state.metrics.record_success();
            state.metrics.record_query_time(start.elapsed().as_nanos() as u64);
            return Some(serialize(&resp, resp.edns_udp_size > 0));
        }

        // Name exists but type doesn't → NODATA
        if zone.name_exists(&q.name) {
            // Add SOA to authority
            if let Some(soa) = zone.soa() {
                resp.authority = soa.clone();
            }
            state.metrics.record_success();
            state.metrics.record_query_time(start.elapsed().as_nanos() as u64);
            return Some(serialize(&resp, resp.edns_udp_size > 0));
        }

        // NXDOMAIN
        resp.set_rcode(RCODE_NXDOMAIN);
        if let Some(soa) = zone.soa() {
            resp.authority = soa.clone();
        }
        // RFC 4035 §3.1.3 / RFC 5155 §7.2.2: include NSEC or NSEC3 proving
        // non-existence when the DO bit is set. Prefer NSEC3 if the zone is
        // configured for opt-out denial.
        if pkt.dnssec_ok {
            if let Some(nsec3) = zone.nsec3_covering(&q.name) {
                resp.authority.push(nsec3);
            } else if let Some((prev, next)) = zone.nsec_covering(&q.name) {
                if let Some(nsec) = zone.nsec_record(&prev, &next) {
                    resp.authority.push(nsec);
                }
            }
        }
        state.metrics.record_nxdomain();
        state.metrics.record_query_time(start.elapsed().as_nanos() as u64);
        return Some(serialize(&resp, resp.edns_udp_size > 0));
    }

    // ── 2. Cache lookup ──────────────────────────────────────────────────────
    match state.cache.get(&q.name, &q.qtype) {
        Some(CacheValue::Records(records)) => {
            state.metrics.record_cache_hit();
            state.metrics.record_success();
            resp.answers = records;
            state.metrics.record_query_time(start.elapsed().as_nanos() as u64);
            return Some(serialize(&resp, resp.edns_udp_size > 0));
        }
        Some(CacheValue::Negative(NegativeKind::NxDomain)) => {
            state.metrics.record_cache_hit();
            state.metrics.record_nxdomain();
            resp.set_rcode(RCODE_NXDOMAIN);
            state.metrics.record_query_time(start.elapsed().as_nanos() as u64);
            return Some(serialize(&resp, resp.edns_udp_size > 0));
        }
        Some(CacheValue::Negative(NegativeKind::NoData)) => {
            state.metrics.record_cache_hit();
            state.metrics.record_success();
            state.metrics.record_query_time(start.elapsed().as_nanos() as u64);
            return Some(serialize(&resp, resp.edns_udp_size > 0));
        }
        None => { state.metrics.record_cache_miss(); }
    }

    // ── 3. Recursive resolution ───────────────────────────────────────────────
    if !pkt.rd() {
        // Recursion not desired and we have no answer
        resp.set_rcode(RCODE_REFUSED);
        return Some(serialize(&resp, resp.edns_udp_size > 0));
    }

    resp.set_ra();

    match state.resolver.resolve(&q.name, &q.qtype) {
        ResolveResult::Answer(upstream) => {
            // ── 4. DNSSEC validation ─────────────────────────────────────────
            if state.config.dnssec_validate && pkt.dnssec_ok && !upstream.answers.is_empty() {
                let rrsigs: Vec<Record> = upstream.answers.iter()
                    .filter(|r| r.rtype == RType::RRSIG)
                    .cloned()
                    .collect();
                let rrset: Vec<Record> = upstream.answers.iter()
                    .filter(|r| r.rtype != RType::RRSIG && r.rtype != RType::DNSKEY)
                    .cloned()
                    .collect();
                let dnskeys: Vec<Record> = upstream.additional.iter()
                    .chain(upstream.answers.iter())
                    .filter(|r| r.rtype == RType::DNSKEY)
                    .cloned()
                    .collect();

                if !rrsigs.is_empty() && !dnskeys.is_empty() {
                    let result = if state.config.dnssec_strict {
                        let resolver = Arc::clone(&state.resolver);
                        let mut fetch = move |name: &str, t: RType| {
                            resolver.fetch_with_rrsig(name, &t)
                        };
                        Validator::chain_validate(&q.name, &rrset, &rrsigs, &mut fetch)
                    } else {
                        Validator::validate_rrset(&rrset, &rrsigs, &dnskeys)
                    };

                    match result {
                        ValidationResult::Bogus(reason) => {
                            eprintln!("[dnssec] BOGUS for {}: {}", q.name, reason);
                            state.metrics.record_dnssec_bogus();
                            state.metrics.record_servfail();
                            resp.set_rcode(RCODE_SERVFAIL);
                            state.metrics.record_query_time(start.elapsed().as_nanos() as u64);
                            return Some(serialize(&resp, resp.edns_udp_size > 0));
                        }
                        ValidationResult::Secure => {
                            eprintln!("[dnssec] SECURE: {}", q.name);
                            state.metrics.record_dnssec_valid();
                        }
                        _ => {}
                    }
                }
            }

            // Cache positive answer
            if let Some(min_ttl) = upstream.answers.iter()
                .filter(|r| r.rtype != RType::RRSIG && r.rtype != RType::OPT)
                .map(|r| r.ttl)
                .min()
            {
                if min_ttl > 0 {
                    state.cache.insert_positive(
                        &q.name, &q.qtype,
                        upstream.answers.iter()
                            .filter(|r| r.rtype != RType::RRSIG)
                            .cloned()
                            .collect(),
                        min_ttl,
                    );
                }
            }

            let rcode = upstream.rcode();
            resp.answers   = upstream.answers;
            resp.authority = upstream.authority;
            resp.additional = upstream.additional;
            resp.set_rcode(rcode);
        }

        ResolveResult::NxDomain(upstream) => {
            // Negative cache with SOA TTL
            let soa_ttl = upstream.authority.iter()
                .find(|r| r.rtype == RType::SOA)
                .map(|r| soa_minimum_ttl(&r.rdata))
                .unwrap_or(state.config.neg_cache_ttl);

            state.cache.insert_negative(&q.name, &q.qtype, NegativeKind::NxDomain, soa_ttl);

            state.metrics.record_nxdomain();
            resp.set_rcode(RCODE_NXDOMAIN);
            resp.authority = upstream.authority;
        }

        ResolveResult::ServFail(reason) => {
            eprintln!("[servfail] {}: {}", q.name, reason);
            state.metrics.record_servfail();
            resp.set_rcode(RCODE_SERVFAIL);
        }
    }

    if resp.rcode() == RCODE_NOERROR {
        state.metrics.record_success();
    }
    state.metrics.record_query_time(start.elapsed().as_nanos() as u64);
    Some(serialize(&resp, resp.edns_udp_size > 0))
}

// ── TCP handler (RFC 1035 §4.2.2 — 2-byte length prefix) ─────────────────────

fn metrics_server(port: u16, metrics: Arc<Metrics>) {
    let listener = match TcpListener::bind(("0.0.0.0", port)) {
        Ok(l) => l,
        Err(e) => { eprintln!("[metrics] bind {}: {}", port, e); return; }
    };
    eprintln!("[metrics] listening on 0.0.0.0:{}/metrics", port);
    for stream in listener.incoming() {
        let Ok(mut s) = stream else { continue };
        let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
        let _ = s.set_write_timeout(Some(Duration::from_secs(2)));
        let mut buf = [0u8; 1024];
        let _ = s.read(&mut buf);
        let body = metrics.export_prometheus();
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(), body
        );
        let _ = s.write_all(resp.as_bytes());
    }
}

fn handle_tcp(mut stream: TcpStream, state: Arc<State>) {
    let peer_ip = stream.peer_addr().map(|a| a.ip())
        .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));

    let _ = stream.set_read_timeout(Some(Duration::from_millis(state.config.tcp_timeout_ms)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(state.config.tcp_timeout_ms)));

    // TCP sessions can carry multiple queries (pipelining)
    loop {
        let mut len_buf = [0u8; 2];
        match stream.read_exact(&mut len_buf) {
            Ok(_) => {}
            Err(_) => break,
        }
        let qlen = u16::from_be_bytes(len_buf) as usize;
        if qlen == 0 || qlen > 65535 { break; }

        let mut data = vec![0u8; qlen];
        if stream.read_exact(&mut data).is_err() { break; }

        state.metrics.record_tcp_query();

        // Intercept zone transfer queries (AXFR / IXFR) — these run only on TCP.
        if let Some(packets) = maybe_zone_transfer(&data, &state) {
            for pkt in packets {
                let rlen = (pkt.len() as u16).to_be_bytes();
                if stream.write_all(&rlen).is_err() { return; }
                if stream.write_all(&pkt).is_err() { return; }
            }
            continue;
        }

        if let Some(resp) = handle_query_public(&data, &state, peer_ip) {
            let rlen = (resp.len() as u16).to_be_bytes();
            if stream.write_all(&rlen).is_err() { break; }
            if stream.write_all(&resp).is_err() { break; }
        }
    }
}

/// If `data` is an AXFR or IXFR query for an authoritative zone, build the
/// response stream. TSIG-signed requests must validate against the keyring or
/// they are refused.
fn maybe_zone_transfer(data: &[u8], state: &State) -> Option<Vec<Vec<u8>>> {
    let pkt = Parser::new(data).parse().ok()?;
    let q = pkt.questions.first()?;
    let is_axfr = matches!(q.qtype, RType::AXFR);
    let is_ixfr = matches!(q.qtype, RType::IXFR);
    if !is_axfr && !is_ixfr { return None; }

    // TSIG: require signature when keyring is configured.
    if !state.tsig_keys.is_empty() {
        if let Err(e) = verify_message(data, &state.tsig_keys) {
            eprintln!("[xfr] TSIG verification failed: {}", e);
            let mut r = Packet::new_response(pkt.id, pkt.flags);
            r.questions = pkt.questions.clone();
            r.set_rcode(RCODE_REFUSED);
            return Some(vec![serialize(&r, false)]);
        }
    }

    let zones = state.zones.read().unwrap().clone();
    let zone = zones.iter().find(|z| z.is_authoritative_for(&q.name))?;

    let mut packets = if is_axfr {
        axfr::axfr_stream(&pkt, zone)
    } else {
        // For IXFR the client's current serial sits in the authority SOA.
        let requester_serial = pkt.authority.iter()
            .find(|r| r.rtype == RType::SOA)
            .and_then(|r| {
                let mut p = Parser::new(&r.rdata);
                p.name().ok()?; p.name().ok()?;
                p.u32().ok()
            })
            .unwrap_or(0);
        let history = state.zone_manager.read().unwrap()
            .ixfr_chain(&q.name, requester_serial);
        axfr::ixfr_stream(&pkt, zone, requester_serial, history)
    };

    // TSIG-sign every outgoing packet when the request itself was signed.
    if !state.tsig_keys.is_empty() {
        if let Some(key) = state.tsig_keys.get("transfer-key.") {
            packets = packets.into_iter().map(|p| sign_message(&p, key)).collect();
        }
    }

    Some(packets)
}

// ── Error responses ───────────────────────────────────────────────────────────

fn error_response(pkt: &Packet, rcode: u8) -> Vec<u8> {
    let mut r = Packet::new_response(pkt.id, pkt.flags);
    r.questions = pkt.questions.clone();
    r.set_rcode(rcode);
    serialize(&r, false)
}

fn formerr_response(data: &[u8]) -> Vec<u8> {
    // Best-effort: extract ID from first 2 bytes
    let id = if data.len() >= 2 {
        u16::from_be_bytes([data[0], data[1]])
    } else { 0 };
    let mut r = Packet::new_response(id, 0);
    r.set_rcode(1); // FORMERR
    serialize(&r, false)
}

fn build_truncated(query: &[u8]) -> Vec<u8> {
    match Parser::new(query).parse() {
        Ok(pkt) => {
            let mut r = Packet::new_response(pkt.id, pkt.flags);
            r.questions = pkt.questions;
            r.set_tc();
            r.set_ra();
            serialize(&r, false)
        }
        Err(_) => formerr_response(query),
    }
}

fn log_query(q: &Question, peer: &IpAddr) {
    eprintln!("[query] {} {:?} IN from {}", q.name, q.qtype, peer);
}
