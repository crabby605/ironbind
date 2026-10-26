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
    net::{IpAddr, SocketAddr, TcpListener, TcpStream, UdpSocket},
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
use std::panic::{self, AssertUnwindSafe};
use std::sync::RwLock;
use std::time::Instant;

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
    if !admit(state, peer_ip) { return None; }
    match respond(data, state, peer_ip, Recursion::Inline) {
        Answer::Ready(resp) => resp,
        Answer::Recursive   => None,
    }
}

fn respond(data: &[u8], state: &State, peer_ip: IpAddr, recursion: Recursion) -> Answer {
    match handle_query(data, state, peer_ip, recursion) {
        Answer::Ready(Some(resp)) => Answer::Ready(Some(maybe_sign_response(data, resp, state))),
        other => other,
    }
}

/// How a query that needs an upstream lookup is handled.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Recursion {
    /// Resolve on the calling thread (TCP/DoT/DoH connection workers)
    Inline,
    /// Return `Answer::Recursive` so a UDP receiver can hand the query off
    Defer,
    /// The handed-off query running on the recursion pool
    Resume,
}

enum Answer {
    /// Bytes to send back, or nothing
    Ready(Option<Vec<u8>>),
    /// Needs an upstream lookup on the recursion pool
    Recursive,
}

/// Rate limit check, done before any parsing so floods cost as little as possible.
/// Dropped silently (RFC 5358 recommendation) and counted in metrics.
fn admit(state: &State, peer_ip: IpAddr) -> bool {
    let Some(rate_limiter) = &state.rate_limiter else { return true };
    if rate_limiter.check(peer_ip) { return true; }
    state.metrics.record_dropped_rate_limited();
    if state.config.log_queries { eprintln!("[ratelimit] dropped query from {}", peer_ip); }
    false
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
        spawn_supervised("cache-eviction", move || loop {
            thread::sleep(Duration::from_secs(60));
            cache.evict_expired();
        });
    }

    // SIGHUP reload watcher: polls the flag set by the signal handler. Zones are
    // also reloaded (and so re-signed) once a day, well inside the 30-day validity.
    {
        let state = Arc::clone(&state);
        spawn_supervised("reload-watcher", move || {
            let mut last_signed = Instant::now();
            loop {
                thread::sleep(Duration::from_secs(1));
                let resign_due = last_signed.elapsed() >= RESIGN_INTERVAL;
                if signals::should_reload() || resign_due {
                    last_signed = Instant::now();
                    eprintln!("[zone-manager] {}, reloading zones", if resign_due { "re-signing" } else { "SIGHUP received" });
                    let mut mgr = state.zone_manager.write().unwrap_or_else(std::sync::PoisonError::into_inner);
                    mgr.reload_all();
                    let reloaded: Vec<Arc<Zone>> = mgr.get_zones();
                    if !reloaded.is_empty() {
                        *state.zones.write().unwrap_or_else(std::sync::PoisonError::into_inner) = reloaded;
                    }
                }
            }
        });
    }

    // Metrics HTTP endpoint (Prometheus scrape target)
    if state.config.metrics_port > 0 {
        let metrics = Arc::clone(&state.metrics);
        let port = state.config.metrics_port;
        spawn_supervised("metrics", move || metrics_server(port, Arc::clone(&metrics)));
    }

    // Connections (TCP/DoT/DoH) and recursive UDP lookups each get a bounded pool,
    // so neither idle clients nor slow upstream servers can hold the UDP receivers.
    let workers = state.config.worker_threads.max(1);
    let connection_pool = Arc::new(ThreadPool::new("conn", workers, workers));
    let recursion_pool = Arc::new(ThreadPool::new("recursion", workers, workers * RECURSION_QUEUE_PER_WORKER));

    // Optional DoT/DoH listeners
    if let Some(dot) = &state.config.dot {
        let state = Arc::clone(&state);
        let pool = Arc::clone(&connection_pool);
        let bind = dot.bind.clone();
        let cert = dot.cert_path.clone();
        let key = dot.key_path.clone();
        spawn_supervised("dot", move || crate::dot::run(
            bind.clone(), cert.clone(), key.clone(), Arc::clone(&state), Arc::clone(&pool)));
    }
    if let Some(doh) = &state.config.doh {
        let state = Arc::clone(&state);
        let pool = Arc::clone(&connection_pool);
        let bind = doh.bind.clone();
        let cert = doh.cert_path.clone();
        let key = doh.key_path.clone();
        spawn_supervised("doh", move || crate::doh::run(
            bind.clone(), cert.clone(), key.clone(), Arc::clone(&state), Arc::clone(&pool)));
    }

    // TCP listener thread
    {
        let state = Arc::clone(&state);
        let addr  = addr.clone();
        let pool  = Arc::clone(&connection_pool);
        spawn_supervised("tcp", move || {
            let listener = match TcpListener::bind(&addr) {
                Ok(listener) => listener,
                Err(e) => { eprintln!("[tcp] bind {}: {}", addr, e); return; }
            };
            eprintln!("[tcp] listening on {}", addr);
            for stream in listener.incoming() {
                match stream {
                    Ok(s) => {
                        let st = Arc::clone(&state);
                        // Every worker busy: the connection is closed instead of queued
                        if !pool.submit(move || handle_tcp(s, st)) {
                            state.metrics.record_dropped_connection();
                        }
                    }
                    Err(e) => eprintln!("[tcp] accept: {}", e),
                }
            }
        });
    }

    // UDP receivers, restarted in place if they ever stop
    run_supervised("udp", || udp_loop(&addr, &state, &recursion_pool));
}

/// A few receiver threads block on the same socket and answer authoritative and
/// cached queries themselves, so the fast path has no hand-off queue: the kernel's
/// socket buffer is the queue, and when it is full the kernel drops the newest
/// packet (clients retry). More receivers than `udp_receivers` contend on the
/// socket lock and answer fewer queries, not more.
fn udp_loop(addr: &str, state: &Arc<State>, recursion_pool: &Arc<ThreadPool>) {
    let sock = match UdpSocket::bind(addr) {
        Ok(sock) => Arc::new(sock),
        Err(e) => { eprintln!("[udp] bind {}: {}", addr, e); return; }
    };
    eprintln!("[udp] listening on {}", addr);

    let receivers: Vec<_> = (0..state.config.udp_receivers.max(1))
        .filter_map(|index| {
            let (sock, state, recursion_pool) = (Arc::clone(&sock), Arc::clone(state), Arc::clone(recursion_pool));
            thread::Builder::new()
                .name(format!("udp-receiver-{}", index))
                .spawn(move || udp_receiver(&sock, &state, &recursion_pool))
                .map_err(|e| eprintln!("[udp] spawn receiver: {}", e))
                .ok()
        })
        .collect();
    // Returns only once every receiver has stopped, and the supervisor rebinds
    for receiver in receivers { let _ = receiver.join(); }
}

fn udp_receiver(sock: &Arc<UdpSocket>, state: &Arc<State>, recursion_pool: &ThreadPool) {
    let mut buf = [0u8; 4096];
    loop {
        let (len, peer) = match sock.recv_from(&mut buf) {
            Ok(received) => received,
            Err(e) => {
                if state.config.log_queries { eprintln!("[udp] recv: {}", e); }
                continue;
            }
        };
        if !admit(state, peer.ip()) { continue; }
        state.metrics.record_udp_query();

        let data = &buf[..len];
        match answer_catching_panics(data, state, peer, Recursion::Defer) {
            Answer::Ready(Some(resp)) => send_udp(sock, data, resp, peer),
            Answer::Ready(None) => {}
            Answer::Recursive => {
                let (data, sock, job_state) = (data.to_vec(), Arc::clone(sock), Arc::clone(state));
                let queued = recursion_pool.submit(move || {
                    if let Answer::Ready(Some(resp)) = answer_catching_panics(&data, &job_state, peer, Recursion::Resume) {
                        send_udp(&sock, &data, resp, peer);
                    }
                });
                // Recursion pool full: drop the newest query, the client retries
                if !queued { state.metrics.record_dropped_recursion_limit(); }
            }
        }
    }
}

/// A query that panics is answered with nothing; the thread keeps going.
fn answer_catching_panics(data: &[u8], state: &State, peer: SocketAddr, recursion: Recursion) -> Answer {
    panic::catch_unwind(AssertUnwindSafe(|| respond(data, state, peer.ip(), recursion)))
        .unwrap_or_else(|_| {
            eprintln!("[udp] query from {} panicked", peer.ip());
            Answer::Ready(None)
        })
}

fn send_udp(sock: &UdpSocket, query: &[u8], resp: Vec<u8>, peer: SocketAddr) {
    // UDP max is the client's EDNS payload size, or 512 without EDNS (RFC 6891 §6.2.5)
    let max = Parser::new(query).parse()
        .map(|parsed| (parsed.edns_udp_size as usize).clamp(512, 4096))
        .unwrap_or(512);
    let resp = if resp.len() > max { build_truncated(query) } else { resp };
    let _ = sock.send_to(&resp, peer);
}

// Every long-running loop runs under a supervisor: if it panics or returns
// (a bind failed, a listener died) it is started again after a backoff of
// 1s doubling to 30s, reset once the loop has stayed up for a minute.

fn run_supervised<F: Fn()>(name: &str, job: F) {
    let mut delay = Duration::from_secs(1);
    loop {
        let started = Instant::now();
        match panic::catch_unwind(AssertUnwindSafe(&job)) {
            Ok(())  => eprintln!("[supervisor] {} stopped, restarting in {:?}", name, delay),
            Err(_)  => eprintln!("[supervisor] {} panicked, restarting in {:?}", name, delay),
        }
        if started.elapsed() > Duration::from_secs(60) { delay = Duration::from_secs(1); }
        thread::sleep(delay);
        delay = (delay * 2).min(Duration::from_secs(30));
    }
}

fn spawn_supervised<F: Fn() + Send + 'static>(name: &'static str, job: F) {
    thread::spawn(move || run_supervised(name, job));
}

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

fn handle_query(data: &[u8], state: &State, peer_ip: IpAddr, recursion: Recursion) -> Answer {
    let start = Instant::now();
    // A deferred query was already counted when the receiver first saw it
    if recursion != Recursion::Resume { state.metrics.record_query(); }

    // Never answer a response, not even with an error: spoofed responses would
    // otherwise bounce traffic between servers.
    if data.len() < 3 || data[2] & 0x80 != 0 { return Answer::Ready(None); }

    // Enforce TSIG on every query when configured. AXFR/IXFR have their own
    // mandatory check in maybe_zone_transfer.
    if state.config.tsig_require_all && !state.tsig_keys.is_empty() {
        if let Err(e) = verify_message(data, &state.tsig_keys) {
            if state.config.log_queries { eprintln!("[tsig] rejecting query from {}: {}", peer_ip, e); }
            let id = if data.len() >= 2 { u16::from_be_bytes([data[0], data[1]]) } else { 0 };
            let mut r = Packet::new_response(id, 0);
            r.set_rcode(RCODE_REFUSED);
            return Answer::Ready(Some(serialize(&r, false)));
        }
    }

    let pkt = match Parser::new(data).parse() {
        Ok(p) => p,
        Err(e) => {
            if state.config.log_queries { eprintln!("[parse] {} {}", peer_ip, e); }
            return Answer::Ready(Some(formerr_response(data)));
        }
    };

    if pkt.is_response() { return Answer::Ready(None); }

    // Only handle standard queries (OPCODE=0)
    if pkt.opcode() != 0 {
        return Answer::Ready(Some(error_response(&pkt, RCODE_NOTIMP)));
    }

    let q = match pkt.questions.first() {
        Some(q) => q.clone(),
        None    => return Answer::Ready(Some(error_response(&pkt, RCODE_NOERROR))),
    };

    if state.config.log_queries { log_query(&q, &peer_ip); }

    // Build response
    let mut resp = Packet::new_response(pkt.id, pkt.flags);
    resp.questions = pkt.questions.clone();
    resp.edns_udp_size = if pkt.edns_udp_size > 0 { pkt.edns_udp_size } else { 0 };
    resp.dnssec_ok = pkt.dnssec_ok;

    // The most specific zone wins, so a child zone is not shadowed by its parent.
    let zones_snapshot: Vec<Arc<Zone>> = state.zones.read().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
    let authoritative_zone = zones_snapshot.iter()
        .filter(|zone| zone.is_authoritative_for(&q.name))
        .max_by_key(|zone| zone.origin.len());
    if let Some(zone) = authoritative_zone {
        resp.set_aa();

        // Follow CNAMEs inside the zone (RFC 1034 §4.3.2). A target outside the
        // zone is returned as-is for the client's resolver to chase.
        let mut current_name = q.name.clone();
        let mut answered = false;
        for _ in 0..MAX_CNAME_CHAIN {
            if let Some(records) = zone.lookup(&current_name, &q.qtype) {
                resp.answers.extend(records.iter().cloned());
                if pkt.dnssec_ok {
                    resp.answers.extend(covering_rrsigs(zone, &current_name, &q.qtype));
                }
                answered = true;
                break;
            }
            if q.qtype == RType::CNAME { break; }
            let Some(cname) = zone.lookup(&current_name, &RType::CNAME).and_then(|c| c.first()) else { break };
            resp.answers.push(cname.clone());
            if pkt.dnssec_ok {
                resp.answers.extend(covering_rrsigs(zone, &current_name, &RType::CNAME));
            }
            let Ok(target) = Parser::new(&cname.rdata).name() else { break };
            if !zone.is_authoritative_for(&target) {
                answered = true;
                break;
            }
            current_name = target;
        }

        if answered {
            state.metrics.record_success();
            state.metrics.record_query_time(start.elapsed().as_nanos() as u64);
            return Answer::Ready(Some(serialize(&resp, resp.edns_udp_size > 0)));
        }

        // Add SOA to authority for both negative answers (RFC 2308 §3)
        if let Some(soa) = zone.soa() {
            resp.authority = soa.clone();
            if pkt.dnssec_ok {
                resp.authority.extend(covering_rrsigs(zone, &zone.origin, &RType::SOA));
            }
        }

        // Name exists but type doesn't → NODATA
        if zone.name_exists(&current_name) {
            // RFC 4035 §3.1.3.1: the NSEC at the name proves the type is absent.
            // An empty non-terminal has no NSEC of its own; the covering one proves it.
            if pkt.dnssec_ok && zone.is_signed() {
                let owner = if zone.lookup(&current_name, &RType::NSEC).is_some() {
                    Some(current_name.as_str())
                } else {
                    zone.nsec_covering_owner(&current_name)
                };
                if let Some(owner) = owner {
                    push_signed_nsec(&mut resp.authority, zone, owner);
                }
            }
            state.metrics.record_success();
            state.metrics.record_query_time(start.elapsed().as_nanos() as u64);
            return Answer::Ready(Some(serialize(&resp, resp.edns_udp_size > 0)));
        }

        // NXDOMAIN
        resp.set_rcode(RCODE_NXDOMAIN);
        // RFC 4035 §3.1.3.2: with the DO bit set, prove both that the name does not
        // exist and that no wildcard at its closest encloser could have matched it.
        // The NSEC3 branch is only used when the zone file carries NSEC3 records.
        if pkt.dnssec_ok {
            if let Some(nsec3) = zone.nsec3_covering(&current_name) {
                resp.authority.push(nsec3);
            } else if zone.is_signed() {
                let wildcard = format!("*.{}", zone.closest_encloser(&current_name));
                let name_owner = zone.nsec_covering_owner(&current_name).map(str::to_string);
                let wildcard_owner = zone.nsec_covering_owner(&wildcard).map(str::to_string);
                if let Some(owner) = &name_owner {
                    push_signed_nsec(&mut resp.authority, zone, owner);
                }
                if let Some(owner) = wildcard_owner.filter(|owner| Some(owner) != name_owner.as_ref()) {
                    push_signed_nsec(&mut resp.authority, zone, &owner);
                }
            }
        }
        state.metrics.record_nxdomain();
        state.metrics.record_query_time(start.elapsed().as_nanos() as u64);
        return Answer::Ready(Some(serialize(&resp, resp.edns_udp_size > 0)));
    }

    // Recursion and the cache are only for allowed client networks; anyone else
    // gets authoritative answers only (no open resolver, no cache snooping).
    if !state.config.allow_recursion.iter().any(|network| network.contains(peer_ip)) {
        resp.set_rcode(RCODE_REFUSED);
        return Answer::Ready(Some(serialize(&resp, resp.edns_udp_size > 0)));
    }

    match state.cache.get(&q.name, &q.qtype) {
        Some(CacheValue::Records(records)) => {
            state.metrics.record_cache_hit();
            state.metrics.record_success();
            resp.answers = records;
            state.metrics.record_query_time(start.elapsed().as_nanos() as u64);
            return Answer::Ready(Some(serialize(&resp, resp.edns_udp_size > 0)));
        }
        Some(CacheValue::Negative(NegativeKind::NxDomain)) => {
            state.metrics.record_cache_hit();
            state.metrics.record_nxdomain();
            resp.set_rcode(RCODE_NXDOMAIN);
            state.metrics.record_query_time(start.elapsed().as_nanos() as u64);
            return Answer::Ready(Some(serialize(&resp, resp.edns_udp_size > 0)));
        }
        Some(CacheValue::Negative(NegativeKind::NoData)) => {
            state.metrics.record_cache_hit();
            state.metrics.record_success();
            state.metrics.record_query_time(start.elapsed().as_nanos() as u64);
            return Answer::Ready(Some(serialize(&resp, resp.edns_udp_size > 0)));
        }
        None => if recursion != Recursion::Resume { state.metrics.record_cache_miss(); },
    }

    if !pkt.rd() {
        // Recursion not desired and we have no answer
        resp.set_rcode(RCODE_REFUSED);
        return Answer::Ready(Some(serialize(&resp, resp.edns_udp_size > 0)));
    }

    resp.set_ra();

    // UDP receivers hand upstream lookups to the recursion pool instead of waiting on them
    if recursion == Recursion::Defer { return Answer::Recursive; }

    match state.resolver.resolve(&q.name, &q.qtype) {
        ResolveResult::Answer(upstream) => {
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
                            if state.config.log_queries { eprintln!("[dnssec] BOGUS for {}: {}", q.name, reason); }
                            state.metrics.record_dnssec_bogus();
                            state.metrics.record_servfail();
                            resp.set_rcode(RCODE_SERVFAIL);
                            state.metrics.record_query_time(start.elapsed().as_nanos() as u64);
                            return Answer::Ready(Some(serialize(&resp, resp.edns_udp_size > 0)));
                        }
                        ValidationResult::Secure => {
                            if state.config.log_queries { eprintln!("[dnssec] SECURE: {}", q.name); }
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
            if state.config.log_queries { eprintln!("[servfail] {}: {}", q.name, reason); }
            state.metrics.record_servfail();
            resp.set_rcode(RCODE_SERVFAIL);
        }
    }

    if resp.rcode() == RCODE_NOERROR {
        state.metrics.record_success();
    }
    state.metrics.record_query_time(start.elapsed().as_nanos() as u64);
    Answer::Ready(Some(serialize(&resp, resp.edns_udp_size > 0)))
}

/// How often zones are reloaded and re-signed. Signatures last 30 days.
const RESIGN_INTERVAL: Duration = Duration::from_secs(24 * 3600);

/// Queued recursive UDP lookups allowed per recursion worker before new ones are dropped.
const RECURSION_QUEUE_PER_WORKER: usize = 16;

/// Longest CNAME chain followed inside an authoritative zone before giving up.
const MAX_CNAME_CHAIN: usize = 8;

/// The stored NSEC at `owner` together with its RRSIG.
fn push_signed_nsec(section: &mut Vec<Record>, zone: &Zone, owner: &str) {
    if let Some(nsec) = zone.lookup(owner, &RType::NSEC) {
        section.extend(nsec.iter().cloned());
        section.extend(covering_rrsigs(zone, owner, &RType::NSEC));
    }
}

/// RRSIGs stored at `name` that cover `covered_type`.
fn covering_rrsigs(zone: &Zone, name: &str, covered_type: &RType) -> Vec<Record> {
    let covered_type_code = u16::from(covered_type);
    zone.lookup(name, &RType::RRSIG)
        .map(|rrsigs| rrsigs.iter()
            .filter(|r| crate::proto::parse_rrsig(&r.rdata)
                .map(|sig| sig.type_covered == covered_type_code)
                .unwrap_or(false))
            .cloned()
            .collect())
        .unwrap_or_default()
}

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

    let zones = state.zones.read().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
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
        let history = state.zone_manager.read().unwrap_or_else(std::sync::PoisonError::into_inner)
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
