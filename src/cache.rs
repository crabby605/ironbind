/// RFC 2308 compliant DNS cache with positive + negative caching
///
/// Features:
/// - **Positive cache**: stores successful answers with their TTL
/// - **Negative cache**: stores NXDOMAIN and NODATA responses per RFC 2308
/// - **TTL enforcement**: entries expire based on minimum TTL in response
/// - **Thread-safe**: uses RwLock for concurrent read access
/// - **Background eviction**: stale entries pruned every 60 seconds
///
/// Cache key: (name.to_lowercase(), qtype_number)
/// This ensures www.example.com and WWW.EXAMPLE.COM map to same cache entry

use std::{
    collections::HashMap,
    sync::RwLock,
    time::{Duration, Instant},
};
use crate::proto::{RType, Record};

#[derive(Debug, Clone)]
pub enum CacheValue {
    /// Positive answer: list of resource records (A, AAAA, CNAME, etc)
    /// TTL is per-record, but we cache by minimum TTL for efficiency
    Records(Vec<Record>),
    /// Negative cache: NXDOMAIN or NODATA with SOA-derived TTL (RFC 2308)
    /// Negative responses cache for shorter times (usually 5-15 minutes)
    Negative(NegativeKind),
}

#[derive(Debug, Clone)]
pub enum NegativeKind {
    /// NXDOMAIN — domain name does not exist at all (query can be for any type)
    NxDomain,
    /// NODATA — domain exists, but this record type does not (e.g., no AAAA for a domain with only A)
    NoData,
}

#[derive(Clone)]
struct Entry {
    value:   CacheValue,
    expires: Instant,           // When this entry expires and should be purged
    /// Original TTL for reference (useful for debugging and statistics)
    ttl:     u32,
}

pub struct Cache {
    // Thread-safe HashMap protected by RwLock
    // Read lock: multiple threads can check cache simultaneously
    // Write lock: only for cache.insert and evict_expired
    inner: RwLock<HashMap<CacheKey, Entry>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    name:  String,  // Always lowercase for case-insensitive lookup
    qtype: u16,     // RType as u16 for hashable key
}

impl Cache {
    pub fn new() -> Self {
        Self { inner: RwLock::new(HashMap::new()) }
    }

    /// Lookup a cached entry by name and query type
    /// Returns Some(value) if found AND not expired, None otherwise
    /// Case-insensitive: WWW.EXAMPLE.COM finds entry for www.example.com
    pub fn get(&self, name: &str, qtype: &RType) -> Option<CacheValue> {
        let key = CacheKey { name: name.to_ascii_lowercase(), qtype: u16::from(qtype) };
        let map = self.inner.read().unwrap();
        match map.get(&key) {
            Some(e) if e.expires > Instant::now() => Some(e.value.clone()),
            _ => None,
        }
    }

    /// Cache a successful answer (positive cache)
    /// TTL is clamped to [1 second, 24 hours] to prevent accidental poisoning
    pub fn insert_positive(&self, name: &str, qtype: &RType, records: Vec<Record>, ttl: u32) {
        let ttl = ttl.clamp(1, 86400);  // Sanity check: 1s to 24h
        let key = CacheKey { name: name.to_ascii_lowercase(), qtype: u16::from(qtype) };
        self.inner.write().unwrap().insert(key, Entry {
            value:   CacheValue::Records(records),
            expires: Instant::now() + Duration::from_secs(ttl as u64),
            ttl,
        });
    }

    /// Cache a negative response (NXDOMAIN or NODATA)
    /// Per RFC 2308: negative cache TTL = min(SOA MINIMUM, SOA TTL), capped at 10800s (3 hours)
    /// This prevents excessive caching of errors while still reducing upstream load
    pub fn insert_negative(&self, name: &str, qtype: &RType, kind: NegativeKind, soa_ttl: u32) {
        let ttl = soa_ttl.min(10800).max(1);  // Clamp to [1s, 3h]
        let key = CacheKey { name: name.to_ascii_lowercase(), qtype: u16::from(qtype) };
        self.inner.write().unwrap().insert(key, Entry {
            value:   CacheValue::Negative(kind),
            expires: Instant::now() + Duration::from_secs(ttl as u64),
            ttl,
        });
    }

    /// Periodic sweep — call every 60s from background thread
    /// Removes all entries past their expiration time (garbage collection)
    pub fn evict_expired(&self) {
        let now = Instant::now();
        self.inner.write().unwrap().retain(|_, v| v.expires > now);
    }

    /// Current number of cached entries (useful for monitoring)
    pub fn size(&self) -> usize {
        self.inner.read().unwrap().len()
    }
}

/// Extract the negative cache TTL from SOA record rdata
///
/// SOA RDATA format: mname rname serial refresh retry expire minimum
/// The MINIMUM field (last u32) becomes the negative cache TTL
/// Typical values: 300-3600 seconds (5 minutes to 1 hour)
///
/// If parsing fails, returns safe default of 300 seconds
pub fn soa_minimum_ttl(soa_rdata: &[u8]) -> u32 {
    // Parse past mname + rname (two DNS names), then 5x u32
    let mut p = crate::proto::Parser::new(soa_rdata);
    if p.name().is_err() { return 300; }  // Malformed SOA
    if p.name().is_err() { return 300; }
    let _serial  = p.u32().unwrap_or(0);
    let _refresh = p.u32().unwrap_or(0);
    let _retry   = p.u32().unwrap_or(0);
    let _expire  = p.u32().unwrap_or(0);
    p.u32().unwrap_or(300) // MINIMUM (last field, defaults to 300s if unreadable)
}
