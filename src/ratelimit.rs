/// Rate limiter — std only
///
/// Two independent caps, both optional:
/// - per source IP: a token bucket per address, held in a bounded table so a
///   flood of spoofed sources can't grow it without limit
/// - global: total queries per second across every source, which still holds
///   when spoofing makes per-IP limiting useless
use std::{
    collections::HashMap,
    hash::{Hash, Hasher},
    net::IpAddr,
    sync::Mutex,
    sync::atomic::{AtomicU64, Ordering},
    time::Instant,
};

/// The per-source table is split into shards so concurrent receivers rarely share a lock.
const SHARDS: usize = 64;

struct Bucket {
    tokens:     f64,
    last_refill: Instant,
}

struct Shard {
    buckets:    HashMap<IpAddr, Bucket>,
    last_prune: Instant,
}

pub struct RateLimiter {
    /// Max tokens per source (burst capacity = 1 second worth). 0 disables per-source limiting.
    capacity: f64,
    /// Tokens added per second
    rate:     f64,
    shards:   Vec<Mutex<Shard>>,
    /// Sources tracked per shard before new ones fall back to the global cap only
    max_sources_per_shard: usize,
    /// Global queries per second. 0 disables the global cap.
    global_limit: u64,
    started: Instant,
    /// Current one-second window for the global cap and the count admitted in it
    global_window: AtomicU64,
    global_count:  AtomicU64,
}

impl RateLimiter {
    pub fn new(queries_per_second: u32, global_queries_per_second: u32, max_tracked_sources: usize) -> Self {
        let now = Instant::now();
        Self {
            capacity: queries_per_second as f64,
            rate:     queries_per_second as f64,
            shards:   (0..SHARDS).map(|_| Mutex::new(Shard { buckets: HashMap::new(), last_prune: now })).collect(),
            max_sources_per_shard: (max_tracked_sources / SHARDS).max(1),
            global_limit: global_queries_per_second as u64,
            started: now,
            global_window: AtomicU64::new(0),
            global_count:  AtomicU64::new(0),
        }
    }

    /// Returns true if the query is allowed, false if rate-limited
    pub fn check(&self, ip: IpAddr) -> bool {
        self.check_source(ip) && self.check_global()
    }

    // ponytail: fixed one-second window, so up to 2x the limit can pass across a window edge; switch to a token bucket if that burst matters
    fn check_global(&self) -> bool {
        if self.global_limit == 0 { return true; }
        let window = self.started.elapsed().as_secs();
        if self.global_window.swap(window, Ordering::Relaxed) != window {
            self.global_count.store(0, Ordering::Relaxed);
        }
        self.global_count.fetch_add(1, Ordering::Relaxed) < self.global_limit
    }

    fn check_source(&self, ip: IpAddr) -> bool {
        if self.capacity <= 0.0 { return true; }
        let now = Instant::now();
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        ip.hash(&mut hasher);
        let shard_index = hasher.finish() as usize % SHARDS;
        let mut shard = self.shards[shard_index].lock().unwrap_or_else(std::sync::PoisonError::into_inner);

        if !shard.buckets.contains_key(&ip) && shard.buckets.len() >= self.max_sources_per_shard {
            // Table full: prune idle sources at most once a second. If it is
            // still full, this source is only subject to the global cap.
            if now.duration_since(shard.last_prune).as_secs() < 1 { return true; }
            shard.last_prune = now;
            let (capacity, rate) = (self.capacity, self.rate);
            shard.buckets.retain(|_, b| b.tokens + now.duration_since(b.last_refill).as_secs_f64() * rate < capacity);
            if shard.buckets.len() >= self.max_sources_per_shard { return true; }
        }

        let bucket = shard.buckets.entry(ip).or_insert(Bucket {
            tokens:     self.capacity,
            last_refill: now,
        });

        // Refill tokens based on elapsed time
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.rate).min(self.capacity);
        bucket.last_refill = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_per_source_and_global_caps() {
        let first: IpAddr = "192.0.2.1".parse().unwrap();
        let second: IpAddr = "192.0.2.2".parse().unwrap();

        let per_source = RateLimiter::new(5, 0, 1000);
        assert_eq!((0..10).filter(|_| per_source.check(first)).count(), 5);
        assert!(per_source.check(second), "other sources keep their own bucket");

        let global = RateLimiter::new(0, 7, 1000);
        let admitted = (0..20u8).filter(|i| global.check(IpAddr::from([198, 51, 100, *i]))).count();
        assert_eq!(admitted, 7);

        // Table bounded: far more sources than slots must not grow it past the cap
        let bounded = RateLimiter::new(5, 0, SHARDS);
        for i in 0..10_000u32 { bounded.check(IpAddr::from(i.to_be_bytes())); }
        let tracked: usize = bounded.shards.iter().map(|s| s.lock().unwrap().buckets.len()).sum();
        assert!(tracked <= SHARDS);
    }
}
