/// Per-IP token bucket rate limiter — std only
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::Mutex,
    time::Instant,
};

struct Bucket {
    tokens:     f64,
    last_refill: Instant,
}

pub struct RateLimiter {
    /// Max tokens (burst capacity = 1 second worth)
    capacity: f64,
    /// Tokens added per second
    rate:     f64,
    buckets:  Mutex<HashMap<IpAddr, Bucket>>,
    /// Last time we pruned stale entries
    last_prune: Mutex<Instant>,
}

impl RateLimiter {
    pub fn new(queries_per_second: u32) -> Self {
        Self {
            capacity: queries_per_second as f64,
            rate:     queries_per_second as f64,
            buckets:  Mutex::new(HashMap::new()),
            last_prune: Mutex::new(Instant::now()),
        }
    }

    /// Returns true if the query is allowed, false if rate-limited
    pub fn check(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut map = self.buckets.lock().unwrap();

        let bucket = map.entry(ip).or_insert(Bucket {
            tokens:     self.capacity,
            last_refill: now,
        });

        // Refill tokens based on elapsed time
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.rate).min(self.capacity);
        bucket.last_refill = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            // Prune stale entries every 60s
            self.maybe_prune(&mut map, now);
            true
        } else {
            false
        }
    }

    fn maybe_prune(&self, map: &mut HashMap<IpAddr, Bucket>, now: Instant) {
        let mut last = self.last_prune.lock().unwrap();
        if now.duration_since(*last).as_secs() < 60 { return; }
        *last = now;
        drop(last);
        // Remove buckets that are full (idle IPs)
        map.retain(|_, b| b.tokens < self.capacity);
    }
}
