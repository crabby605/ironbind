/// Metrics — Prometheus-compatible DNS metrics
///
/// Tracks DNS server metrics for monitoring:
/// - Query count (by type, response code)
/// - Cache hit/miss rates
/// - Query latency (min/avg/max)
/// - DNSSEC validation results
/// - Zone statistics

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// DNS metrics collector
pub struct Metrics {
    /// Total queries received
    total_queries: AtomicU64,
    /// Cache hits
    cache_hits: AtomicU64,
    /// Cache misses
    cache_misses: AtomicU64,
    /// Successful queries (RCODE 0)
    success_count: AtomicU64,
    /// NXDOMAIN responses (RCODE 3)
    nxdomain_count: AtomicU64,
    /// SERVFAIL responses (RCODE 2)
    servfail_count: AtomicU64,
    /// DNSSEC validations successful
    dnssec_valid: AtomicU64,
    /// DNSSEC validations failed (BOGUS)
    dnssec_bogus: AtomicU64,
    /// TCP queries
    tcp_queries: AtomicU64,
    /// UDP queries
    udp_queries: AtomicU64,
    /// Total query time (nanoseconds)
    total_query_time: AtomicU64,
    /// Queries processed
    query_count_for_avg: AtomicU64,
}

impl Metrics {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            total_queries: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            success_count: AtomicU64::new(0),
            nxdomain_count: AtomicU64::new(0),
            servfail_count: AtomicU64::new(0),
            dnssec_valid: AtomicU64::new(0),
            dnssec_bogus: AtomicU64::new(0),
            tcp_queries: AtomicU64::new(0),
            udp_queries: AtomicU64::new(0),
            total_query_time: AtomicU64::new(0),
            query_count_for_avg: AtomicU64::new(0),
        })
    }

    // Query counting
    pub fn record_query(&self) {
        self.total_queries.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_udp_query(&self) {
        self.udp_queries.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_tcp_query(&self) {
        self.tcp_queries.fetch_add(1, Ordering::Relaxed);
    }

    // Cache metrics
    pub fn record_cache_hit(&self) {
        self.cache_hits.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_cache_miss(&self) {
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
    }

    // Response code metrics
    pub fn record_success(&self) {
        self.success_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_nxdomain(&self) {
        self.nxdomain_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_servfail(&self) {
        self.servfail_count.fetch_add(1, Ordering::Relaxed);
    }

    // DNSSEC metrics
    pub fn record_dnssec_valid(&self) {
        self.dnssec_valid.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_dnssec_bogus(&self) {
        self.dnssec_bogus.fetch_add(1, Ordering::Relaxed);
    }

    // Query timing
    pub fn record_query_time(&self, duration_ns: u64) {
        self.total_query_time.fetch_add(duration_ns, Ordering::Relaxed);
        self.query_count_for_avg.fetch_add(1, Ordering::Relaxed);
    }

    // Getters
    pub fn get_total_queries(&self) -> u64 {
        self.total_queries.load(Ordering::Relaxed)
    }

    pub fn get_cache_hit_rate(&self) -> f64 {
        let hits = self.cache_hits.load(Ordering::Relaxed) as f64;
        let misses = self.cache_misses.load(Ordering::Relaxed) as f64;
        if hits + misses == 0.0 {
            0.0
        } else {
            hits / (hits + misses)
        }
    }

    pub fn get_avg_query_time_ms(&self) -> f64 {
        let total = self.total_query_time.load(Ordering::Relaxed) as f64;
        let count = self.query_count_for_avg.load(Ordering::Relaxed) as f64;
        if count == 0.0 {
            0.0
        } else {
            (total / count) / 1_000_000.0 // ns to ms
        }
    }

    // Prometheus-style output
    pub fn export_prometheus(&self) -> String {
        let mut output = String::new();

        output.push_str("# HELP ironbind_queries_total Total DNS queries received\n");
        output.push_str("# TYPE ironbind_queries_total counter\n");
        output.push_str(&format!("ironbind_queries_total {}\n", self.total_queries.load(Ordering::Relaxed)));

        output.push_str("# HELP ironbind_queries_udp UDP queries\n");
        output.push_str("# TYPE ironbind_queries_udp counter\n");
        output.push_str(&format!("ironbind_queries_udp {}\n", self.udp_queries.load(Ordering::Relaxed)));

        output.push_str("# HELP ironbind_queries_tcp TCP queries\n");
        output.push_str("# TYPE ironbind_queries_tcp counter\n");
        output.push_str(&format!("ironbind_queries_tcp {}\n", self.tcp_queries.load(Ordering::Relaxed)));

        output.push_str("# HELP ironbind_cache_hits Cache hits\n");
        output.push_str("# TYPE ironbind_cache_hits counter\n");
        output.push_str(&format!("ironbind_cache_hits {}\n", self.cache_hits.load(Ordering::Relaxed)));

        output.push_str("# HELP ironbind_cache_misses Cache misses\n");
        output.push_str("# TYPE ironbind_cache_misses counter\n");
        output.push_str(&format!("ironbind_cache_misses {}\n", self.cache_misses.load(Ordering::Relaxed)));

        output.push_str("# HELP ironbind_cache_hit_rate Cache hit rate\n");
        output.push_str("# TYPE ironbind_cache_hit_rate gauge\n");
        output.push_str(&format!("ironbind_cache_hit_rate {:.4}\n", self.get_cache_hit_rate()));

        output.push_str("# HELP ironbind_responses_success Successful responses\n");
        output.push_str("# TYPE ironbind_responses_success counter\n");
        output.push_str(&format!("ironbind_responses_success {}\n", self.success_count.load(Ordering::Relaxed)));

        output.push_str("# HELP ironbind_responses_nxdomain NXDOMAIN responses\n");
        output.push_str("# TYPE ironbind_responses_nxdomain counter\n");
        output.push_str(&format!("ironbind_responses_nxdomain {}\n", self.nxdomain_count.load(Ordering::Relaxed)));

        output.push_str("# HELP ironbind_responses_servfail SERVFAIL responses\n");
        output.push_str("# TYPE ironbind_responses_servfail counter\n");
        output.push_str(&format!("ironbind_responses_servfail {}\n", self.servfail_count.load(Ordering::Relaxed)));

        output.push_str("# HELP ironbind_dnssec_valid Valid DNSSEC signatures\n");
        output.push_str("# TYPE ironbind_dnssec_valid counter\n");
        output.push_str(&format!("ironbind_dnssec_valid {}\n", self.dnssec_valid.load(Ordering::Relaxed)));

        output.push_str("# HELP ironbind_dnssec_bogus BOGUS DNSSEC signatures\n");
        output.push_str("# TYPE ironbind_dnssec_bogus counter\n");
        output.push_str(&format!("ironbind_dnssec_bogus {}\n", self.dnssec_bogus.load(Ordering::Relaxed)));

        output.push_str("# HELP ironbind_query_time_ms Average query time in milliseconds\n");
        output.push_str("# TYPE ironbind_query_time_ms gauge\n");
        output.push_str(&format!("ironbind_query_time_ms {:.4}\n", self.get_avg_query_time_ms()));

        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_creation() {
        let metrics = Metrics::new();
        assert_eq!(metrics.get_total_queries(), 0);
    }

    #[test]
    fn test_metrics_counting() {
        let metrics = Metrics::new();
        metrics.record_query();
        metrics.record_query();
        assert_eq!(metrics.get_total_queries(), 2);
    }

    #[test]
    fn test_cache_hit_rate() {
        let metrics = Metrics::new();
        metrics.record_cache_hit();
        metrics.record_cache_hit();
        metrics.record_cache_miss();
        assert!((metrics.get_cache_hit_rate() - 2.0/3.0).abs() < 0.001);
    }
}

