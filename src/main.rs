mod advanced;
mod anchor;
mod axfr;
mod cache;
mod config;
mod dnssec;
mod doh;
mod dot;
mod metrics;
mod proto;
mod ratelimit;
mod resolver;
mod server;
mod signals;
mod threadpool;
mod tsig;
mod zone;
mod zone_manager;
mod zone_signing;

use std::sync::{Arc, RwLock};
use config::ServerConfig;
use resolver::{Resolver, ResolverConfig};
use ratelimit::RateLimiter;
use metrics::Metrics;
use tsig::{TsigKey, TsigKeyring};
use zone_manager::ZoneManager;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // ── Load config ──────────────────────────────────────────────────────────
    let cfg = if let Some(path) = args.get(1) {
        match ServerConfig::load(path) {
            Ok(c) => {
                eprintln!("[config] loaded from {}", path);
                c
            }
            Err(e) => {
                eprintln!("[config] failed to load {}: {} — using defaults", path, e);
                ServerConfig::default()
            }
        }
    } else {
        eprintln!("[config] no config file specified, using defaults (bind 0.0.0.0:5353)");
        let mut c = ServerConfig::default();
        c.port = 5353; // non-privileged for dev
        c
    };

    eprintln!("[config] bind={} dnssec_validate={} use_forwarders={}",
        cfg.bind_addr(), cfg.dnssec_validate, cfg.use_forwarders);

    // ── Load zones via ZoneManager (supports SIGHUP reload) ──────────────────
    let mut zone_manager = ZoneManager::new();
    for path in &cfg.zone_files {
        let origin = std::path::Path::new(path)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or(".")
            .trim_end_matches(".zone")
            .to_string();
        if let Err(e) = zone_manager.load_zone(&origin, path) {
            eprintln!("[zone] failed to load {}: {}", path, e);
        }
    }

    let mut zones: Vec<Arc<zone::Zone>> = zone_manager.get_zones();

    // Always load example.local if no zones specified (dev convenience)
    if zones.is_empty() {
        let mut z = zone::Zone::new("example.local");
        z.add(proto::Record {
            name:  "example.local".into(),
            rtype: proto::RType::A,
            class: proto::CLASS_IN,
            ttl:   300,
            rdata: std::net::Ipv4Addr::new(127, 0, 0, 1).octets().to_vec(),
        });
        z.add(proto::Record {
            name:  "example.local".into(),
            rtype: proto::RType::TXT,
            class: proto::CLASS_IN,
            ttl:   300,
            rdata: {
                let txt = b"ironbind test zone";
                let mut v = vec![txt.len() as u8];
                v.extend_from_slice(txt);
                v
            },
        });
        eprintln!("[zone] loaded built-in example.local zone");
        zones.push(Arc::new(z));
    }

    // ── Resolver ─────────────────────────────────────────────────────────────
    let mut res_cfg = ResolverConfig::from_resolv_conf();
    res_cfg.use_forwarders = cfg.use_forwarders;

    // ── Rate limiter ─────────────────────────────────────────────────────────
    let rate_limiter = cfg.rate_limit.as_ref().map(|rl| {
        eprintln!("[ratelimit] {} qps per-ip={}", rl.queries_per_second, rl.per_ip);
        Arc::new(RateLimiter::new(rl.queries_per_second))
    });

    // ── TSIG keyring (secrets resolved from Keychain, file, or inline) ───────
    let mut keyring = TsigKeyring::new();
    for k in &cfg.tsig_keys {
        match k.secret_source.resolve() {
            Ok(secret) => {
                eprintln!("[tsig] loaded key '{}' ({} bytes)", k.name, secret.len());
                keyring.insert(TsigKey {
                    name: k.name.clone(),
                    algorithm: k.algorithm.clone(),
                    secret,
                });
            }
            Err(e) => eprintln!("[tsig] failed to load key '{}': {}", k.name, e),
        }
    }

    // ── Assemble state ────────────────────────────────────────────────────────
    let state = Arc::new(server::State {
        zones:        RwLock::new(zones),
        cache:        Arc::new(cache::Cache::new()),
        resolver:     Arc::new(Resolver::new(res_cfg)),
        config:       Arc::new(cfg),
        rate_limiter,
        metrics:      Metrics::new(),
        zone_manager: Arc::new(RwLock::new(zone_manager)),
        tsig_keys:    Arc::new(keyring),
    });

    // ── Signal handlers ──────────────────────────────────────────────────────
    signals::setup_signal_handler();

    // ── Run ───────────────────────────────────────────────────────────────────
    eprintln!("[ironbind] starting up");
    server::run(state);
}
