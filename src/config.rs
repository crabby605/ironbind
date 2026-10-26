/// Hand-rolled TOML parser (zero deps) — supports:
///   strings, integers, booleans, arrays of strings
///   [sections] and inline key = value
use std::{collections::HashMap, fs, net::IpAddr};

#[derive(Debug, Clone)]
pub enum TomlVal {
    Str(String),
    Int(i64),
    Bool(bool),
    Array(Vec<String>),
}

type Section = HashMap<String, TomlVal>;

#[derive(Debug, Default)]
pub struct Toml {
    global:   Section,
    sections: HashMap<String, Section>,
}

impl Toml {
    pub fn parse_file(path: &str) -> std::io::Result<Self> {
        let content = fs::read_to_string(path)?;
        Ok(Self::parse_str(&content))
    }

    pub fn parse_str(s: &str) -> Self {
        let mut t = Toml::default();
        let mut current_section: Option<String> = None;

        for raw in s.lines() {
            let line = strip_comment(raw).trim().to_string();
            if line.is_empty() { continue; }

            if line.starts_with('[') && line.ends_with(']') {
                current_section = Some(line[1..line.len()-1].trim().to_string());
                continue;
            }

            if let Some((k, v)) = parse_kv(&line) {
                let map = match &current_section {
                    Some(sec) => t.sections.entry(sec.clone()).or_default(),
                    None      => &mut t.global,
                };
                map.insert(k, v);
            }
        }
        t
    }

    fn get<'a>(&'a self, section: Option<&str>, key: &str) -> Option<&'a TomlVal> {
        match section {
            Some(s) => self.sections.get(s)?.get(key),
            None    => self.global.get(key),
        }
    }

    pub fn str(&self, section: Option<&str>, key: &str) -> Option<&str> {
        match self.get(section, key)? {
            TomlVal::Str(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn int(&self, section: Option<&str>, key: &str) -> Option<i64> {
        match self.get(section, key)? {
            TomlVal::Int(n) => Some(*n),
            TomlVal::Str(s) => s.parse().ok(),
            _ => None,
        }
    }

    pub fn bool(&self, section: Option<&str>, key: &str) -> Option<bool> {
        match self.get(section, key)? {
            TomlVal::Bool(b) => Some(*b),
            TomlVal::Str(s)  => match s.as_str() { "true" => Some(true), "false" => Some(false), _ => None },
            _ => None,
        }
    }

    pub fn array(&self, section: Option<&str>, key: &str) -> Vec<String> {
        match self.get(section, key) {
            Some(TomlVal::Array(a)) => a.clone(),
            Some(TomlVal::Str(s))   => vec![s.clone()],
            _ => vec![],
        }
    }
}

fn strip_comment(line: &str) -> &str {
    // Don't strip inside strings
    let mut in_str = false;
    for (i, c) in line.char_indices() {
        match c {
            '"' => in_str = !in_str,
            '#' if !in_str => return &line[..i],
            _ => {}
        }
    }
    line
}

fn parse_kv(line: &str) -> Option<(String, TomlVal)> {
    let eq = line.find('=')?;
    let key = line[..eq].trim().to_string();
    let val_str = line[eq+1..].trim();
    let val = parse_value(val_str)?;
    Some((key, val))
}

fn parse_value(s: &str) -> Option<TomlVal> {
    if s.starts_with('"') && s.ends_with('"') {
        return Some(TomlVal::Str(s[1..s.len()-1].to_string()));
    }
    if s == "true"  { return Some(TomlVal::Bool(true));  }
    if s == "false" { return Some(TomlVal::Bool(false)); }
    if s.starts_with('[') && s.ends_with(']') {
        let inner = &s[1..s.len()-1];
        let items: Vec<String> = inner.split(',')
            .map(|p| p.trim().trim_matches('"').to_string())
            .filter(|p| !p.is_empty())
            .collect();
        return Some(TomlVal::Array(items));
    }
    if let Ok(n) = s.parse::<i64>() { return Some(TomlVal::Int(n)); }
    // bare string
    if !s.is_empty() { return Some(TomlVal::Str(s.to_string())); }
    None
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub bind:            String,
    pub port:            u16,
    pub use_forwarders:  bool,
    pub dnssec_validate: bool,
    /// When true, validation walks the full chain from IANA root anchors down
    /// to the answer's zone instead of trusting any DNSKEY the upstream sent.
    pub dnssec_strict:   bool,
    /// Client networks allowed to use recursion and the cache. Everyone may
    /// query the authoritative zones. A public resolver sets 0.0.0.0/0 and ::/0.
    pub allow_recursion: Vec<Network>,
    pub cache_max:       usize,
    pub neg_cache_ttl:   u32,
    pub zone_files:      Vec<String>,
    pub log_level:       String,
    /// Log every query (and per-query errors) to stderr. Off by default: at
    /// load this writes megabytes per second.
    pub log_queries:     bool,
    pub tcp_timeout_ms:  u64,
    pub rate_limit:      Option<RateLimitConfig>,
    /// HTTP port for Prometheus metrics scraping. 0 = disabled.
    pub metrics_port:    u16,
    /// Worker threads for recursive lookups, and separately for TCP/DoT/DoH connections.
    pub worker_threads:  usize,
    /// Threads receiving on the UDP socket and answering authoritative/cached queries.
    /// More is not faster: they contend on the socket lock (2 measured best on a 10-core M4).
    pub udp_receivers:   usize,
    /// DNS-over-TLS listener (typically port 853).
    pub dot:             Option<TlsListenerConfig>,
    /// DNS-over-HTTPS listener (typically port 443).
    pub doh:             Option<TlsListenerConfig>,
    /// TSIG keys keyed by name. Empty disables TSIG.
    pub tsig_keys:       Vec<TsigKeyConfig>,
    /// If true, every incoming query must carry a valid TSIG signature.
    /// AXFR/IXFR always require TSIG when a keyring is present, regardless.
    pub tsig_require_all: bool,
}

#[derive(Debug, Clone)]
pub struct TlsListenerConfig {
    pub bind:      String,
    pub cert_path: String,
    pub key_path:  String,
}

#[derive(Debug, Clone)]
pub struct TsigKeyConfig {
    pub name:      String,
    pub algorithm: String,
    /// How to retrieve the shared secret. Exactly one variant is used.
    pub secret_source: TsigSecretSource,
}

#[derive(Debug, Clone)]
pub enum TsigSecretSource {
    /// Base64-encoded secret inline in the config (discouraged).
    Inline(String),
    /// OS keychain service name. Looked up via /usr/bin/security on macOS
    /// (Keychain) or `secret-tool` on Linux (libsecret / GNOME Keyring / KWallet).
    Keychain(String),
    /// Path to a file whose contents are the base64-encoded secret.
    File(String),
}

impl TsigSecretSource {
    /// Resolve to raw secret bytes, decoding base64 along the way.
    pub fn resolve(&self) -> Result<Vec<u8>, String> {
        use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
        let b64 = match self {
            Self::Inline(s) => s.clone(),
            Self::File(path) => std::fs::read_to_string(path)
                .map_err(|e| format!("read {}: {}", path, e))?
                .trim().to_string(),
            Self::Keychain(service) => read_keychain(service)?,
        };
        B64.decode(&b64).map_err(|e| format!("invalid base64: {}", e))
    }
}

#[cfg(target_os = "macos")]
fn read_keychain(service: &str) -> Result<String, String> {
    let out = std::process::Command::new("security")
        .args(["find-generic-password", "-w", "-s", service])
        .output()
        .map_err(|e| format!("invoke security: {}", e))?;
    if !out.status.success() {
        return Err(format!(
            "macOS Keychain service '{}' not found: {}",
            service, String::from_utf8_lossy(&out.stderr).trim(),
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

#[cfg(target_os = "linux")]
fn read_keychain(service: &str) -> Result<String, String> {
    let out = std::process::Command::new("secret-tool")
        .args(["lookup", "service", service])
        .output()
        .map_err(|e| format!(
            "invoke secret-tool: {} (install libsecret-tools)", e
        ))?;
    if !out.status.success() || out.stdout.is_empty() {
        return Err(format!(
            "libsecret service '{}' not found: {}",
            service, String::from_utf8_lossy(&out.stderr).trim(),
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn read_keychain(_service: &str) -> Result<String, String> {
    Err("Keychain lookup not supported on this platform; use secret_file instead".to_string())
}

/// Loopback, private, link-local and carrier-grade NAT ranges: recursion stays
/// off the public internet unless allow_recursion says otherwise.
const DEFAULT_ALLOW_RECURSION: &[&str] = &[
    "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "169.254.0.0/16", "100.64.0.0/10", "::1/128", "fc00::/7", "fe80::/10",
];

/// An address range written as `address/prefix`, or a bare address.
#[derive(Debug, Clone)]
pub struct Network {
    address: IpAddr,
    prefix:  u8,
}

impl Network {
    pub fn parse(text: &str) -> Option<Self> {
        let (address_text, prefix_text) = match text.split_once('/') {
            Some((address, prefix)) => (address, Some(prefix)),
            None => (text, None),
        };
        let address: IpAddr = address_text.trim().parse().ok()?;
        let max_prefix = if address.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix_text {
            Some(p) => p.trim().parse::<u8>().ok().filter(|p| *p <= max_prefix)?,
            None => max_prefix,
        };
        Some(Self { address, prefix })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        // IPv4 clients on an IPv6 socket arrive as ::ffff:a.b.c.d
        match (self.address, ip.to_canonical()) {
            (IpAddr::V4(network), IpAddr::V4(ip)) => {
                let mask = u32::MAX.checked_shl(32 - self.prefix as u32).unwrap_or(0);
                u32::from(network) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(network), IpAddr::V6(ip)) => {
                let mask = u128::MAX.checked_shl(128 - self.prefix as u32).unwrap_or(0);
                u128::from(network) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Per source IP (ignored when per_ip is false)
    pub queries_per_second: u32,
    pub per_ip: bool,
    /// Across all sources; 0 = no global cap
    pub global_queries_per_second: u32,
    /// Size limit of the per-source table
    pub max_tracked_sources: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind:            "0.0.0.0".to_string(),
            port:            53,
            use_forwarders:  true,
            dnssec_validate: true,
            dnssec_strict:   false,
            allow_recursion: DEFAULT_ALLOW_RECURSION.iter().filter_map(|n| Network::parse(n)).collect(),
            cache_max:       100_000,
            neg_cache_ttl:   300,
            zone_files:      vec![],
            log_level:       "info".to_string(),
            log_queries:     false,
            tcp_timeout_ms:  5000,
            rate_limit:      None,
            metrics_port:    0,
            worker_threads:  64,
            udp_receivers:   2,
            dot:             None,
            doh:             None,
            tsig_keys:       Vec::new(),
            tsig_require_all: false,
        }
    }
}

impl ServerConfig {
    pub fn load(path: &str) -> std::io::Result<Self> {
        let t = Toml::parse_file(path)?;
        let mut c = ServerConfig::default();

        if let Some(b) = t.str(Some("server"), "bind")        { c.bind = b.to_string(); }
        if let Some(p) = t.int(Some("server"), "port")        { c.port = p as u16; }
        if let Some(v) = t.bool(Some("server"), "use_forwarders") { c.use_forwarders = v; }
        if let Some(v) = t.bool(Some("server"), "dnssec_validate") { c.dnssec_validate = v; }
        if let Some(v) = t.bool(Some("server"), "dnssec_strict")   { c.dnssec_strict = v; }
        if t.get(Some("server"), "allow_recursion").is_some() {
            c.allow_recursion = Vec::new();
            for entry in t.array(Some("server"), "allow_recursion") {
                match Network::parse(&entry) {
                    Some(network) => c.allow_recursion.push(network),
                    None => return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("allow_recursion: '{}' is not an address or CIDR network", entry),
                    )),
                }
            }
        }
        if let Some(v) = t.int(Some("cache"),  "max_entries") { c.cache_max = v as usize; }
        if let Some(v) = t.int(Some("cache"),  "neg_ttl")     { c.neg_cache_ttl = v as u32; }
        if let Some(v) = t.str(Some("server"), "log_level")   { c.log_level = v.to_string(); }
        if let Some(v) = t.bool(Some("server"), "log_queries") { c.log_queries = v; }
        if let Some(v) = t.int(Some("server"), "tcp_timeout_ms") { c.tcp_timeout_ms = v as u64; }
        if let Some(v) = t.int(Some("server"), "worker_threads") { c.worker_threads = v as usize; }
        if let Some(v) = t.int(Some("server"), "udp_receivers")  { c.udp_receivers = v as usize; }
        if let Some(v) = t.int(Some("metrics"), "port") { c.metrics_port = v as u16; }

        if let (Some(b), Some(cert), Some(key)) = (
            t.str(Some("dot"), "bind"),
            t.str(Some("dot"), "cert"),
            t.str(Some("dot"), "key"),
        ) {
            c.dot = Some(TlsListenerConfig {
                bind: b.to_string(), cert_path: cert.to_string(), key_path: key.to_string(),
            });
        }
        if let (Some(b), Some(cert), Some(key)) = (
            t.str(Some("doh"), "bind"),
            t.str(Some("doh"), "cert"),
            t.str(Some("doh"), "key"),
        ) {
            c.doh = Some(TlsListenerConfig {
                bind: b.to_string(), cert_path: cert.to_string(), key_path: key.to_string(),
            });
        }

        if let (Some(n), Some(a)) = (t.str(Some("tsig"), "name"), t.str(Some("tsig"), "algorithm")) {
            let src = if let Some(s) = t.str(Some("tsig"), "secret_keychain") {
                Some(TsigSecretSource::Keychain(s.to_string()))
            } else if let Some(s) = t.str(Some("tsig"), "secret_file") {
                Some(TsigSecretSource::File(s.to_string()))
            } else {
                t.str(Some("tsig"), "secret").map(|s| TsigSecretSource::Inline(s.to_string()))
            };
            if let Some(src) = src {
                c.tsig_keys.push(TsigKeyConfig {
                    name: n.to_string(),
                    algorithm: a.to_string(),
                    secret_source: src,
                });
            }
        }
        if let Some(v) = t.bool(Some("tsig"), "require_all_queries") { c.tsig_require_all = v; }

        c.zone_files = t.array(Some("zones"), "files");

        let per_source = t.int(Some("ratelimit"), "queries_per_second");
        let global = t.int(Some("ratelimit"), "global_queries_per_second");
        if per_source.is_some() || global.is_some() {
            c.rate_limit = Some(RateLimitConfig {
                queries_per_second: per_source.unwrap_or(0).max(0) as u32,
                per_ip: t.bool(Some("ratelimit"), "per_ip").unwrap_or(true),
                global_queries_per_second: global.unwrap_or(0).max(0) as u32,
                max_tracked_sources: t.int(Some("ratelimit"), "max_tracked_sources").unwrap_or(100_000).max(1) as usize,
            });
        }

        Ok(c)
    }

    pub fn bind_addr(&self) -> String {
        // IPv6 literals need bracket-wrapping per RFC 3986 §3.2.2.
        if self.bind.contains(':') && !self.bind.starts_with('[') {
            format!("[{}]:{}", self.bind, self.port)
        } else {
            format!("{}:{}", self.bind, self.port)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_contains() {
        let private = Network::parse("10.0.0.0/8").unwrap();
        assert!(private.contains("10.20.30.40".parse().unwrap()));
        assert!(!private.contains("11.0.0.1".parse().unwrap()));
        assert!(private.contains("::ffff:10.1.2.3".parse().unwrap()), "IPv4-mapped client");
        assert!(Network::parse("0.0.0.0/0").unwrap().contains("203.0.113.9".parse().unwrap()));
        assert!(Network::parse("::/0").unwrap().contains("2001:db8::1".parse().unwrap()));
        assert!(Network::parse("192.0.2.7").unwrap().contains("192.0.2.7".parse().unwrap()));
        assert!(Network::parse("10.0.0.0/33").is_none());
        assert!(Network::parse("not-an-ip").is_none());
    }
}
