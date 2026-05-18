# ironbind

A BIND-shaped authoritative + recursive DNS server, written from scratch in Rust.

## What it does

- **Authoritative serving** for zones loaded from RFC 1035 zone files (A, AAAA, CNAME, MX, NS, SOA, TXT, PTR, SRV, NAPTR, DNSKEY, DS, RRSIG, NSEC, NSEC3, NSEC3PARAM)
- **Recursive resolution** via forwarders (`/etc/resolv.conf`) with iterative fallback from the root servers; CNAME chasing; TCP failover on truncation
- **DNSSEC validation** with real crypto — RSA-SHA256/512, ECDSA P-256/P-384, Ed25519 (uses the `rsa`, `p256`, `p384`, `ed25519-dalek` crates)
- **Full chain of trust** anchored at the pinned IANA root KSKs (KSK-2017, KSK-2024) when `dnssec_strict = true`
- **Denial of existence** — emits NSEC or NSEC3 (RFC 5155) on authoritative NXDOMAIN
- **Zone signing** producing RRSIG records
- **AXFR + IXFR** over TCP (RFC 5936, RFC 1995) with on-disk delta history for true incremental transfers
- **TSIG (HMAC-SHA256)** signing and verification on transfers and (optionally) every query (RFC 8945)
- **DNS-over-TLS** (RFC 7858) and **DNS-over-HTTPS** (RFC 8484) via `rustls`
- **Positive + negative caching** (RFC 2308) with TTL eviction
- **Rate limiting** per source IP
- **Prometheus `/metrics`** endpoint with query, cache, RCODE, DNSSEC, and latency counters
- **SIGHUP hot reload** — `kill -HUP` swaps in new zones atomically without dropping queries
- **Bounded worker thread pool** — query floods queue instead of spawning unbounded threads
- **IPv4 + IPv6** binds (v6 literals auto-bracketed)

## Quick start

```bash
./setup.sh                                  # generates keys, TLS cert, config.toml
cargo build --release
./target/release/ironbind config.toml
```

In another terminal:

```bash
dig @127.0.0.1 -p 5353 example.com A
dig @127.0.0.1 -p 5353 example.com MX
dig @127.0.0.1 -p 5353 example.com TXT
dig @127.0.0.1 -p 5353 +tcp api.example.com         # follows CNAME
dig @127.0.0.1 -p 5353 nonexistent.example.com      # NXDOMAIN with NSEC
```

Metrics:
```bash
curl http://127.0.0.1:9090/metrics
```

## Setup

`setup.sh` generates:

| File | Purpose |
|------|---------|
| `keys/Kexample.com+008+zsk.private` | DNSSEC zone signing key (RSA-2048) |
| `keys/Kexample.com+008+ksk.private` | DNSSEC key signing key (RSA-4096) |
| `tls/cert.pem`, `tls/key.pem` | Self-signed TLS cert for DoT/DoH |
| `config.toml` | References the TSIG secret by Keychain service name |

The TSIG HMAC secret is stored in the OS keychain — never written to the repo:

| Platform | Backend |
|----------|---------|
| macOS | Keychain via `security add-generic-password` (service `ironbind-tsig`) |
| Linux | libsecret via `secret-tool store` (gnome-keyring / KWallet) |
| Other / headless | `secrets/tsig.b64` with mode 600 fallback |

Linux users: install `libsecret-tools` (Debian/Ubuntu) or `libsecret` (Fedora/Arch).

`keys/`, `tls/`, and `secrets/` are gitignored.

## Configuration

Full annotated `config.toml`:

```toml
[server]
bind             = "0.0.0.0"     # or "::" for IPv6, or any literal
port             = 5353
worker_threads   = 64
use_forwarders   = true          # try /etc/resolv.conf before iterative
dnssec_validate  = true          # validate RRSIGs on recursive answers
dnssec_strict    = false         # if true, walk full chain from IANA anchors
tcp_timeout_ms   = 5000

[zones]
files = ["example.com.zone"]

[cache]
max_entries = 100000
neg_ttl     = 300

[ratelimit]
queries_per_second = 1000
per_ip             = true

[metrics]
port = 9090                      # 0 disables Prometheus endpoint

[tsig]
name      = "transfer-key."
algorithm = "hmac-sha256."
# Pick ONE secret source:
secret_keychain = "ironbind-tsig"      # recommended (OS keyring)
# secret_file   = "secrets/tsig.b64"   # mode-600 file
# secret        = "BASE64=="           # inline (testing only)
require_all_queries = false      # if true, every query must carry valid TSIG

[dot]
bind = "0.0.0.0:8853"            # use 853 in production (needs root)
cert = "tls/cert.pem"
key  = "tls/key.pem"

[doh]
bind = "0.0.0.0:8443"            # use 443 in production (needs root)
cert = "tls/cert.pem"
key  = "tls/key.pem"
```

Omit any section to disable that feature. With no `[zones]`, ironbind serves a built-in `example.local` zone for sanity-checking.

## Usage

### Authoritative queries

Drop a zone file like `example.com.zone` (see the one in this repo) and reference it in `[zones].files`. Standard RFC 1035 syntax: `$ORIGIN`, `$TTL`, all record types listed above.

### Recursive resolution

Set `use_forwarders = true` to delegate to whatever's in `/etc/resolv.conf`. Disable to force iterative resolution from the root.

### DNS-over-TLS

```bash
kdig -d @127.0.0.1 -p 8853 +tls example.com
```

### DNS-over-HTTPS

```bash
# POST with application/dns-message
curl -sk --data-binary @query.bin -H 'content-type: application/dns-message' \
     https://127.0.0.1:8443/dns-query | xxd

# GET with base64url ?dns=
curl -sk "https://127.0.0.1:8443/dns-query?dns=$(base64 -i query.bin | tr '+/' '-_' | tr -d '=')"
```

### Zone transfers

With a TSIG key configured, transfers must be signed:

```bash
dig @127.0.0.1 -p 5353 -y hmac-sha256:transfer-key.:$SECRET example.com AXFR
dig @127.0.0.1 -p 5353 -y hmac-sha256:transfer-key.:$SECRET \
    example.com IXFR=2024010101
```

IXFR returns a real delta chain when the requester's serial is reachable from history; otherwise it falls back to a full AXFR.

### Hot reload

Edit zone files, bump the serial, then:

```bash
kill -HUP $(pgrep ironbind)
```

The zone manager diffs old vs new, appends the delta to its IXFR history, and atomically swaps in the new snapshot.

### Prometheus

```
ironbind_queries_total           queries served (all transports)
ironbind_queries_udp             "
ironbind_queries_tcp             includes DoT/DoH
ironbind_cache_hits / _misses    "
ironbind_cache_hit_rate          gauge, 0.0–1.0
ironbind_responses_success       NOERROR
ironbind_responses_nxdomain      NXDOMAIN
ironbind_responses_servfail      SERVFAIL
ironbind_dnssec_valid            SECURE validations
ironbind_dnssec_bogus            BOGUS validations
ironbind_query_time_ms           avg latency
```

## Testing

```bash
./quick_test.sh   # builds, spawns a server on a random port, runs core tests
./test.sh         # extended suite
```

## What's not in here

- IXFR with arbitrarily deep history (kept bounded; falls back to AXFR on gap)
- NSEC3 closest-encloser / wildcard denial proofs
- Notify (RFC 1996) — secondaries must poll
- DNSCrypt
- Dynamic updates (RFC 2136)

## Layout

```
src/
  main.rs            entry, wires everything
  server.rs          UDP/TCP listeners, query pipeline
  proto.rs           wire format: parse, build, compression
  zone.rs            zone file parser, RRset store, NSEC/NSEC3 helpers
  zone_manager.rs    hot reload, IXFR history
  zone_signing.rs    DNSSEC zone signing (RRSIG generation)
  resolver.rs        forwarder + iterative resolver
  cache.rs           positive/negative cache with TTL eviction
  dnssec.rs          validation: RSA / ECDSA / Ed25519 + chain of trust
  anchor.rs          pinned IANA root KSK trust anchors
  tsig.rs            HMAC-SHA256 TSIG sign/verify
  axfr.rs            AXFR + IXFR packet streams
  dot.rs / doh.rs    TLS-fronted listeners (rustls)
  metrics.rs         Prometheus exposition
  ratelimit.rs       per-IP token bucket
  threadpool.rs      bounded worker pool
  signals.rs         SIGHUP handler
  config.rs          TOML parser + ServerConfig
```
