# ironbind

A BIND-shaped authoritative + recursive DNS server, written from scratch in Rust.

![ironbind serving a signed zone file and following a CNAME, a signed NSEC proof validated by Unbound, cached recursion compared with Quad9, Google and Cloudflare, DNS-over-HTTPS, and Prometheus metrics including load-shedding counters](demo.gif)

## What it does

- **Authoritative serving** for zones loaded from RFC 1035 zone files (A, AAAA, CNAME, MX, NS, SOA, TXT, PTR, SRV, NAPTR, DNSKEY, DS, RRSIG, NSEC, NSEC3, NSEC3PARAM)
- **Recursive resolution** via forwarders (`/etc/resolv.conf`) with iterative fallback from the root servers; CNAME chasing; TCP failover on truncation
- **Spoofing-resistant upstream queries** — random IDs and source ports, connected sockets, replies must match the ID and question, and bailiwick checks on referrals, glue and answers
- **Recursion access control** — `allow_recursion` limits recursion and the cache to listed networks (private ranges by default); everyone can query the authoritative zones
- **DNSSEC validation** with real crypto — RSA-SHA256/512, ECDSA P-256/P-384, Ed25519 (uses the `rsa`, `p256`, `p384`, `ed25519-dalek` crates)
- **Full chain of trust** anchored at the pinned IANA root KSKs (KSK-2017, KSK-2024) when `dnssec_strict = true`
- **Zone signing** at load time and every 24 hours: when `keys/K<zone>+008+zsk.private` exists the zone is signed with RSA-SHA256, DNSKEY records are published, and the KSK signs the DNSKEY RRset
- **Authenticated denial of existence** — a signed NSEC chain in canonical order; NXDOMAIN carries the proofs for the name and the wildcard, NODATA the NSEC at the name. Validated end to end with Unbound
- **AXFR + IXFR** over TCP (RFC 5936, RFC 1995) with on-disk delta history for true incremental transfers
- **TSIG (HMAC-SHA256)** signing and verification on transfers and (optionally) every query (RFC 8945)
- **DNS-over-TLS** (RFC 7858) and **DNS-over-HTTPS** (RFC 8484) via `rustls`
- **Positive + negative caching** (RFC 2308) with TTL eviction
- **Rate limiting** per source IP (bounded table, so spoofed floods can't grow it) and globally
- **Prometheus `/metrics`** endpoint with query, cache, RCODE, DNSSEC, and latency counters
- **SIGHUP hot reload** — `kill -HUP` swaps in new zones atomically without dropping queries
- **Load shedding** — UDP receivers answer authoritative and cached queries inline; recursion, TCP/DoT/DoH each run on bounded pools that drop the newest work when full, counted in metrics
- **Self-healing** — a panicking query is contained to its worker, and every listener restarts itself with backoff if it dies or fails to bind
- **IPv4 + IPv6** binds (v6 literals auto-bracketed)

## Quick start

```bash
./setup.sh                                  # generates keys, TLS cert, config.toml
cargo build --release
./target/release/ironbind config.toml
```

In another terminal:

```bash
dig @127.0.0.1 -p 5000 example.com A
dig @127.0.0.1 -p 5000 example.com MX
dig @127.0.0.1 -p 5000 example.com TXT
dig @127.0.0.1 -p 5000 +tcp api.example.com         # follows CNAME
dig @127.0.0.1 -p 5000 +dnssec www.example.com      # answer + RRSIG
dig @127.0.0.1 -p 5000 +dnssec nonexistent.example.com   # NXDOMAIN with NSEC
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
port             = 5000          # 5353 clashes with mDNSResponder on macOS
worker_threads   = 64            # recursion pool and connection pool size
udp_receivers    = 2             # threads reading the UDP socket; more contend and get slower
use_forwarders   = true          # try /etc/resolv.conf before iterative
dnssec_validate  = true          # validate RRSIGs on recursive answers
dnssec_strict    = false         # if true, walk full chain from IANA anchors
allow_recursion  = ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "::1/128", "fc00::/7"]
                                 # who may recurse / use the cache (default: loopback, private, CGNAT, link-local)
tcp_timeout_ms   = 5000          # also applies to DoT/DoH connections
log_queries      = false         # log every query to stderr (megabytes per second under load)

[zones]
files = ["example.com.zone"]

[cache]
max_entries = 100000
neg_ttl     = 300

[ratelimit]
queries_per_second        = 1000     # per source IP
per_ip                    = true
global_queries_per_second = 200000   # across all sources; still holds when sources are spoofed
max_tracked_sources       = 100000   # size limit of the per-source table

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

Omit any section to disable that feature. An invalid value stops the server at startup rather than falling back to defaults. With no `[zones]`, ironbind serves a built-in `example.local` zone for sanity-checking.

## Usage

### Authoritative queries

Drop a zone file like `example.com.zone` (see the one in this repo) and reference it in `[zones].files`. Standard RFC 1035 syntax: `$ORIGIN`, `$TTL`, multi-line records in parentheses, quoted TXT strings, and the record types listed above. CNAMEs inside the zone are followed in the answer.

### DNSSEC signing

Run `./setup.sh` (or drop your own RSA keys at `keys/K<zone>+008+zsk.private` and `keys/K<zone>+008+ksk.private`) and the zone is signed every time it loads, including on SIGHUP. Fetch the KSK to build a DS record for the parent (`dnssec-dsfromkey` ships with BIND's tools):

```bash
dig @127.0.0.1 -p 5000 example.com DNSKEY | dnssec-dsfromkey -f - example.com
```

Signatures are valid for 30 days and the zone is re-signed every 24 hours. Answers, NXDOMAIN and NODATA proofs all validate as secure in Unbound anchored on the zone's KSK.

### Recursive resolution

Set `use_forwarders = true` to delegate to whatever's in `/etc/resolv.conf`. Disable to force iterative resolution from the root.

Recursion is only offered to `allow_recursion` networks; other clients get REFUSED for anything outside the authoritative zones. To run a public resolver like 1.1.1.1 or Quad9, open it up and keep the rate limits on, since open resolvers get used for amplification:

```toml
[server]
allow_recursion = ["0.0.0.0/0", "::/0"]

[ratelimit]
queries_per_second        = 100
global_queries_per_second = 200000
```

![ironbind against Quad9, Google and Cloudflare: warm-cache and cold-name query times from bench.sh](comparison.gif)

`./bench.sh NAME [N]` reproduces the comparison: warm cache on localhost answers in under a millisecond; cold names depend on the upstream path.

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
dig @127.0.0.1 -p 5000 -y hmac-sha256:transfer-key.:$SECRET example.com AXFR
dig @127.0.0.1 -p 5000 -y hmac-sha256:transfer-key.:$SECRET \
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
ironbind_dropped_rate_limited    queries dropped by the rate limiter
ironbind_dropped_recursion_limit recursive UDP queries dropped, recursion pool full
ironbind_dropped_connections     TCP/DoT/DoH connections closed, all workers busy
```

## Resilience

Load-tested on loopback on an Apple M4 (10 cores), with the load generator sharing those cores:

| Scenario | Result |
|----------|--------|
| UDP, 200k queries/s offered | 200k/s answered, 100% |
| UDP, 400k–825k packets/s offered | ~210k/s answered at best; the rest dropped by the kernel, server stays up at ~16 MB |
| Pipelined TCP | ~160k qps, 100% answered, 0 wrong |
| 12M fuzzed / malformed packets, with and without TSIG enforced | no crashes |
| 200 idle TCP connections | UDP latency unchanged (0.1 ms) |
| Listener port taken at startup | retried with backoff, came up once the port was free |

macOS loopback tops out around 800k packets/s, so floods beyond that need a separate load box.

A panicking query is contained to that query, and every listener restarts itself with backoff. For failures nothing in-process can catch (OOM kill, `SIGKILL`), `ironbind.service` runs it under systemd with `Restart=always` and a raised `LimitNOFILE`; install steps are at the top of the file.

## Testing

```bash
./quick_test.sh   # builds, spawns a server on a random port, runs core tests
./test.sh         # extended suite
```

## What's not in here

- IXFR with arbitrarily deep history (kept bounded; falls back to AXFR on gap)
- NSEC3 signing (signed zones use NSEC, so names can be enumerated by walking the chain)
- Response rate limiting (RRL); per-IP and global caps only
- Wildcard records (`*` owners load but aren't synthesized)
- Automatic SOA serial bump on re-signing, so secondaries only pick up new signatures on the next serial change
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
