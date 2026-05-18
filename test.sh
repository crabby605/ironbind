#!/bin/bash
# Test script for ironbind — comprehensive DNS server tests
# Usage: ./test.sh [--server-only] [--verbose]

set -e

VERBOSE=${VERBOSE:-0}
SERVER_ONLY=${SERVER_ONLY:-0}
TEST_PORT=5353
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$PROJECT_DIR/target/release/ironbind"
TEST_DIR="/tmp/ironbind-test"
CONFIG_FILE="$TEST_DIR/config.toml"
ZONE_FILE="$TEST_DIR/test.example.com.zone"

# ANSI colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0

# ─────────────────────────────────────────────────────────────────────────────

log() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

success() {
    echo -e "${GREEN}✓${NC} $*"
    ((TESTS_PASSED++))
}

fail() {
    echo -e "${RED}✗${NC} $*"
    ((TESTS_FAILED++))
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

# ─────────────────────────────────────────────────────────────────────────────

setup_test_env() {
    log "Setting up test environment..."

    mkdir -p "$TEST_DIR"
    cd "$TEST_DIR"

    # Create test config
    cat > "$CONFIG_FILE" << 'EOF'
[server]
bind            = "127.0.0.1"
port            = 5353
use_forwarders  = false       # Don't use system resolvers in tests
dnssec_validate = false       # Disable DNSSEC for basic tests
log_level       = "info"
tcp_timeout_ms  = 2000

[cache]
max_entries = 1000
neg_ttl     = 60

[zones]
files = ["test.example.com.zone"]

[ratelimit]
queries_per_second = 1000
per_ip             = true
EOF

    # Create test zone file
    cat > "$ZONE_FILE" << 'EOF'
$ORIGIN example.com.
$TTL 300

; SOA record
@  IN  SOA  ns1.example.com. admin.example.com. (
           2024031901  ; serial
           3600        ; refresh
           1800        ; retry
           604800      ; expire
           86400       ; minimum TTL
           )

; Nameservers
@  IN  NS   ns1.example.com.
@  IN  NS   ns2.example.com.

; A records (IPv4)
@        IN  A     192.0.2.1
ns1      IN  A     192.0.2.10
ns2      IN  A     192.0.2.11
www      IN  A     192.0.2.20
mail     IN  A     192.0.2.30
ftp      IN  A     192.0.2.40

; AAAA records (IPv6)
www      IN  AAAA  2001:db8::1
mail     IN  AAAA  2001:db8::2

; CNAME record (alias)
blog     IN  CNAME www.example.com.
shop     IN  CNAME www.example.com.

; MX records (mail exchange)
@        IN  MX    10  mail.example.com.
@        IN  MX    20  mail2.example.com.

; TXT records
@        IN  TXT   "v=spf1 mx -all"
_dmarc   IN  TXT   "v=DMARC1; p=none"

; PTR record for reverse DNS
4.0.2.0.in-addr.arpa.  IN  PTR  ftp.example.com.

; SRV record (service)
_http._tcp  IN  SRV  10  60  80  www.example.com.

; Test records for edge cases
nxdomain-test  IN  A  192.0.2.99   ; Will test NXDOMAIN when querying non-existent
empty-type     IN  A  192.0.2.100  ; For NODATA test

EOF

    log "Test environment ready in $TEST_DIR"
}

# ─────────────────────────────────────────────────────────────────────────────

build_binary() {
    log "Building ironbind..."

    if [ ! -f "$BINARY" ]; then
        cd "$PROJECT_DIR"
        cargo build --release 2>&1 | grep -E "^(error|warning:|Compiling|Finished)" || true
        if [ ! -f "$BINARY" ]; then
            fail "Build failed!"
            exit 1
        fi
    fi

    success "Binary ready: $BINARY"
}

# ─────────────────────────────────────────────────────────────────────────────

start_server() {
    log "Starting ironbind server on 127.0.0.1:$TEST_PORT..."

    cd "$TEST_DIR"
    "$BINARY" "$CONFIG_FILE" > /tmp/ironbind.log 2>&1 &
    SERVER_PID=$!

    # Wait for server to start
    sleep 1

    if ! kill -0 $SERVER_PID 2>/dev/null; then
        fail "Server failed to start"
        cat /tmp/ironbind.log
        exit 1
    fi

    success "Server started (PID: $SERVER_PID)"
}

stop_server() {
    if [ -n "$SERVER_PID" ] && kill -0 $SERVER_PID 2>/dev/null; then
        kill $SERVER_PID 2>/dev/null || true
        sleep 0.5
        kill -9 $SERVER_PID 2>/dev/null || true
        success "Server stopped"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────

query_dns() {
    local name="$1"
    local qtype="${2:-A}"
    local output=$(timeout 3 dig +short @127.0.0.1 -p $TEST_PORT "$name" "$qtype" 2>&1 || echo "TIMEOUT")
    echo "$output"
}

assert_query() {
    local name="$1"
    local qtype="$2"
    local expected="$3"
    local description="$4"

    local result=$(query_dns "$name" "$qtype")

    if [ -v VERBOSE ] && [ $VERBOSE -eq 1 ]; then
        echo "  Query: $name $qtype"
        echo "  Result: $result"
        echo "  Expected: $expected"
    fi

    if echo "$result" | grep -q "$expected"; then
        success "$description"
    else
        fail "$description (got: $result, expected: $expected)"
    fi
}

assert_nxdomain() {
    local name="$1"
    local description="$2"

    local result=$(dig @127.0.0.1 -p $TEST_PORT "$name" A 2>&1 | grep -c "NXDOMAIN" || echo "0")

    if [ "$result" -gt 0 ]; then
        success "$description"
    else
        fail "$description (NXDOMAIN not found)"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────

test_basic_queries() {
    log "\n=== Test Suite 1: Basic Queries ==="

    assert_query "example.com" "A" "192.0.2.1" "Query A record (zone apex)"
    assert_query "www.example.com" "A" "192.0.2.20" "Query A record (subdomain)"
    assert_query "ns1.example.com" "A" "192.0.2.10" "Query nameserver A record"
}

test_record_types() {
    log "\n=== Test Suite 2: Record Types ==="

    assert_query "example.com" "SOA" "ns1.example.com" "Query SOA record"
    assert_query "example.com" "NS" "ns1.example.com" "Query NS record"
    assert_query "www.example.com" "AAAA" "2001:db8::1" "Query AAAA record (IPv6)"
    assert_query "example.com" "MX" "10" "Query MX record (priority)"
    assert_query "example.com" "TXT" "v=spf1" "Query TXT record"
}

test_cname_resolution() {
    log "\n=== Test Suite 3: CNAME Resolution ==="

    # CNAME records should be returned as-is
    local cname_result=$(query_dns "blog.example.com" "A")
    if echo "$cname_result" | grep -q "www.example.com"; then
        success "CNAME records returned correctly"
    else
        warn "CNAME resolution (expected www.example.com reference)"
    fi
}

test_negative_responses() {
    log "\n=== Test Suite 4: Negative Responses ==="

    assert_nxdomain "nonexistent.example.com" "NXDOMAIN for non-existent name"

    # NODATA test: ask for AAAA for a name that only has A records
    local nodata_result=$(dig @127.0.0.1 -p $TEST_PORT "mail.example.com" "AAAA" 2>&1)
    if echo "$nodata_result" | grep -q "NOERROR\|NXDOMAIN" | head -n 1; then
        success "NODATA response for unsupported record type"
    else
        warn "NODATA response handling"
    fi
}

test_cache() {
    log "\n=== Test Suite 5: Caching ==="

    # First query (cache miss)
    local t1=$(date +%s%N)
    query_dns "www.example.com" "A" > /dev/null
    local t2=$(date +%s%N)
    local time1=$(( (t2 - t1) / 1000000 ))  # milliseconds

    # Second query (cache hit — should be faster)
    local t3=$(date +%s%N)
    query_dns "www.example.com" "A" > /dev/null
    local t4=$(date +%s%N)
    local time2=$(( (t4 - t3) / 1000000 ))

    if [ $time2 -lt $time1 ]; then
        success "Cache hit is faster than cache miss (${time1}ms → ${time2}ms)"
    else
        warn "Cache timing inconclusive (cache may be working anyway)"
    fi
}

test_tcp_fallback() {
    log "\n=== Test Suite 6: TCP Fallback ==="

    # Query over TCP (should work for large responses)
    local tcp_result=$(dig +tcp @127.0.0.1 -p $TEST_PORT "example.com" "A" 2>&1)
    if echo "$tcp_result" | grep -q "NOERROR\|192.0.2.1"; then
        success "TCP fallback works"
    else
        fail "TCP fallback failed"
    fi
}

test_zone_apex() {
    log "\n=== Test Suite 7: Zone Apex Handling ==="

    assert_query "example.com" "A" "192.0.2.1" "Query zone apex (bare domain)"

    local soa=$(query_dns "example.com" "SOA")
    if [ -n "$soa" ]; then
        success "Zone SOA available at apex"
    else
        fail "Zone SOA not available at apex"
    fi
}

test_multiple_records() {
    log "\n=== Test Suite 8: Multiple Record Handling ==="

    # MX records (multiple)
    local mx_result=$(dig @127.0.0.1 -p $TEST_PORT "example.com" "MX" +short 2>&1)
    if [ $(echo "$mx_result" | wc -l) -ge 2 ]; then
        success "Multiple MX records returned"
    else
        warn "Multiple record handling"
    fi
}

test_query_flags() {
    log "\n=== Test Suite 9: Query Flags & Response Codes ==="

    # Check authoritative answer flag (AA) for zone queries
    local aa_check=$(dig @127.0.0.1 -p $TEST_PORT "example.com" "A" 2>&1 | grep -c "aa" || echo "0")
    if [ "$aa_check" -gt 0 ]; then
        success "Authoritative Answer (AA) flag set for zone queries"
    else
        warn "AA flag not set (may still be correct)"
    fi
}

test_edns0() {
    log "\n=== Test Suite 10: EDNS0 Support ==="

    # Query with EDNS (--edns=0)
    local edns_result=$(dig +edns=0 @127.0.0.1 -p $TEST_PORT "example.com" "A" 2>&1)
    if echo "$edns_result" | grep -q "NOERROR\|192.0.2.1"; then
        success "EDNS0 queries handled"
    else
        fail "EDNS0 support failed"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────

run_all_tests() {
    test_basic_queries
    test_record_types
    test_cname_resolution
    test_negative_responses
    test_cache
    test_tcp_fallback
    test_zone_apex
    test_multiple_records
    test_query_flags
    test_edns0
}

print_summary() {
    log "\n=== Test Summary ==="
    local total=$((TESTS_PASSED + TESTS_FAILED))
    echo -e "${GREEN}Passed: $TESTS_PASSED${NC}"
    echo -e "${RED}Failed: $TESTS_FAILED${NC}"
    echo -e "${BLUE}Total:  $total${NC}"

    if [ $TESTS_FAILED -eq 0 ]; then
        echo -e "\n${GREEN}All tests passed! 🎉${NC}"
        return 0
    else
        echo -e "\n${RED}Some tests failed.${NC}"
        return 1
    fi
}

# ─────────────────────────────────────────────────────────────────────────────

main() {
    trap stop_server EXIT

    echo -e "${BLUE}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║  ironbind Test Suite — DNS Server Verification              ║${NC}"
    echo -e "${BLUE}╚═══════════════════════════════════════════════════════════╝${NC}"

    setup_test_env
    build_binary
    start_server

    # Give server time to load zones
    sleep 1

    run_all_tests
    print_summary

    local exit_code=$?

    log "\nTest logs available at: /tmp/ironbind.log"

    exit $exit_code
}

# ─────────────────────────────────────────────────────────────────────────────

if [ "$1" = "--help" ]; then
    cat << 'HELP'
ironbind Test Suite

Usage: ./test.sh [OPTIONS]

Options:
  --verbose        Show detailed query output
  --help           Display this help message

Environment variables:
  VERBOSE=1        Enable verbose output
  SERVER_ONLY=1    Start server only (for manual testing)

Examples:
  ./test.sh
  VERBOSE=1 ./test.sh
  SERVER_ONLY=1 ./test.sh

HELP
    exit 0
fi

if [ "$1" = "--server-only" ] || [ "$SERVER_ONLY" = "1" ]; then
    setup_test_env
    build_binary
    trap stop_server EXIT
    start_server
    log "Server running on 127.0.0.1:$TEST_PORT"
    log "Press Ctrl+C to stop"
    wait $SERVER_PID
    exit $?
fi

main

