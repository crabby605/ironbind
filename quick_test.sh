#!/bin/bash
# Simpler test script for ironbind — quick verification
# Run with: ./quick_test.sh

set -e

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$PROJECT_DIR/target/release/ironbind"
TEST_DIR="/tmp/ironbind-test-$$"
TEST_PORT=$((15000 + RANDOM % 10000))

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${BLUE}[*]${NC} $*"; }
success() { echo -e "${GREEN}✓${NC} $*"; }
fail() { echo -e "${RED}✗${NC} $*"; exit 1; }

# Cleanup on exit
cleanup() {
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null || true
        sleep 0.5
        kill -9 "$SERVER_PID" 2>/dev/null || true
    fi
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

log "Building ironbind..."
cd "$PROJECT_DIR"
if [ ! -f "$BINARY" ]; then
    cargo build --release 2>&1 | tail -5
fi
[ -f "$BINARY" ] || fail "Build failed"
success "Binary built"

log "Setting up test environment in $TEST_DIR..."
mkdir -p "$TEST_DIR"

success "Test environment ready"

log "Using port $TEST_PORT for test server..."

# Create minimal config with dynamic port
cat > "$TEST_DIR/config.toml" << EOF
[server]
bind            = "127.0.0.1"
port            = $TEST_PORT
use_forwarders  = false
dnssec_validate = false

[cache]
max_entries = 1000
neg_ttl     = 60

[zones]
files = ["test.zone"]

[ratelimit]
queries_per_second = 1000
per_ip             = true
EOF
cat > "$TEST_DIR/test.zone" << 'EOF'
$ORIGIN example.com.
$TTL 300

@  IN  SOA  ns1.example.com. admin.example.com. 2024031901 3600 1800 604800 86400

@  IN  NS   ns1.example.com.
@  IN  A    192.0.2.1
ns1 IN  A    192.0.2.10
www IN  A    192.0.2.20
www IN  AAAA 2001:db8::1
EOF

success "Test environment ready"

log "Starting DNS server on 127.0.0.1:$TEST_PORT..."
cd "$TEST_DIR"
"$BINARY" config.toml > /tmp/ironbind-test.log 2>&1 &
SERVER_PID=$!
sleep 2

if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    fail "Server failed to start"
fi
success "Server running (PID: $SERVER_PID)"

log "Running tests..."

# Test 1: Query A record
result=$(dig +short +timeout=2 @127.0.0.1 -p "$TEST_PORT" example.com A 2>&1 || true)
if echo "$result" | grep -q "192.0.2.1"; then
    success "Test 1: A record query"
else
    fail "Test 1: A record query failed (got: $result)"
fi

# Test 2: Query subdomain
result=$(dig +short +timeout=2 @127.0.0.1 -p "$TEST_PORT" www.example.com A 2>&1 || true)
if echo "$result" | grep -q "192.0.2.20"; then
    success "Test 2: Subdomain A record"
else
    fail "Test 2: Subdomain A record failed (got: $result)"
fi

# Test 3: Query AAAA record
result=$(dig +short +timeout=2 @127.0.0.1 -p "$TEST_PORT" www.example.com AAAA 2>&1 || true)
if echo "$result" | grep -q "2001:db8::1"; then
    success "Test 3: AAAA record query"
else
    fail "Test 3: AAAA record query failed (got: $result)"
fi

# Test 4: Query SOA record
result=$(dig +short +timeout=2 @127.0.0.1 -p "$TEST_PORT" example.com SOA 2>&1 || true)
if echo "$result" | grep -q "ns1.example.com"; then
    success "Test 4: SOA record query"
else
    fail "Test 4: SOA record query failed (got: $result)"
fi

# Test 5: NXDOMAIN for non-existent name
result=$(dig +timeout=2 @127.0.0.1 -p "$TEST_PORT" nonexistent.example.com A 2>&1 || true)
if echo "$result" | grep -q "NXDOMAIN"; then
    success "Test 5: NXDOMAIN response"
else
    fail "Test 5: NXDOMAIN response failed (got: $result)"
fi

# Test 6: Query NS record
result=$(dig +short +timeout=2 @127.0.0.1 -p "$TEST_PORT" example.com NS 2>&1 || true)
if echo "$result" | grep -q "ns1.example.com"; then
    success "Test 6: NS record query"
else
    fail "Test 6: NS record query failed (got: $result)"
fi

echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  All tests passed! ✓                              ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════╝${NC}"

