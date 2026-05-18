#!/usr/bin/env bash
# ironbind setup — generate keys/certs and stash secrets in the macOS Keychain.
#
# Produces:
#   keys/Kexample.com+008+zsk.private   — DNSSEC zone signing key (RSA-2048)
#   keys/Kexample.com+008+ksk.private   — DNSSEC key signing key (RSA-2048)
#   tls/cert.pem, tls/key.pem           — self-signed cert for DoT/DoH
#   config.toml                         — references Keychain by service name
#
# Secrets that should not live in the repo (TSIG shared secret) go into the
# Keychain. The server reads them at startup via `security find-generic-password`.

set -euo pipefail

# Detect OS — macOS uses /usr/bin/security (Keychain), Linux uses secret-tool
# (libsecret / GNOME Keyring / KWallet). Falls back to a chmod 600 file when
# neither is available (e.g. headless servers, CI).
OS="$(uname -s)"
KEYCHAIN_SERVICE="ironbind-tsig"
TSIG_NAME="transfer-key."
TSIG_ALGO="hmac-sha256."
ZONE="example.com"

mkdir -p keys tls

# ── 1. TSIG secret ────────────────────────────────────────────────────────────
echo "→ Generating TSIG HMAC-SHA256 secret"
TSIG_SECRET="$(openssl rand -base64 32)"

store_in_file() {
  mkdir -p secrets
  umask 077
  printf '%s' "$TSIG_SECRET" > secrets/tsig.b64
  chmod 600 secrets/tsig.b64
  echo "  wrote secrets/tsig.b64 (mode 600)"
  SECRET_LINE='secret_file = "secrets/tsig.b64"'
}

case "$OS" in
  Darwin)
    security delete-generic-password -s "$KEYCHAIN_SERVICE" >/dev/null 2>&1 || true
    security add-generic-password \
      -a "$TSIG_NAME" -s "$KEYCHAIN_SERVICE" -w "$TSIG_SECRET" -T "" -U
    echo "  stored in macOS Keychain under service '$KEYCHAIN_SERVICE'"
    SECRET_LINE="secret_keychain = \"$KEYCHAIN_SERVICE\""
    ;;
  Linux)
    if command -v secret-tool >/dev/null 2>&1; then
      # libsecret stores key/value attribute pairs; we key by service name.
      if printf '%s' "$TSIG_SECRET" | secret-tool store \
            --label="ironbind TSIG ($TSIG_NAME)" service "$KEYCHAIN_SERVICE"; then
        echo "  stored in libsecret (gnome-keyring/KWallet) under service '$KEYCHAIN_SERVICE'"
        SECRET_LINE="secret_keychain = \"$KEYCHAIN_SERVICE\""
      else
        echo "  secret-tool failed (no D-Bus session?); falling back to file"
        store_in_file
      fi
    else
      echo "  secret-tool not installed — install 'libsecret-tools' (Debian/Ubuntu)"
      echo "  or 'libsecret' (Fedora/Arch) for keyring support; using file fallback"
      store_in_file
    fi
    ;;
  *)
    echo "  no keychain integration for $OS — using file fallback"
    store_in_file
    ;;
esac

# ── 2. DNSSEC keys (RSA-2048, alg 8) ─────────────────────────────────────────
echo "→ Generating DNSSEC ZSK + KSK for $ZONE"
openssl genrsa -out "keys/K${ZONE}+008+zsk.private" 2048 2>/dev/null
openssl genrsa -out "keys/K${ZONE}+008+ksk.private" 4096 2>/dev/null
chmod 600 keys/*.private

# ── 3. Self-signed TLS cert for DoT / DoH ────────────────────────────────────
echo "→ Generating self-signed TLS cert (CN=localhost) for DoT/DoH"
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout tls/key.pem -out tls/cert.pem \
  -days 365 -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null
chmod 600 tls/key.pem

# ── 4. Config that references the Keychain (no secrets in the file) ──────────
echo "→ Writing config.toml"
cat > config.toml <<EOF
[server]
bind            = "0.0.0.0"
port            = 5353
worker_threads  = 64
dnssec_validate = true
dnssec_strict   = false
tcp_timeout_ms  = 5000

[zones]
files = ["example.com.zone"]

[metrics]
port = 9090

[tsig]
name      = "$TSIG_NAME"
algorithm = "$TSIG_ALGO"
$SECRET_LINE
require_all_queries = false

[dot]
bind = "0.0.0.0:8853"
cert = "tls/cert.pem"
key  = "tls/key.pem"

[doh]
bind = "0.0.0.0:8443"
cert = "tls/cert.pem"
key  = "tls/key.pem"
EOF

cat <<DONE

Setup complete.

  DNSSEC keys      : keys/K${ZONE}+008+{zsk,ksk}.private
  TLS cert/key     : tls/cert.pem, tls/key.pem
  TSIG secret      : ${OS} Keychain (service '$KEYCHAIN_SERVICE')
  Config           : config.toml

Run:  cargo run --release -- config.toml
DONE
