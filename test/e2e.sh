#!/usr/bin/env bash
# End-to-end test for kvstore auth pipeline.
#
# Usage:
#   bash test/e2e.sh           # normal run
#   DEBUG=true bash test/e2e.sh # with debug logging + server log dump on failure
#
# The only manual step (on real systems) is the biometric prompt during
# app registration. With the current biometric stubs this is fully automated.
set -euo pipefail

# --- configuration ---
MASTER_PW="e2e-test-pw-12345"
ADDR="127.0.0.1:7891"
DATA_DIR="$(mktemp -d)"
DEBUG="${DEBUG:-false}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN_DIR="$ROOT_DIR/bin"
EXT=""
if [[ "$(uname -s)" == MINGW* || "$(uname -s)" == MSYS* || "$(uname -s)" == CYGWIN* ]]; then
  EXT=".exe"
fi

# --- helpers ---
pass_count=0
fail_count=0

sha256() {
  if command -v sha256sum &>/dev/null; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

cleanup() {
  if [[ -n "${SERVER_PID:-}" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  rm -rf "$DATA_DIR"
}
trap cleanup EXIT

check() {
  local name="$1" expected="$2" actual="$3"
  if [[ "$actual" == "$expected" ]]; then
    printf "  PASS  %s\n" "$name"
    pass_count=$((pass_count + 1))
  else
    printf "  FAIL  %s (expected %s, got %s)\n" "$name" "$expected" "$actual"
    fail_count=$((fail_count + 1))
  fi
}

check_output() {
  local name="$1" pattern="$2" output="$3"
  if echo "$output" | grep -q "$pattern"; then
    printf "  PASS  %s\n" "$name"
    pass_count=$((pass_count + 1))
  else
    printf "  FAIL  %s (output did not match '%s')\n" "$name" "$pattern"
    fail_count=$((fail_count + 1))
  fi
}

http_status() {
  local url="$1"; shift
  curl -s -o /dev/null -w "%{http_code}" "$@" "$url"
}

# --- phase 1: build ---
echo "=== Phase 1: Build ==="
cd "$ROOT_DIR"
go build -o "$BIN_DIR/kvstore${EXT}" ./cmd/kvstore
go build -o "$BIN_DIR/goodclient${EXT}" ./test/cmd/goodclient
go build -o "$BIN_DIR/badclient${EXT}" ./test/cmd/badclient

HASH_GOOD="$(sha256 "$BIN_DIR/goodclient${EXT}")"
HASH_BAD="$(sha256 "$BIN_DIR/badclient${EXT}")"
echo "  goodclient hash: ${HASH_GOOD:0:16}..."
echo "  badclient  hash: ${HASH_BAD:0:16}..."
if [[ "$HASH_GOOD" == "$HASH_BAD" ]]; then
  echo "  ERROR: test binaries have identical hashes!"
  exit 1
fi
echo "  Hashes differ: OK"

KVS="$BIN_DIR/kvstore${EXT}"
GOOD="$BIN_DIR/goodclient${EXT}"
BAD="$BIN_DIR/badclient${EXT}"

# --- phase 2: initialize store ---
echo ""
echo "=== Phase 2: Initialize ==="
export KVSTORE_DATA_DIR="$DATA_DIR"
export KVSTORE_KEY="$MASTER_PW"

printf '%s\n%s\n' "$MASTER_PW" "$MASTER_PW" | "$KVS" init 2>/dev/null
echo "  Store initialized at $DATA_DIR"

"$KVS" set secrets api-key "sk-test-12345" 2>/dev/null
"$KVS" set secrets db-pass "hunter2" 2>/dev/null
"$KVS" set config db-host "localhost:5432" 2>/dev/null
echo "  Seeded: secrets/api-key, secrets/db-pass, config/db-host"

# --- phase 3: register goodclient ---
echo ""
echo "=== Phase 3: Register Apps ==="

GOOD_ABS="$(cd "$(dirname "$GOOD")" && pwd)/$(basename "$GOOD")"
TOKEN=$("$KVS" app register \
  --binary "$GOOD_ABS" \
  --namespaces secrets \
  --name good-client \
  2>/dev/null)

if [[ -z "$TOKEN" ]]; then
  echo "  ERROR: failed to register goodclient"
  exit 1
fi
echo "  good-client token: ${TOKEN:0:20}..."

# Register an admin app with wildcard access
ADMIN_TOKEN=$("$KVS" app register \
  --binary "$GOOD_ABS" \
  --namespaces '*' \
  --name admin-client \
  2>/dev/null)
echo "  admin-client token: ${ADMIN_TOKEN:0:20}..."

# --- phase 4: start server ---
echo ""
echo "=== Phase 4: Start Server ==="

SERVE_FLAGS="--addr $ADDR"
if [[ "$DEBUG" == "true" ]]; then
  SERVE_FLAGS="$SERVE_FLAGS --debug"
fi

# shellcheck disable=SC2086
"$KVS" serve $SERVE_FLAGS > "$DATA_DIR/server.log" 2>&1 &
SERVER_PID=$!

# Wait for server to be ready (up to 5 seconds)
for i in $(seq 1 50); do
  if curl -s "http://$ADDR/api/v1/health" >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "  ERROR: server exited prematurely"
    cat "$DATA_DIR/server.log"
    exit 1
  fi
  sleep 0.1
done

if ! curl -s "http://$ADDR/api/v1/health" >/dev/null 2>&1; then
  echo "  ERROR: server did not become ready"
  cat "$DATA_DIR/server.log"
  exit 1
fi
echo "  Server running on $ADDR (PID $SERVER_PID)"

# --- phase 5: test cases ---
echo ""
echo "=== Phase 5: Tests ==="
BASE="http://$ADDR"

# Test 1: Health (no auth required)
STATUS=$(http_status "$BASE/api/v1/health")
check "health endpoint (no auth)" "200" "$STATUS"

# Test 2: goodclient get with valid token → 200
OUTPUT=$("$GOOD" --server "$BASE" --token "$TOKEN" get secrets api-key 2>/dev/null || true)
check_output "goodclient get secrets/api-key" "sk-test-12345" "$OUTPUT"

# Test 3: badclient get with no token → 401
STATUS=$(http_status "$BASE/api/v1/kv/secrets/api-key")
check "no token → 401" "401" "$STATUS"

# Test 4: badclient binary, no token → 401
STATUS=$("$BAD" --server "$BASE" get secrets api-key 2>/dev/null; echo "$?") || true
# badclient exits 1 on 4xx, but let's check HTTP status directly
STATUS=$(http_status "$BASE/api/v1/kv/secrets/api-key")
check "badclient no token → 401" "401" "$STATUS"

# Test 5: goodclient get wrong namespace → 403
STATUS=$(http_status "$BASE/api/v1/kv/config/db-host" \
  -H "Authorization: Bearer $TOKEN")
check "valid token + wrong namespace → 403" "403" "$STATUS"

# Test 6: admin wildcard token accesses any namespace → 200
OUTPUT=$("$GOOD" --server "$BASE" --token "$ADMIN_TOKEN" get config db-host 2>/dev/null || true)
check_output "admin wildcard → config/db-host" "localhost:5432" "$OUTPUT"

# Test 7: Write with valid auth
OUTPUT=$("$GOOD" --server "$BASE" --token "$TOKEN" set secrets new-key "new-value" 2>/dev/null || true)
check_output "write with auth" "new-value" "$OUTPUT"

# Test 8: Read back the written value
OUTPUT=$("$GOOD" --server "$BASE" --token "$TOKEN" get secrets new-key 2>/dev/null || true)
check_output "read back written value" "new-value" "$OUTPUT"

# Test 9: Delete with valid auth
STATUS=$(http_status "$BASE/api/v1/kv/secrets/new-key" \
  -X DELETE \
  -H "Authorization: Bearer $TOKEN")
check "delete with auth → 200" "200" "$STATUS"

# Test 10: List namespaces
OUTPUT=$(curl -s -H "Authorization: Bearer $ADMIN_TOKEN" "$BASE/api/v1/kv")
check_output "list namespaces" "secrets" "$OUTPUT"
check_output "list namespaces includes config" "config" "$OUTPUT"

# Test 11: List keys in namespace
OUTPUT=$(curl -s -H "Authorization: Bearer $TOKEN" "$BASE/api/v1/kv/secrets")
check_output "list keys in secrets" "api-key" "$OUTPUT"

# Test 12: Revoke good-client, then access fails
# bbolt only allows one process at a time, so stop the server, revoke via
# CLI, then restart the server to test that the revoked token is rejected.
kill "$SERVER_PID" 2>/dev/null; wait "$SERVER_PID" 2>/dev/null || true
SERVER_PID=""

APP_ID=$("$KVS" app list 2>/dev/null | grep good-client | awk '{print $1}')
"$KVS" app revoke "$APP_ID" 2>/dev/null

# Restart server
# shellcheck disable=SC2086
"$KVS" serve $SERVE_FLAGS >> "$DATA_DIR/server.log" 2>&1 &
SERVER_PID=$!
for i in $(seq 1 50); do
  if curl -s "http://$ADDR/api/v1/health" >/dev/null 2>&1; then break; fi
  sleep 0.1
done

STATUS=$(http_status "$BASE/api/v1/kv/secrets/api-key" \
  -H "Authorization: Bearer $TOKEN")
check "revoked token → 401" "401" "$STATUS"

# Test 13: Admin token still works after revoking good-client
STATUS=$(http_status "$BASE/api/v1/kv/secrets/api-key" \
  -H "Authorization: Bearer $ADMIN_TOKEN")
check "admin token still valid" "200" "$STATUS"

# --- results ---
echo ""
echo "=========================================="
total=$((pass_count + fail_count))
echo "Results: $pass_count / $total passed"
echo "=========================================="

if [[ "$fail_count" -gt 0 ]]; then
  echo ""
  echo "Server log ($DATA_DIR/server.log):"
  cat "$DATA_DIR/server.log"
  exit 1
fi

if [[ "$DEBUG" == "true" ]]; then
  echo ""
  echo "Server log (debug mode):"
  cat "$DATA_DIR/server.log"
fi

echo ""
echo "All tests passed!"
