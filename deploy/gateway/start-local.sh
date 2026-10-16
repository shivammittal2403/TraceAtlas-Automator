#!/usr/bin/env bash
# Start single-user employee behind an authenticated local Caddy gateway.
set -Eeuo pipefail
umask 077

ROOT="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
WORKSPACE="${TRACEATLAS_WORKSPACE:-$ROOT/cases}"
CADDYFILE="$ROOT/deploy/gateway/Caddyfile"

fail() { printf '[traceatlas-gateway] %s\n' "$1" >&2; exit 1; }
command -v caddy >/dev/null 2>&1 || fail "Caddy >=2.8 is required"
command -v python3 >/dev/null 2>&1 || fail "Python 3.10+ is required"
case "${TRACEATLAS_WORKFORCE_ENABLED:-0}" in
  1|true|yes) ;;
  *) fail "Set TRACEATLAS_WORKFORCE_ENABLED=1 explicitly for approved investigations" ;;
esac
[[ -n "${TRACEATLAS_GATEWAY_PASSWORD_HASH:-}" ]] || fail "Set TRACEATLAS_GATEWAY_PASSWORD_HASH using 'caddy hash-password'"
# Only hash credentials are accepted, never a plaintext password.
case "$TRACEATLAS_GATEWAY_PASSWORD_HASH" in
  '$2a$'*|'$2b$'*|'$2y$'*|'$argon2id$'*) ;;
  *) fail "Expected a password hash (bcrypt or argon2id), not plaintext" ;;
esac

if [[ -z "${TRACEATLAS_CONSOLE_GATEWAY_TOKEN:-}" ]]; then
  TRACEATLAS_CONSOLE_GATEWAY_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"
fi
[[ "${#TRACEATLAS_CONSOLE_GATEWAY_TOKEN}" -ge 32 ]] || fail "Internal gateway token too short"

export TRACEATLAS_CONSOLE_GATEWAY_TOKEN
export TRACEATLAS_CONSOLE_GATEWAY_ORIGIN="http://127.0.0.1:8780"
export TRACEATLAS_PUBLIC_DIR="$ROOT/public"
export PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}"
export PYTHONDONTWRITEBYTECODE=1

mkdir -p "$WORKSPACE"
chmod 700 "$WORKSPACE"
caddy validate --config "$CADDYFILE" --adapter caddyfile >/dev/null

CONSOLE_PID=""
cleanup() {
  if [[ -n "$CONSOLE_PID" ]]; then
    kill "$CONSOLE_PID" 2>/dev/null || true
    wait "$CONSOLE_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

python3 -m traceatlas.cli --workspace "$WORKSPACE" employee serve --port 8765 &
CONSOLE_PID="$!"

printf '[traceatlas-gateway] Authenticated entrypoint: http://127.0.0.1:8780/\n'
printf '[traceatlas-gateway] Employee UI: http://127.0.0.1:8780/employee/\n'
printf '[traceatlas-gateway] Cloud /api routes are intentionally not mounted.\n'
caddy run --config "$CADDYFILE" --adapter caddyfile
