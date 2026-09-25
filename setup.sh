#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
STATE_DIR="$ROOT_DIR/.traceatlas"
VENV_DIR="$STATE_DIR/venv"
OPENOSINT_ROOT="$ROOT_DIR/packages/openosint"
OPENOSINT_VENV="$STATE_DIR/openosint-venv"
LOCK_DIR="$STATE_DIR/setup.lock"
LOG_FILE="$STATE_DIR/setup.log"
MARKER_FILE="$STATE_DIR/ready"

info() { printf '[traceatlas] %s\n' "$*" >&2; }
warn() { printf '[traceatlas] WARNING: %s\n' "$*" >&2; }
die() { printf '[traceatlas] ERROR: %s\n' "$*" >&2; exit 1; }

on_error() {
  local code=$?
  printf '[traceatlas] Setup stopped at line %s (exit %s).\n' "${BASH_LINENO[0]:-unknown}" "$code" >&2
  printf '[traceatlas] Diagnostic log: %s\n' "$LOG_FILE" >&2
  exit "$code"
}
trap on_error ERR

mkdir -p "$STATE_DIR"
touch "$LOG_FILE"
if ! mkdir "$LOCK_DIR" 2>/dev/null; then
  LOCK_PID=""
  [[ -f "$LOCK_DIR/pid" ]] && LOCK_PID="$(sed -n '1p' "$LOCK_DIR/pid")"
  if [[ "$LOCK_PID" =~ ^[0-9]+$ ]] && kill -0 "$LOCK_PID" 2>/dev/null; then
    die "Another setup is running with process ID $LOCK_PID."
  fi
  warn "Recovering an interrupted setup lock."
  [[ -f "$LOCK_DIR/pid" ]] && rm -f "$LOCK_DIR/pid"
  rmdir "$LOCK_DIR" 2>/dev/null || die "Cannot recover stale setup lock: $LOCK_DIR"
  mkdir "$LOCK_DIR"
fi
printf '%s\n' "$$" >"$LOCK_DIR/pid"
cleanup_lock() {
  rm -f "$LOCK_DIR/pid" 2>/dev/null || true
  rmdir "$LOCK_DIR" 2>/dev/null || true
}
trap cleanup_lock EXIT

python_compatible() {
  "$1" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' >/dev/null 2>&1
}

select_python() {
  local candidate
  if [[ -n "${TRACEATLAS_PYTHON:-}" ]]; then
    if command -v "$TRACEATLAS_PYTHON" >/dev/null 2>&1 && python_compatible "$TRACEATLAS_PYTHON"; then
      command -v "$TRACEATLAS_PYTHON"
      return 0
    fi
    die "TRACEATLAS_PYTHON is not a working Python 3.10+ interpreter."
  fi
  for candidate in python3.13 python3.12 python3.11 python3.10 python3 python; do
    if command -v "$candidate" >/dev/null 2>&1 && python_compatible "$candidate"; then
      command -v "$candidate"
      return 0
    fi
  done
  return 1
}

SYSTEM_PYTHON="$(select_python)" || die "Python 3.10 or newer is required. Install Python, then rerun ./start.sh."
info "Using $($SYSTEM_PYTHON --version 2>&1)"

runtime_python() {
  if [[ -x "$VENV_DIR/bin/python" ]] && python_compatible "$VENV_DIR/bin/python"; then
    printf '%s\n' "$VENV_DIR/bin/python"
    return 0
  fi
  if [[ -x "$VENV_DIR/Scripts/python.exe" ]] && python_compatible "$VENV_DIR/Scripts/python.exe"; then
    printf '%s\n' "$VENV_DIR/Scripts/python.exe"
    return 0
  fi
  return 1
}

openosint_python() {
  local candidate
  for candidate in "$OPENOSINT_VENV/bin/python" "$OPENOSINT_VENV/Scripts/python.exe"; do
    if [[ -x "$candidate" ]] && python_compatible "$candidate"; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

openosint_healthy() {
  local candidate="$1"
  PYTHONPATH="$OPENOSINT_ROOT" "$candidate" -c \
    'import openosint, fastapi, mcp, requests' >/dev/null 2>&1
}

run_optional_install() {
  local limit="${TRACEATLAS_OPENOSINT_TIMEOUT:-180}"
  if command -v timeout >/dev/null 2>&1; then
    timeout --signal=TERM --kill-after=10s "${limit}s" "$@"
  else
    "$@"
  fi
}

RUNTIME_PYTHON=""
if RUNTIME_PYTHON="$(runtime_python)"; then
  info "Existing isolated runtime is healthy."
else
  info "Creating isolated runtime..."
  if "$SYSTEM_PYTHON" -m venv "$VENV_DIR" >>"$LOG_FILE" 2>&1; then
    RUNTIME_PYTHON="$(runtime_python)" || die "Virtual environment was created but its Python is unusable."
  else
    warn "Python venv support is unavailable; using system Python with isolated PYTHONPATH."
    warn "The core has no mandatory third-party dependencies, so operation can continue safely."
    RUNTIME_PYTHON="$SYSTEM_PYTHON"
  fi
fi

export PYTHONPATH="$ROOT_DIR/src${PYTHONPATH:+:$PYTHONPATH}"
export PYTHONDONTWRITEBYTECODE=1

SOURCE_FINGERPRINT="$("$SYSTEM_PYTHON" - "$ROOT_DIR" <<'PY'
import hashlib
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
digest = hashlib.sha256()
paths = [root / ".gitignore", root / "pyproject.toml", root / "setup.sh", root / "set.sh", root / "start.sh"]
paths.extend(sorted((root / "src").rglob("*.py")))
paths.extend(sorted((root / "tests").rglob("*.py")))
upstream = root / "packages" / "openosint"
for name in ("pyproject.toml", "uv.lock", "LICENSE"):
    paths.append(upstream / name)
paths.extend(sorted((upstream / "openosint").rglob("*.py")))
for path in paths:
    if path.is_file():
        digest.update(path.relative_to(root).as_posix().encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
print(digest.hexdigest())
PY
)"

if [[ "${TRACEATLAS_FORCE_SETUP:-0}" != "1" && -f "$MARKER_FILE" ]]; then
  SAVED_FINGERPRINT="$(awk -F= '$1 == "fingerprint" {print $2}' "$MARKER_FILE")"
  SAVED_OPENOSINT="$(awk -F= '$1 == "openosint" {print $2}' "$MARKER_FILE")"
  if [[ "$SAVED_FINGERPRINT" == "$SOURCE_FINGERPRINT" ]] && \
     VERSION="$("$RUNTIME_PYTHON" -m traceatlas.cli --version 2>/dev/null)"; then
    if [[ "${TRACEATLAS_SKIP_OPENOSINT:-0}" == "1" ]]; then
      info "TraceAtlas Automator $VERSION is already configured and verified."
      exit 0
    fi
    if [[ "$SAVED_OPENOSINT" == "ready" ]] && \
       OPENOSINT_PYTHON="$(openosint_python)" && openosint_healthy "$OPENOSINT_PYTHON"; then
      info "TraceAtlas Automator $VERSION and OpenOSINT are already configured and verified."
      exit 0
    fi
    if [[ "$SAVED_OPENOSINT" != "ready" && "${TRACEATLAS_RETRY_OPENOSINT:-0}" != "1" ]]; then
      info "TraceAtlas Automator $VERSION core is already configured and verified."
      warn "Optional OpenOSINT setup previously ended as $SAVED_OPENOSINT; set TRACEATLAS_RETRY_OPENOSINT=1 to retry."
      exit 0
    fi
  fi
fi

info "Checking source compilation..."
"$RUNTIME_PYTHON" -m compileall -q "$ROOT_DIR/src" >>"$LOG_FILE" 2>&1
if [[ -d "$OPENOSINT_ROOT/openosint" ]]; then
  "$RUNTIME_PYTHON" -m compileall -q "$OPENOSINT_ROOT/openosint" >>"$LOG_FILE" 2>&1
fi

if [[ "${TRACEATLAS_SKIP_TESTS:-0}" != "1" ]]; then
  info "Running complete regression tests..."
  "$RUNTIME_PYTHON" -m unittest discover -s "$ROOT_DIR/tests" -v >>"$LOG_FILE" 2>&1
else
  warn "Tests skipped because TRACEATLAS_SKIP_TESTS=1."
fi

VERSION="$("$RUNTIME_PYTHON" -m traceatlas.cli --version)"
info "TraceAtlas Automator $VERSION is operational."

OPENOSINT_STATUS="unavailable"
if [[ "${TRACEATLAS_SKIP_OPENOSINT:-0}" == "1" ]]; then
  OPENOSINT_STATUS="skipped"
  warn "OpenOSINT installation skipped because TRACEATLAS_SKIP_OPENOSINT=1."
elif [[ ! -f "$OPENOSINT_ROOT/pyproject.toml" ]]; then
  warn "The bundled OpenOSINT compatibility package is missing."
else
  OPENOSINT_PYTHON=""
  if OPENOSINT_PYTHON="$(openosint_python)"; then
    info "Existing OpenOSINT runtime found."
  else
    info "Creating a separate OpenOSINT runtime..."
    if "$SYSTEM_PYTHON" -m venv "$OPENOSINT_VENV" >>"$LOG_FILE" 2>&1; then
      OPENOSINT_PYTHON="$(openosint_python)" || true
    else
      warn "Could not create the optional OpenOSINT virtual environment."
    fi
  fi
  if [[ -n "$OPENOSINT_PYTHON" ]] && ! openosint_healthy "$OPENOSINT_PYTHON"; then
    info "Installing the bundled OpenOSINT package and declared compatible dependencies..."
    if command -v uv >/dev/null 2>&1; then
      run_optional_install env UV_PROJECT_ENVIRONMENT="$OPENOSINT_VENV" \
        uv sync --locked --no-dev --project "$OPENOSINT_ROOT" >>"$LOG_FILE" 2>&1 || true
    fi
    if openosint_healthy "$OPENOSINT_PYTHON" || \
       run_optional_install "$OPENOSINT_PYTHON" -m pip install --disable-pip-version-check \
         -e "$OPENOSINT_ROOT" >>"$LOG_FILE" 2>&1; then
      info "OpenOSINT dependencies installed."
    else
      warn "OpenOSINT dependency installation failed; TraceAtlas core remains available."
      warn "Review $LOG_FILE and rerun ./set.sh after network/package-manager recovery."
    fi
  fi
  if [[ -n "$OPENOSINT_PYTHON" ]] && openosint_healthy "$OPENOSINT_PYTHON" && \
     PYTHONPATH="$OPENOSINT_ROOT" "$OPENOSINT_PYTHON" -m openosint.cli --help \
       >>"$LOG_FILE" 2>&1; then
    OPENOSINT_STATUS="ready"
    info "OpenOSINT compatibility runtime is operational."
  fi
fi

info "Checking optional integrations..."
"$RUNTIME_PYTHON" -m traceatlas.cli --workspace "$STATE_DIR/doctor-cases" \
  integrations doctor --json >"$STATE_DIR/integrations.json" 2>>"$LOG_FILE"
"$RUNTIME_PYTHON" -m traceatlas.cli --workspace "$STATE_DIR/doctor-cases" \
  intel doctor --json >"$STATE_DIR/intelligence.json" 2>>"$LOG_FILE"
"$RUNTIME_PYTHON" -m traceatlas.cli --workspace "$STATE_DIR/doctor-cases" \
  capabilities doctor --json >"$STATE_DIR/capabilities.json" 2>>"$LOG_FILE"

{
  printf 'version=%s\n' "$VERSION"
  printf 'python=%s\n' "$RUNTIME_PYTHON"
  printf 'fingerprint=%s\n' "$SOURCE_FINGERPRINT"
  printf 'openosint=%s\n' "$OPENOSINT_STATUS"
  printf 'verified_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} >"$MARKER_FILE"

info "Setup complete."
info "Run: ./start.sh --help"
info "Optional-tool report: $STATE_DIR/integrations.json"
info "Intelligence readiness: $STATE_DIR/intelligence.json"
info "Upstream capability readiness: $STATE_DIR/capabilities.json"
info "OpenOSINT readiness: $OPENOSINT_STATUS"
