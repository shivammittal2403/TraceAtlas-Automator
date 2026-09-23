#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

if [[ "${TRACEATLAS_SKIP_SETUP:-0}" != "1" ]]; then
  bash "$ROOT_DIR/setup.sh"
fi

RUNTIME_PYTHON=""
for candidate in "$ROOT_DIR/.traceatlas/venv/bin/python" \
                 "$ROOT_DIR/.traceatlas/venv/Scripts/python.exe" \
                 python3 python; do
  if [[ "$candidate" == */* ]]; then
    [[ -x "$candidate" ]] || continue
    RUNTIME_PYTHON="$candidate"
    break
  fi
  if command -v "$candidate" >/dev/null 2>&1; then
    RUNTIME_PYTHON="$(command -v "$candidate")"
    break
  fi
done

[[ -n "$RUNTIME_PYTHON" ]] || {
  printf '[traceatlas] ERROR: No usable Python runtime was found.\n' >&2
  exit 1
}

export PYTHONPATH="$ROOT_DIR/src${PYTHONPATH:+:$PYTHONPATH}"
export PYTHONDONTWRITEBYTECODE=1

if [[ $# -eq 0 ]]; then
  set -- --help
fi

exec "$RUNTIME_PYTHON" -m traceatlas.cli "$@"

