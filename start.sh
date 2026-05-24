#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${ENV_FILE:-$ROOT_DIR/.env}"

load_env() {
  if [[ ! -f "$ENV_FILE" ]]; then
    echo "Missing env file: $ENV_FILE"
    echo "Create it from template:"
    echo "  cp .env.example .env"
    exit 1
  fi

  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
}

if [[ $# -gt 0 ]]; then
  echo "Usage: $0"
  exit 1
fi

load_env
cd "$ROOT_DIR"

mkdir -p "$ROOT_DIR/data"

export DATABASE_URL="${DATABASE_URL_LOCAL:-sqlite:///$ROOT_DIR/data/outlook-manager.db}"
export REDIS_URL="${REDIS_URL_LOCAL-}"

RUNNER=()
if command -v uv >/dev/null 2>&1; then
  RUNNER=(uv run python)
else
  PYTHON_BIN="${PYTHON_BIN:-$ROOT_DIR/.venv/bin/python}"
  if [[ ! -x "$PYTHON_BIN" ]]; then
    PYTHON_BIN="python3"
  fi
  RUNNER=("$PYTHON_BIN")
fi

echo "Starting local app..."
echo "DATABASE_URL=$DATABASE_URL"
if [[ -n "$REDIS_URL" ]]; then
  echo "REDIS_URL=$REDIS_URL"
else
  echo "REDIS_URL=(disabled)"
fi
exec "${RUNNER[@]}" main.py
