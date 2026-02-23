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

export DATABASE_URL="${DATABASE_URL_LOCAL:-postgresql://outlook:outlook@localhost:5432/outlook_manager}"
export REDIS_URL="${REDIS_URL_LOCAL:-redis://localhost:6379/0}"

PYTHON_BIN="${PYTHON_BIN:-$ROOT_DIR/.venv/bin/python}"
if [[ ! -x "$PYTHON_BIN" ]]; then
  PYTHON_BIN="python3"
fi

echo "Starting local app..."
echo "DATABASE_URL=$DATABASE_URL"
echo "REDIS_URL=$REDIS_URL"
exec "$PYTHON_BIN" main.py
