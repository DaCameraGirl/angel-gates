#!/usr/bin/env bash
set -euo pipefail

PYTHON=${ANGEL_PYTHON:-/opt/angel-gates/.venv/bin/python}
ANGEL_EDGE_DB=${ANGEL_EDGE_DB:-/var/lib/angel-edge/angel-edge.sqlite3}
ANGEL_DEVICE_KEY_FILE=${ANGEL_DEVICE_KEY_FILE:-/var/lib/angel-edge/device.key}
ANGEL_EDGE_HOST=${ANGEL_EDGE_HOST:-0.0.0.0}
ANGEL_EDGE_PORT=${ANGEL_EDGE_PORT:-8765}

args=(
  "$PYTHON" -m edge.angel_edge
  --db "$ANGEL_EDGE_DB"
  --device-key-file "$ANGEL_DEVICE_KEY_FILE"
  serve
  --host "$ANGEL_EDGE_HOST"
  --port "$ANGEL_EDGE_PORT"
)

if [[ -n "${ANGEL_RELAY_URL:-}" ]]; then
  : "${ANGEL_RELAY_TOKEN:?ANGEL_RELAY_TOKEN is required when ANGEL_RELAY_URL is set}"
  args+=(--relay-url "$ANGEL_RELAY_URL" --relay-token "$ANGEL_RELAY_TOKEN")
fi

if [[ -n "${ANGEL_CAMERA_URL:-}" ]]; then
  : "${ANGEL_CAMERA_TOKEN:?ANGEL_CAMERA_TOKEN is required when ANGEL_CAMERA_URL is set}"
  args+=(--camera-url "$ANGEL_CAMERA_URL" --camera-token "$ANGEL_CAMERA_TOKEN")
fi

exec "${args[@]}"
