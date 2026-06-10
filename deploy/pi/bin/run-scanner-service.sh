#!/usr/bin/env bash
set -euo pipefail

PYTHON=${ANGEL_PYTHON:-/opt/angel-gates/.venv/bin/python}
ANGEL_SCANNER_EDGE_URL=${ANGEL_SCANNER_EDGE_URL:-http://127.0.0.1:8765}
ANGEL_SCANNER_ID=${ANGEL_SCANNER_ID:-pedestal-qr-1}
ANGEL_SCANNER_INPUT=${ANGEL_SCANNER_INPUT:-stdin}
ANGEL_SCANNER_BAUDRATE=${ANGEL_SCANNER_BAUDRATE:-9600}
: "${ANGEL_SCANNER_EDGE_TOKEN:?ANGEL_SCANNER_EDGE_TOKEN is required}"
: "${ANGEL_SCANNER_GATE_ID:?ANGEL_SCANNER_GATE_ID is required}"

args=(
  "$PYTHON" -m edge.angel_edge
  scanner-service
  --edge-url "$ANGEL_SCANNER_EDGE_URL"
  --edge-token "$ANGEL_SCANNER_EDGE_TOKEN"
  --gate-id "$ANGEL_SCANNER_GATE_ID"
  --scanner-id "$ANGEL_SCANNER_ID"
  --input "$ANGEL_SCANNER_INPUT"
  --baudrate "$ANGEL_SCANNER_BAUDRATE"
)

if [[ -n "${ANGEL_SCANNER_SERIAL_PORT:-}" ]]; then
  args+=(--serial-port "$ANGEL_SCANNER_SERIAL_PORT")
fi

if [[ -n "${ANGEL_SCANNER_EVDEV_PATH:-}" ]]; then
  args+=(--evdev-path "$ANGEL_SCANNER_EVDEV_PATH")
fi

exec "${args[@]}"
