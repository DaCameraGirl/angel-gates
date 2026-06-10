#!/usr/bin/env bash
set -euo pipefail

umask 0077
PYTHON=${ANGEL_PYTHON:-/opt/angel-gates/.venv/bin/python}
ANGEL_EDGE_DB=${ANGEL_EDGE_DB:-/var/lib/angel-edge/angel-edge.sqlite3}
ANGEL_DEVICE_KEY_FILE=${ANGEL_DEVICE_KEY_FILE:-/var/lib/angel-edge/device.key}
ANGEL_COMMISSIONING_PAYLOAD_FILE=${ANGEL_COMMISSIONING_PAYLOAD_FILE:-/var/lib/angel-edge/commissioning-payload.json}

install -d -m 0750 "$(dirname "$ANGEL_COMMISSIONING_PAYLOAD_FILE")"
payload=$("$PYTHON" -m edge.angel_edge \
  --db "$ANGEL_EDGE_DB" \
  --device-key-file "$ANGEL_DEVICE_KEY_FILE" \
  commissioning-payload)

printf '%s\n' "$payload" > "$ANGEL_COMMISSIONING_PAYLOAD_FILE"
chmod 0640 "$ANGEL_COMMISSIONING_PAYLOAD_FILE"
printf '%s\n' "$payload"
