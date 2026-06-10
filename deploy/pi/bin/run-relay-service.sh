#!/usr/bin/env bash
set -euo pipefail

PYTHON=${ANGEL_PYTHON:-/opt/angel-gates/.venv/bin/python}
ANGEL_EDGE_DB=${ANGEL_EDGE_DB:-/var/lib/angel-edge/angel-edge.sqlite3}
ANGEL_RELAY_HOST=${ANGEL_RELAY_HOST:-127.0.0.1}
ANGEL_RELAY_PORT=${ANGEL_RELAY_PORT:-8766}
ANGEL_RELAY_DRIVER=${ANGEL_RELAY_DRIVER:-logging}
: "${ANGEL_RELAY_TOKEN:?ANGEL_RELAY_TOKEN is required}"

exec "$PYTHON" -m edge.angel_edge \
  --db "$ANGEL_EDGE_DB" \
  relay-service \
  --host "$ANGEL_RELAY_HOST" \
  --port "$ANGEL_RELAY_PORT" \
  --token "$ANGEL_RELAY_TOKEN" \
  --driver "$ANGEL_RELAY_DRIVER"
