#!/usr/bin/env bash
set -euo pipefail

PYTHON=${ANGEL_PYTHON:-/opt/angel-gates/.venv/bin/python}
ANGEL_EDGE_DB=${ANGEL_EDGE_DB:-/var/lib/angel-edge/angel-edge.sqlite3}
ANGEL_ANCHOR_POLL_SECONDS=${ANGEL_ANCHOR_POLL_SECONDS:-10}
: "${ANGEL_WITNESS_URL:?ANGEL_WITNESS_URL is required}"
: "${ANGEL_WITNESS_TOKEN:?ANGEL_WITNESS_TOKEN is required}"

exec "$PYTHON" -m edge.angel_edge \
  --db "$ANGEL_EDGE_DB" \
  anchor-publisher \
  --witness-url "$ANGEL_WITNESS_URL" \
  --witness-token "$ANGEL_WITNESS_TOKEN" \
  --poll-seconds "$ANGEL_ANCHOR_POLL_SECONDS"
