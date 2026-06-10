#!/usr/bin/env bash
set -euo pipefail

PYTHON=${ANGEL_PYTHON:-/opt/angel-gates/.venv/bin/python}
ANGEL_EDGE_DB=${ANGEL_EDGE_DB:-/var/lib/angel-edge/angel-edge.sqlite3}
ANGEL_CAMERA_HOST=${ANGEL_CAMERA_HOST:-127.0.0.1}
ANGEL_CAMERA_PORT=${ANGEL_CAMERA_PORT:-8767}
ANGEL_CAMERA_ID=${ANGEL_CAMERA_ID:-front-gate-cam}
ANGEL_CAMERA_STORAGE_PATH=${ANGEL_CAMERA_STORAGE_PATH:-/var/lib/angel-edge/camera-clips}
ANGEL_CAMERA_CLIP_SECONDS=${ANGEL_CAMERA_CLIP_SECONDS:-8}
ANGEL_CAMERA_RETENTION_DAYS=${ANGEL_CAMERA_RETENTION_DAYS:-14}
ANGEL_FFMPEG_PATH=${ANGEL_FFMPEG_PATH:-/usr/bin/ffmpeg}
: "${ANGEL_CAMERA_TOKEN:?ANGEL_CAMERA_TOKEN is required}"
: "${ANGEL_CAMERA_RTSP_URL:?ANGEL_CAMERA_RTSP_URL is required}"

exec "$PYTHON" -m edge.angel_edge \
  --db "$ANGEL_EDGE_DB" \
  camera-service \
  --host "$ANGEL_CAMERA_HOST" \
  --port "$ANGEL_CAMERA_PORT" \
  --token "$ANGEL_CAMERA_TOKEN" \
  --rtsp-url "$ANGEL_CAMERA_RTSP_URL" \
  --camera-id "$ANGEL_CAMERA_ID" \
  --storage-path "$ANGEL_CAMERA_STORAGE_PATH" \
  --clip-seconds "$ANGEL_CAMERA_CLIP_SECONDS" \
  --retention-days "$ANGEL_CAMERA_RETENTION_DAYS" \
  --ffmpeg-path "$ANGEL_FFMPEG_PATH"
