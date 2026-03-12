#!/bin/sh
set -e
# Railway inject PORT sebagai env var — fallback ke 5000
_PORT="${PORT:-5000}"
echo "[entrypoint] Starting gunicorn on port $_PORT"
exec gunicorn \
  --bind "0.0.0.0:$_PORT" \
  --workers 2 \
  --threads 4 \
  --timeout 120 \
  app:app
