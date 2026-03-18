#!/usr/bin/env bash
set -e
source .venv/bin/activate

if [ ! -f config.source ]; then
  echo "ERROR: config.source not found. Copy config.source.example and fill in your settings:"
  echo "  cp config.source.example config.source && nano config.source"
  exit 1
fi
source config.source

mkdir -p logs
LOG="logs/malhaus_$(date +%Y%m%d_%H%M%S).log"
echo "[run.sh] logging to $LOG"

gunicorn \
  --workers 2 \
  --bind 127.0.0.1:8000 \
  --timeout 1800 \
  --capture-output \
  --access-logfile - \
  --error-logfile - \
  "webapp.app:create_app()" 2>&1 | tee "$LOG"
