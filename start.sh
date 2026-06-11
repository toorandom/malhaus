#!/bin/bash
# Start both the malhaus web app and the MCP server.
# The MCP server runs in the background; gunicorn is the foreground process
# so Docker tracks its lifecycle correctly.
set -e

echo "[start.sh] Starting Malhaus MCP server on port ${MALHAUS_MCP_PORT:-8001}..."
python /app/mcp_server.py &

echo "[start.sh] Starting Malhaus web app on port 8000..."
exec /app/.venv/bin/gunicorn \
    --workers 2 \
    --bind 0.0.0.0:8000 \
    --timeout 1800 \
    --capture-output \
    --access-logfile - \
    --error-logfile - \
    "webapp.app:create_app()"
