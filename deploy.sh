#!/usr/bin/env bash
# Deploy latest changes from this git repo to the running malhaus2 server.
# Run from inside maltriage-public:  ./deploy.sh
set -e

REPO="$(cd "$(dirname "$0")" && pwd)"
SERVER=/home/toorandom/maltriage

echo "[deploy] pulling latest..."
git -C "$REPO" pull

echo "[deploy] syncing files to $SERVER..."
rsync -av --relative \
    agent/heuristics.py \
    agent/llm_loop.py \
    agent/llm_factory.py \
    agent/preflight.py \
    agent/postprocess.py \
    agent/strings_llm.py \
    agent/suspicious.py \
    agent/triage_agent.py \
    agent/visualizations.py \
    tools/cli_tools.py \
    tools/ghidra_malhaus \
    webapp/routes.py \
    webapp/api_routes.py \
    webapp/templates/ \
    webapp/static/ \
    "$SERVER/"

echo "[deploy] reloading gunicorn..."
PID=$(pgrep -f "gunicorn.*webapp.app" | head -1)
if [ -n "$PID" ]; then
    kill -HUP "$PID"
    echo "[deploy] HUP sent to gunicorn master (pid $PID)"
else
    echo "[deploy] WARNING: gunicorn not found — restart manually with ./run.sh"
fi

echo "[deploy] done."
