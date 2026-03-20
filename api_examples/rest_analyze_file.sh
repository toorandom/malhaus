#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# REST API — analyze a local file (direct multipart upload)
#
# Usage:
#   ./rest_analyze_file.sh <path/to/file> [archive_password]
#
# Environment variables:
#   MALTRIAGE_HOST   — base URL of your malhaus instance (default: https://your-domain.com)
#   MALTRIAGE_TOKEN  — your mh_... API key
#
# IMPORTANT: If your server uses a self-signed TLS certificate, add -k to
# every curl command below to skip certificate verification, e.g.:
#   curl -sk ...   instead of   curl -s ...
#
# To send a password-protected ZIP/RAR, pass the password as the second
# argument:
#   ./rest_analyze_file.sh archive.zip mypassword
# ---------------------------------------------------------------------------

HOST="${MALTRIAGE_HOST:-https://your-domain.com}"
TOKEN="${MALTRIAGE_TOKEN:?Set MALTRIAGE_TOKEN to your mh_... API key}"
FILE="${1:?Usage: $0 <path/to/file> [archive_password]}"
ARCHIVE_PASSWORD="${2:-}"
POLL_INTERVAL=5

# ── 1. Submit ────────────────────────────────────────────────────────────────
echo "Submitting: $FILE"

if [ -n "$ARCHIVE_PASSWORD" ]; then
  SUBMIT=$(curl -s -X POST "$HOST/api/v1/analyze" \
    -H "Authorization: Bearer $TOKEN" \
    -F "file=@$FILE" \
    -F "archive_password=$ARCHIVE_PASSWORD")
else
  SUBMIT=$(curl -s -X POST "$HOST/api/v1/analyze" \
    -H "Authorization: Bearer $TOKEN" \
    -F "file=@$FILE")
fi

JOB_ID=$(echo "$SUBMIT" | python3 -c "import sys,json; print(json.load(sys.stdin)['job_id'])" 2>/dev/null)
if [ -z "$JOB_ID" ]; then
  echo "Error: could not get job_id. Server response:" >&2
  echo "$SUBMIT" >&2
  exit 1
fi
echo "Job ID: $JOB_ID"

# ── 2. Poll until done ───────────────────────────────────────────────────────
echo "Polling..."
while true; do
  RESP=$(curl -s "$HOST/api/v1/jobs/$JOB_ID" \
    -H "Authorization: Bearer $TOKEN")

  STATUS=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['status'])" 2>/dev/null)
  echo "  status: $STATUS"

  case "$STATUS" in
    done|failed) break ;;
  esac
  sleep "$POLL_INTERVAL"
done

# ── 3. Print result as JSON ──────────────────────────────────────────────────
echo ""
echo "$RESP" | python3 -c "
import sys, json
r = json.load(sys.stdin)
if r['status'] == 'failed':
    print(json.dumps({'status': 'failed', 'error': r.get('error')}, indent=2))
    sys.exit(1)
print(json.dumps(r, indent=2))
"
