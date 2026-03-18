#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# REST API — analyze a local file (direct multipart upload)
#
# The file is sent in a single POST request. No pre-upload step needed.
# ---------------------------------------------------------------------------

HOST="${MALTRIAGE_HOST:-https://your-domain.com}"
TOKEN="${MALTRIAGE_TOKEN:?Set MALTRIAGE_TOKEN to your mh_... API key}"
FILE="${1:?Usage: $0 <path/to/file>}"
POLL_INTERVAL=5

# ── 1. Submit ────────────────────────────────────────────────────────────────
echo "Submitting: $FILE"

SUBMIT=$(curl -s -X POST "$HOST/api/v1/analyze" \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@$FILE")

echo "Response: $SUBMIT"

JOB_ID=$(echo "$SUBMIT" | python3 -c "import sys,json; print(json.load(sys.stdin)['job_id'])" 2>/dev/null)
if [ -z "$JOB_ID" ]; then
  echo "Error: could not get job_id from response" >&2
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

# ── 3. Print result ──────────────────────────────────────────────────────────
echo ""
echo "$RESP" | python3 -c "
import sys, json
r = json.load(sys.stdin)
if r['status'] == 'failed':
    print('FAILED:', r.get('error'))
    sys.exit(1)
v = r['verdict']
print(f\"Risk     : {v['risk_level']} (confidence {v['confidence']}%)\")
print(f\"SHA-256  : {r['sha256']}\")
print(f\"Report   : $HOST{r['report_url']}\")
print()
print('Top reasons:')
for reason in r.get('top_reasons', []):
    print(f'  - {reason}')
"
