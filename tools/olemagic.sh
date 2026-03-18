#!/usr/bin/env bash

OLEDUMP="$(dirname "$0")/oledump.py"

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <office_file>" >&2
  exit 1
fi

FILE="$1"

if [[ ! -f "$FILE" ]]; then
  echo "Error: file not found: $FILE" >&2
  exit 1
fi

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

echo "["

first=1

while IFS= read -r line; do
  line="${line%$'\r'}"

  # Example:
  # 13: m     985 '_VBA_PROJECT_CUR/VBA/ThisWorkbook'
  if [[ "$line" =~ ^[[:space:]]*([A-Za-z0-9]+):[[:space:]]*([^[:space:]]*)[[:space:]]+([0-9]+)[[:space:]]+\'([^\']+)\' ]]; then
    ID="${BASH_REMATCH[1]}"
    FLAGS="${BASH_REMATCH[2]}"
    SIZE="${BASH_REMATCH[3]}"
    NAME="${BASH_REMATCH[4]}"

    OUT="$TMPDIR/stream_${ID}.bin"
    MAGIC="unavailable"
    FIRST100=""

    $OLEDUMP -s "$ID" -d "$FILE" > "$OUT" 2>/dev/null || true

    if [[ -s "$OUT" ]]; then
      MAGIC=$(file -b "$OUT" | cut -d, -f1)
      FIRST100=$(head -c 100 "$OUT" | base64 | tr -d '\n')
    fi

    IS_MACRO=false
    IS_MACRO_CODE=false
    if [[ "$FLAGS" == *m* || "$FLAGS" == *M* ]]; then IS_MACRO=true; fi
    if [[ "$FLAGS" == *m* ]]; then IS_MACRO_CODE=true; fi

    if [[ $first -eq 0 ]]; then echo ","; fi
    first=0

    cat <<EOF
  {
    "stream_id": $ID,
    "name": "$(printf '%s' "$NAME" | sed 's/"/\\"/g')",
    "size": $SIZE,
    "oledump_flags": "$(printf '%s' "$FLAGS" | sed 's/"/\\"/g')",
    "is_macro": $IS_MACRO,
    "is_macro_code": $IS_MACRO_CODE,
    "magic": "$(printf '%s' "$MAGIC" | sed 's/"/\\"/g')",
    "first_hundred_bytes_base64": "$FIRST100",
    "raw_line": "$(printf '%s' "$line" | sed 's/"/\\"/g')"
  }
EOF
  fi
done < <($OLEDUMP -A "$FILE")

echo
echo "]"
