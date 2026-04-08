#!/usr/bin/env bash
# scripts/scrape-download-center.sh
#
# Probes https://motu.com/en-us/download-center/download/<N> for N in 1..MAX
# and records the HTTP status code and Location redirect for each ID.
#
# Usage:
#   ./scripts/scrape-download-center.sh
#   ./scripts/scrape-download-center.sh --max 500
#   ./scripts/scrape-download-center.sh --max 3000 --delay 0.3 --out captures/motu-downloads.csv
#   ./scripts/scrape-download-center.sh --resume   # skip IDs already in the output file
#
# Output CSV columns:
#   id, http_code, redirect_url

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────
MAX=3000
DELAY=0.2          # seconds between requests (be polite)
OUT="captures/motu-downloads.csv"
RESUME=0
BASE_URL="https://motu.com/en-us/download-center/download"

# ── Argument parsing ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --max)    MAX="$2";    shift 2 ;;
        --delay)  DELAY="$2";  shift 2 ;;
        --out)    OUT="$2";    shift 2 ;;
        --resume) RESUME=1;    shift   ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

mkdir -p "$(dirname "$OUT")"

# ── Resume support ─────────────────────────────────────────────────────────────
declare -A DONE
if [[ $RESUME -eq 1 && -f "$OUT" ]]; then
    while IFS=, read -r id _rest; do
        DONE["$id"]=1
    done < <(tail -n +2 "$OUT")   # skip header
    echo "Resuming — ${#DONE[@]} IDs already recorded."
fi

# ── Write CSV header if file doesn't exist yet ────────────────────────────────
if [[ ! -f "$OUT" ]]; then
    echo "id,http_code,redirect_url" > "$OUT"
fi

# ── Main loop ─────────────────────────────────────────────────────────────────
echo "Probing $BASE_URL/1 .. /$MAX  (delay=${DELAY}s, output=$OUT)"
echo ""

for (( i=1; i<=MAX; i++ )); do
    # Skip if already done (resume mode)
    if [[ ${DONE["$i"]+_} ]]; then
        continue
    fi

    url="${BASE_URL}/${i}"

    # -s  silent, -o /dev/null  discard body
    # -w  write-out format: http_code and redirect_url
    # --max-time 10  per-request timeout
    # No -L: we want the raw redirect Location, not the final destination
    result=$(curl -s -o /dev/null \
        --max-time 10 \
        -w "%{http_code},%{redirect_url}" \
        "$url" 2>/dev/null) || result="ERR,"

    http_code="${result%%,*}"
    redirect="${result#*,}"

    # Sanitize redirect URL for CSV (wrap in quotes if it contains commas)
    if [[ "$redirect" == *","* ]]; then
        redirect="\"$redirect\""
    fi

    echo "${i},${http_code},${redirect}" >> "$OUT"

    # Print progress
    if [[ -n "$redirect" ]]; then
        printf "  [%4d] %3s  %s\n" "$i" "$http_code" "$redirect"
    else
        printf "  [%4d] %3s\n" "$i" "$http_code"
    fi

    sleep "$DELAY"
done

echo ""
echo "Done. Results saved to: $OUT"
echo ""

# ── Summary ───────────────────────────────────────────────────────────────────
echo "Summary:"
echo "  Total probed : $(( MAX ))"
echo "  With redirect: $(awk -F, 'NR>1 && $3!="" {count++} END{print count+0}' "$OUT")"
echo "  404 / missing: $(awk -F, 'NR>1 && $2=="404" {count++} END{print count+0}' "$OUT")"
echo "  Errors       : $(awk -F, 'NR>1 && $2=="ERR" {count++} END{print count+0}' "$OUT")"
