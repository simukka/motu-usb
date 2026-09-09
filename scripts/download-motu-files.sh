#!/usr/bin/env bash
# scripts/download-motu-files.sh
#
# Reads the CSV produced by scrape-download-center.sh and downloads every file
# that has a non-empty redirect_url.
#
# Usage:
#   ./scripts/download-motu-files.sh
#   ./scripts/download-motu-files.sh --csv captures/motu-downloads.csv --out captures/downloads
#   ./scripts/download-motu-files.sh --filter "\.dmg$|\.pkg$|\.exe$|\.zip$"
#   ./scripts/download-motu-files.sh --dry-run
#   ./scripts/download-motu-files.sh --jobs 4     # parallel downloads
#
# CSV format expected (from scrape-download-center.sh):
#   id,http_code,redirect_url

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────
CSV="captures/motu-downloads.csv"
OUT_DIR="captures/downloads"
FILTER=""          # optional regex to restrict which URLs to download
DRY_RUN=0
JOBS=1             # concurrent curl processes
DELAY=0.1          # seconds between launches (single-job mode)
SKIP_EXISTING=1    # skip files already on disk

# ── Argument parsing ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --csv)     CSV="$2";     shift 2 ;;
        --out)     OUT_DIR="$2"; shift 2 ;;
        --filter)  FILTER="$2";  shift 2 ;;
        --dry-run) DRY_RUN=1;    shift   ;;
        --jobs)    JOBS="$2";    shift 2 ;;
        --delay)   DELAY="$2";   shift 2 ;;
        --no-skip) SKIP_EXISTING=0; shift ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

# ── Validate inputs ───────────────────────────────────────────────────────────
if [[ ! -f "$CSV" ]]; then
    echo "ERROR: CSV file not found: $CSV" >&2
    echo "Run scripts/scrape-download-center.sh first." >&2
    exit 1
fi

mkdir -p "$OUT_DIR"

# ── Parse CSV → collect (id, url) pairs ──────────────────────────────────────
declare -a IDS
declare -a URLS

while IFS=, read -r id http_code redirect_url; do
    # Skip header
    [[ "$id" == "id" ]] && continue

    # Strip surrounding quotes that may wrap URLs with commas
    redirect_url="${redirect_url%\"}"
    redirect_url="${redirect_url#\"}"

    # Skip rows with no redirect / non-2xx/3xx codes
    [[ -z "$redirect_url" ]]  && continue
    [[ "$http_code" == "ERR" ]] && continue
    [[ "$http_code" == "404" ]] && continue

    # Optional regex filter on URL
    if [[ -n "$FILTER" ]]; then
        echo "$redirect_url" | grep -qE "$FILTER" || continue
    fi

    IDS+=("$id")
    URLS+=("$redirect_url")
done < "$CSV"

TOTAL="${#URLS[@]}"
echo "CSV         : $CSV"
echo "Output dir  : $OUT_DIR"
echo "Filter      : ${FILTER:-<none>}"
echo "To download : $TOTAL URLs"
echo "Parallel    : $JOBS job(s)"
[[ $DRY_RUN -eq 1 ]] && echo "Mode        : DRY RUN (nothing will be downloaded)"
echo ""

if [[ $TOTAL -eq 0 ]]; then
    echo "No URLs to download. Exiting."
    exit 0
fi

# ── Download function ─────────────────────────────────────────────────────────
download_one() {
    local id="$1"
    local url="$2"

    # Derive filename:
    # 1. Use the last path component from the URL (before any query string)
    local filename
    filename="$(basename "${url%%\?*}")"

    # 2. If that's empty or generic (e.g. "download"), prefix with the ID
    if [[ -z "$filename" || "$filename" == "download" || "$filename" == "get" ]]; then
        filename="${id}-download"
    fi

    # 3. Always prefix with the ID so filenames stay unique across IDs
    local dest="${OUT_DIR}/${id}-${filename}"

    if [[ $SKIP_EXISTING -eq 1 && -f "$dest" ]]; then
        echo "  [${id}] SKIP (exists)  $dest"
        return 0
    fi

    if [[ $DRY_RUN -eq 1 ]]; then
        echo "  [${id}] DRY-RUN  $url  ->  $dest"
        return 0
    fi

    echo "  [${id}] Downloading $url"
    if curl -sS -L \
            --max-time 300 \
            --retry 3 \
            --retry-delay 5 \
            -o "$dest" \
            "$url"; then
        local size
        size=$(du -sh "$dest" 2>/dev/null | cut -f1)
        echo "  [${id}] OK  $size  ->  $dest"
    else
        echo "  [${id}] FAILED  $url" >&2
        rm -f "$dest"   # remove partial file
    fi
}

export -f download_one
export OUT_DIR SKIP_EXISTING DRY_RUN

# ── Dispatch: parallel or sequential ─────────────────────────────────────────
if [[ $JOBS -gt 1 ]]; then
    # Requires GNU parallel or xargs -P
    if command -v parallel &>/dev/null; then
        echo "Using GNU parallel with $JOBS jobs."
        # Build input as "id|url" lines, pipe to parallel
        for (( i=0; i<TOTAL; i++ )); do
            printf '%s|%s\n' "${IDS[$i]}" "${URLS[$i]}"
        done | parallel -j "$JOBS" --colsep '\|' download_one {1} {2}
    else
        echo "GNU parallel not found — falling back to xargs -P $JOBS."
        for (( i=0; i<TOTAL; i++ )); do
            printf '%s\t%s\n' "${IDS[$i]}" "${URLS[$i]}"
        done | xargs -P "$JOBS" -I{} bash -c '
            id="${1%%	*}"; url="${1#*	}"
            download_one "$id" "$url"
        ' _ {}
    fi
else
    # Sequential
    for (( i=0; i<TOTAL; i++ )); do
        download_one "${IDS[$i]}" "${URLS[$i]}"
        sleep "$DELAY"
    done
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "Done."
if [[ $DRY_RUN -eq 0 ]]; then
    file_count=$(find "$OUT_DIR" -maxdepth 1 -type f | wc -l)
    total_size=$(du -sh "$OUT_DIR" 2>/dev/null | cut -f1)
    echo "  Files in $OUT_DIR : $file_count"
    echo "  Total size        : $total_size"
fi
