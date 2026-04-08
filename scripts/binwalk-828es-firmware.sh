#!/usr/bin/env bash
# scripts/binwalk-828es-firmware.sh
#
# Downloads the earliest and currently-running 828ES firmware images and
# extracts their filesystems using binwalk.
#
# Earliest  : MOTU AVB 1.3.2+59  for 828ES (2017-10-20, beta)
# Current   : MOTU AVB 1.3.4+172 for 828ES and 8PreES (2018-07-30)
#             — matches the 2018-07-27 kernel build date seen on the device
#
# Prerequisites:
#   sudo apt install binwalk python3-lzma squashfs-tools jefferson mtd-utils
#   pip3 install jefferson   # jffs2 extractor (if not via apt)
#
# Usage:
#   ./scripts/binwalk-828es-firmware.sh
#   ./scripts/binwalk-828es-firmware.sh --out captures/firmware  --skip-download
#   ./scripts/binwalk-828es-firmware.sh --also-newest            # also fetch 1.4.0+90954

set -euo pipefail

# ── Firmware URLs ─────────────────────────────────────────────────────────────
URL_EARLIEST="https://cdn-data.motu.com/downloads/audio/AVB/firmware/io/beta/171020/MOTU%20AVB%201.3.2%2B59%20for%20828ES.update"
FILE_EARLIEST="MOTU_AVB_1.3.2+59_828ES.update"

URL_CURRENT="https://cdn-data.motu.com/downloads/audio/AVB/firmware/io/180730/MOTU%20AVB%201.3.4%2B172%20for%20828ES%20and%208PreES.update"
FILE_CURRENT="MOTU_AVB_1.3.4+172_828ES.update"

URL_NEWEST="https://cdn-data.motu.com/downloads/audio/AVB/firmware/io/release/20220412/MOTU%20AVB%201.4.0%2B90954%20for%20828ES%20and%208PreES.update"
FILE_NEWEST="MOTU_AVB_1.4.0+90954_828ES.update"

# ── Defaults ──────────────────────────────────────────────────────────────────
OUT_DIR="captures/firmware"
SKIP_DOWNLOAD=0
ALSO_NEWEST=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --out)            OUT_DIR="$2"; shift 2 ;;
        --skip-download)  SKIP_DOWNLOAD=1; shift ;;
        --also-newest)    ALSO_NEWEST=1; shift ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

mkdir -p "$OUT_DIR"

# ── Helpers ───────────────────────────────────────────────────────────────────
check_dep() {
    if ! command -v "$1" &>/dev/null; then
        echo "WARNING: '$1' not found. Install it for full extraction." >&2
    fi
}

download_fw() {
    local url="$1" dest="$2"
    if [[ -f "$dest" ]]; then
        echo "  [skip] $dest already exists"
    else
        echo "  Downloading $(basename "$dest") ..."
        curl -sS -L --max-time 120 --retry 3 -o "$dest" "$url"
        echo "  -> $(du -sh "$dest" | cut -f1)"
    fi
}

analyze_and_extract() {
    local fw="$1"
    local label="$2"
    local out="${OUT_DIR}/$(basename "${fw%.update}")"

    echo ""
    echo "════════════════════════════════════════════════════════"
    echo "  $label"
    echo "  File : $fw"
    echo "════════════════════════════════════════════════════════"

    # ── Step 1: hexdump of first 256 bytes (spot custom header) ──────────────
    echo ""
    echo "── Header (first 256 bytes) ──────────────────────────────"
    xxd -l 256 "$fw"

    # ── Step 2: binwalk scan (signatures + entropy) ───────────────────────────
    echo ""
    echo "── binwalk -Me scan ──────────────────────────────────────"
    binwalk -Me --directory="$out" "$fw" || true

    # ── Step 3: show extracted tree ───────────────────────────────────────────
    echo ""
    echo "── Extracted tree ($out) ─────────────────────────────────"
    if [[ -d "$out" ]]; then
        find "$out" -maxdepth 4 | sort | head -80
    else
        echo "  (nothing extracted)"
    fi

    # ── Step 4: find and mount jffs2 images ──────────────────────────────────
    echo ""
    echo "── Searching for jffs2 images ───────────────────────────"
    local jffs2_files
    jffs2_files=$(find "$out" -name "*.jffs2" -o -name "*.jffs" 2>/dev/null | head -20) || true
    # Also look for raw jffs2 magic (0x19 0x85) in extracted blobs
    find "$out" -type f -size +4k 2>/dev/null | while read -r f; do
        if xxd -l 2 "$f" 2>/dev/null | grep -q "1985"; then
            echo "  Possible jffs2 : $f"
        fi
    done || true
    if [[ -n "$jffs2_files" ]]; then
        echo "$jffs2_files"
        echo ""
        echo "  To mount jffs2 (requires mtd-utils + root or user-mode JFFS2):"
        echo "    modprobe mtdram total_size=32768 erase_size=64"
        echo "    modprobe mtdblock"
        echo "    dd if=<file>.jffs2 of=/dev/mtd0"
        echo "    mount -t jffs2 /dev/mtdblock0 /mnt/jffs2"
        echo "  Or with jefferson (no root needed):"
        echo "    jefferson -d <outdir> <file>.jffs2"
    fi

    # ── Step 5: find and extract squashfs images ──────────────────────────────
    echo ""
    echo "── Searching for squashfs images ────────────────────────"
    find "$out" -name "*.squashfs" -o -name "squashfs-root" -type d 2>/dev/null | head -20 || true
    find "$out" -type f -size +4k 2>/dev/null | while read -r f; do
        if xxd -l 4 "$f" 2>/dev/null | grep -qiE "7371 7368|6873 7173"; then
            echo "  Possible squashfs : $f"
            echo "    unsquashfs -d ${f%.squashfs}-root $f"
        fi
    done || true

    # ── Step 6: find kernel uImages ──────────────────────────────────────────
    echo ""
    echo "── Searching for uImage / zImage / kernel ───────────────"
    find "$out" -type f 2>/dev/null | while read -r f; do
        local magic
        magic=$(xxd -l 4 "$f" 2>/dev/null | awk '{print $2$3}' | tr -d ' ') || continue
        case "$magic" in
            27051956) echo "  uImage (U-Boot)  : $f" ;;
            1f8b0800|1f8b0808) echo "  gzip / zImage?   : $f" ;;
            d00dfeed|feedface|cafebabe) echo "  Mach-O / DTB     : $f" ;;
        esac
    done || true

    echo ""
    echo "── Done: $label ──────────────────────────────────────────"
    echo "   Extraction root: $out"
}

# ── Dependency check ──────────────────────────────────────────────────────────
echo "Checking dependencies..."
for dep in binwalk xxd curl file jefferson unsquashfs; do
    check_dep "$dep"
done

# ── Download ──────────────────────────────────────────────────────────────────
if [[ $SKIP_DOWNLOAD -eq 0 ]]; then
    echo ""
    echo "Downloading firmware images..."
    download_fw "$URL_EARLIEST" "${OUT_DIR}/${FILE_EARLIEST}"
    download_fw "$URL_CURRENT"  "${OUT_DIR}/${FILE_CURRENT}"
    [[ $ALSO_NEWEST -eq 1 ]] && download_fw "$URL_NEWEST" "${OUT_DIR}/${FILE_NEWEST}"
fi

# ── Verify files exist ────────────────────────────────────────────────────────
for f in "${OUT_DIR}/${FILE_EARLIEST}" "${OUT_DIR}/${FILE_CURRENT}"; do
    if [[ ! -f "$f" ]]; then
        echo "ERROR: $f not found. Run without --skip-download first." >&2
        exit 1
    fi
done

# ── Analyze each firmware ─────────────────────────────────────────────────────
analyze_and_extract "${OUT_DIR}/${FILE_EARLIEST}" "EARLIEST: MOTU AVB 1.3.2+59 (2017-10-20, beta)"
analyze_and_extract "${OUT_DIR}/${FILE_CURRENT}"  "CURRENT on device: MOTU AVB 1.3.4+172 (2018-07-30)"
if [[ $ALSO_NEWEST -eq 1 && -f "${OUT_DIR}/${FILE_NEWEST}" ]]; then
    analyze_and_extract "${OUT_DIR}/${FILE_NEWEST}" "NEWEST AVAILABLE: MOTU AVB 1.4.0+90954 (2022-04-12)"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════════"
echo "  All done. Extracted directories:"
echo "════════════════════════════════════════════════════════"
find "$OUT_DIR" -maxdepth 1 -type d | sort

echo ""
echo "Next steps:"
echo "  # Compare tamio between firmware versions:"
echo "  diff <(strings captures/firmware/MOTU_AVB_1.3.2+59_828ES/_828ES.update.extracted/**/*tamio* 2>/dev/null | sort) \\"
echo "       <(strings captures/firmware/MOTU_AVB_1.3.4+172_828ES/_828ES.update.extracted/**/*tamio* 2>/dev/null | sort)"
echo ""
echo "  # Extract jffs2 user partition with jefferson (no root needed):"
echo "  jefferson -d captures/firmware/jffs2-root <jffs2-image>"
echo ""
echo "  # Find libssgl.so in the extracted tree:"
echo "  find captures/firmware -name 'libssgl.so'"
