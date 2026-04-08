#!/usr/bin/env bash
# scripts/extract-828es-firmware.sh
#
# Extracts the root filesystem, kernel, and preset from 828ES firmware images.
# Uses hardcoded offsets discovered via binwalk scan.
#
# Firmware files (download with scripts/binwalk-828es-firmware.sh first):
#   firmware/MOTU_AVB_1.3.2+59_828ES.update   (earliest, 2017-10-20)
#   firmware/MOTU_AVB_1.3.4+172_828ES.update  (running on device, 2018-07-30)
#
# Usage:
#   ./scripts/extract-828es-firmware.sh
#   ./scripts/extract-828es-firmware.sh --fw firmware/MOTU_AVB_1.3.4+172_828ES.update
#   ./scripts/extract-828es-firmware.sh --dir captures/firmware
#
# Prerequisites:
#   apt install binwalk file
#   # For ext2: apt install e2tools  or use debugfs (no root needed)
#   # For squashfs: apt install squashfs-tools
#   # For cramfs: apt install cramfsprogs
#   # For jffs2: pip3 install jefferson

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────
FW_DIR="firmware"
SPECIFIC_FW=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dir) FW_DIR="$2"; shift 2 ;;
        --fw)  SPECIFIC_FW="$2"; shift 2 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

# ── Known firmware descriptors ────────────────────────────────────────────────
# Format: "label|filename|kernel_offset|rootfs_offset|preset_offset"
# Offsets are DECIMAL bytes into the .update file.
#
# Offsets from binwalk scan of 1.3.2+59 (confirmed identical structure in 1.3.4+172):
#   kernel uImage  : 0x640180  =  6554048
#   rootfs gzip    : 0x820180  =  8520064
#   preset gzip    : 0xA32C60  = 10693728
#
declare -a FW_ENTRIES=(
    "1.3.2+59 (earliest, 2017-10-20)|MOTU_AVB_1.3.2+59_828ES.update|6554048|8520064|10693728"
    "1.3.4+172 (running on device, 2018-07-30)|MOTU_AVB_1.3.4+172_828ES.update|6554048|8520064|10693728"
)

# ── Helpers ───────────────────────────────────────────────────────────────────
extract_blob() {
    local src="$1" offset="$2" dest="$3"
    echo "  dd skip=$offset -> $dest"
    dd if="$src" bs=1 skip="$offset" status=none 2>/dev/null > "${dest}.gz.raw"
    # Peek at magic to decide if it's really gzip
    local magic
    magic=$(xxd -l 2 "${dest}.gz.raw" | awk '{print $2}')
    if [[ "$magic" == "1f8b" ]]; then
        zcat "${dest}.gz.raw" > "$dest" 2>/dev/null \
            || { echo "    WARNING: gzip decompression failed (truncated stream ok)"; true; }
        rm -f "${dest}.gz.raw"
        echo "    -> $(du -sh "$dest" | cut -f1)  [$(file -b "$dest")]"
    else
        mv "${dest}.gz.raw" "$dest"
        echo "    -> not gzip (magic=$magic), saved raw $(du -sh "$dest" | cut -f1)"
    fi
}

identify_rootfs() {
    local img="$1"
    local type
    type=$(file -b "$img")
    echo ""
    echo "  Filesystem type: $type"
    echo ""

    if echo "$type" | grep -qi "ext2\|ext3\|ext4"; then
        echo "  ── ext2/3/4 ─────────────────────────────────────────────────"
        echo "  List files (no root needed):"
        echo "    debugfs -R 'ls -l /' $img"
        echo "    debugfs -R 'cat /etc/passwd' $img"
        echo "  Extract all (no root needed, needs e2tools):"
        echo "    e2cp -a $img:/ $out_rootfs_dir/"
        echo "  Or with debugfs dump:"
        echo "    debugfs -R 'rdump / $out_rootfs_dir' $img"

    elif echo "$type" | grep -qi "squashfs"; then
        echo "  ── squashfs ─────────────────────────────────────────────────"
        echo "  Extract (no root needed):"
        echo "    unsquashfs -d ${img%.img}-squashfs $img"
        if command -v unsquashfs &>/dev/null; then
            echo ""
            echo "  Running unsquashfs now..."
            unsquashfs -d "${img%.img}-squashfs" "$img" || true
        fi

    elif echo "$type" | grep -qi "cpio"; then
        echo "  ── cpio initramfs ───────────────────────────────────────────"
        local cpio_dir="${img%.img}-cpio"
        mkdir -p "$cpio_dir"
        echo "  Extracting cpio..."
        (cd "$cpio_dir" && cpio -idmv --no-absolute-filenames < "../$(basename "$img")") || true
        echo "  Extracted to $cpio_dir"

    elif echo "$type" | grep -qi "cramfs"; then
        echo "  ── cramfs ───────────────────────────────────────────────────"
        echo "  Extract (needs root OR cramfs-tools):"
        echo "    sudo mount -t cramfs -o loop $img /mnt/cramfs"
        echo "    # OR (no root, if cramfsck supports it):"
        echo "    cramfsck -x ${img%.img}-cramfs $img"

    elif echo "$type" | grep -qi "data\|DOS/MBR"; then
        echo "  ── Unknown / raw — running binwalk on extracted rootfs ──────"
        echo "  binwalk -Me $img"
        binwalk -Me "$img" || true

    else
        echo "  ── Unrecognised — try:"
        echo "    binwalk $img"
        echo "    hexdump -C $img | head -4"
    fi
}

process_firmware() {
    local label="$1"
    local filename="$2"
    local kernel_off="$3"
    local rootfs_off="$4"
    local preset_off="$5"

    local fw="${FW_DIR}/${filename}"
    if [[ ! -f "$fw" ]]; then
        echo "  SKIP: $fw not found (run scripts/binwalk-828es-firmware.sh first)"
        return
    fi

    local slug
    slug=$(echo "$filename" | sed 's/\.update$//' | tr ' +,' '---')
    local out_dir="${FW_DIR}/${slug}-extracted"
    mkdir -p "$out_dir"

    echo ""
    echo "════════════════════════════════════════════════════════"
    echo "  $label"
    echo "  Source : $fw ($(du -sh "$fw" | cut -f1))"
    echo "  Output : $out_dir"
    echo "════════════════════════════════════════════════════════"

    # ── Kernel ────────────────────────────────────────────────────────────────
    echo ""
    echo "── 1. Kernel uImage (offset $kernel_off) ─────────────────"
    local out_kernel="${out_dir}/kernel-uImage.bin"
    if [[ ! -f "$out_kernel" ]]; then
        # uImage is not gzip-wrapped at that offset — it's a raw uImage blob
        # The uImage header is 64 bytes; image size from binwalk: 1863052 bytes
        dd if="$fw" bs=1 skip="$kernel_off" count=1863116 status=none > "$out_kernel" 2>/dev/null || true
        echo "  -> $(du -sh "$out_kernel" | cut -f1)  uImage ARM Linux 2.6.32-rc8"
    else
        echo "  -> [skip] $out_kernel already exists"
    fi

    # ── Rootfs ────────────────────────────────────────────────────────────────
    echo ""
    echo "── 2. Root filesystem (offset $rootfs_off) ───────────────"
    local out_rootfs="${out_dir}/rootfs.img"
    local out_rootfs_dir="${out_dir}/rootfs"
    if [[ ! -f "$out_rootfs" ]]; then
        extract_blob "$fw" "$rootfs_off" "$out_rootfs"
    else
        echo "  -> [skip] $out_rootfs already exists ($(du -sh "$out_rootfs" | cut -f1))"
    fi
    if [[ -f "$out_rootfs" ]]; then
        identify_rootfs "$out_rootfs"
    fi

    # ── Preset ────────────────────────────────────────────────────────────────
    echo ""
    echo "── 3. Device preset (offset $preset_off) ─────────────────"
    local out_preset="${out_dir}/Audio_Interface.motuavbpreset"
    if [[ ! -f "$out_preset" ]]; then
        extract_blob "$fw" "$preset_off" "$out_preset"
        # Presets are often JSON or plist — peek inside
        echo "  First 256 bytes:"
        head -c 256 "$out_preset" | cat -v || true
    else
        echo "  -> [skip] $out_preset already exists"
    fi

    # ── Find key binaries in extracted tree ───────────────────────────────────
    echo ""
    echo "── Searching for key binaries in extracted tree ──────────"
    for target in libssgl.so tamio MOTUAVBController libssl.so; do
        found=$(find "$out_dir" -name "$target" 2>/dev/null | head -5) || true
        if [[ -n "$found" ]]; then
            echo "  FOUND $target:"
            while IFS= read -r f; do
                echo "    $f  ($(file -b "$f" | cut -c1-60))"
            done <<< "$found"
        fi
    done

    echo ""
    echo "  Full extracted tree ($out_dir):"
    find "$out_dir" -maxdepth 5 | sort | head -100
}

# ── Main ──────────────────────────────────────────────────────────────────────
if [[ -n "$SPECIFIC_FW" ]]; then
    # Single file mode — run binwalk scan first then extract
    echo "Scanning $SPECIFIC_FW ..."
    binwalk "$SPECIFIC_FW"
    echo ""
    echo "Extracting with binwalk -Me ..."
    binwalk -Me "$SPECIFIC_FW"
else
    # Process known firmware entries
    for entry in "${FW_ENTRIES[@]}"; do
        IFS='|' read -r label filename kernel_off rootfs_off preset_off <<< "$entry"
        process_firmware "$label" "$filename" "$kernel_off" "$rootfs_off" "$preset_off"
    done
fi

echo ""
echo "════════════════════════════════════════════════════════"
echo "  All done."
echo "  Key binaries to copy to captures/ for Ghidra:"
echo "    find $FW_DIR -name 'libssgl.so' -o -name 'tamio' -o -name 'MOTUAVBController'"
echo "════════════════════════════════════════════════════════"
