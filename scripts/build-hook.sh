#!/usr/bin/env bash
# build-hook.sh — cross-compile tamio-hook.c for ARM926EJ-S (armv5t, soft-float).
#
# Requires:  sudo apt-get install gcc-arm-linux-gnueabi
#
# Usage:
#   bash scripts/build-hook.sh
#
# Output:
#   /tmp/tamio-hook.so   (upload this to the device)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="${SCRIPT_DIR}/tamio-hook.c"
OUT="/tmp/tamio-hook.so"

CC="${CC:-arm-linux-gnueabi-gcc}"

if ! command -v "$CC" &>/dev/null; then
    echo "ERROR: $CC not found."
    echo "Install with:  sudo apt-get install gcc-arm-linux-gnueabi"
    exit 1
fi

echo "Building ${OUT} ..."
"$CC"                    \
    -march=armv5t        \
    -msoft-float         \
    -shared              \
    -fPIC                \
    -O1                  \
    -Wall                \
    -o "${OUT}"          \
    "${SRC}"             \
    -ldl

SIZE=$(stat -c%s "${OUT}")
echo "Done: ${OUT} (${SIZE} bytes)"
echo
echo "Next step — upload to device:"
echo "  bash scripts/deploy-hook.sh <device-ip>"
