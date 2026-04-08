#!/usr/bin/env bash
# scripts/windows-capture.sh — Orchestrate a fresh Windows VM USB capture session.
#
# Automates everything that must happen on the Linux host:
#   1. Load usbmon, mount debugfs if needed
#   2. Find the 828ES and print its bus/dev
#   3. Verify the device is NOT already claimed by a Linux driver
#   4. Start usbmon-capture.py in the background, streaming to a timestamped JSONL
#   5. Print step-by-step instructions for the Windows VM operator
#   6. On Ctrl+C / finish: stop capture, print packet count, show analyze command
#
# Prerequisites on Linux host:
#   sudo apt install usbutils python3   (already present on most distros)
#   pip install pyusb                   (only needed for windows-driver-session.py)
#
# Usage:
#   sudo ./scripts/windows-capture.sh
#   sudo ./scripts/windows-capture.sh --out captures/my-session.jsonl
#   sudo ./scripts/windows-capture.sh --label "clock-source-change"
#   sudo ./scripts/windows-capture.sh --no-wait   # skip the operator prompts
#
# After capture:
#   python3 scripts/analyze-capture.py captures/windows-<timestamp>.jsonl

set -euo pipefail

# ─── Colour helpers ───────────────────────────────────────────────────────────
RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'
CYN='\033[0;36m'; BLD='\033[1m';    RST='\033[0m'

info()  { echo -e "${CYN}[INFO]${RST}  $*"; }
ok()    { echo -e "${GRN}[OK]${RST}    $*"; }
warn()  { echo -e "${YLW}[WARN]${RST}  $*"; }
err()   { echo -e "${RED}[ERR]${RST}   $*" >&2; }
step()  { echo -e "\n${BLD}──────────────────────────────────────────────${RST}"; \
          echo -e "${BLD}  $*${RST}"; \
          echo -e "${BLD}──────────────────────────────────────────────${RST}"; }
prompt(){ echo -e "\n${YLW}▶ $* — press ENTER when done...${RST}"; read -r _; }

# ─── Defaults ─────────────────────────────────────────────────────────────────
MOTU_VID="07fd"
MOTU_PID="0005"
LABEL=""
NO_WAIT=0
OUT_FILE=""
CAPTURE_PID=""

# ─── Argument parsing ─────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --out)      OUT_FILE="$2"; shift 2 ;;
        --label)    LABEL="$2";    shift 2 ;;
        --no-wait)  NO_WAIT=1;     shift   ;;
        -h|--help)
            sed -n '2,/^set -/p' "$0" | grep '^#' | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) err "Unknown option: $1"; exit 1 ;;
    esac
done

# ─── Must run as root ─────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    err "This script requires root (needed for usbmon and debugfs)."
    echo "  sudo $0 $*"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CAPTURES_DIR="$REPO_ROOT/captures"
mkdir -p "$CAPTURES_DIR"

# ─── Output file name ─────────────────────────────────────────────────────────
TS="$(date +%Y%m%d-%H%M%S)"
if [[ -z "$OUT_FILE" ]]; then
    if [[ -n "$LABEL" ]]; then
        OUT_FILE="$CAPTURES_DIR/windows-${TS}-${LABEL}.jsonl"
    else
        OUT_FILE="$CAPTURES_DIR/windows-${TS}.jsonl"
    fi
fi
info "Capture output : $OUT_FILE"

# ─── Step 1: Mount debugfs ────────────────────────────────────────────────────
step "1 / 6 — Ensuring debugfs and usbmon are available"

if ! mountpoint -q /sys/kernel/debug; then
    info "Mounting debugfs at /sys/kernel/debug..."
    mount -t debugfs none /sys/kernel/debug
    ok "debugfs mounted."
else
    ok "debugfs already mounted."
fi

if [[ ! -d /sys/kernel/debug/usb/usbmon ]]; then
    info "Loading usbmon kernel module..."
    modprobe usbmon
    sleep 0.5
    ok "usbmon loaded."
else
    ok "usbmon already available."
fi

# ─── Step 2: Find the 828ES ──────────────────────────────────────────────────
step "2 / 6 — Locating MOTU 828ES"

BUS=""
DEV=""
PRODUCT=""
for SYSDEV in /sys/bus/usb/devices/*; do
    [[ -f "$SYSDEV/idVendor" ]] || continue
    [[ "$(cat "$SYSDEV/idVendor")" == "$MOTU_VID" ]] || continue
    [[ -f "$SYSDEV/idProduct" ]] || continue
    [[ "$(cat "$SYSDEV/idProduct")" == "$MOTU_PID" ]] || continue
    BUS="$(cat "$SYSDEV/busnum")"
    DEV="$(cat "$SYSDEV/devnum")"
    PRODUCT="$(cat "$SYSDEV/product" 2>/dev/null || echo 'MOTU')"
    SYSFS_PATH="$SYSDEV"
    break
done

if [[ -z "$BUS" ]]; then
    err "No MOTU 828ES (${MOTU_VID}:${MOTU_PID}) found."
    err "Plug in the device first, then re-run this script."
    exit 1
fi

ok "Found: ${PRODUCT}  bus=${BUS} dev=${DEV}  (${SYSFS_PATH##*/})"

# ─── Step 3: Check the device is not claimed by a competing driver ────────────
step "3 / 6 — Checking for competing driver claims"

CLAIMED_IFS=()
for IF_DIR in "$SYSFS_PATH"/"${SYSFS_PATH##*/}":*/; do
    [[ -L "$IF_DIR/driver" ]] || continue
    DRV="$(basename "$(readlink "$IF_DIR/driver")")"
    IFNUM="$(cat "$IF_DIR/bInterfaceNumber" 2>/dev/null || echo '?')"
    CLAIMED_IFS+=("if${IFNUM}=${DRV}")
done

if [[ ${#CLAIMED_IFS[@]} -gt 0 ]]; then
    warn "Some interfaces are bound to Linux drivers: ${CLAIMED_IFS[*]}"
    warn "This is normal (audio interfaces bind to snd-usb-audio etc.)."
    warn "Interface 5 (vendor bulk) must NOT be claimed by any driver during VM use."
    # Check specifically for interface 5
    IF5_DRIVER=""
    IF5_DIR="${SYSFS_PATH}/${SYSFS_PATH##*/}:1.5"
    if [[ -L "$IF5_DIR/driver" ]]; then
        IF5_DRIVER="$(basename "$(readlink "$IF5_DIR/driver")")"
        err "Interface 5 is currently bound to '${IF5_DRIVER}'!"
        err "Unbind it before passing the device to the VM:"
        err "  echo '${SYSFS_PATH##*/}:1.5' > /sys/bus/usb/drivers/${IF5_DRIVER}/unbind"
        exit 1
    else
        ok "Interface 5 is unbound — safe to pass to Windows VM."
    fi
else
    ok "No competing driver claims detected."
fi

# ─── Step 4: Create usbmon device node if needed ─────────────────────────────
step "4 / 6 — Setting up usbmon capture interface"

USBMON_DEV="/dev/usbmon${BUS}"
if [[ ! -c "$USBMON_DEV" ]]; then
    MAJOR="$(awk '/usbmon/{print $1}' /proc/devices 2>/dev/null || true)"
    if [[ -n "$MAJOR" ]]; then
        mknod "$USBMON_DEV" c "$MAJOR" "$BUS"
        ok "Created $USBMON_DEV (major=$MAJOR, minor=$BUS)"
    else
        warn "Cannot create $USBMON_DEV — will fall back to text-mode usbmon (32-byte cap)."
        USBMON_DEV=""
    fi
else
    ok "Binary usbmon device: $USBMON_DEV"
fi

# ─── Step 5: Start capture in background ─────────────────────────────────────
step "5 / 6 — Starting usbmon-capture.py"

CAPTURE_SCRIPT="$SCRIPT_DIR/usbmon-capture.py"
if [[ ! -f "$CAPTURE_SCRIPT" ]]; then
    err "Cannot find $CAPTURE_SCRIPT"
    exit 1
fi

CAPTURE_LOG="${OUT_FILE%.jsonl}.capture.log"

cleanup() {
    if [[ -n "$CAPTURE_PID" ]] && kill -0 "$CAPTURE_PID" 2>/dev/null; then
        info "Stopping capture (PID $CAPTURE_PID)..."
        kill -INT "$CAPTURE_PID"
        wait "$CAPTURE_PID" 2>/dev/null || true
    fi

    if [[ -f "$OUT_FILE" ]]; then
        LINES="$(wc -l < "$OUT_FILE" 2>/dev/null || echo 0)"
        echo ""
        ok "Capture saved: $OUT_FILE ($LINES packets)"
        echo ""
        echo -e "${BLD}Analyze the capture:${RST}"
        echo "  python3 scripts/analyze-capture.py $OUT_FILE"
        echo ""
        echo -e "${BLD}Quick packet count by direction:${RST}"
        grep -c '"direction": "OUT"' "$OUT_FILE" 2>/dev/null | \
            xargs -I{} echo "  OUT: {} frames" || true
        grep -c '"direction": "IN"' "$OUT_FILE" 2>/dev/null | \
            xargs -I{} echo "  IN:  {} frames" || true
        echo ""
        info "Capture subprocess log: $CAPTURE_LOG"
    fi
}
trap cleanup EXIT INT TERM

sudo .venv/bin/python3 "$CAPTURE_SCRIPT" \
    --device "${BUS}:${DEV}" \
    --save "$OUT_FILE" \
    >"$CAPTURE_LOG" 2>&1 \
    &
CAPTURE_PID=$!
sleep 0.5

if ! kill -0 "$CAPTURE_PID" 2>/dev/null; then
    err "usbmon-capture.py exited immediately. Subprocess log:"
    cat "$CAPTURE_LOG" >&2
    exit 1
fi
ok "Capture running (PID $CAPTURE_PID) → $OUT_FILE"
info "Subprocess log : $CAPTURE_LOG  (tail -f to follow)"

# ─── Step 6: Operator instructions ───────────────────────────────────────────
step "6 / 6 — Windows VM session — follow these steps in order"

cat <<'INSTRUCTIONS'

  ┌─────────────────────────────────────────────────────────────────────┐
  │  LINUX HOST (already done)                                          │
  │    ✓  usbmon loaded and capturing                                   │
  │    ✓  Capture streaming to JSONL file above                         │
  └─────────────────────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────────────────────────────────┐
  │  WINDOWS VM — perform each action, then press ENTER here            │
  └─────────────────────────────────────────────────────────────────────┘

  Action 1 — Pass USB device to VM
    QEMU/virt-manager:   Devices → USB Redirect → select MOTU 828ES
    VirtualBox:          Devices → USB → MOTU 828ES
    After pass-through the device disappears from lsusb on the host and
    re-appears with the same bus/dev (or a new address).

  Action 2 — Open MOTU Control software in Windows
    Let it connect fully (status bar shows device name, not "Searching...")

  Action 3 — Perform each scenario:
    a) Change clock source (e.g. Internal → ADAT)
    b) Change sample rate (e.g. 44100 → 48000)
    c) Move a mixer fader (any channel)
    d) Toggle a mute button
    e) Change a routing entry (e.g. Main L to a different source)
    f) Close and reopen MOTU Control (tests reconnect sequence)
    g) Disconnect and reconnect the USB cable (tests cold-boot sequence)

  Action 4 — Return USB device to Linux host
    QEMU/virt-manager:   Devices → USB Redirect → unredirect MOTU 828ES
    VirtualBox:          Devices → USB → uncheck MOTU 828ES

INSTRUCTIONS

if [[ "$NO_WAIT" -eq 1 ]]; then
    info "--no-wait set: running until Ctrl+C."
    wait "$CAPTURE_PID"
else
    prompt "Action 1: pass USB device to Windows VM"
    prompt "Action 2: MOTU Control is open and connected in Windows"
    prompt "Actions 3a-3f: clock, sample rate, fader, mute, routing, reconnect"
    prompt "Action 4: return USB device to Linux host"

    info "Stopping capture..."
    kill -INT "$CAPTURE_PID" 2>/dev/null || true
    wait "$CAPTURE_PID" 2>/dev/null || true
    CAPTURE_PID=""
fi
