#!/bin/sh
# device-capture.sh — Run on the 828ES ARM via UART to capture what tamio
# reads and writes to /dev/ssmac_avb while a Windows VM (or our Linux driver)
# is connected over USB.
#
# Three capture methods are provided; use whichever works with your kernel:
#
#   METHOD 1 (default): strace tamio
#     Shows the raw read() return values from fd → /dev/ssmac_avb.
#     Requires strace to be in PATH (it is on this device at /opt/strace).
#
#   METHOD 2: watch /proc/PID/fd/N via a background reader
#     Tries to open the same fd through /proc and tee the data.
#     Only works if the fd is opened O_RDWR (it usually is).
#
#   METHOD 3: direct /dev/ssmac_avb read (requires tamio to be killed)
#     Kill tamio, then read ssmac_avb directly. Device will lose connectivity
#     but ssmac_avb data will be unfiltered by tamio.
#
# Output:
#   /tmp/ssmac-capture.log   — text log with hexdump lines
#   /tmp/ptth-requests.log   — filtered PTTH frames only
#
# Retrieve with:
#   nc -l -p 9998 < /tmp/ssmac-capture.log   (on device)
#   nc 10.0.1.205 9998 > captures/device-ssmac.log  (on host)
#
# USAGE:
#   sh scripts/device-capture.sh [method1|method2|method3] [output_port]
#
# Run on device via UART:
#   chmod +x /tmp/device-capture.sh && sh /tmp/device-capture.sh

set -e

OUTLOG=/tmp/ssmac-capture.log
NC_PORT=${2:-9998}
METHOD=${1:-method1}

echo "=== MOTU 828ES ssmac_avb capture ==="
echo "Method: $METHOD"
echo "Output: $OUTLOG"
echo "Date:   $(date)"
echo ""

# ─── Helper: find tamio PID ───────────────────────────────────────────────────

get_tamio_pid() {
    # BusyBox ps does not support aux; use /proc instead
    for d in /proc/[0-9]*; do
        [ -f "$d/cmdline" ] || continue
        cmd=$(cat "$d/cmdline" 2>/dev/null | tr '\0' ' ')
        case "$cmd" in
            *tamio*) echo "${d##*/}"; return 0 ;;
        esac
    done
    return 1
}

# ─── Helper: find fd number for /dev/ssmac_avb in tamio ─────────────────────

get_ssmac_fd() {
    pid=$1
    for fd in /proc/$pid/fd/*; do
        target=$(readlink "$fd" 2>/dev/null) || continue
        case "$target" in
            */ssmac_avb) echo "${fd##*/}"; return 0 ;;
        esac
    done
    return 1
}

# ─── METHOD 1: strace tamio ───────────────────────────────────────────────────

run_method1() {
    TAMIO_PID=$(get_tamio_pid) || {
        echo "ERROR: tamio is not running. Start the device normally then run this."
        exit 1
    }
    echo "tamio PID: $TAMIO_PID"

    SSMAC_FD=$(get_ssmac_fd "$TAMIO_PID") || {
        echo "ERROR: /dev/ssmac_avb fd not found in tamio's fd table."
        echo "       Check: ls -la /proc/$TAMIO_PID/fd"
        exit 1
    }
    echo "ssmac_avb fd in tamio: $SSMAC_FD"
    echo ""
    echo "Starting strace... Connect Windows VM now."
    echo "Press Ctrl+C to stop."
    echo ""

    # strace on tamio, filtering only read/write on the ssmac fd.
    # -xx: print non-printable as hex.  -s 65536: large string limit.
    # We cannot filter by fd with strace on this kernel, so filter the output.
    strace -p "$TAMIO_PID" \
           -e trace=read,write \
           -s 65536 \
           -xx \
           -t \
           2>&1 | grep "read($SSMAC_FD,\|write($SSMAC_FD," \
           | tee "$OUTLOG"
}

# ─── METHOD 2: passive /proc/pid/fd tee ──────────────────────────────────────
# Opens the same file descriptor through /proc and reads it in parallel.
# Note: both tamio and this reader will race to consume data — only use for
# debugging, not for production capture.

run_method2() {
    TAMIO_PID=$(get_tamio_pid) || {
        echo "ERROR: tamio not running"; exit 1
    }
    SSMAC_FD=$(get_ssmac_fd "$TAMIO_PID") || {
        echo "ERROR: ssmac_avb fd not found"; exit 1
    }
    FD_PATH="/proc/$TAMIO_PID/fd/$SSMAC_FD"
    echo "Reading from: $FD_PATH"
    echo "WARNING: data is SHARED with tamio — some packets may be lost."

    while true; do
        dd if="$FD_PATH" bs=4096 count=1 2>/dev/null | hexdump -C
        echo "--- $(date) ---"
    done | tee "$OUTLOG"
}

# ─── METHOD 3: kill tamio and read directly ───────────────────────────────────
# DESTRUCTIVE: kills tamio. Device will lose USB connectivity on clean disconnect.
# Use only when you need raw, unfiltered ssmac_avb data.

run_method3() {
    echo "WARNING: This will kill tamio and break USB/AVB connectivity."
    echo "         You will need to reboot to restore normal operation."
    echo "         Press Enter to continue, Ctrl+C to abort."
    read _dummy

    TAMIO_PID=$(get_tamio_pid) && {
        echo "Killing tamio (PID $TAMIO_PID)..."
        kill "$TAMIO_PID"
        sleep 2
    }

    # Also kill watchdog if present (tamiorun monitor_procs loop)
    for d in /proc/[0-9]*; do
        [ -f "$d/cmdline" ] || continue
        cmd=$(cat "$d/cmdline" 2>/dev/null | tr '\0' ' ')
        case "$cmd" in
            *tamiorun*) kill "${d##*/}" 2>/dev/null || true ;;
        esac
    done

    echo "Reading /dev/ssmac_avb directly. Connect Windows VM now."
    echo "Hex output → $OUTLOG"
    echo "Press Ctrl+C to stop."

    while true; do
        dd if=/dev/ssmac_avb bs=4096 count=1 2>/dev/null \
            | hexdump -C \
            | tee -a "$OUTLOG"
        echo "--- $(date) ---" | tee -a "$OUTLOG"
    done
}

# ─── Start the nc listener to stream log back to host ────────────────────────

start_nc_streamer() {
    # Run in background: keep the log streaming to host on demand.
    # On host: nc 10.0.1.205 $NC_PORT > captures/device-ssmac.log
    (tail -f "$OUTLOG" | nc -l -p "$NC_PORT") &
    NC_PID=$!
    echo "nc listener PID $NC_PID on port $NC_PORT"
    echo "  On HOST: nc 10.0.1.205 $NC_PORT > captures/device-$(date +%s)-ssmac.log"
    echo ""
}

# ─── Main ────────────────────────────────────────────────────────────────────

echo "" > "$OUTLOG"
start_nc_streamer

case "$METHOD" in
    method1) run_method1 ;;
    method2) run_method2 ;;
    method3) run_method3 ;;
    *)
        echo "Unknown method: $METHOD"
        echo "Usage: $0 [method1|method2|method3]"
        exit 1
        ;;
esac
