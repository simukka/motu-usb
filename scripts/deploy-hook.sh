#!/usr/bin/env bash
# deploy-hook.sh — upload tamio-hook.so to the device, inject it into tamio,
#                  and tail the log.
#
# The device must be accessible via telnet (start with:
#   sudo cargo run --example start_telnet).
#
# Usage:
#   bash scripts/deploy-hook.sh <device-ip>
#   bash scripts/deploy-hook.sh 10.0.1.205
#
# How it works:
#   1. Uploads /tmp/tamio-hook.so via netcat (no scp/ssh required).
#   2. On the device, sends SIGSTOP to tamio to freeze it.
#   3. Writes the LD_PRELOAD env var into tamio's /proc/<pid>/environ is not
#      writable, so instead we:
#        a. Write the .so to /tmp/ (tmpfs, writable).
#        b. Kill tamio — /etc/rc5.d/S40tamiorun watches for it and restarts
#           it automatically (confirmed from process list: pid 569 is the
#           S40tamiorun watchdog shell script).
#        c. But we need LD_PRELOAD set BEFORE tamio re-starts.
#           We patch S40tamiorun by writing a wrapper and symlinking it.
#   4. Tails /tmp/tamio-hook.log via nc.
#
# WARNING: killing tamio drops the USB session.  You will need to reconnect
# with `cargo run --example connect` after the device restarts tamio (~2s).
#
# Alternative (no restart): /proc/<pid>/mem patching to hook at runtime.
# That requires knowing tamio's GOT offsets — see Ghidra analysis.

set -euo pipefail

DEVICE_IP="${1:-10.0.1.205}"
DEVICE_PORT=23   # telnet
SO_LOCAL="/tmp/tamio-hook.so"
SO_REMOTE="/tmp/tamio-hook.so"
NC_UPLOAD_PORT=9876

if [[ ! -f "$SO_LOCAL" ]]; then
    echo "ERROR: ${SO_LOCAL} not found.  Run: bash scripts/build-hook.sh"
    exit 1
fi

SO_SIZE=$(stat -c%s "$SO_LOCAL")
echo "=== Uploading ${SO_LOCAL} (${SO_SIZE} bytes) to ${DEVICE_IP}:${NC_UPLOAD_PORT} ==="

# ── Step 1: Start nc listener on device via telnet ──────────────────────────
#
# We can't assume netcat on the host can reach the device directly — we use
# the device's own /usr/bin/nc to receive.  We send the telnet commands via
# a here-doc piped into `nc $DEVICE_IP 23`.
#
# Telnet negotiation: send IAC WONT for any DO requests, then our commands.

send_telnet_cmd() {
    # $1 = command string; waits ~1s for output
    printf '%s\n' "$1" | nc -q1 "${DEVICE_IP}" "${DEVICE_PORT}" 2>/dev/null || true
}

echo "Starting nc listener on device ..."
# Run nc in background on device, capturing to SO_REMOTE
(
printf 'nc -l -p %d > %s &\n' "${NC_UPLOAD_PORT}" "${SO_REMOTE}"
sleep 0.5
) | nc "${DEVICE_IP}" "${DEVICE_PORT}" &>/dev/null &
sleep 1

# ── Step 2: Upload the .so ──────────────────────────────────────────────────
echo "Sending .so ..."
nc "${DEVICE_IP}" "${NC_UPLOAD_PORT}" < "${SO_LOCAL}"
sleep 0.5

# ── Step 3: Verify size on device ───────────────────────────────────────────
echo "Verifying upload ..."
(
printf 'wc -c %s\n' "${SO_REMOTE}"
sleep 0.5
) | nc "${DEVICE_IP}" "${DEVICE_PORT}"

# ── Step 4: Wrap tamio launch with LD_PRELOAD ────────────────────────────────
#
# S40tamiorun starts tamio like:
#   /opt/tamio
# We can't edit the script directly (rootfs is ext2, read-only in practice
# unless we remount).  Instead we write a wrapper to /tmp/tamio that
# sets LD_PRELOAD and execs the real binary, then bind-mount it.
#
# If bind-mount is unavailable, we just kill tamio and set LD_PRELOAD
# in /proc/sys... which doesn't exist.  Simplest reliable approach:
# use /proc/<pid>/mem to write the env — but that's complex.
#
# SIMPLEST APPROACH that works given the watchdog:
# The watchdog script at pid 569 simply re-execs /opt/tamio.
# We can write a /tmp/tamio wrapper and mount --bind it over /opt/tamio.
# The watchdog will then exec our wrapper.
echo "Installing LD_PRELOAD wrapper ..."
(
cat << 'HEREDOC'
cat > /tmp/tamio-wrapper.sh << 'EOF'
#!/bin/sh
export LD_PRELOAD=/tmp/tamio-hook.so
exec /opt/tamio.real "$@"
EOF
chmod +x /tmp/tamio-wrapper.sh
# Copy real tamio only if not already done
[ -f /opt/tamio.real ] || cp /opt/tamio /opt/tamio.real
# Bind mount the wrapper — needs root (we are root)
mount --bind /tmp/tamio-wrapper.sh /opt/tamio
echo "WRAPPER_INSTALLED"
HEREDOC
sleep 1
) | nc "${DEVICE_IP}" "${DEVICE_PORT}"

# ── Step 5: Kill tamio — watchdog restarts it via /opt/tamio (now wrapper) ──
echo "Restarting tamio with LD_PRELOAD ..."
(
printf 'kill $(cat /var/volatile/run/MOTUAVBController.pid 2>/dev/null || pidof tamio)\n'
sleep 0.3
printf 'sleep 1 && pidof tamio\n'
sleep 2
) | nc "${DEVICE_IP}" "${DEVICE_PORT}"

echo ""
echo "=== tamio should be running with hook now ==="
echo "Tailing /tmp/tamio-hook.log (Ctrl-C to stop):"
echo ""

# ── Step 6: Live tail of hook log via nc ─────────────────────────────────────
(
printf 'tail -f /tmp/tamio-hook.log\n'
sleep 9999
) | nc "${DEVICE_IP}" "${DEVICE_PORT}"
