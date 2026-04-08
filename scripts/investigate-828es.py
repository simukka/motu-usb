#!/usr/bin/env python3
"""
scripts/investigate-828es.py

Connects to the 828ES via Telnet, runs all root-shell investigation commands
documented in research.md (Day Three), retrieves each output file via base64,
and saves them to captures/root-*.txt ready for offline analysis.

Usage:
    python3 scripts/investigate-828es.py <host>
    python3 scripts/investigate-828es.py 192.168.1.42 --password secret
    python3 scripts/investigate-828es.py 192.168.1.42 --only 07
    python3 scripts/investigate-828es.py 192.168.1.42 --output-dir /tmp/828es

Requires: pip install telnetlib3
"""

import argparse
import asyncio
import base64
import re
import sys
from pathlib import Path

try:
    import telnetlib3
except ImportError:
    print("ERROR: telnetlib3 not installed")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

CAPTURES_DIR = Path(__file__).resolve().parent.parent / "captures"
PROMPT = "# "

# Each step: (step_id, description, remote_tmp_path, shell_command, timeout_secs)
STEPS = [
    (
        "01-sysinfo",
        "System overview (uname, OS release, mounts, disk)",
        "/tmp/root-01-sysinfo.txt",
        "{ uname -a; cat /proc/version; cat /etc/arago-release 2>/dev/null"
        " || cat /etc/os-release 2>/dev/null; mount; df -h;"
        " } > /tmp/root-01-sysinfo.txt 2>&1",
        30,
    ),
    (
        "02-processes",
        "Running processes",
        "/tmp/root-02-processes.txt",
        "{ ps -w 2>/dev/null || ps; } > /tmp/root-02-processes.txt 2>&1",
        30,
    ),
    (
        "03-gadget",
        "USB / ssmac_avb_char (major 233) device nodes",
        "/tmp/root-03-gadget.txt",
        "{ find /dev -type c | while read f; do ls -la \"$f\"; done"
        " | awk -F'[ ,]+' '{print $5, $0}' | sort -n;"
        " echo '---';"
        " find /dev -type c 2>/dev/null | while read f;"
        " do maj=$(ls -la \"$f\" | awk '{print $5}' | tr -d ',');"
        " [ \"$maj\" = \"233\" ] && echo \"FOUND ssmac: $f\"; done;"
        " } > /tmp/root-03-gadget.txt 2>&1",
        60,
    ),
    (
        "04-network",
        "Network interfaces and routing",
        "/tmp/root-04-network.txt",
        "{ ip link show 2>/dev/null || ifconfig -a; echo;"
        " cat /proc/net/dev; echo;"
        " ip addr show 2>/dev/null; ip route show 2>/dev/null || route -n;"
        " } > /tmp/root-04-network.txt 2>&1",
        30,
    ),
    (
        "05-listeners",
        "Listening TCP/UDP ports",
        "/tmp/root-05-listeners.txt",
        "{ netstat -tlnp 2>/dev/null || ss -tlnp;"
        " netstat -ulnp 2>/dev/null || ss -ulnp;"
        " } > /tmp/root-05-listeners.txt 2>&1",
        30,
    ),
    (
        "06-binaries",
        "Find MOTU/AVB/ssmac binaries and /proc/*/exe links",
        "/tmp/root-06-binaries.txt",
        r"{ find /usr /opt /sbin /bin -type f \("
        r" -name 'httpd' -o -name 'motu*' -o -name 'avb*' -o -name 'usb*'"
        r" -o -name 'datastore*' -o -name 'gadget*'"
        r" -o -name 'ssmac*' -o -name 'ss_*' \) 2>/dev/null;"
        r" echo;"
        r" ls -la /proc/*/exe 2>/dev/null | grep -v 'Permission denied';"
        r" } > /tmp/root-06-binaries.txt 2>&1",
        60,
    ),
    #     curl
    # -sh: curl: not found
    # (
    #     "07-http",
    #     "Test HTTP server from device with curl",
    #     "/tmp/root-07-http.txt",
    #     "{ curl -sv http://localhost/datastore 2>&1; echo '---';"
    #     " curl -sv http://localhost/nonexistent 2>&1; echo '---';"
    #     " curl -sv -H 'If-None-Match: 1' http://localhost/datastore 2>&1;"
    #     " } > /tmp/root-07-http.txt 2>&1",
    #     60,
    # ),
    (
        "08-strings",
        "Strings in handler binaries (NREK/PTTH/MOTU/ssmac constants)",
        "/tmp/root-08-strings.txt",
        r"find /usr /opt /sbin /bin -type f \("
        r" -name 'httpd' -o -name 'motu*' -o -name 'avb*' -o -name 'usb*'"
        r" -o -name 'gadget*' -o -name 'ssmac*' -o -name 'ss_*' \) 2>/dev/null"
        r" | while read f; do echo \"=== $f ===\";"
        r" strings \"$f\" | grep -iE"
        r" 'NREK|PTTH|UTOM|MOTU|ssmac|session|chunk|datastore|ETag|ping|pong|connect|serial';"
        r" done > /tmp/root-08-strings.txt 2>&1",
        300,  # strings over all binaries can be slow
    ),
    (
        "09-fds",
        "Open fds + memory maps of ssmac_avb_char owners (major 233)",
        "/tmp/root-09-fds.txt",
        "{ for p in /proc/[0-9]*/fd; do"
        " pid=${p%/fd}; pid=${pid##*/};"
        " out=$(ls -la \"$p\" 2>/dev/null | grep -iE 'ssmac|233|avb|usb');"
        " [ -n \"$out\" ] && printf '\\n=== PID %s ===\\n%s\\n' \"$pid\" \"$out\""
        " && ls -la \"$p\" 2>/dev/null"
        " && cat \"/proc/$pid/maps\" 2>/dev/null"
        " && cat \"/proc/$pid/cmdline\" 2>/dev/null | tr '\\0' ' ';"
        " done; } > /tmp/root-09-fds.txt 2>&1",
        60,
    ),
    (
        "11-datastore",
        "Find datastore / JSON / DB files",
        "/tmp/root-11-datastore.txt",
        "{ find / -path /proc -prune -o -path /sys -prune"
        " -o -type f \\( -name 'datastore*' -o -name '*.json' -o -name '*.db' \\)"
        " -print 2>/dev/null"
        " | while read f; do echo \"=== $f ===\"; head -c 4096 \"$f\"; done;"
        " } > /tmp/root-11-datastore.txt 2>&1",
        120,
    ),
    (
        "12-tools",
        "Available debug tools (strace, gdb, tcpdump, ...)",
        "/tmp/root-12-tools.txt",
        "which strace ltrace gdb tcpdump nc socat hexdump od"
        " > /tmp/root-12-tools.txt 2>&1",
        15,
    ),
]

# ---------------------------------------------------------------------------
# Async telnet helpers  (telnetlib3 — works on Python 3.13+)
# ---------------------------------------------------------------------------

def vprint(verbose: bool, text: str) -> None:
    """Print raw telnet output when verbose mode is on."""
    if not verbose or not text.strip():
        return
    for line in text.replace("\r\n", "\n").replace("\r", "\n").splitlines():
        print(f"  \033[2m│ {line}\033[0m")


async def read_until(
    reader, marker: str, timeout: float = 30.0, verbose: bool = False
) -> str:
    """Accumulate text from the reader until `marker` appears or timeout."""
    buf = ""
    try:
        async with asyncio.timeout(timeout):
            while marker not in buf:
                chunk = await reader.read(4096)
                if not chunk:
                    break
                if verbose:
                    vprint(verbose, chunk)
                buf += chunk
    except (asyncio.TimeoutError, TimeoutError):
        pass  # return whatever we collected
    return buf

# ---------------------------------------------------------------------------
# Main coroutine
# ---------------------------------------------------------------------------

async def investigate(args) -> None:
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # ── Connect ──────────────────────────────────────────────────────────────
    print(f"Connecting to {args.host}:{args.port} ...")
    try:
        reader, writer = await asyncio.wait_for(
            telnetlib3.open_connection(args.host, args.port, encoding="utf-8"),
            timeout=15,
        )
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)

    verbose = args.verbose
    shell_ready = False

    # Handle optional login prompt (some telnet daemons go straight to shell)
    initial = await read_until(reader, "login:", timeout=5.0, verbose=verbose)
    if "login:" in initial:
        print("  Login prompt — sending 'root'")
        writer.write("root\n")
        # Device may require a password, or may drop straight to the shell prompt
        post_login = await read_until(reader, "Password:", timeout=5.0, verbose=verbose)
        if "Password:" in post_login:
            print("  Password prompt — sending password")
            writer.write(args.password + "\n")
        elif PROMPT in post_login:
            # Got the shell prompt immediately — no password required
            shell_ready = True

    if not shell_ready:
        print("  Waiting for shell prompt ...")
        greeting = await read_until(reader, PROMPT, timeout=15.0, verbose=verbose)
        if PROMPT not in greeting:
            print("WARNING: no prompt received — device may need manual interaction.", file=sys.stderr)
        else:
            shell_ready = True

    if shell_ready:
        print("  Shell ready.\n")

    # ── Always grab /proc/devices first — tiny and always useful ─────────────
    if not args.only:
        proc_dev_local = out_dir / "root-00-proc-devices.txt"
        print("  [00] /proc/devices")
        writer.write("cat /proc/devices\n")
        raw = await read_until(reader, PROMPT, timeout=10.0, verbose=verbose)
        lines = raw.replace("\r\n", "\n").split("\n")
        content = "\n".join(lines[1:]).rstrip()  # drop echoed command
        proc_dev_local.write_text(content)
        print(f"       → {proc_dev_local.name}  ({len(content)} bytes)\n")

    # ── Run investigation steps ──────────────────────────────────────────────
    results: dict[str, bool] = {}

    for step_id, description, remote_file, cmd, timeout in STEPS:
        if args.only and not step_id.startswith(args.only):
            continue

        local_file = out_dir / f"root-{step_id}.txt"
        print(f"  [{step_id}] {description}")

        print(f"           Running ... ", end="", flush=True)
        if verbose:
            print()  # newline so verbose output starts on its own line
        writer.write(cmd + "\n")
        await read_until(reader, PROMPT, timeout=timeout, verbose=verbose)
        if not verbose:
            print("done")
        else:
            print(f"           done")

        print(f"           Fetching {remote_file} ... ", end="", flush=True)
        
        writer.write(f"cat {remote_file}\n")
        raw = await read_until(reader, PROMPT, timeout=10.0, verbose=verbose)
        lines = raw.replace("\r\n", "\n").split("\n")
        content = "\n".join(lines[1:]).rstrip()  # drop echoed command
        local_file.write_text(content)
        print(f"       → {local_file.name}  ({len(content)} bytes)\n")
        
        ok = False
        if len(content) > 0:
            ok = True

        results[step_id] = ok
        print()

    writer.write("exit\n")
    writer.close()

    # ── Summary ──────────────────────────────────────────────────────────────
    print("─" * 60)
    print("Summary:")
    for step_id, description, *_ in STEPS:
        if args.only and not step_id.startswith(args.only):
            continue
        status = "✓" if results.get(step_id) else "✗"
        print(f"  {status}  root-{step_id}.txt")
    print(f"\nAll output saved to: {out_dir}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Run 828ES root-shell investigation commands via Telnet "
            "and save output to captures/root-*.txt."
        )
    )
    parser.add_argument("host", help="IP address or hostname of the 828ES")
    parser.add_argument("--port", type=int, default=23, help="Telnet port (default: 23)")
    parser.add_argument(
        "--password", default="", help="Root password if required (default: empty)"
    )
    parser.add_argument(
        "--only",
        metavar="STEP",
        help="Run only steps whose ID starts with STEP, e.g. '07' or '08-strings'",
    )
    parser.add_argument(
        "--output-dir",
        default=str(CAPTURES_DIR),
        help=f"Directory for output files (default: {CAPTURES_DIR})",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Print raw telnet responses as they arrive (base64 blobs are suppressed)",
    )
    args = parser.parse_args()
    asyncio.run(investigate(args))


if __name__ == "__main__":
    main()
