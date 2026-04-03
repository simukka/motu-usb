#!/usr/bin/env bash
# probe-usb.sh — Diagnose MOTU USB interface classes for CDC/RNDIS network access
# Run as root (or with sudo) for full sysfs driver binding info.
set -euo pipefail

MOTU_VID="07fd"

# ─── Colour helpers ──────────────────────────────────────────────────────────
RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'
CYN='\033[0;36m'; BLD='\033[1m'; RST='\033[0m'
info()  { echo -e "${CYN}[INFO]${RST}  $*"; }
ok()    { echo -e "${GRN}[OK]${RST}    $*"; }
warn()  { echo -e "${YLW}[WARN]${RST}  $*"; }
found() { echo -e "${GRN}[FOUND]${RST} $*"; }
miss()  { echo -e "${RED}[MISS]${RST}  $*"; }
hdr()   { echo -e "\n${BLD}══════════════════════════════════════════════════${RST}"; \
          echo -e "${BLD}  $*${RST}"; \
          echo -e "${BLD}══════════════════════════════════════════════════${RST}"; }

# ─── USB class code decoder ───────────────────────────────────────────────────
decode_class() {
    local cls="$1" sub="$2" proto="$3"
    case "$cls" in
        0x01|01) echo "Audio (UAC)" ;;
        0x02|02) case "$sub" in
                    0x02|02) echo "CDC - Abstract Control Model (ACM / serial)" ;;
                    0x06|06) echo "CDC-ECM - Ethernet Control Model  ← NETWORK" ;;
                    0x0d|0d|0D) echo "CDC-NCM - Network Control Model  ← NETWORK" ;;
                    0x0e|0e|0E) echo "CDC - Ethernet Emulation Model (EEM)  ← NETWORK" ;;
                    *) echo "CDC Communications (subclass 0x$sub)" ;;
                 esac ;;
        0x0a|0a|0A) echo "CDC-Data  ← NETWORK data channel" ;;
        0xe0|e0|E0) if [[ "$sub" == "0x01" || "$sub" == "01" ]] && \
                       [[ "$proto" == "0x03" || "$proto" == "03" ]]; then
                        echo "RNDIS (Wireless Controller class)  ← NETWORK"
                    else
                        echo "Wireless Controller (subclass 0x$sub proto 0x$proto)"
                    fi ;;
        0xef|ef|EF) case "$sub:$proto" in
                        0x02:0x01|02:01) echo "Misc - Interface Association Descriptor (IAD)" ;;
                        0x04:0x01|04:01) echo "RNDIS over Ethernet (Misc class)  ← NETWORK" ;;
                        *) echo "Miscellaneous (subclass 0x$sub proto 0x$proto)" ;;
                    esac ;;
        0xff|ff|FF) echo "Vendor Specific (FF)" ;;
        *) echo "Class 0x$cls sub 0x$sub proto 0x$proto" ;;
    esac
}

# ─── 1. Find MOTU devices ─────────────────────────────────────────────────────
hdr "1. Detecting MOTU devices (VID $MOTU_VID)"

mapfile -t MOTU_LINES < <(lsusb | grep -i "$MOTU_VID" || true)

if [[ ${#MOTU_LINES[@]} -eq 0 ]]; then
    miss "No MOTU devices found on USB bus. Is the device powered on and connected?"
    exit 1
fi

declare -a MOTU_IDS
for line in "${MOTU_LINES[@]}"; do
    # "Bus 003 Device 007: ID 07fd:0008 Mark of the Unicorn M Series"
    busdev=$(echo "$line" | grep -oP 'Bus \K\d+')
    devnum=$(echo "$line" | grep -oP 'Device \K\d+')
    vid_pid=$(echo "$line" | grep -oP 'ID \K[\da-fA-F:]+')
    name=$(echo "$line" | sed 's/.*ID [^ ]* //')
    ok "Bus $busdev Device $devnum  │  $vid_pid  │  $name"
    MOTU_IDS+=("${vid_pid}|${busdev}|${devnum}")
done

# ─── 2. Full USB descriptor per device ───────────────────────────────────────
hdr "2. Full USB descriptors"

for entry in "${MOTU_IDS[@]}"; do
    vid_pid="${entry%%|*}"         # 07fd:xxxx
    rest="${entry#*|}"
    bus="${rest%%|*}"
    dev="${rest##*|}"

    echo ""
    info "──────────────────────────────────────────────────────"
    info "Device: $vid_pid  Bus $bus Dev $dev"
    info "──────────────────────────────────────────────────────"

    # lsusb -D works on the device node directly (requires r permission)
    devnode="/dev/bus/usb/$(printf '%03d' "$((10#$bus))")/$(printf '%03d' "$((10#$dev))")"
    if [[ -r "$devnode" ]]; then
        lsusb -D "$devnode" 2>/dev/null || lsusb -v -d "$vid_pid" 2>/dev/null
    else
        warn "Cannot read $devnode directly — falling back to lsusb -v (may need sudo)"
        lsusb -v -d "$vid_pid" 2>/dev/null
    fi
done

# ─── 3. Parse interface classes looking for network interfaces ────────────────
hdr "3. Interface class analysis — looking for CDC / RNDIS / network interfaces"

FOUND_NETWORK=0

for entry in "${MOTU_IDS[@]}"; do
    vid_pid="${entry%%|*}"
    rest="${entry#*|}"
    bus="${rest%%|*}"
    dev="${rest##*|}"

    echo ""
    info "Scanning interfaces on $vid_pid (Bus $bus Dev $dev)"

    devnode="/dev/bus/usb/$(printf '%03d' "$((10#$bus))")/$(printf '%03d' "$((10#$dev))")"
    if [[ -r "$devnode" ]]; then
        raw=$(lsusb -D "$devnode" 2>/dev/null)
    else
        raw=$(lsusb -v -d "$vid_pid" 2>/dev/null)
    fi

    # Extract interface blocks
    intf_num=""
    cls=""; sub=""; proto=""
    while IFS= read -r raw_line; do
        line="${raw_line#"${raw_line%%[! ]*}"}"   # ltrim

        if [[ "$line" =~ bInterfaceNumber[[:space:]]+([0-9]+) ]]; then
            intf_num="${BASH_REMATCH[1]}"
            cls=""; sub=""; proto=""
        elif [[ "$line" =~ bInterfaceClass[[:space:]]+(0x[0-9a-fA-F]+|[0-9]+) ]]; then
            cls="${BASH_REMATCH[1]}"
        elif [[ "$line" =~ bInterfaceSubClass[[:space:]]+(0x[0-9a-fA-F]+|[0-9]+) ]]; then
            sub="${BASH_REMATCH[1]}"
        elif [[ "$line" =~ bInterfaceProtocol[[:space:]]+(0x[0-9a-fA-F]+|[0-9]+) ]]; then
            proto="${BASH_REMATCH[1]}"
            if [[ -n "$cls" ]]; then
                desc=$(decode_class "$cls" "$sub" "$proto")
                if echo "$desc" | grep -q "NETWORK\|CDC-ECM\|CDC-NCM\|RNDIS\|EEM\|CDC-Data"; then
                    found "Interface $intf_num: class=$cls sub=$sub proto=$proto → $desc"
                    FOUND_NETWORK=1
                else
                    info "Interface $intf_num: class=$cls sub=$sub proto=$proto → $desc"
                fi
            fi
        fi
    done <<< "$raw"
done

echo ""
if [[ "$FOUND_NETWORK" -eq 1 ]]; then
    ok "At least one network-capable interface was found!"
else
    warn "No CDC/RNDIS/network interface classes found in USB descriptors."
    warn "The device may use a vendor-specific protocol (class FF) for HTTP access."
fi

# ─── 4. What drivers are currently bound? ────────────────────────────────────
hdr "4. Current driver bindings (sysfs)"

info "Checking /sys/bus/usb/drivers/ for MOTU device bindings..."

for entry in "${MOTU_IDS[@]}"; do
    vid_pid="${entry%%|*}"
    rest="${entry#*|}"
    bus="${rest%%|*}"
    dev="${rest##*|}"
    buspad=$(printf '%03d' "$((10#$bus))")
    devpad=$(printf '%03d' "$((10#$dev))")

    # sysfs path is like /sys/bus/usb/devices/3-3 — find it by matching idVendor
    vid="${vid_pid%%:*}"
    pid="${vid_pid##*:}"

    echo ""
    info "Looking for sysfs node: idVendor=$vid idProduct=$pid"

    for sysdev in /sys/bus/usb/devices/*/; do
        [[ -f "$sysdev/idVendor" ]] || continue
        sv=$(cat "$sysdev/idVendor" 2>/dev/null)
        sp=$(cat "$sysdev/idProduct" 2>/dev/null)
        [[ "$sv" == "$vid" && "$sp" == "$pid" ]] || continue

        devpath=$(basename "$sysdev")
        ok "Found sysfs device: $devpath"

        # Check each interface
        for iface_dir in "${sysdev}"*/; do
            [[ -d "$iface_dir" ]] || continue
            iface=$(basename "$iface_dir")
            [[ "$iface" =~ ^${devpath}:[0-9]+ ]] || continue

            # Read driver symlink
            if [[ -L "${iface_dir}driver" ]]; then
                drv=$(readlink "${iface_dir}driver" | xargs basename)
                echo -e "  Interface ${iface##*:}  →  driver: ${GRN}${drv}${RST}"
            else
                echo -e "  Interface ${iface##*:}  →  driver: ${YLW}(none — unbound)${RST}"
            fi
        done
    done
done

# ─── 5. Active kernel modules for USB networking ─────────────────────────────
hdr "5. USB networking kernel modules"

NET_MODS=(cdc_ether cdc_ncm rndis_host cdc_eem cdc_subset usbnet snd_usb_audio)
for mod in "${NET_MODS[@]}"; do
    if lsmod | grep -q "^${mod}"; then
        ok "$mod  is loaded"
    else
        warn "$mod  NOT loaded"
    fi
done

# ─── 6. Existing USB network interfaces ──────────────────────────────────────
hdr "6. USB network interfaces visible to the OS"

USB_NETS=$(ip link show | grep -E 'usb[0-9]|enp.*u[0-9]|eth.*usb' || true)
if [[ -n "$USB_NETS" ]]; then
    found "USB network interfaces detected:"
    echo "$USB_NETS"
else
    miss "No USB-backed network interfaces detected (usb0, enp*u*, etc.)"
fi

# ─── Summary ─────────────────────────────────────────────────────────────────
hdr "Summary"
echo ""
echo "Next steps depend on the interface classes found above:"
echo ""
echo "  CDC-ECM / CDC-NCM found  →  Strategy 2a: bind cdc_ether / cdc_ncm to that interface"
echo "  RNDIS found              →  Strategy 2b: bind rndis_host to that interface"
echo "  Only class FF found      →  Strategy 4: USB traffic capture required"
echo "  Unbound interface(s)     →  Try: sudo modprobe cdc_ether  (or rndis_host)"
echo ""
echo "Share this output and we'll determine the exact next step."
echo ""
