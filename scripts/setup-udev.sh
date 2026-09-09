#!/usr/bin/env bash
# Sets up udev rules for MOTU USB devices and adds the current user to plugdev.

set -euo pipefail

UDEV_RULE_FILE="/etc/udev/rules.d/99-motu.rules"
UDEV_RULE='SUBSYSTEM=="usb", ATTRS{idVendor}=="07fd", ATTRS{idProduct}=="0005", MODE="0660", GROUP="plugdev"'
TARGET_USER="${SUDO_USER:-$USER}"

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run with sudo:" >&2
    echo "  sudo bash $0" >&2
    exit 1
fi

echo "Creating udev rule at ${UDEV_RULE_FILE}..."
echo "${UDEV_RULE}" > "${UDEV_RULE_FILE}"
echo "Done."

echo "Reloading udev rules..."
udevadm control --reload-rules
udevadm trigger
echo "Done."

echo "Adding user '${TARGET_USER}' to the 'plugdev' group..."
if ! getent group plugdev > /dev/null; then
    groupadd plugdev
    echo "Created group 'plugdev'."
fi
usermod -aG plugdev "${TARGET_USER}"
echo "Done."

echo ""
echo "Setup complete! Please log out and back in (or run 'newgrp plugdev')"
echo "for the group change to take effect, then reconnect the MOTU device."
