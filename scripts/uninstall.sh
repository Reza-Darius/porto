#!/bin/bash

if [[ -z ${SUDO_USER} ]]; then
    echo "Please run as root: sudo $0"
    exit 1
fi

BIN_NAME="porto"
INSTALL_USER="${SUDO_USER}"

INSTALL_PATH="/usr/local/bin/${BIN_NAME}"
SERVICE_PATH="/etc/systemd/system/${BIN_NAME}.service"

CONFIG_FOLDER="/etc/porto"

# stop and disable the service
systemctl stop porto 2>/dev/null
systemctl disable porto 2>/dev/null

# remove service file
rm -f "$SERVICE_PATH"
systemctl daemon-reload

rm -f "${INSTALL_PATH}"
rm -rf "$CONFIG_FOLDER"

# remove user from group before deleting group
if id -nG "${INSTALL_USER}" | grep -qw "porto"; then
    gpasswd -d "${INSTALL_USER}" porto > /dev/null 2>&1
fi

# remove system user and group
getent passwd porto > /dev/null 2>&1 && userdel porto
getent group porto > /dev/null 2>&1 && groupdel porto

echo "Porto uninstalled successfully."
echo "You may need to log out and back in for group changes to take effect."
