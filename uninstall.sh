#!/bin/bash

if [[ "$EUID" -ne 0 ]]; then
    echo "Please run as root: sudo $0"
    exit 1
fi

INSTALL_USER="${SUDO_USER}"

# stop and disable the service
systemctl stop porto 2>/dev/null
systemctl disable porto 2>/dev/null

# remove service file
rm -f /etc/systemd/system/porto.service
systemctl daemon-reload

# remove binary
rm -f /usr/local/bin/porto

# remove config
rm -rf /etc/porto

# remove user from group before deleting group
if id -nG "${INSTALL_USER}" | grep -qw "porto"; then
    gpasswd -d "${INSTALL_USER}" porto
fi

# remove system user and group
getent passwd porto > /dev/null 2>&1 && userdel porto
getent group porto > /dev/null 2>&1 && groupdel porto

echo "Porto uninstalled successfully."
echo "You may need to log out and back in for group changes to take effect."
