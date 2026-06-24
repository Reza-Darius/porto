#! /bin/bash

# install script for the porto proxy service

# check if porto is already installed
if command -v porto >/dev/null 2>&1; then
  # TODO: deal with upgrades
  echo "porto is already installed"
  exit 1
fi

if [[ -z "$SUDO_USER" ]]; then
  echo "Please run this script using sudo, not as root directly."
  exit 1
fi

INSTALL_USER=${SUDO_USER}
INSTALL_PATH="/usr/local/bin/porto"
SERVICE_PATH="/etc/systemd/system/porto.service"

# download the binary from the repo and make sure the hash matches before installing
BINARY_URL="https://github.com/you/porto/releases/latest/download/porto-x86_64-linux"
CHECKSUM_URL="${BINARY_URL}.sha256"

curl -fsSL "$BINARY_URL" -o /tmp/porto
curl -fsSL "$CHECKSUM_URL" -o /tmp/porto.sha256

if ! cd /tmp && sha256sum -c porto.sha256; then
  echo "warning: checksum verification failed"
  exit 1
fi

install -o root -g root -m 755 /tmp/porto ${INSTALL_PATH}

# create the group if it doesn't exist
getent group porto >/dev/null 2>&1 || groupadd --system porto

# create the user if it doesn't exist, assigning to the existing group
getent passwd porto >/dev/null 2>&1 || useradd \
  --system \
  --no-create-home \
  --shell /usr/sbin/nologin \
  --gid porto \
  --comment "Porto proxy daemon" \
  porto

# add the install user to the group if not already a member
if ! id -nG "${INSTALL_USER}" | grep -qw "porto"; then
  usermod -aG porto "${INSTALL_USER}"
fi

# generate/install service file
install -o root -g root -m 644 /tmp/porto.service ${SERVICE_PATH}
systemctl daemon-reload

# finish up
su - "$INSTALL_USER"
