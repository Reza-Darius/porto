#! /bin/bash

# install script for the porto proxy service

# check if porto is already installed
if command -v porto >/dev/null 2>&1; then
  # TODO: deal with upgrades
  echo "porto is already installed"
  exit 1
fi

if [[ -z "${SUDO_USER}" ]]; then
  echo "Please run this script using sudo, not as root directly."
  exit 1
fi

INSTALL_USER=${SUDO_USER}
BIN_NAME="porto"
INSTALL_PATH="/usr/local/bin/${BIN_NAME}"
SERVICE_PATH="/etc/systemd/system/${BIN_NAME}.service"

echo "downloading binaries"

# download the binary from the repo and make sure the hash matches before installing
BINARY_URL="https://github.com/Reza-Darius/porto/releases/download/test-release/${BIN_NAME}"
CHECKSUM_URL="${BINARY_URL}.sha256"

if ! curl -fsSL "$BINARY_URL" -o /tmp/porto; then
  echo "binary download failed"
  exit 1
fi

if ! curl -fsSL "$CHECKSUM_URL" -o /tmp/porto.sha256; then
  echo "checksum download failed"
  exit 1
fi

if ! cd /tmp && sha256sum -c porto.sha256; then
  echo "warning: checksum verification failed"
  exit 1
fi

echo "binary passed"
echo "installing..."

install -o root -g root -m 755 /tmp/porto "${INSTALL_PATH}"

# create the group if it doesn't exist
if ! getent group porto >/dev/null 2>&1; then
  echo "creating user group"
  groupadd --system porto
fi

# create the user if it doesn't exist, assigning to the existing group
if ! getent passwd porto >/dev/null 2>&1; then
  echo "creating user"
  useradd \
    --system \
    --no-create-home \
    --shell /usr/sbin/nologin \
    --gid porto \
    --comment "Porto proxy daemon" \
    porto
fi

# add the install user to the group if not already a member
if ! id -nG "${INSTALL_USER}" | grep -qw "porto"; then
  usermod -aG porto "${INSTALL_USER}"
fi

# generate/install service file
install -o root -g root -m 644 /tmp/porto.service "${SERVICE_PATH}"
systemctl daemon-reload

# finish up
su - "{$INSTALL_USER}"
