#! /bin/bash

# install script for the porto proxy service
#
if [[ -z "${SUDO_USER}" ]]; then
  echo "Please run this script using sudo, not as root directly."
  exit 1
fi

INSTALL_USER=${SUDO_USER}
BIN_NAME="porto"

BINARY_URL="https://github.com/Reza-Darius/porto/releases/download/latest/${BIN_NAME}"
SCRIPTS_URL="https://raw.githubusercontent.com/Reza-Darius/porto/refs/heads/main/scripts"

SERVICE_URL="${SCRIPTS_URL}/porto.service"
HELP_CONFIG_URL="${SCRIPTS_URL}/help_porto.toml"

INSTALL_PATH="/usr/local/bin/${BIN_NAME}"
SERVICE_PATH="/etc/systemd/system/${BIN_NAME}.service"

CONFIG_FOLDER="/etc/porto"
TMP_FOLDER="/tmp/porto"

mkdir -p $TMP_FOLDER
mkdir -p $CONFIG_FOLDER

# check if porto is already installed
if ! command -v porto >/dev/null 2>&1; then
  echo "downloading binaries"

  if ! curl -fsSL "$BINARY_URL" -o "${TMP_FOLDER}/porto"; then
    echo "binary download failed"
    exit 1
  fi

  install -o root -g root -m 755 "${TMP_FOLDER}/porto" "${INSTALL_PATH}"
fi

echo "binary installed, checking group and settings"

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
  echo "adding $INSTALL_USER to porto group"
  usermod -aG porto "${INSTALL_USER}"
fi

echo "setting up systemd service"

# generate/install service file
if ! curl -fsSL "${SERVICE_URL}" -o "${TMP_FOLDER}/porto.service"; then
  echo "failed to download service file"
  exit 1
fi

install -o root -g root -m 644 "${TMP_FOLDER}/porto.service" "${SERVICE_PATH}"
systemctl daemon-reload

# generate config
if [[ ! -f "${CONFIG_FOLDER}/porto.toml" ]]; then
  curl -fsSL "${HELP_CONFIG_URL}"-o "{$CONFIG_FOLDER}/porto.toml"
fi

# finish up
# su - "${INSTALL_USER}"
rm -rf $TMP_FOLDER
echo "install successful!"
