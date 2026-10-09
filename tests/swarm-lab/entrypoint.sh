#!/bin/sh
set -eu

TARGET_USER="${TARGET_USER:-segmentra}"
TARGET_PASSWORD="${TARGET_PASSWORD:-segmentra123!}"
TARGET_HOME="/home/${TARGET_USER}"
SSH_KEY_PATH="/runtime-keys/id_ed25519.pub"

id "${TARGET_USER}" >/dev/null 2>&1 || adduser -D -s /bin/sh "${TARGET_USER}"
echo "${TARGET_USER}:${TARGET_PASSWORD}" | chpasswd
mkdir -p /etc/sudoers.d
echo "${TARGET_USER} ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/segmentra
chmod 440 /etc/sudoers.d/segmentra

mkdir -p /run/sshd "${TARGET_HOME}/.ssh"
ssh-keygen -A >/dev/null
chmod 700 "${TARGET_HOME}/.ssh"
if [ -f "${SSH_KEY_PATH}" ]; then
  cp "${SSH_KEY_PATH}" "${TARGET_HOME}/.ssh/authorized_keys"
  chmod 600 "${TARGET_HOME}/.ssh/authorized_keys"
fi
chown -R "${TARGET_USER}:${TARGET_USER}" "${TARGET_HOME}/.ssh"

# sshd listens on 22 and on SSH_PORT. The lab publishes SSH_PORT on the host with the same number, so
# Segmentra (which allows its management SSH port in the baseline rule) sees the port it connects to.
SSH_PORT="${SSH_PORT:-22}"
cat >> /etc/ssh/sshd_config <<CFG
Port 22
Port ${SSH_PORT}
PasswordAuthentication yes
PubkeyAuthentication yes
PermitRootLogin no
UsePAM no
KbdInteractiveAuthentication no
CFG
/usr/sbin/sshd

# Hand over to the stock dind entrypoint (starts dockerd). Docker's own rules are created by it.
exec dockerd-entrypoint.sh "$@"
