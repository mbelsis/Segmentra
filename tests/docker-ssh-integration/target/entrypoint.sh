#!/bin/sh
set -eu

TARGET_USER="${TARGET_USER:-segmentra}"
TARGET_PASSWORD="${TARGET_PASSWORD:-segmentra123!}"
TARGET_HOME="/home/${TARGET_USER}"
SSH_KEY_PATH="/runtime-keys/id_ed25519.pub"

if ! id "${TARGET_USER}" >/dev/null 2>&1; then
  adduser -D -s /bin/sh "${TARGET_USER}"
fi

echo "${TARGET_USER}:${TARGET_PASSWORD}" | chpasswd

mkdir -p /etc/sudoers.d
echo "${TARGET_USER} ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/segmentra
chmod 440 /etc/sudoers.d/segmentra

mkdir -p /run/sshd
ssh-keygen -A

mkdir -p "${TARGET_HOME}/.ssh"
chmod 700 "${TARGET_HOME}/.ssh"
if [ -f "${SSH_KEY_PATH}" ]; then
  cp "${SSH_KEY_PATH}" "${TARGET_HOME}/.ssh/authorized_keys"
  chmod 600 "${TARGET_HOME}/.ssh/authorized_keys"
fi
chown -R "${TARGET_USER}:${TARGET_USER}" "${TARGET_HOME}/.ssh"

cat >> /etc/ssh/sshd_config <<EOF
PasswordAuthentication yes
PubkeyAuthentication yes
PermitRootLogin no
UsePAM no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
EOF

iptables -F
iptables -X
iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
iptables -P FORWARD ACCEPT

exec /usr/sbin/sshd -D -e
