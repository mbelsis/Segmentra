#!/bin/sh
set -eu

TARGET_USER="${TARGET_USER:-segmentra}"
TARGET_PASSWORD="${TARGET_PASSWORD:-segmentra123!}"
TARGET_HOME="/home/${TARGET_USER}"
SSH_KEY_PATH="/runtime-keys/id_ed25519.pub"

if ! id "${TARGET_USER}" >/dev/null 2>&1; then
  useradd -m -s /bin/bash "${TARGET_USER}"
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

cat >> /etc/ssh/sshd_config <<SSHD
PasswordAuthentication yes
PubkeyAuthentication yes
PermitRootLogin no
UsePAM no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
SSHD

iptables -F
iptables -X
iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
iptables -P FORWARD ACCEPT

# rsyslog with imklog (Debian's default rsyslog.conf loads it) reads the kernel log; that is
# where iptables -j LOG lines land. Kernel messages from a container's network namespace are
# only emitted when net.netfilter.nf_log_all_netns=1 on the Docker host (nflog-sysctl service).
rm -f /run/rsyslogd.pid
rsyslogd

exec /usr/sbin/sshd -D -e
