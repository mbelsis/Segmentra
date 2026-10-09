#!/bin/sh
set -eu
mkdir -p /run/dbus /var/backups/segmentra
mkdir -p /run/sshd /home/segmentra/.ssh
if [ -f /runtime-keys/id_ed25519.pub ]; then
  install -m 600 -o segmentra -g segmentra /runtime-keys/id_ed25519.pub /home/segmentra/.ssh/authorized_keys
  chown segmentra:segmentra /home/segmentra/.ssh
  chmod 700 /home/segmentra/.ssh
fi
ssh-keygen -A
/usr/sbin/sshd
if [ "$MANAGER" = firewalld ]; then
  rm -f /run/dbus/pid
  dbus-daemon --system --fork
  firewalld --nofork --nopid &
  daemon=$!
  trap 'kill "$daemon"; exit 0' TERM INT
  while ! firewall-cmd --state >/dev/null 2>&1; do sleep 1; done
else
  # This is UFW's own boot loader; no Segmentra code runs on restart.
  ufw allow 22/tcp
  ufw --force enable
  trap 'exit 0' TERM INT
fi
touch /run/manager-ready
while :; do sleep 1 & wait $!; done
