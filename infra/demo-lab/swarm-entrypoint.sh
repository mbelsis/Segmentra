#!/bin/sh
set -eu

# Management account: what Segmentra logs in with. Key only; the key comes from scripts/demo-lab.py.
id segmentra >/dev/null 2>&1 || adduser -D -s /bin/sh segmentra
usermod -p '*' segmentra
mkdir -p /etc/sudoers.d /home/segmentra/.ssh
echo "${DEMO_MGMT_PUBLIC_KEY}" > /home/segmentra/.ssh/authorized_keys
chmod 700 /home/segmentra/.ssh
chmod 600 /home/segmentra/.ssh/authorized_keys
chown -R segmentra:segmentra /home/segmentra/.ssh
echo "segmentra ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/segmentra
chmod 440 /etc/sudoers.d/segmentra

# sshd also listens on SSH_PORT. When the API runs outside Docker, that port is published with the same
# number, so the port Segmentra connects to is the one its management rule allows.
# Only once: a restarted container keeps this file.
grep -q '^# segmentra lab' /etc/ssh/sshd_config || cat >> /etc/ssh/sshd_config <<SSHD
# segmentra lab
Port 22
Port ${SSH_PORT:-22}
PubkeyAuthentication yes
PasswordAuthentication no
# The SSH executor opens many short connections in a row, often to all nodes at once.
MaxStartups 100:30:200
PermitRootLogin no
UsePAM no
SSHD
/usr/sbin/sshd

# Firewall log lines reach rsyslog through kmsg-forward.py, not rsyslog's own kernel input (see that file).
sed -i '/imklog/s/^/#/' /etc/rsyslog.conf
rm -f /var/run/rsyslogd.pid /run/rsyslogd.pid
rsyslogd
python3 /kmsg-forward.py &

# Hand over to the stock Docker-in-Docker entrypoint, which starts dockerd and its own firewall rules.
exec dockerd-entrypoint.sh "$@"
