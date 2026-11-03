#!/bin/sh
set -eu

# Management account: what Segmentra logs in with. Key only; the key comes from scripts/demo-lab.py.
id segmentra >/dev/null 2>&1 || useradd -m -s /bin/bash segmentra
usermod -p '*' segmentra
mkdir -p /home/segmentra/.ssh
echo "${DEMO_MGMT_PUBLIC_KEY}" > /home/segmentra/.ssh/authorized_keys
chmod 700 /home/segmentra/.ssh
chmod 600 /home/segmentra/.ssh/authorized_keys
chown -R segmentra:segmentra /home/segmentra/.ssh
echo "segmentra ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/segmentra
chmod 440 /etc/sudoers.d/segmentra

# Account for the sample ssh and telnet traffic. No sudo, reachable only inside the lab network.
id demo >/dev/null 2>&1 || useradd -m -s /bin/bash demo
echo "demo:demo" | chpasswd

# Port 22 is Segmentra's management port, which a policy never blocks when no management network is
# configured. The sample ssh traffic uses port 2222, so the policy decides who gets in.
cat >> /etc/ssh/sshd_config <<SSHD
Port 22
Port 2222
PasswordAuthentication yes
PermitRootLogin no
UsePAM no
KbdInteractiveAuthentication no
SSHD

iptables -F
iptables -X
iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
iptables -P FORWARD ACCEPT

# Firewall log lines reach rsyslog through kmsg-forward.py, not rsyslog's own kernel input (see that file).
sed -i '/imklog/s/^/#/' /etc/rsyslog.conf
rm -f /run/rsyslogd.pid
rsyslogd
python3 /kmsg-forward.py &

# telnet
echo "telnet stream tcp nowait root /usr/sbin/telnetd telnetd" > /etc/inetd.conf
/usr/sbin/inetd /etc/inetd.conf

# web page for curl
echo "Hello from $(hostname)" > /srv/www/index.html
python3 -m http.server 80 --directory /srv/www >/dev/null 2>&1 &

exec /usr/sbin/sshd -D -e
