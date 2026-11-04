#!/bin/sh
# Guest setup: the distribution's firewall packages, a sudo user with the test key, test listeners started at boot.
set -eu
SSH_PORT=$1
PUBKEY=$2
if grep -q '^ID=ubuntu' /etc/os-release; then
  # UFW first, as Ubuntu ships it. run.mjs moves this VM to nftables and iptables later.
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq --no-install-recommends ufw iptables nftables python3
  ufw allow 22/tcp
  ufw allow "$SSH_PORT/tcp"
  ufw --force enable
  systemctl enable ufw
  SSHD=ssh
elif [ -f /etc/debian_version ]; then
  export DEBIAN_FRONTEND=noninteractive
  echo 'iptables-persistent iptables-persistent/autosave_v4 boolean false' | debconf-set-selections
  echo 'iptables-persistent iptables-persistent/autosave_v6 boolean false' | debconf-set-selections
  apt-get update -qq
  apt-get install -y -qq --no-install-recommends iptables nftables iptables-persistent python3
  SSHD=ssh
else
  dnf install -y -q firewalld iptables-services nftables python3 policycoreutils-python-utils
  # SELinux stays as the distribution set it: sshd may only use the extra port with this.
  semanage port -a -t ssh_port_t -p tcp "$SSH_PORT" 2>/dev/null || semanage port -m -t ssh_port_t -p tcp "$SSH_PORT"
  systemctl enable --now firewalld
  firewall-cmd --permanent --add-port="$SSH_PORT/tcp"
  firewall-cmd --reload
  SSHD=sshd
fi
id segmentra >/dev/null 2>&1 || useradd -m -s /bin/sh segmentra
usermod -p '*' segmentra
printf 'segmentra ALL=(ALL) NOPASSWD:ALL\n' > /etc/sudoers.d/segmentra
chmod 440 /etc/sudoers.d/segmentra
install -d -m 700 -o segmentra -g segmentra /home/segmentra/.ssh
printf '%s\n' "$PUBKEY" > /home/segmentra/.ssh/authorized_keys
chown segmentra:segmentra /home/segmentra/.ssh/authorized_keys
chmod 600 /home/segmentra/.ssh/authorized_keys
command -v restorecon >/dev/null 2>&1 && restorecon -R /home/segmentra/.ssh
mkdir -p /etc/ssh/sshd_config.d
printf 'Port 22\nPort %s\n' "$SSH_PORT" > /etc/ssh/sshd_config.d/10-segmentra-test.conf
# Ubuntu 24.04 starts sshd from ssh.socket, whose ports are generated from the sshd configuration.
systemctl daemon-reload
if systemctl is-enabled --quiet ssh.socket 2>/dev/null; then systemctl restart ssh.socket; fi
systemctl restart "$SSHD"
cat > /usr/local/bin/seg-listen.py <<'PY'
#!/usr/bin/env python3
import socket, threading
def serve(port):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(('0.0.0.0', port)); s.listen(16)
    while True:
        c, _ = s.accept(); c.close()
for p in (8081, 8082, 8083):
    threading.Thread(target=serve, args=(p,), daemon=True).start()
threading.Event().wait()
PY
cat > /etc/systemd/system/seg-listen.service <<'UNIT'
[Unit]
Description=Test TCP listeners
After=network.target
[Service]
ExecStart=/usr/bin/python3 /usr/local/bin/seg-listen.py
Restart=always
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now seg-listen
