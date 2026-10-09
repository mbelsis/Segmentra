FROM ubuntu:24.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    firewalld ufw nftables iptables python3 dbus kmod procps iproute2 openssh-server sudo \
    && rm -rf /var/lib/apt/lists/*
COPY entrypoint.sh /entrypoint.sh
COPY systemctl-test.sh /usr/local/bin/systemctl
RUN chmod 755 /entrypoint.sh /usr/local/bin/systemctl
RUN useradd -m -s /bin/sh segmentra && passwd -d segmentra \
    && printf 'segmentra ALL=(ALL) NOPASSWD:ALL\n' > /etc/sudoers.d/segmentra \
    && chmod 440 /etc/sudoers.d/segmentra \
    && printf 'PasswordAuthentication no\nPermitRootLogin no\n' > /etc/ssh/sshd_config.d/segmentra-test.conf
ENTRYPOINT ["/entrypoint.sh"]
