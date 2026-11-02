# Demo machines for scripts/demo-lab.py: a small Debian server with the services and clients the
# sample traffic uses. For a test environment only: never expose these containers.
FROM debian:bookworm-slim

LABEL segmentra.demo-lab="1"

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl inetutils-telnetd iproute2 iptables iputils-ping openbsd-inetd \
      openssh-client openssh-server procps python3 rsyslog sshpass sudo telnet \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd /srv/www \
 && ssh-keygen -A

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
