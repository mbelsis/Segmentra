# Debian target for the parts of the lab that Alpine cannot exercise:
#   - rsyslog + kernel log access: Firewall Learning and Policy Impact Analysis sessions collect
#     the FW-AUDIT kernel log lines through rsyslog (needs a privileged container, see compose)
#   - python3: the Ansible executor runs Python modules on the host
FROM debian:bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates iproute2 iptables iputils-ping netcat-openbsd openssh-server procps python3 rsyslog sudo \
 && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22

ENTRYPOINT ["/entrypoint.sh"]
