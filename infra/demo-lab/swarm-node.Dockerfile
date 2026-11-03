# A Swarm node for the swarm lab of scripts/demo-lab.py: Docker-in-Docker (its own daemon, network
# namespace and iptables) that also runs sshd, so Segmentra manages its firewall like a real server.
# For a test environment only: never expose these containers.
FROM docker:27-dind

LABEL segmentra.demo-lab="1"

RUN apk upgrade --no-cache openssh-client-common openssh-client-default openssh-keygen \
 && apk add --no-cache bash curl iproute2 iptables iputils openssh-server python3 rsyslog shadow sudo \
 && mkdir -p /run/sshd \
 && ssh-keygen -A

COPY swarm-entrypoint.sh kmsg-forward.py /
RUN chmod +x /swarm-entrypoint.sh

ENTRYPOINT ["/swarm-entrypoint.sh"]
CMD []
