# A Docker Swarm node for the lab: a privileged Docker-in-Docker container (its own Docker
# daemon, network namespace and iptables) that also runs sshd, so Segmentra manages its firewall
# over SSH like a real server.
FROM docker:27-dind

RUN apk upgrade --no-cache openssh-client-common openssh-client-default openssh-keygen \
 && apk add --no-cache bash curl iproute2 iptables iputils netcat-openbsd openssh-server shadow sudo

# Host keys are baked into the image so they stay the same across `lab.sh up` runs (Segmentra verifies
# SSH host keys and refuses a changed key). Rebuilding the image changes them.
RUN ssh-keygen -A

COPY entrypoint.sh /usr/local/bin/swarm-node-entrypoint.sh
RUN chmod +x /usr/local/bin/swarm-node-entrypoint.sh

EXPOSE 22
ENTRYPOINT ["/usr/local/bin/swarm-node-entrypoint.sh"]
CMD []
