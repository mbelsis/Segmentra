FROM python:3.12-slim

# openssh-client: Ansible's default "ssh" connection plugin shells out to ssh/scp/sftp.
# sshpass:        required by Ansible for password-based SSH (ansible_password).
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-client sshpass \
 && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir ansible-core==2.16.4

# Host key handling: keep host key checking ON, but trust-on-first-use (accept-new):
# unknown hosts are added to the known_hosts file on first connect, while a CHANGED
# key for a known host fails the connection. ServerAlive*: a host that stops answering mid-run
# (its multiplexed master connection would otherwise hang until the playbook timeout) is
# reported unreachable after ~60 s. known_hosts lives on a volume
# (see docker-compose.yml) so it survives container rebuilds.
ENV ANSIBLE_HOST_KEY_CHECKING=True \
    ANSIBLE_SSH_ARGS="-C -o ControlMaster=auto -o ControlPersist=60s -o ServerAliveInterval=15 -o ServerAliveCountMax=4 -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/runner/ssh/known_hosts" \
    ANSIBLE_RETRY_FILES_ENABLED=False

WORKDIR /runner
COPY playbooks /runner/playbooks

# /bundles is shared with the API container (which runs as uid 1000) and /runner/ssh holds
# known_hosts. Pre-create both so fresh named volumes get sensible ownership.
RUN mkdir -p /bundles /runner/ssh \
 && chown 1000:1000 /bundles \
 && chmod 0700 /runner/ssh

CMD ["sleep", "infinity"]
