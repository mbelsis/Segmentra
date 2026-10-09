#!/usr/bin/env bash
# Docker Swarm lab on Docker Desktop: 3 privileged Docker-in-Docker nodes (1 manager, 2 workers) that
# also run sshd, an overlay network, a published nginx service, and two outside client containers.
#
#   tests/swarm-lab/lab.sh up        build the image, create the lab, form the swarm, deploy the service
#   tests/swarm-lab/lab.sh down      remove everything
#   tests/swarm-lab/lab.sh status
#
# Nodes: 172.28.77.11-13 (SSH published on 127.0.0.1:2231-2233, user segmentra), clients 172.28.77.50/51.
set -euo pipefail
cd "$(dirname "$0")"

NET=segswarm-lab
SUBNET=172.28.77.0/24
IMAGE=segmentra-swarm-node:lab

node_ip()   { echo "172.28.77.1$1"; }
node_port() { echo "223$1"; }

up() {
  docker build -q -t "$IMAGE" . >/dev/null
  docker network inspect "$NET" >/dev/null 2>&1 || docker network create --subnet "$SUBNET" "$NET" >/dev/null
  for i in 1 2 3; do
    docker rm -f "segswarm-node$i" >/dev/null 2>&1 || true
    docker run -d --privileged --name "segswarm-node$i" --hostname "node$i" --network "$NET" --ip "$(node_ip $i)" \
      -p "127.0.0.1:$(node_port $i):$(node_port $i)" -e "SSH_PORT=$(node_port $i)" -e DOCKER_TLS_CERTDIR= "$IMAGE" >/dev/null
  done
  echo "waiting for the Docker daemons..."
  for _ in $(seq 1 60); do
    ok=0; for i in 1 2 3; do docker exec "segswarm-node$i" docker info >/dev/null 2>&1 && ok=$((ok+1)); done
    [ "$ok" = 3 ] && break; sleep 2
  done
  [ "$ok" = 3 ] || { echo "Docker daemons did not start" >&2; exit 1; }

  docker exec segswarm-node1 docker swarm init --advertise-addr "$(node_ip 1)" >/dev/null
  token=$(docker exec segswarm-node1 docker swarm join-token -q worker)
  for i in 2 3; do docker exec "segswarm-node$i" docker swarm join --token "$token" "$(node_ip 1):2377" >/dev/null; done
  docker exec segswarm-node1 docker network create -d overlay --attachable lab-overlay >/dev/null
  docker exec segswarm-node1 docker service create --name web --replicas 3 --network lab-overlay \
    --publish published=8080,target=80 nginx:alpine >/dev/null

  for c in 50 51; do
    docker rm -f "segswarm-client$c" >/dev/null 2>&1 || true
    docker run -d --name "segswarm-client$c" --network "$NET" --ip "172.28.77.$c" alpine:3.20 sleep 86400 >/dev/null
    docker exec "segswarm-client$c" apk add --no-cache curl >/dev/null
  done
  status
}

down() {
  for c in segswarm-client50 segswarm-client51 segswarm-node1 segswarm-node2 segswarm-node3; do docker rm -f -v "$c" >/dev/null 2>&1 || true; done
  docker network rm "$NET" >/dev/null 2>&1 || true
  echo "swarm lab removed"
}

status() {
  docker exec segswarm-node1 docker node ls --format '{{.Hostname}} {{.Status}} {{.ManagerStatus}}'
  docker exec segswarm-node1 docker service ls --format '{{.Name}} {{.Replicas}} {{.Ports}}'
}

case "${1:-}" in up) up ;; down) down ;; status) status ;; *) echo "usage: $0 up|down|status" >&2; exit 2 ;; esac
