# syntax=docker/dockerfile:1
#
# Segmentra API image (multi-stage).
#   build   - full install + TypeScript build of shared/compiler/executor/api
#   deps    - production-only node_modules for the API and DB (migrations/seed) workspaces
#   runtime - non-root image with ssh/scp/sshpass (SSH executor) and the docker CLI
#             (Ansible executor uses `docker exec` against the ansible-runner container)
#
# The entrypoint runs database migrations and the role/admin seed before starting the API.

ARG NODE_IMAGE=node:20-bookworm-slim

# ---------------------------------------------------------------- build
FROM ${NODE_IMAGE} AS build
WORKDIR /app

COPY package.json package-lock.json ./
COPY apps/api/package.json apps/api/
COPY apps/web/package.json apps/web/
COPY packages/shared/package.json packages/shared/
COPY packages/compiler/package.json packages/compiler/
COPY packages/executor/package.json packages/executor/
COPY packages/db/package.json packages/db/
RUN npm ci --no-audit --no-fund

COPY packages/shared packages/shared
COPY packages/compiler packages/compiler
COPY packages/executor packages/executor
COPY apps/api apps/api
RUN npm run build -w @segmentra/api

# ---------------------------------------------------------------- deps (production only)
FROM ${NODE_IMAGE} AS deps
WORKDIR /app
# Toolchain only in case a native module (bcrypt) has no prebuilt binary for this platform.
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 make g++ \
 && rm -rf /var/lib/apt/lists/*

COPY package.json package-lock.json ./
COPY apps/api/package.json apps/api/
COPY apps/web/package.json apps/web/
COPY packages/shared/package.json packages/shared/
COPY packages/compiler/package.json packages/compiler/
COPY packages/executor/package.json packages/executor/
COPY packages/db/package.json packages/db/
RUN npm ci --omit=dev --no-audit --no-fund \
      --workspace @segmentra/api \
      --workspace @segmentra/db \
      --workspace @segmentra/shared \
      --workspace @segmentra/compiler \
      --workspace @segmentra/executor

# ---------------------------------------------------------------- runtime
FROM ${NODE_IMAGE} AS runtime

# openssh-client: ssh/scp for the SSH executor, readiness checks and firewall audit
# sshpass:        password-based SSH credentials
# docker CLI:     Ansible executor (`docker exec <ANSIBLE_RUNNER_CONTAINER> ansible-playbook ...`)
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-client sshpass ca-certificates tini \
 && rm -rf /var/lib/apt/lists/*
COPY --from=docker:27-cli /usr/local/bin/docker /usr/local/bin/docker

ENV NODE_ENV=production \
    PORT=8080 \
    BUNDLES_DIR=/bundles \
    SEGMENTRA_KNOWN_HOSTS=/home/node/.ssh/known_hosts

WORKDIR /app

COPY --from=deps /app /app
COPY --from=build /app/packages/shared/dist packages/shared/dist
COPY --from=build /app/packages/compiler/dist packages/compiler/dist
COPY --from=build /app/packages/executor/dist packages/executor/dist
COPY --from=build /app/apps/api/dist apps/api/dist
COPY packages/db/migrations packages/db/migrations
COPY packages/db/scripts packages/db/scripts
COPY demo-data demo-data
COPY infra/app/docker-entrypoint.sh /usr/local/bin/segmentra-entrypoint

# Run as the unprivileged "node" user (uid/gid 1000). The bundles mount point and the
# SSH known_hosts directory are pre-created with the right owner so fresh named volumes
# inherit it. For the Ansible executor the user also needs access to the mounted
# /var/run/docker.sock: docker-compose.yml adds the socket's group via `group_add`
# (DOCKER_GID). See docs/installation.md for the security implications.
RUN chmod 0755 /usr/local/bin/segmentra-entrypoint \
 && mkdir -p /bundles /home/node/.ssh \
 && chown -R node:node /bundles /home/node/.ssh \
 && chmod 0700 /home/node/.ssh

USER node

EXPOSE 8080

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/segmentra-entrypoint"]
CMD ["node", "apps/api/dist/index.js"]
