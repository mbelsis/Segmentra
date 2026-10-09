# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Segmentra is an on-premise web-based fleet firewall and microsegmentation management tool for Linux servers. It lets teams define intent-based access policies (allow/deny) and deploy them at scale to nftables/iptables with versioning, approvals, deployment bundles, and audit trails.

## Monorepo Structure

This is a TypeScript monorepo using npm workspaces:

- **apps/api** — Express.js backend (PostgreSQL, JWT auth, RBAC)
- **apps/web** — React 19 UI (Vite, React Router 7)
- **packages/shared** — Shared TypeScript types (e.g., `RoleName`)
- **packages/compiler** — Transforms policy rules into nftables/iptables configs per host
- **packages/executor** — Deployment runners (Ansible via Docker, SSH Direct), host readiness checks, firewall audit
- **packages/db** — PostgreSQL migrations (node-pg-migrate, plain `.sql` files only) and seed scripts
- **infra/** — Dockerfiles for the API (multi-stage, non-root, runs migrations on start), web (nginx) and Ansible runner containers

## Commands

```bash
# Full local dev setup (starts Postgres, runs migrations, builds, launches API + UI)
./start.sh dev          # macOS/Linux
start.bat dev           # Windows

# Individual commands
npm install             # Install all workspace dependencies
npm run build           # Build all workspaces in dependency order (shared, compiler, executor, api, web)
npm run dev             # Start API only (runs/watches apps/api/dist/index.js — build first)
npm run lint            # Lint all workspaces (only apps/web has a real ESLint config)
npm run db:migrate      # Run database migrations (packages/db/scripts/migrate.js -> node-pg-migrate)
npm run db:seed         # Seed RBAC roles, system tags and the initial admin user
npm run test:integration:ssh-docker   # Docker-based SSH deployment integration test

# Workspace-specific
npm run dev -w apps/api           # API dev server (port 8080)
cd apps/web && npm run dev        # Vite dev server (port 5173)
npm run build -w @segmentra/compiler   # also builds @segmentra/shared
npm run build -w @segmentra/executor
npm run build -w apps/api              # also builds shared, compiler and executor
```

There is no unit test framework. The automated test is `npm run test:integration:ssh-docker` (see `tests/README.md`): it builds the API image, starts PostgreSQL plus three Alpine SSH targets, deploys real policies via the SSH executor and verifies `iptables` rules and live traffic. Add `-- --keep` to leave the stack running.

### Migrations

Migrations live in `packages/db/migrations` as plain `NNN_description.sql` files (no `.js` wrappers — node-pg-migrate would run both). A file without `-- Up Migration` / `-- Down Migration` markers runs entirely as the up migration; if you add a `-- Down Migration` section you must also add `-- Up Migration` at the top. Write migrations idempotently (`IF NOT EXISTS`, guarded `DO` blocks). `scripts/migrate.js` first removes duplicate `pgmigrations` rows left by the old `.js` wrappers, then runs `node-pg-migrate up`.

## Architecture

### Request Flow
UI → HTTP with Bearer JWT → `requireAuth` middleware → `requireRole` check → route handler → PostgreSQL → JSON response

### Deployment Flow
Policy version approved → deployment created → compiler generates per-host rules → executor (Ansible/SSH) deploys → status tracked in `deployment_hosts` → audit events logged → background jobs monitor timeouts

### Key Patterns

- **Auth middleware** (`apps/api/src/middleware/auth.ts`): `requireAuth` validates JWT, `requireRole(...roles)` checks RBAC. Extends Express Request with `auth?: AuthUser`.
- **Validation**: Zod schemas throughout — `safeParse()` → check `success` → 400 on failure.
- **Environment config**: `apps/api/src/lib/env.ts` validates env vars with Zod: `PORT`, `DATABASE_URL`, `JWT_SECRET` (min 32 chars when `NODE_ENV=production`, known defaults refused), `SEGMENTRA_KEK_B64`, `BUNDLES_DIR`, `ANSIBLE_RUNNER_CONTAINER`, `SEGMENTRA_BOOTSTRAP_TOKEN`, `CORS_ORIGIN`, `NODE_ENV`, `TRUST_PROXY`. Read elsewhere: `SEGMENTRA_KNOWN_HOSTS` (SSH known_hosts path; host keys are verified with `StrictHostKeyChecking=accept-new`), `SEGMENTRA_ALLOW_PRIVATE_WEBHOOKS` (`true` allows notification webhooks to loopback/link-local/cloud-metadata addresses; RFC1918 is always allowed), `SEGMENTRA_SSH_COMMAND_TIMEOUT_MS` (per-SSH-command timeout, default 5 min), `SEGMENTRA_ASKPASS_DIR` (directory for the `SSH_ASKPASS` helper script used for key passphrases; default OS temp dir), `SEGMENTRA_SKIP_MIGRATIONS=1` (API container entrypoint skips migrations + seed), and `SEGMENTRA_ADMIN_PASSWORD` (seed script: initial admin password; required to create the admin when `NODE_ENV=production`).
- **Database access**: Direct `node-pg` pool queries (`apps/api/src/db/pool.ts`), no ORM.
- **Secret encryption**: AES-256-GCM for SSH keys/passwords, LDAP passwords and Kubernetes cluster credentials (kubeconfig/token and CA, types `K8S_CREDENTIALS` / `TLS_CA_CERT`) in the `secret_store` table. Key = `SEGMENTRA_KEK_B64` (32 bytes base64); if unset it is derived from `JWT_SECRET` (SHA-256), so rotating `JWT_SECRET` then breaks stored secrets. Set the KEK before storing secrets.
- **API client** (`apps/web/src/lib/api.ts`): Typed fetch wrapper with JWT injection and error handling.
- **Background jobs**: Seven interval tasks started in `apps/api/src/index.ts`: stale host deployment timeouts (2 min), scheduled deployments (1 min), expired firewall-audit sessions (1 min), tag rule evaluation (5 min), deployment expiry (1 min, `services/deployment-expiry.ts`; claims expired deployments atomically and runs the expiry action — `NOTIFY_ONLY` marks them `EXPIRED` and notifies, `REMOVE` removes Segmentra's nft table / iptables chains from the hosts, `REVERT` redeploys the previous successfully deployed version; also sends 24h "expiring soon" warnings), inventory discovery (1 min; atomically claims due enabled discovery profiles and runs them in the background — `services/discovery.ts`; runs left `RUNNING` by a previous process are marked `FAILED` once at startup), and policy test session expiry (1 min; restores original rules and collects logs, retrying on failure).
- **SSH credentials** (`services/ssh-credentials.ts`): each credential has a scope (`GLOBAL`, `TAG`, `VLAN`, `HOST`, or `NONE` = never chosen automatically) and a `priority`; a host can also be explicitly assigned one (`hosts.ssh_credential_id`, admin only). Resolution: assigned → `HOST` → `TAG` → `VLAN` → `GLOBAL`, within a level highest priority then newest. Credentials authenticate with a key (optionally passphrase-protected, fed via `SSH_ASKPASS`) or a password (`sshpass -e`), and escalate with sudo (`sudo_mode`: `NOPASSWD`, `LOGIN_PASSWORD`, `SUDO_PASSWORD`); every root step runs as `sudo sh -c`, so full sudo rights are required.

### Kubernetes

`apps/api/src/routes/kubernetes.ts` generates NetworkPolicy manifests from approved policy versions (`ipBlock` peers; TAG sources also yield `namespaceSelector` + `podSelector` peers for workloads mapped to the tag) and, with stored cluster credentials, applies/checks/removes them through `apps/api/src/services/k8s-client.ts` (a small HTTPS client; server-side apply; only touches policies labelled `app.kubernetes.io/managed-by: segmentra`). Cilium ignores `ipBlock` for in-cluster pod traffic, so clusters record their CNI and generation warns. `npm run test:integration:k8s -- <kindnet|calico|cilium>` tests all of it on a kind cluster (needs Docker, kind, kubectl, and cilium-cli for Cilium) against a running API.

### Compiler

`packages/compiler/src/compile.ts` takes host config + policy rules and outputs nftables or iptables rulesets with a SHA256 hash. nftables output replaces only `table inet segmentra`; iptables output only manages Segmentra's `SEGMENTRA-IN` / `SEGMENTRA-OUT` (and `SEGMENTRA-FWD` for FORWARD rules on gateways) chains, jumped to from `INPUT` / `OUTPUT` / `FORWARD`. "Allow" in those chains is `RETURN`, so the rest of the built-in chain and its policy still apply; other tools' rules (Docker, fail2ban) are left alone. Supports `logOnlyMode` for firewall learning (traffic discovery without blocking) and FORWARD rules with an explicit destination (IoT/OT gateways, protected devices).

### Executor

`packages/executor/src/` provides:
- `run-ansible.ts` — Ansible CLI via Docker container
- `run-ssh.ts` — Direct SSH rule application
- `read-rules.ts` — Read current host rules via SSH
- `check-host-readiness.ts` — Verify host capabilities before deployment
- `audit-ssh.ts` — Firewall learning: deploy log-only rules, collect/parse traffic logs, restore
- `firewall-backup.ts`, `nft-scripts.ts`, `iptables-scripts.ts` — backup/restore and apply scripts scoped to Segmentra's table/chains
- `remove-policy.ts` — remove Segmentra's rules from a host (policy expiry `REMOVE`)
- `discover-host.ts` — read-only host facts for inventory discovery
- `ssh-options.ts` — shared SSH options, known_hosts handling, askpass, sudo wrapping and sudo error classification

### RBAC Roles
Four roles: `viewer`, `operator`, `approver`, `admin`. Policy versions follow a lifecycle: `DRAFT` → `PENDING_APPROVAL` → `APPROVED` / `REJECTED` → `DEPLOYED`; `APPROVED`, `DEPLOYED` and `PENDING_APPROVAL` versions can be moved to `ARCHIVED`.

## Local Environment

- API: http://localhost:8080
- Web UI: http://localhost:5173
- PostgreSQL: localhost:15432
- Default credentials: admin/admin123 (created by `npm run db:seed` in development when `SEGMENTRA_ADMIN_PASSWORD` is unset; in production the seed refuses to create the default password)
- Dev JWT secret: generated once into the untracked `.dev-jwt-secret` by `start.sh` / `run.sh` when `JWT_SECRET` is not set

## Docker Deployment

`docker compose up -d` runs `segmentra-db` (127.0.0.1:15432, healthchecked), `segmentra-ansible-runner` (`container_name: segmentra-ansible-runner`), `segmentra-app` (the API on 127.0.0.1:8080; non-root, `NODE_ENV=production`, entrypoint runs migrations + seed, refuses to start without `JWT_SECRET` / `SEGMENTRA_KEK_B64`) and `segmentra-web` (nginx, port 80). `./install.sh --production` generates these secrets into `.env`. The API container mounts `/var/run/docker.sock` only for the Ansible executor (`docker exec`) — that is root-equivalent on the Docker host; SSH-executor-only installs can remove the mount, or use the hardened override `docker compose -f docker-compose.yml -f docker-compose.hardened.yml up -d --build` (no Docker socket, Ansible runner only with `--profile ansible`, read-only filesystems, dropped capabilities, only nginx published; see `docs/security.md`).
