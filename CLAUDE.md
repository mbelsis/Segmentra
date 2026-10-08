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
- **Environment config**: `apps/api/src/lib/env.ts` validates env vars with Zod: `PORT`, `DATABASE_URL`, `JWT_SECRET` (min 32 chars when `NODE_ENV=production`, known defaults refused), `SEGMENTRA_KEK_B64`, `BUNDLES_DIR`, `ANSIBLE_RUNNER_CONTAINER`, `SEGMENTRA_BOOTSTRAP_TOKEN`, `CORS_ORIGIN`, `NODE_ENV`, `TRUST_PROXY`. Read elsewhere: `SEGMENTRA_KNOWN_HOSTS` (SSH known_hosts path; host keys are verified with `StrictHostKeyChecking=accept-new`), `SEGMENTRA_ALLOW_PRIVATE_WEBHOOKS` (`true` allows notification webhooks to loopback/link-local/cloud-metadata addresses; RFC1918 is always allowed), `SEGMENTRA_SSH_COMMAND_TIMEOUT_MS`, and `SEGMENTRA_ADMIN_PASSWORD` (seed script: initial admin password; required to create the admin when `NODE_ENV=production`).
- **Database access**: Direct `node-pg` pool queries (`apps/api/src/db/pool.ts`), no ORM.
- **Secret encryption**: AES-256-GCM for SSH keys/passwords and LDAP passwords in the `secret_store` table. Key = `SEGMENTRA_KEK_B64` (32 bytes base64); if unset it is derived from `JWT_SECRET` (SHA-256), so rotating `JWT_SECRET` then breaks stored secrets. Set the KEK before storing secrets.
- **API client** (`apps/web/src/lib/api.ts`): Typed fetch wrapper with JWT injection and error handling.
- **Background jobs**: Six interval tasks started in `apps/api/src/index.ts`: stale host deployment timeouts (2 min), scheduled deployments (1 min), expired firewall-audit sessions (1 min), tag rule evaluation (5 min), deployment expiry (1 min; marks deployments `EXPIRED` and sends a notification — `REMOVE`/`REVERT` expiry actions only notify that a manual rollback/redeploy is required, nothing is changed on hosts), and policy test session expiry (1 min; restores original rules and collects logs, retrying on failure).

### Compiler

`packages/compiler/src/compile.ts` takes host config + policy rules and outputs nftables or iptables rulesets with SHA256 hash. Supports `logOnlyMode` for firewall learning (traffic discovery without blocking).

### Executor

`packages/executor/src/` provides:
- `run-ansible.ts` — Ansible CLI via Docker container
- `run-ssh.ts` — Direct SSH rule application
- `read-rules.ts` — Read current host rules via SSH
- `check-host-readiness.ts` — Verify host capabilities before deployment
- `audit-ssh.ts` — Firewall learning: deploy log-only rules, collect/parse traffic logs, restore

### RBAC Roles
Four roles: `viewer`, `operator`, `approver`, `admin`. Policy versions follow a lifecycle: `DRAFT` → `PENDING_APPROVAL` → `APPROVED` / `REJECTED` → `DEPLOYED`; `APPROVED`, `DEPLOYED` and `PENDING_APPROVAL` versions can be moved to `ARCHIVED`.

## Local Environment

- API: http://localhost:8080
- Web UI: http://localhost:5173
- PostgreSQL: localhost:15432
- Default credentials: admin/admin123 (created by `npm run db:seed` in development when `SEGMENTRA_ADMIN_PASSWORD` is unset; in production the seed refuses to create the default password)
- Dev JWT secret: generated once into the untracked `.dev-jwt-secret` by `start.sh` / `run.sh` when `JWT_SECRET` is not set

## Docker Deployment

`docker compose up -d` runs db (127.0.0.1:15432, healthchecked), ansible-runner (`container_name: segmentra-ansible-runner`), the API (non-root, `NODE_ENV=production`, entrypoint runs migrations + seed, refuses to start without `JWT_SECRET` / `SEGMENTRA_KEK_B64`) and nginx web. `./install.sh --production` generates these secrets into `.env`. The API container mounts `/var/run/docker.sock` only for the Ansible executor (`docker exec`) — that is root-equivalent on the Docker host; SSH-executor-only installs can remove the mount.
