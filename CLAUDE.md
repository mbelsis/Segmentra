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
- **packages/db** — PostgreSQL migrations (node-pg-migrate) and seed scripts
- **infra/** — Dockerfiles for API and Ansible runner containers

## Commands

```bash
# Full local dev setup (starts Postgres, runs migrations, builds, launches API + UI)
./start.sh dev          # macOS/Linux
start.bat dev           # Windows

# Individual commands
npm install             # Install all workspace dependencies
npm run build           # Build all workspaces
npm run dev             # Start API only (watches dist/index.js)
npm run lint            # Lint all workspaces
npm run format          # Format all workspaces
npm run db:migrate      # Run database migrations
npm run db:seed         # Seed initial RBAC roles

# Workspace-specific
npm run dev -w apps/api           # API dev server (port 8080)
cd apps/web && npm run dev        # Vite dev server (port 5173)
npm run build -w @segmentra/compiler
npm run build -w @segmentra/executor
```

No test framework is currently configured.

## Architecture

### Request Flow
UI → HTTP with Bearer JWT → `requireAuth` middleware → `requireRole` check → route handler → PostgreSQL → JSON response

### Deployment Flow
Policy version approved → deployment created → compiler generates per-host rules → executor (Ansible/SSH) deploys → status tracked in `deployment_hosts` → audit events logged → background jobs monitor timeouts

### Key Patterns

- **Auth middleware** (`apps/api/src/middleware/auth.ts`): `requireAuth` validates JWT, `requireRole(...roles)` checks RBAC. Extends Express Request with `auth?: AuthUser`.
- **Validation**: Zod schemas throughout — `safeParse()` → check `success` → 400 on failure.
- **Environment config**: `apps/api/src/lib/env.ts` validates env vars with Zod (PORT, DATABASE_URL, JWT_SECRET, SEGMENTRA_KEK_B64, BUNDLES_DIR).
- **Database access**: Direct `node-pg` pool queries (`apps/api/src/db/pool.ts`), no ORM.
- **Secret encryption**: AES-256-GCM with optional KEK for SSH keys and LDAP passwords in `secret_store` table.
- **API client** (`apps/web/src/lib/api.ts`): Typed fetch wrapper with JWT injection and error handling.
- **Background jobs**: Three interval tasks in `apps/api/src/index.ts` — stale deployment timeouts (2min), scheduled deployments (1min), expired audit sessions (1min).

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
Four roles: `viewer`, `operator`, `approver`, `admin`. Policy versions follow a lifecycle: DRAFT → SUBMITTED → APPROVED/REJECTED → DEPLOYED.

## Local Environment

- API: http://localhost:8080
- Web UI: http://localhost:5173
- PostgreSQL: localhost:15432
- Default credentials: admin/admin123 (auto-created by start script)
