# Segmentra Architecture Documentation

This document provides detailed technical information about Segmentra's architecture, API endpoints, database schema, file structure, and troubleshooting.

---

## Table of Contents

1. [File Structure](#file-structure)
2. [API Endpoints](#api-endpoints)
3. [Database Schema](#database-schema)
4. [Deployment Executors](#deployment-executors)
5. [Advanced Features](#advanced-features)
   - [Firewall Learning (Traffic Discovery)](#firewall-learning-traffic-discovery)
   - [Drift Detection & Configuration Compliance](#drift-detection--configuration-compliance)
   - [Safety Guardrails](#safety-guardrails)
   - [High-Risk Policy Detection](#high-risk-policy-detection)
   - [Policy Impact Analysis](#policy-impact-analysis)
   - [Host Readiness Verification](#host-readiness-verification)
   - [SSH Credential Resolution](#ssh-credential-resolution)
   - [Inventory Discovery](#inventory-discovery)
   - [Scheduled Deployments](#scheduled-deployments)
   - [Host Policy Visualization](#host-policy-visualization)
   - [Auto-Tagging Rule Engine](#auto-tagging-rule-engine)
   - [Policy Templates](#policy-templates)
   - [Visual Topology Design](#visual-topology-design)
   - [Policy Auto-Recommendations](#policy-auto-recommendations)
   - [Integrations Framework](#integrations-framework)
   - [On-Device Policy Testing](#on-device-policy-testing)
   - [Kubernetes Microsegmentation](#kubernetes-microsegmentation)
   - [OT/IoT Microsegmentation](#otiot-microsegmentation)
   - [Policy Expiry](#policy-expiry)
   - [Notification System](#notification-system)
   - [Security Posture Audit](#security-posture-audit)
   - [Role-Based Access Control (RBAC)](#role-based-access-control-rbac)
6. [Firewall Backend Configuration](#firewall-backend-configuration)
   - [Generated Firewall Rules](#generated-firewall-rules)
   - [Async Deployment Execution](#async-deployment-execution)
   - [Login Security](#login-security)
7. [Troubleshooting](#troubleshooting)
8. [Configuration Details](#configuration-details)
   - [Environment Variables](#environment-variables)
   - [Background Jobs](#background-jobs)
   - [Docker Compose Configuration](#docker-compose-configuration)
   - [Security Considerations](#security-considerations)
   - [Secret Storage & Encryption](#secret-storage--encryption)
   - [Current v1 Limitations](#current-v1-limitations)

---

## File Structure

```
apps/
  api/                         # Express API (TypeScript)
    src/
      db/                      # PostgreSQL pool
      middleware/              # JWT auth + RBAC (requireAuth, requireRole)
      routes/                  # REST endpoints
        admin.ts               # Users, LDAP, AD group mapping, executor + management VLAN settings
        audit.ts
        auth.ts
        compliance.ts          # Drift detection & compliance checking
        dashboard.ts
        deployments.ts         # Deployments, executors, scheduled deployments, stale-host timeout
        enforcement-points.ts  # Switch/gateway enforcement
        flow-collectors.ts     # NetFlow/sFlow collectors
        health.ts
        host-readiness.ts      # Host capability verification
        integrations.ts        # SIEM/SOAR/Vuln/ThreatIntel integrations
        iot-assets.ts          # IoT/OT assets and gateway assignments
        kubernetes.ts          # Kubernetes clusters, NetworkPolicy generation
        notifications.ts       # Notification channel management
        policy-testing.ts      # On-device policy testing
        recommendations.ts     # Policy auto-recommendations
        security-audit.ts      # Security posture scanning
        ssh-credentials.ts     # SSH credentials (scopes, sudo modes)
        topology.ts            # Visual topology design
        troubleshoot.ts        # Lookups, simulation, Firewall Learning
        inventory/             # hosts.ts, interfaces.ts, tags.ts, vlans.ts, tag-rules.ts, discovery.ts
        policies/              # policy-sets.ts, policy-versions.ts, policy-rules.ts, policy-code.ts, render.ts, templates.ts
      services/                # Business logic, e.g.:
        ssh-credentials.ts     # Credential resolution + decryption for SSH connections
        discovery.ts           # Inventory discovery runs and scheduler
        deployment-expiry.ts   # Policy expiry processor (NOTIFY_ONLY / REMOVE / REVERT)
        forward-rules.ts       # FORWARD rules / protected devices for IoT gateways
        policy-diff.ts         # Policy version comparison
        safety-check.ts        # Pre-deployment safety validation
        high-risk.ts           # High-risk policy detection
        log-parser.ts          # Firewall log parsing for learning sessions
        audit-scheduler.ts     # Background job for expired audit sessions
        tag-rule-engine.ts     # Auto-tagging evaluation engine
        template-engine.ts     # Policy template instantiation / auto-apply
        recommendation-engine.ts # Audit-to-policy recommendations
        topology-to-policy.ts  # Visual topology -> policy conversion
        policy-test-analyzer.ts  # Policy test gap analysis
        notifications.ts       # Multi-channel notification delivery
        excessive-rules-audit.ts # Security posture scanning engine
        secrets.ts, crypto.ts  # Encrypted secret store (AES-256-GCM)
      lib/                     # env.ts (environment config), safe-http.ts, rule validation, ...
      index.ts                 # Express app entry point + background jobs
  web/                         # React UI (Vite)
    src/
      components/              # AppShell, RequireAuth, RequireRole, DiscoveryTab, HostPolicyVisualization
      pages/                   # One page per navigation entry (Dashboard, Inventory, Policy Sets, ...)
      lib/                     # API client, auth helpers
infra/
  app/Dockerfile               # API container: multi-stage, non-root, docker CLI + openssh-client + sshpass
  app/docker-entrypoint.sh     # Validates secrets, runs migrations + seed, starts the API
  web/                         # nginx image (UI + /api proxy)
  ansible-runner/              # Ansible container + playbooks (only needed for the Ansible executor)
    Dockerfile
    playbooks/
      apply-firewall.yml
packages/
  db/                          # node-pg-migrate migrations + scripts
    migrations/                # 001_init.sql ... 030_credential_scopes.sql (plain SQL)
    scripts/
      migrate.js
      seed-roles.js            # Roles + initial admin user
  shared/                      # shared TS types
  compiler/                    # nftables/iptables and native firewalld/UFW rendering
    src/
      compile.ts               # Per-host rulesets; supports logOnlyMode for firewall learning
  executor/                    # Ansible runner + SSH direct executor
    src/
      run-ansible.ts
      run-ssh.ts               # SSH Direct apply with lockout auto-revert
      read-rules.ts            # Read Segmentra's live rules + drift hash
      check-host-readiness.ts  # Host capability verification
      audit-ssh.ts             # Firewall learning/audit session management
      discover-host.ts         # Read-only fact collection for inventory discovery
      remove-policy.ts         # Remove Segmentra's rules (expiry REMOVE)
      firewall-backup.ts       # Scoped backup/restore snippets (+ persistSnippet)
      persist-scripts.ts       # Reboot persistence via the distro's own service (shell + output parser)
      persistence.ts           # checkHostPersistence (read-only check: readiness, compliance, Ansible)
      ssh-options.ts           # SSH/sudo/askpass helpers
      types.ts                 # Shared executor types
docker-compose.yml             # segmentra-db, segmentra-ansible-runner, segmentra-app, segmentra-web
docker-compose.hardened.yml    # Hardened production override (see docs/security.md)
```

---

## API Endpoints

Base URL: `http://localhost:8080/api` (behind the bundled nginx: `http://<host>/api`).

Routers are mounted in `apps/api/src/index.ts` (inventory and policy sub-routers in `routes/inventory/index.ts` and `routes/policies/index.ts`). Unless noted otherwise every endpoint requires a valid JWT (`Authorization: Bearer <token>`); the roles listed are the ones passed to `requireRole(...)`. "All roles" means `viewer`, `operator`, `approver` and `admin`. Unauthenticated endpoints: `GET /health`, `POST /auth/login`, `POST /auth/logout` and `POST /admin/bootstrap`.

### Health

- `GET /health` — liveness check (no auth)

### Authentication

- `POST /auth/login` — Body: `{ "username": "...", "password": "..." }`. Tries a local user (`users.password_hash`) first, then LDAP. Failed attempts are rate-limited per client IP (see [Login Security](#login-security)).
- `POST /auth/logout` — stateless (the client drops the JWT)
- `GET /auth/me` — current user + roles
- `POST /auth/change-password` — change the current local user's password

### Admin (`admin`)

- `POST /admin/bootstrap` — one-time creation of the first local admin; requires `token`, optional `username`, and `password` (12+ characters, at most 72 UTF-8 bytes). Stores a bcrypt hash so the account can log in again. No JWT required, enabled only when `SEGMENTRA_BOOTSTRAP_TOKEN` is set (404 otherwise), 3 attempts per IP per 15 minutes. First-user creation is serialized with a database table lock.
- `GET /admin/roles`
- `GET /admin/ldap-settings` / `PUT /admin/ldap-settings` — the bind password is never returned; an empty password on save keeps the stored one
- `GET /admin/ad-group-role-map` / `POST /admin/ad-group-role-map` / `DELETE /admin/ad-group-role-map/:id`
- `GET /admin/executor-setting` / `PUT /admin/executor-setting` — deployment executor (`ansible` or `ssh`)
- `GET /admin/management-vlan-setting` / `PUT /admin/management-vlan-setting`
- `GET /admin/users`, `GET /admin/users/:id`, `POST /admin/users`, `PUT /admin/users/:id`, `DELETE /admin/users/:id`
- `POST /admin/users/:id/reset-password` — local users only (`409 ldap_user_password` for LDAP users)

### Inventory (read: all roles; write: `operator`, `admin`)

#### Hosts
- `GET /hosts?hostname=&ip=&tag=&vlan=&env=&backend=&enabled=&page=&limit=` — hosts with tags, VLAN info and `effective_credential` (paginated, default 50, max 1000 per page)
- `GET /hosts/:id` — host with tags, VLAN info and `effective_credential`
- `POST /hosts` — Body: `{ hostname, mgmtIp?, sshPort?, environment?, osFamily?, firewallBackend?: 'nftables'|'iptables'|'firewalld'|'ufw'|'auto', vlanId?, tagIds?, enabled?, sshCredentialId? }`
- `PUT /hosts/:id` — same fields, all optional
- `DELETE /hosts/:id` — deletes the host; `409 host_has_deployment_history` if it has deployment history (disable it instead)
- `POST /hosts/bulk/delete`, `/bulk/assign-vlan`, `/bulk/assign-tag`, `/bulk/set-enabled`, `/bulk/import` (CSV import)

`effective_credential` is a non-secret summary of the SSH credential the host would use: `{ id, name, authMethod, sudoMode, scopeType, via: 'ASSIGNED'|'HOST'|'TAG'|'VLAN'|'GLOBAL', scopeName }` (`null` when no credential applies). `sshCredentialId` (uuid, or `null` to clear) sets the explicit credential assignment `hosts.ssh_credential_id`; only `admin` may send it (`403` for operators). See [SSH credential resolution](#ssh-credential-resolution).

#### Interfaces
- `GET /hosts/:id/interfaces`
- `POST /hosts/:id/interfaces` — Body: `{ name, role?, ipAddress?, cidr?, vlanId?, isPrimary?, enabled? }`
- `PUT /interfaces/:interfaceId`
- `DELETE /interfaces/:interfaceId`

#### Tags
- `GET /tags`
- `POST /tags` — Body: `{ name, description? }`
- `PUT /tags/:id`
- `DELETE /tags/:id` — `409` while policy or template rules reference the tag

#### VLANs
- `GET /vlans`
- `POST /vlans` — Body: `{ vlanTag, name, description?, subnet? }` (`vlan_tag` is unique)
- `PUT /vlans/:id`
- `DELETE /vlans/:id` — `409` while policy or template rules reference the VLAN

#### Tag Rules (Auto-Tagging)
- `GET /tag-rules` — rules with match counts
- `GET /tag-rules/:id` — rule with matched hosts
- `POST /tag-rules/preview` — Body: `{ criteria }`; returns `{ hosts: [{ id, hostname }] }` without writing anything
- `POST /tag-rules` — Body: `{ name, tagId, enabled?, priority?, criteria: { conditions: [{ field, operator, value }], logic: 'AND'|'OR' } }`; an enabled rule is applied immediately
- `PUT /tag-rules/:id`
- `DELETE /tag-rules/:id` — also removes the tags this rule assigned
- `POST /tag-rules/:id/evaluate`, `POST /tag-rules/evaluate-all`, `POST /tag-rules/evaluate-host/:hostId`

#### Discovery (read: all roles; profiles: `admin`; run: `operator`, `admin`)
- `GET /discovery/profiles` — profiles with their target sets and last run
- `GET /discovery/profiles/:id`
- `POST /discovery/profiles` — Body: `{ name, enabled?, scheduleIntervalMinutes?: number|null, defaultTagName? (default 'new-server'), targets: [{ sshCredentialId, sshPort?, cidrs?, vlanIds? }] }` (1–20 target sets)
- `PUT /discovery/profiles/:id`
- `DELETE /discovery/profiles/:id`
- `POST /discovery/profiles/:id/run` — starts a run in the background (`202 { runId, status: 'RUNNING' }`; `409 discovery_running` if one is already running)
- `GET /discovery/profiles/:id/runs` — run history
- `GET /discovery/runs/:runId` — run with per-address results

### Policies + Approvals

#### Policy Sets (read: all roles; write: `operator`, `admin`)
- `GET /policy-sets`
- `POST /policy-sets` — Body: `{ name, description?, scopeType: 'TAG'|'VLAN'|'HOST_LIST', scopeTagId?, scopeVlanId?, hostIds? }`
- `GET /policy-sets/:id`
- `PUT /policy-sets/:id`
- `DELETE /policy-sets/:id`
- `POST /compliance/reports` — `operator`, `approver`, `admin`. Generates and stores a compliance evidence snapshot (frameworks, period, thresholds, optional `liveDrift` for operator/admin). `GET /compliance/reports`, `GET /compliance/reports/:id?format=json|html|csv&dataset=` — all roles; reports are immutable and the SHA-256 is re-checked on every read. See [compliance-reports.md](compliance-reports.md)
- `GET /policy-sets/:id/export?format=yaml|json&version=latest|N|<id>` — all roles. Policy as code: the policy set as a `segmentra.io/v1` `PolicySet` document (names instead of ids, deterministic output). See [policy-as-code.md](policy-as-code.md)
- `POST /policy-sets/import?dryRun=&updateScope=` — `operator`, `admin`. Body: YAML text, the document as JSON, or `{ content }`. Creates the policy set or a DRAFT version; idempotent; never approves; `dryRun` rolls back; an existing set's scope is only changed with `updateScope`. `400` with `problems[{path,message}]` for an invalid document, `409 ambiguous_policy_set`

#### Policy Versions
- `GET /policy-sets/:id/versions` — all roles
- `POST /policy-sets/:id/versions` — `operator`, `admin`. Creates a `DRAFT` version. Body: `{ changeSummary?, interfaceScopeType?, interfaceScopeRoles?, interfaceScopeNames? }`
- `GET /policy-versions/pending-approval` — `approver`, `admin`. Versions in `PENDING_APPROVAL`
- `GET /policy-versions/:versionId` — all roles
- `PUT /policy-versions/:versionId` — `operator`, `admin`; only while `DRAFT` or `REJECTED`
- `POST /policy-versions/:versionId/submit-approval` — `operator`, `admin`. Status → `PENDING_APPROVAL`; evaluates and sets `is_high_risk`
- `POST /policy-versions/:versionId/approve` — `approver`, `admin`. Refused (`403`) for the creator, the submitter and anyone who edited the version (`policy_version_editors`) — this applies to every version, including for admins
- `POST /policy-versions/:versionId/reject` — `approver`, `admin`. Body: `{ reason }`
- `POST /policy-versions/:versionId/clone` — `operator`, `admin`. Copies the version and its rules into a new `DRAFT`
- `DELETE /policy-versions/:versionId` — `operator`, `admin`. Only `DRAFT` or `REJECTED` versions
- `POST /policy-versions/:versionId/archive` — `operator`, `admin`. `APPROVED`, `DEPLOYED` or `PENDING_APPROVAL` → `ARCHIVED`

#### Policy Rules (read: all roles; write: `operator`, `admin`)
- `GET /policy-versions/:versionId/rules`
- `POST /policy-versions/:versionId/rules` — Body: `{ orderIndex, direction: 'IN'|'OUT'|'BOTH'|'FORWARD', action: 'ALLOW'|'DENY', protocol, ports?, sourceType, sourceValue, destinationType?, destinationValue?, logMode?, comment?, usePolicyInterfaceScope?, interfaceScopeType?, interfaceScopeRoles?, interfaceScopeNames? }`. `destinationType` (`CIDR|TAG|VLAN|HOST|IOT_ASSET`) and `destinationValue` are required for `FORWARD` rules and must be empty otherwise.
- `PUT /policy-rules/:ruleId` — partial update; rules can only be added, changed or deleted while the version is `DRAFT` or `REJECTED`
- `DELETE /policy-rules/:ruleId`

#### Policy Utilities
- `GET /policy-versions/:versionId/diff?fromVersionId=...` — all roles. Rule list diff between two versions
- `GET /policy-versions/:versionId/render/host/:hostId` — `operator`, `admin`. Per-host nft/iptables preview: `{ backend, sha256, text }`
- `POST /policy-versions/:candidateVersionId/impact-diff` — all roles. Semantic impact analysis
  - Body: `{ currentVersionId: string, hostIds: string[] }`
  - Returns: `{ diff: Array<{ hostId, hostname, changes: { newAllows, removedAllows, newDenies, removedDenies }, summary }> }`

#### Policy Templates (read: all roles; write: `operator`, `admin`)
- `GET /policy-templates` — templates with rule and instantiation counts
- `GET /policy-templates/categories`
- `GET /policy-templates/:id`
- `POST /policy-templates` — Body: `{ name, category?, targetTagId?, autoApply?, interfaceScopeType?, ... }`
- `PUT /policy-templates/:id`, `DELETE /policy-templates/:id`
- `GET /policy-templates/:id/rules`, `POST /policy-templates/:id/rules`
- `PUT /policy-templates/rules/:ruleId`, `DELETE /policy-templates/rules/:ruleId`
- `POST /policy-templates/:id/instantiate` — creates policy set + DRAFT version + rules
- `POST /policy-templates/:id/preview` — all roles; preview of what instantiation would create

### Deployments (read: all roles; write: `operator`, `admin`)

- `POST /deployments` — Body: `{ policyVersionId, mode: 'CANARY'|'PROGRESSIVE'|'FULL', targetQuery: { tags?, vlans?, hosts? }, canarySize?, batchSize?, scheduledAt?, expiresAt?, expiryAction?: 'NOTIFY_ONLY'|'REMOVE'|'REVERT' }`
  - The policy version must be `APPROVED` or `DEPLOYED`; disabled hosts are skipped
  - Status is `SCHEDULED` when `scheduledAt` is in the future, otherwise `QUEUED`
  - **Safety check**: verifies SSH access is preserved. `FULL` mode is blocked (`400 safety_check_failed`) if SSH would be blocked; `CANARY`/`PROGRESSIVE` only warn
  - **High risk**: the version's risk is re-evaluated with the real target count; a high-risk deployment is created with `requires_approval = true` and cannot start until a second person approves it
- `GET /deployments?search=&mode=&status=&tag=&vlan=&fromDate=&toDate=&sortBy=&sortOrder=&page=&limit=` — paginated list (max 100 per page)
- `GET /deployments/:deploymentId`
- `GET /deployments/:deploymentId/hosts` — per-host status
- `GET /deployments/:deploymentId/artifacts` — bundles
- `GET /executions/:executionId/logs` — stdout/stderr of an execution
- `POST /deployments/:deploymentId/start` — claims a `QUEUED`/`SCHEDULED` deployment, returns `202` and runs the executor in the background (`409 deployment_requires_approval` while an approval is pending)
- `POST /deployments/:deploymentId/approve` — `approver`, `admin`. Approves a deployment with `requires_approval`; the creator cannot approve their own deployment (`403`)
- `POST /deployments/:deploymentId/pause` — `RUNNING` → `PAUSED`. The host being deployed finishes; the executor stops before the next host, and not-yet-started hosts stay `PENDING`
- `POST /deployments/:deploymentId/resume` — continues a `PAUSED` deployment with the remaining hosts
- `POST /deployments/:deploymentId/stop` (alias `/cancel`) — `SCHEDULED`/`QUEUED`/`RUNNING`/`PAUSED` → `CANCELLED`; unfinished hosts are marked `SKIPPED` (a host mid-deploy records its real result)
- `POST /deployments/:deploymentId/retry-failed` — for `FAILED`/`PARTIAL` deployments: resets failed hosts (and hosts skipped by a halted canary/progressive rollout) to `PENDING` and sets the deployment back to `QUEUED`; start it again with `/start`

Host deployments that stay `RUNNING` for more than 10 minutes are marked `FAILED` ("Deployment timeout: Host did not respond within 10 minutes"). The check runs every 2 minutes and when deployments or deployment hosts are fetched.

### Dashboard (any authenticated user)

- `GET /dashboard/stats` — deployment totals, running deployments, success rate, status breakdown, top deployers, recent and current deployments, 30-day activity

### Audit (all roles)

- `GET /audit?actor=&action=&entityType=&from=&to=` — last 500 matching audit events

### Compliance & Drift Detection (`operator`, `admin`)

- `GET /compliance/hosts/:hostId` — `{ hostId, hostname, status: 'compliant'|'drifted'|'unknown'|'error', currentHash, expectedHash, backend, lastDeployment, message?, error? }`. Compares the hash of Segmentra's live rules with `deployment_hosts.applied_live_hash` (see [Drift Detection](#drift-detection--configuration-compliance)). Also returns `persistence: { status, state, method, warnings, error }`: whether the distribution's boot configuration holds the same Segmentra state (`state: in_sync|differs|missing|none|learning`); a compliant host whose boot configuration differs or is missing keeps status `compliant` with a message
- `POST /compliance/hosts/bulk` — Body: `{ hostIds: string[] }`

### Host Readiness (`operator`, `admin`)

- `POST /host-readiness/hosts/:hostId/check` — `{ hostname, ready, backend: 'nftables'|'iptables'|'firewalld'|'ufw'|'unknown', nftVersion?, iptablesVersion?, sudoAccess, sudoMode: 'nopasswd'|'password', sudoError?: 'password_required'|'wrong_password'|'tty_required'|'not_permitted', kernelSupport, errors[], warnings[] }`
  - Verifies nft/iptables availability, sudo with the credential's privilege escalation mode (`id -u` + a ruleset read via `sudo sh -c`) and kernel support
  - Updates `firewall_backend` if it is `auto`
  - Also returns `persistence?: { distro, method, available, status, warnings[], notes[] }` (read-only check of reboot persistence; see [Reboot persistence](#reboot-persistence))

### Troubleshoot (read: all roles; actions: `operator`, `admin`)

- `GET /troubleshoot/policies/by-ip?ip=...` — which policies apply to an IP
- `GET /troubleshoot/hosts/:hostId/policies` — policies deployed to a host
- `GET /troubleshoot/policy-versions/:versionId/hosts` — hosts running a version
- `POST /troubleshoot/simulate-communication` — Body: `{ sourceIp, sourcePort?, destIp, destPort?, protocol? }`

#### Firewall Learning (Audit Sessions)

- `POST /troubleshoot/audit/start` — Body: `{ hosts: uuid[], durationMinutes: 1-1440 }`. Backs up Segmentra's own rules, deploys a log-only policy and configures rsyslog
- `GET /troubleshoot/audit/sessions`
- `GET /troubleshoot/audit/sessions/:id`
- `POST /troubleshoot/audit/sessions/:id/restore` — restore now and collect/parse the logs
- `GET /troubleshoot/audit/sessions/:id/logs` — parsed entries and flows
- `POST /troubleshoot/audit/sessions/:id/cancel` — restore and mark `CANCELLED`

### SSH Credentials (`admin`)

- `GET /ssh-credentials` — `id, name, username, auth_method, sudo_mode, scope_type, scope_id, scope_name, priority, created_at, has_passphrase, has_sudo_password, assigned_host_count, discovery_target_count` (no secret values or secret IDs)
- `POST /ssh-credentials` — Body: `{ name, username, authMethod: 'KEY', privateKeyPem, passphrase? }` or `{ name, username, authMethod: 'PASSWORD', password }`, plus `sudoMode?: 'NOPASSWD'|'LOGIN_PASSWORD'|'SUDO_PASSWORD'` (default `NOPASSWD`), `sudoPassword?` (required for `SUDO_PASSWORD`), `scopeType?: 'GLOBAL'|'TAG'|'VLAN'|'HOST'|'NONE'` (default `GLOBAL`), `scopeId?` (tag/VLAN/host id for `TAG`/`VLAN`/`HOST`), `priority?` (-1000..1000, default 0)
  - The key (and passphrase) is validated with `ssh-keygen -y`. Errors: `400 invalid_key_or_passphrase`, `400 invalid_sudo_mode` (`LOGIN_PASSWORD` with a key credential), `400 sudo_password_required`, `400 scope_id_required`, `400 scope_not_found`; passwords and passphrases must not contain line breaks
- `PUT /ssh-credentials/:id` — Body: `{ name?, username?, scopeType?, scopeId?, priority?, sudoMode?, sudoPassword?, password?, passphrase? }`. `password` only for password credentials; `passphrase` only for key credentials (validated against the stored key; `null`/`''` removes it if the key is unencrypted); omitted secrets are kept. The private key cannot be replaced: create a new credential instead
- `DELETE /ssh-credentials/:id` — refused with `409` while the credential is used by a discovery target set (`credential_in_use_by_discovery`), explicitly assigned to hosts (`credential_assigned_to_hosts`) or used by an enforcement point (`credential_used_by_enforcement_points`). Secrets no other credential shares are deleted with it

Create, update and delete are audited (`SSH_CREDENTIAL_CREATE`, `SSH_CREDENTIAL_UPDATE`, `SSH_CREDENTIAL_DELETE`) without secrets.

### Visual Topology (read: all roles; write: `operator`, `admin`)

- `GET /topology/views`, `GET /topology/views/:id`
- `POST /topology/views`, `PUT /topology/views/:id`, `DELETE /topology/views/:id`
- `POST /topology/views/:id/flows`, `DELETE /topology/flows/:flowId`
- `POST /topology/views/:id/generate-policies` — generates DRAFT policy sets from the flows
- `GET /topology/auto-discover` — builds a topology from inventory and deployed policies

The Topology page itself is only shown to `operator` and `admin` in the UI.

### Policy Recommendations (read: all roles; write: `operator`, `admin`)

- `GET /recommendations?status=&hostId=`
- `GET /recommendations/:id`
- `POST /recommendations/generate` — Body: `{ auditSessionId, hostId }`
- `POST /recommendations/:id/accept`, `POST /recommendations/:id/reject`
- `POST /recommendations/:id/apply` — applies an accepted recommendation as a DRAFT policy version

### Integrations (`admin`, all endpoints)

- `GET /integrations`, `GET /integrations/:id` (with recent events), `POST /integrations`, `PUT /integrations/:id`, `DELETE /integrations/:id`
- `POST /integrations/:id/test`, `POST /integrations/:id/sync`
- `GET /integrations/:id/events`
- `GET /integrations/vulnerabilities/by-host/:hostId`
- `GET /integrations/threat-intel` — active threat intelligence entries

Secret fields (API keys, tokens) are masked in responses (e.g. `••••abcd`); sending the masked value back on update keeps the stored value.

### Policy Testing (read: all roles; actions: `operator`, `approver`, `admin`)

- `GET /policy-test/sessions?hostId=&status=`
- `GET /policy-test/sessions/:id`
- `POST /policy-test/start` — Body: `{ policyVersionId, hostId, durationMinutes? (1-1440, default 30) }`
- `POST /policy-test/sessions/:id/stop`
- `POST /policy-test/sessions/:id/collect-logs`
- `POST /policy-test/sessions/:id/analyze`

### Kubernetes (read: all roles; clusters: `admin`; sync/map/generate: `operator`, `admin`)

- `GET /k8s/clusters`, `GET /k8s/clusters/:id`
- `POST /k8s/clusters`, `PUT /k8s/clusters/:id`, `DELETE /k8s/clusters/:id`
- `POST /k8s/clusters/:id/sync` — not implemented: returns `501 not_implemented`, no Kubernetes API call
- `GET /k8s/clusters/:id/workloads?namespace=&kind=`
- `POST /k8s/workloads/:workloadId/map-tag`
- `GET /k8s/clusters/:id/network-policies`
- `POST /k8s/clusters/:id/deploy-policy` — Body: `{ policyVersionId, namespace, policyName }`. Generates an Ingress-only NetworkPolicy manifest from an `APPROVED`/`DEPLOYED` version, stores it with status `GENERATED` and returns it with warnings for rules that cannot be expressed (DENY, FORWARD, ICMP, ...). The manifest is **not** applied to the cluster (UI: "Generate NetworkPolicy")

### OT/IoT Assets (read: all roles; write: `operator`, `admin`)

- `GET /iot-assets?assetType=&zone=&vlanId=`, `GET /iot-assets/:id`
- `POST /iot-assets`, `PUT /iot-assets/:id`, `DELETE /iot-assets/:id`
- `POST /iot-assets/bulk-import`
- `POST /iot-assets/:id/gateways` — Body: `{ gatewayIds: uuid[] }` (assign gateway hosts that protect the asset)
- `DELETE /iot-assets/:id/gateways/:hostId`
- `GET /iot-assets/gateways/list` — gateway hosts with protected assets and FORWARD rule counts
- `GET /iot-assets/gateways/:hostId`
- `POST /iot-assets/:id/tags`, `DELETE /iot-assets/:id/tags/:tagId`
- `GET /iot-assets/:id/flows`
- `POST /iot-assets/:id/baseline`

### Flow Collectors (read: `viewer`, `operator`, `admin`; write: `admin`)

- `GET /flow-collectors`, `GET /flow-collectors/:id`, `GET /flow-collectors/:id/flows`
- `POST /flow-collectors`, `PUT /flow-collectors/:id`, `DELETE /flow-collectors/:id`

### Enforcement Points (read: all roles; write: `admin`; deploy: `operator`, `admin`)

- `GET /enforcement-points`, `GET /enforcement-points/:id`, `GET /enforcement-points/:id/acls`
- `POST /enforcement-points`, `PUT /enforcement-points/:id`, `DELETE /enforcement-points/:id`
- `POST /enforcement-points/:id/deploy-acl` — Body: `{ policyVersionId, aclName, aclConfig }` (version must be `APPROVED`/`DEPLOYED`)

### Notifications (`admin`)

- `GET /notifications/channels`, `GET /notifications/channels/:id`
- `POST /notifications/channels` — Body: `{ name, type: 'slack'|'webhook'|'email', config: {}, enabled? }`
- `PUT /notifications/channels/:id`, `DELETE /notifications/channels/:id`
- `POST /notifications/channels/:id/test`
- `POST /notifications/channels/:id/rules` — Body: `{ eventType, enabled? }`
- `DELETE /notifications/rules/:ruleId`
- `GET /notifications/log?status=&limit=`

Webhook URLs and secrets are masked in responses like integration secrets.

### Security Posture Audit (read: all roles; scan: `operator`, `admin`)

- `POST /security-audit/scan` (also `GET`) — runs a full scan, stores the result and returns the findings
- `GET /security-audit/latest` — latest stored scan
- `GET /security-audit/history` — last 20 scans
- `GET /security-audit/summary` — finding counts of the latest scan

---

## Database Schema

Migrations live in `packages/db/migrations/` as plain `NNN_description.sql` files (001–032), applied by `npm run db:migrate` (`packages/db/scripts/migrate.js` → node-pg-migrate). There are no `.js` wrappers: node-pg-migrate loads both `.js` and `.sql` files with the same name, so older releases ran most migrations twice.

### Auth & RBAC

#### `users`
- `id` (uuid, PK)
- `username` (text, unique)
- `display_name` (text)
- `email` (text)
- `password_hash` (text, nullable) — For local authentication
- `directory_subject` (text) — AD GUID or DN for LDAP users
- `is_active` (boolean)
- `created_at` (timestamptz)
- `last_login_at` (timestamptz)

#### `roles`
- `id` (uuid, PK)
- `name` (text, unique) — `viewer|operator|approver|admin`
- `description` (text)

#### `user_roles`
- `user_id` (uuid, FK → users.id)
- `role_id` (uuid, FK → roles.id)
- Primary key: `(user_id, role_id)`

#### `ldap_settings`
- `id` (uuid, PK)
- `enabled` (boolean)
- `url` (text)
- `bind_dn` (text)
- `bind_password_secret_id` (uuid, FK → secret_store.id)
- `base_dn` (text)
- `user_filter` (text)
- `group_filter` (text)
- `use_ldaps` (boolean)
- `tls_ca_cert_secret_id` (uuid, FK → secret_store.id, nullable)
- `created_at` (timestamptz)

#### `ad_group_role_map`
- `id` (uuid, PK)
- `ad_group_dn` (text)
- `role_id` (uuid, FK → roles.id)

#### `secret_store`
- `id` (uuid, PK)
- `name` (text)
- `type` (text, no CHECK) — e.g. `SSH_KEY`, `SSH_KEY_PASSPHRASE`, `SSH_PASSWORD`, `SUDO_PASSWORD`, `LDAP_BIND`
- `encrypted_blob` (bytea)
- `created_at` (timestamptz)
- `rotated_at` (timestamptz, nullable)
- `is_active` (boolean)

### Inventory

#### `tags`
- `id` (uuid, PK)
- `name` (text, unique)
- `description` (text)
- `is_system` (boolean, default false) — system tags `iot-gateway` and `bastion` (migration 020)

#### `vlans`
- `id` (uuid, PK)
- `vlan_tag` (int, unique since migration 021)
- `name` (text)
- `description` (text)
- `subnet` (text, nullable) — VLAN subnet; used for VLAN sources, management VLAN baseline SSH access and discovery targets

#### `hosts`
- `id` (uuid, PK)
- `hostname` (text, unique)
- `mgmt_ip` (inet)
- `ssh_port` (int, default 22) — SSH port for deployments
- `environment` (text)
- `os_family` (text)
- `firewall_backend` (text) — `auto|nftables|iptables|firewalld|ufw`
- `vlan_id` (uuid, FK → vlans.id, nullable)
- `enabled` (boolean, default true) — Disabled hosts are skipped from deployments
- `ssh_credential_id` (uuid, FK → ssh_credentials.id, nullable, ON DELETE SET NULL) — explicit SSH credential assignment; overrides scope resolution (migration 030)
- `created_at` (timestamptz)
- `updated_at` (timestamptz)

**Important Notes**:
- **SSH Port**: The `ssh_port` field (default: 22) specifies which SSH port to use when connecting to the host for deployments. Both Ansible and SSH Direct executors automatically use the configured port for each host.
- **Disabled Hosts**: Hosts with `enabled=false` are **automatically skipped** from all policy deployments. Disabled hosts will never receive firewall policies, even if they are included in deployment target queries (tags, VLANs, or direct host selection). They will be marked as `SKIPPED` in deployment status with the message "Host is disabled".

#### `host_tags`
- `host_id` (uuid, FK → hosts.id)
- `tag_id` (uuid, FK → tags.id)
- `source` (text, default `manual`) — `manual|rule|integration` (migration 009)
- `source_rule_id` (uuid, FK → tag_rules.id, nullable)
- Primary key: `(host_id, tag_id)` — Many-to-many relationship

#### `host_interfaces`
- `id` (uuid, PK)
- `host_id` (uuid, FK → hosts.id)
- `name` (text) — Interface name (e.g., `eth0`, `ens3`)
- `role` (text) — Interface role (e.g., `data`, `management`)
- `ip_address` (inet, nullable)
- `cidr` (int, nullable) — prefix length
- `vlan_id` (uuid, FK → vlans.id, nullable)
- `is_primary` (boolean)
- `enabled` (boolean)
- `created_at` (timestamptz)

### Policies

#### `policy_sets`
- `id` (uuid, PK)
- `name` (text)
- `description` (text)
- `scope_type` (text) — `TAG|VLAN|HOST_LIST`
- `scope_tag_id` (uuid, FK → tags.id, nullable)
- `scope_vlan_id` (uuid, FK → vlans.id, nullable)
- `created_by` (uuid, FK → users.id)
- `created_at` (timestamptz)
- `source_template_id` (uuid, FK → policy_templates.id, nullable)

#### `policy_set_hosts`
- `policy_set_id` (uuid, FK → policy_sets.id)
- `host_id` (uuid, FK → hosts.id)
- Primary key: `(policy_set_id, host_id)` — Only used when `scope_type=HOST_LIST`

#### `policy_versions`
- `id` (uuid, PK)
- `policy_set_id` (uuid, FK → policy_sets.id)
- `version_number` (int) — unique per policy set (`uq_policy_versions_set_version`, migration 025)
- `status` (text) — `DRAFT|PENDING_APPROVAL|APPROVED|REJECTED|DEPLOYED|ARCHIVED`
- `submitted_by` (uuid, FK users, ON DELETE SET NULL) — user who submitted the version for approval
- `change_summary` (text, nullable)
- `created_by` (uuid, FK → users.id)
- `created_at` (timestamptz)
- `submitted_at` (timestamptz, nullable)
- `approved_by` (uuid, FK → users.id, nullable)
- `approved_at` (timestamptz, nullable)
- `rejected_by` (uuid, FK → users.id, nullable)
- `rejected_at` (timestamptz, nullable)
- `rejection_reason` (text, nullable)
- `interface_scope_type` (text) — `ALL_INTERFACES|INTERFACE_NAME|INTERFACE_ROLE`
- `interface_scope_names` (text[], nullable)
- `interface_scope_roles` (text[], nullable)
- `is_high_risk` (boolean, default false)
- `source_template_id` (uuid, FK → policy_templates.id, nullable)
- `expires_at` (timestamptz, nullable), `expiry_action` (text, default `NOTIFY_ONLY`) — migration 017 (the expiry used at runtime is the one on `deployments`)

#### `policy_version_editors` (migration 025)
- `policy_version_id` (uuid, FK → policy_versions.id), `user_id` (uuid, FK → users.id), `created_at`
- Primary key: `(policy_version_id, user_id)` — users who edited a version; they cannot approve it

#### `policy_rules`
- `id` (uuid, PK)
- `policy_version_id` (uuid, FK → policy_versions.id)
- `order_index` (int)
- `direction` (text, default `IN`) — `IN|OUT|BOTH|FORWARD` (CHECK since migration 028)
- `action` (text) — `ALLOW|DENY`
- `protocol` (text) — `tcp|udp|icmp|any`
- `ports` (text, nullable) — Normalized format: `"22"` or `"80,443"` or `"1000-2000"`
- `source_type` (text) — `CIDR|TAG|VLAN|HOST`
- `source_value` (text) — CIDR string OR tag_id/vlan_id/host_id serialized
- `destination_type` (text, nullable) — `CIDR|TAG|VLAN|HOST|IOT_ASSET`; required for `FORWARD` rules, NULL otherwise (migration 028)
- `destination_value` (text, nullable) — CIDR or the id of the tag/VLAN/host/IoT asset
- `log_mode` (text) — `NONE|LOG|LOG_RATE_LIMITED`
- `comment` (text)
- `use_policy_interface_scope` (boolean, default true)
- `interface_scope_type` (text, nullable) — Rule-level override
- `interface_scope_roles` (text[], nullable)
- `interface_scope_names` (text[], nullable)

### Deployments & Execution

#### `deployments`
- `id` (uuid, PK)
- `policy_version_id` (uuid, FK → policy_versions.id) — Must be APPROVED or DEPLOYED
- `mode` (text) — `CANARY|PROGRESSIVE|FULL`
- `target_query` (jsonb) — `{ tags: uuid[], vlans: uuid[], hosts: uuid[] }`
- `target_count` (int)
- `created_by` (uuid, FK → users.id)
- `created_at` (timestamptz)
- `started_at` (timestamptz, nullable)
- `finished_at` (timestamptz, nullable)
- `status` (text) — `SCHEDULED|QUEUED|RUNNING|PAUSED|SUCCEEDED|FAILED|PARTIAL|CANCELLED|EXPIRED`
- `requires_approval` (boolean, default false) — set for high-risk deployments; a second person must approve
- `approved_by` (uuid, FK → users.id, nullable)
- `approved_at` (timestamptz, nullable)
- `canary_size` (int, nullable)
- `batch_size` (int, nullable)
- `scheduled_at` (timestamptz, nullable) — For deferred/scheduled deployments (migration 007)
- `expires_at` (timestamptz, nullable), `expiry_action` (text, default `NOTIFY_ONLY`: `NOTIFY_ONLY|REMOVE|REVERT`), `expired` (boolean, default false) — migration 017
- `progress` (jsonb, nullable) — live progress of a running deployment (migration 023)
- `notes` (text, nullable) — e.g. why a system-created revert deployment exists (migration 026)
- `revert_of_deployment_id` (uuid, FK → deployments.id, nullable) — set on the deployment created by an expiry REVERT (migration 026)
- `expiry_outcome` (jsonb, nullable) — result of the expiry action (migration 026)

#### `deployment_hosts`
- `deployment_id` (uuid, FK → deployments.id)
- `host_id` (uuid, FK → hosts.id)
- `status` (text) — `PENDING|RUNNING|SUCCEEDED|FAILED|SKIPPED` (`PAUSED` only on rows from older versions)
- `started_at` (timestamptz, nullable)
- `finished_at` (timestamptz, nullable)
- `message` (text, nullable)
- `applied_hash` (text, nullable) — SHA-256 of the compiled policy text (not comparable with a live read)
- `applied_live_hash` (text, nullable) — `v2:`-prefixed hash of Segmentra's own live rules read back after apply; the drift baseline (migration 025)
- `expiry_status`, `expiry_message` (text, nullable), `expiry_processed_at` (timestamptz, nullable) — per-host result of the expiry action (migration 026)
- `rollback_performed` (boolean, default false)
- `persistence_status` (text, nullable) — reboot persistence of this host after the deployment: `persisted|not_persisted|removed|unknown`; NULL = not reported (host failed before that step, or deployed by an older version) (migration 032)
- `persistence_method` (text, nullable) — `nftables.service|netfilter-persistent|iptables-services|firewalld|ufw` (migration 032)
- `persistence_message` (text, nullable) — summary plus warnings/notes, e.g. `firewalld_active: …`, `iptables_persistent_missing: …`, `unsupported_distro: …` (migration 032)
- Primary key: `(deployment_id, host_id)`

#### `deployment_artifacts`
- `id` (uuid, PK)
- `deployment_id` (uuid, FK → deployments.id)
- `bundle_path` (text)
- `bundle_hash` (text)
- `manifest` (jsonb)
- `created_at` (timestamptz)

#### `execution_runs`
- `id` (uuid, PK)
- `deployment_id` (uuid, FK → deployments.id)
- `executor_type` (text) — `ansible_cli|ssh_direct`
- `command` (text)
- `exit_code` (int, nullable)
- `stdout_path` (text, nullable)
- `stderr_path` (text, nullable)
- `started_at` (timestamptz)
- `finished_at` (timestamptz, nullable)
- `status` (text, default `RUNNING`) — e.g. `RUNNING|DONE`

### Auditing

#### `audit_events`
- `id` (uuid, PK)
- `actor_user_id` (uuid, FK → users.id, nullable)
- `action` (text) — e.g., `DEPLOYMENT_CREATED`, `DEPLOYMENT_FINISHED`, `POLICY_APPROVED`
- `entity_type` (text) — e.g., `DEPLOYMENT`, `POLICY_VERSION`
- `entity_id` (uuid)
- `timestamp` (timestamptz)
- `ip_address` (inet, nullable)
- `metadata` (jsonb) — Rich metadata for the event
- `siem_forwarded_at` (timestamptz, nullable) — set when an API process claims the row for SIEM forwarding (see Integrations)

**Deployment Audit Metadata Structure**:
```json
{
  "policySetName": "DMZ Servers",
  "policyVersionNumber": 1,
  "deploymentMode": "CANARY",
  "targetType": "Tags, Hosts",
  "targetTags": ["web-servers", "dmz"],
  "targetVlans": [],
  "targetHosts": ["webserver01", "webserver02"],
  "result": "SUCCEEDED|FAILED|PARTIAL",
  "createdAt": "2026-01-08T18:10:43Z",
  "startedAt": "2026-01-08T18:11:02Z",
  "finishedAt": "2026-01-08T18:15:30Z",
  "hostCounts": {
    "total": 10,
    "succeeded": 8,
    "failed": 2,
    "skipped": 0
  }
}
```

### Secrets / SSH

#### `ssh_credentials`
- `id` (uuid, PK)
- `name` (text)
- `username` (text)
- `private_key_secret_id` (uuid, FK → secret_store.id, nullable) — private key (`auth_method = 'KEY'`)
- `passphrase_secret_id` (uuid, FK → secret_store.id, nullable) — key passphrase
- `password_secret_id` (uuid, FK → secret_store.id, nullable) — login password (`auth_method = 'PASSWORD'`)
- `auth_method` (text) — `KEY|PASSWORD`
- `sudo_mode` (text, default `NOPASSWD`) — `NOPASSWD|LOGIN_PASSWORD|SUDO_PASSWORD` (migration 029; `LOGIN_PASSWORD` only with `PASSWORD` auth)
- `sudo_password_secret_id` (uuid, FK → secret_store.id, nullable) — separate sudo password (required for `SUDO_PASSWORD`)
- `scope_type` (text) — `GLOBAL|TAG|VLAN|HOST|NONE` (CHECK since migration 030; `NONE` = stored only, never chosen automatically)
- `scope_id` (uuid, nullable) — tag/VLAN/host id for `TAG`/`VLAN`/`HOST`, NULL for `GLOBAL`/`NONE` (CHECK); no FK, so a deleted tag/VLAN/host leaves the credential matching nothing
- `priority` (integer, default 0) — tie-breaker within one resolution level, higher wins (migration 030)
- `created_at` (timestamptz)

CHECK constraints: `auth_method` `KEY` needs `private_key_secret_id`, `PASSWORD` needs `password_secret_id` (migration 024); `LOGIN_PASSWORD` needs `auth_method = 'PASSWORD'` and `SUDO_PASSWORD` needs `sudo_password_secret_id` (migration 029).

### Firewall Learning & Settings

#### `firewall_audit_sessions`
- `id` (uuid, PK)
- `host_id` (uuid, FK → hosts.id)
- `status` (text, default `RUNNING`) — e.g. `RUNNING|COMPLETED|FAILED|CANCELLED`
- `duration_minutes` (integer)
- `started_at` (timestamptz)
- `scheduled_restore_at` (timestamptz)
- `restored_at` (timestamptz, nullable)
- `backup_path` (text) — Path to the backup on the host (`/var/backups/segmentra/...`)
- `log_file_path` (text) — Path to log file on remote server
- `log_data` (jsonb, nullable) — Parsed log entries and communication flows
- `created_by` (uuid, FK → users.id)
- `created_at` (timestamptz)

#### `system_settings`
- `key` (text, PK) — e.g., `deployment_executor`, `management_vlan_id`
- `value` (text)
- `description` (text, nullable)
- `updated_at` (timestamptz)

### Notifications

#### `notification_channels`
- `id` (uuid, PK), `name`, `type` (slack/webhook/email), `config` (jsonb, masked display copy only), `enabled`
- `config_secret_id` (FK → secret_store, type `NOTIFICATION_CONFIG`): the full config (webhook URL, `authHeader`, `customHeaders`) encrypted with AES-256-GCM
- `created_by`, `created_at`, `updated_at`

#### `notification_rules`
- `id` (uuid, PK), `channel_id` (FK), `event_type`, `enabled`, `filter` (jsonb, optional)

#### `notification_log`
- `id` (uuid, PK), `channel_id` (FK), `event_type`, `subject`, `payload` (jsonb)
- `status` (PENDING/SENT/FAILED), `error_message`, `sent_at`, `created_at`

### Auto-Tagging

#### `tag_rules`
- `id` (uuid, PK)
- `tag_id` (uuid, FK → tags.id)
- `name` (text)
- `description` (text, nullable)
- `enabled` (boolean, default true)
- `priority` (integer, default 0)
- `criteria` (jsonb) — `{ conditions: [{field, operator, value}], logic: 'AND'|'OR' }`
- `created_by` (uuid, FK → users.id)
- `created_at`, `updated_at` (timestamptz)

#### `tag_rule_results`
- `tag_rule_id` (uuid, FK → tag_rules.id)
- `host_id` (uuid, FK → hosts.id)
- `matched` (boolean)
- `evaluated_at` (timestamptz)
- Primary key: `(tag_rule_id, host_id)`

**Note**: `host_tags` table extended with `source` ('manual'|'rule'|'integration') and `source_rule_id` columns.

### Policy Templates

#### `policy_templates`
- `id` (uuid, PK)
- `name`, `description`, `category` (text)
- `target_tag_id` (uuid, FK → tags.id, nullable)
- `auto_apply` (boolean, default false)
- `interface_scope_type`, `interface_scope_roles[]`, `interface_scope_names[]`
- `created_by`, `created_at`, `updated_at`

#### `policy_template_rules`
- Mirrors `policy_rules` schema (order_index, direction, action, protocol, ports, source_type, source_value, destination_type, destination_value, log_mode, comment, interface scope overrides)
- `policy_template_id` (uuid, FK → policy_templates.id)

**Note**: `policy_sets` and `policy_versions` extended with `source_template_id` column.

### Visual Topology

#### `topology_views`
- `id` (uuid, PK), `name`, `description`
- `layout_data` (jsonb) — Node positions and edge data
- `created_by`, `created_at`, `updated_at`

#### `topology_flows`
- `id` (uuid, PK), `topology_view_id` (FK)
- `source_type`, `source_value`, `target_type`, `target_value`
- `direction`, `action`, `protocol`, `ports`, `comment`

### Policy Recommendations

#### `policy_recommendations`
- `id` (uuid, PK)
- `audit_session_id` (uuid, FK → firewall_audit_sessions.id)
- `host_id` (uuid, FK → hosts.id)
- `status` — `PENDING|ACCEPTED|REJECTED|APPLIED`
- `recommended_rules` (jsonb) — Array of rules with confidence and flow count
- `confidence_score` (numeric)
- `reviewed_by`, `reviewed_at`, `applied_policy_version_id`

### Integrations

#### `integrations`
- `id` (uuid, PK), `type` (siem/soar/vulnerability_db/threat_intel), `provider`, `name`
- `enabled`, `config` (jsonb, masked display copy only), `credentials_secret_id` (FK → secret_store)
- `config_secret_id` (FK → secret_store, type `INTEGRATION_CONFIG`): the full config (e.g. `apiKey`) encrypted with AES-256-GCM
- `last_sync_at`, `last_sync_status`

#### `integration_events`
- `id`, `integration_id` (FK), `direction` (inbound/outbound), `event_type`, `payload` (jsonb), `status`

#### `host_vulnerabilities`
- `host_id` (FK), `integration_id` (FK), `cve_id`, `severity`, `status` (open/patched/mitigated)

#### `threat_intel_entries`
- `integration_id` (FK), `entry_type` (ip/cidr), `value`, `threat_type`, `confidence`, `expires_at`

### Policy Test Sessions

#### `policy_test_sessions`
- `id` (uuid, PK)
- `policy_version_id` (FK), `host_id` (FK)
- `status` — e.g. `PENDING|DEPLOYING|RUNNING|COLLECTING|COMPLETED|FAILED`
- `duration_minutes`, `started_at`, `scheduled_end_at`, `completed_at`
- `backup_path`, `log_file_path`, `raw_log_data` (jsonb)
- `analysis_results` (jsonb) — matchedFlows, unmatchedFlows, unexpectedBlocks, unexpectedAllows, summary

### Kubernetes

#### `k8s_clusters`
- `id`, `name`, `api_server_url`, `auth_type`, `credentials_secret_id`, `ca_cert_secret_id`
- `default_namespace`, `last_sync_at`, `last_sync_status`, `enabled`

#### `k8s_workloads`
- `cluster_id` (FK), `namespace`, `kind`, `name`, `labels` (jsonb), `pod_ips[]`, `service_cluster_ip`, `service_ports` (jsonb)

#### `k8s_workload_tags`
- `workload_id` (FK), `tag_id` (FK), `source` (label_sync/manual)

#### `k8s_network_policies`
- `cluster_id` (FK), `policy_version_id` (FK), `namespace`, `policy_name`, `manifest` (jsonb), `status` (`GENERATED` for manifests created by deploy-policy), `deployed_hash`

### OT/IoT

#### `iot_assets`
- `id`, `name`, `asset_type` (plc/hmi/sensor/camera/printer/hvac/medical/other)
- `vendor`, `model`, `firmware_version`, `mac_address`, `ip_address`
- `vlan_id` (FK), `zone` (Purdue level text), `criticality`, `fingerprint` (jsonb)

#### `iot_asset_tags`
- `asset_id` (FK), `tag_id` (FK)

#### `flow_collectors`
- `id`, `name`, `type` (netflow_v5/v9/sflow/ipfix/span_analyzer), `listen_address`, `listen_port`, `config` (jsonb), `enabled`

#### `iot_observed_flows`
- `collector_id` (FK), `source_ip`, `source_port`, `dest_ip`, `dest_port`, `protocol`, `bytes_total`, `packets_total`, `first_seen_at`, `last_seen_at`

#### `enforcement_points`
- `id`, `name`, `type` (switch_acl/gateway_firewall), `vendor`, `mgmt_ip`, `ssh_credential_id` (FK)

#### `enforcement_acls`
- `enforcement_point_id` (FK), `policy_version_id` (FK), `acl_name`, `acl_config`, `status`, `deployed_hash`

#### `iot_asset_gateways` (migration 019)
- `asset_id` (FK → iot_assets.id), `host_id` (FK → hosts.id) — gateway hosts that protect an asset. Forwarded traffic to a protected asset is dropped on the gateway unless a `FORWARD` rule allows it
- Primary key: `(asset_id, host_id)`

### Inventory Discovery (migration 027)

#### `discovery_profiles`
- `id`, `name` (unique), `enabled`
- `schedule_interval_minutes` (int, nullable) — NULL = manual runs only; 1..525600
- `default_tag_name` (text, default `new-server`) — tag applied to imported hosts
- `next_run_at`, `last_run_at`, `created_by`, `created_at`, `updated_at`

#### `discovery_targets`
- `id`, `profile_id` (FK, cascade), `position`
- `ssh_credential_id` (FK → ssh_credentials.id, ON DELETE RESTRICT)
- `ssh_port` (default 22), `cidrs` (text[]), `vlan_ids` (uuid[], no FK; VLANs without a subnet are skipped)

#### `discovery_runs`
- `id`, `profile_id` (FK, cascade), `trigger` (`manual|scheduled`), `status` (`RUNNING|SUCCEEDED|FAILED`)
- `started_at`, `finished_at`, counters `addresses_scanned`, `ssh_open`, `login_ok`, `imported`, `already_present`, `login_failed`
- `results` (jsonb) — per-address results (addresses with an open SSH port, capped), `error`, `created_by`
- At most one `RUNNING` run per profile (partial unique index)

### Security Posture Audit (migration 022)

#### `security_audit_results`
- `id`, `findings` (jsonb), `summary` (jsonb), `triggered_by` (FK → users.id), `created_at`

---

## Deployment Executors

Segmentra supports two deployment executors, selectable in **Admin → Deployment Executor** (`system_settings.deployment_executor`; the default after migration 003 is `ansible`). The hardened compose override has no Ansible runner, so it requires SSH Direct.

### Ansible

- Runs `infra/ansible-runner/playbooks/apply-firewall.yml` against all target hosts in one playbook run (Ansible's parallel forks)
- On a failed apply, a `rescue` block restores the host from that run's scoped backup (raw table/chains or native Segmentra policy objects/blocks)
- Raw nftables/iptables have no lockout auto-revert; native firewalld/UFW use `apply-manager.yml` with a systemd rollback timer, fresh SSH connection, and strict persistence verification
- The `CANARY` / `PROGRESSIVE` gates are not applied: all hosts are deployed in the same run
- Requires the Ansible container (`segmentra-ansible-runner`) and the Docker socket in the API container
- Uses `become: true` (sudo) for privileged operations; the sudo password (if any) is passed as `ansible_become_password` in a temporary `host_vars` file, passphrase-protected keys are loaded into an `ssh-agent` in the runner (see [security.md](security.md#how-secrets-are-used-when-connecting-to-hosts))

#### How Ansible Executor Connects to the Container

**Connection Mechanism: Docker Socket (Not SSH)**

The app connects to the Ansible executor container using **Docker's API**, not SSH.

**How it works:**

1. **Docker Socket Mounting**
   - The `segmentra-app` container mounts the Docker socket:
     ```yaml
     volumes:
       - /var/run/docker.sock:/var/run/docker.sock
     ```
   - This gives the API container access to the Docker daemon on the host.

2. **Docker Exec Command**
   - When Ansible executor is selected, the code runs:
     ```bash
     docker exec segmentra-ansible-runner ansible-playbook -i /bundles/.../inventory.ini /runner/playbooks/apply-firewall.yml
     ```
   - This executes `ansible-playbook` inside the `segmentra-ansible-runner` container.

3. **Shared Volume**
   - Both containers share the `segmentra_bundles` volume:
     ```yaml
     volumes:
       - segmentra_bundles:/bundles
     ```
   - The API container writes deployment bundles (inventory, per-host policy files, temporary key files and `host_vars` password files) to `/bundles/<deploymentId>/`; key and password files are deleted when the playbook finishes
   - The Ansible runner container reads from the same path.

**Visual Flow:**

```
┌─────────────────────────────────┐
│  segmentra-app (API Container)  │
│                                  │
│  1. Generates deployment bundle │
│     → writes to /bundles/...    │
│                                  │
│  2. Executes:                    │
│     docker exec                  │
│       segmentra-ansible-runner   │
│       ansible-playbook ...       │
│                                  │
│  (via Docker socket)             │
└──────────┬──────────────────────┘
           │ Docker Socket
           │ /var/run/docker.sock
           ▼
┌─────────────────────────────────┐
│  Docker Daemon (Host)            │
│                                  │
│  Executes command in container  │
└──────────┬──────────────────────┘
           │
           ▼
┌─────────────────────────────────┐
│  segmentra-ansible-runner       │
│                                  │
│  - Runs ansible-playbook         │
│  - Reads from /bundles/...       │
│  - Connects to target hosts      │
│    via SSH (using SSH keys)      │
└─────────────────────────────────┘
```

**Important Points:**

- **No SSH between containers**: The API container uses Docker exec via the socket.
- **SSH is used by Ansible**: The Ansible runner connects to target hosts via SSH using the SSH credentials you configure.
- **Security Note**: Mounting `/var/run/docker.sock` gives the API container full Docker access. Treat it as **high trust**.

**Code Reference:**

The connection happens in `packages/executor/src/run-ansible.ts`:
```typescript
const child = spawn('docker', ['exec', params.runnerContainer, 'ansible-playbook', ...]);
```

This runs the `docker` CLI command from inside the API container, which communicates with the Docker daemon through the mounted socket.

### SSH Direct

- Lightweight direct SSH/SCP execution, no Ansible or Docker socket needed
- Requires `ssh` and `scp` on the API host (plus `sshpass` for password credentials; all included in the API image)
- Runs every root step as `sudo sh -c '…'` (passwordless, or with the sudo password on stdin)
- Runs sequentially (one host at a time) and applies the `CANARY` / `PROGRESSIVE` gates (see [Async Deployment Execution](#async-deployment-execution))
- **Lockout protection:** before applying, it schedules an automatic revert on the host (via `systemd-run` or `nohup`, default 120 s); if Segmentra cannot reach the host again after the apply, the previous state is restored

**Both executors:**
- Need an account with full sudo rights (`ALL`), not root
- Back up only Segmentra's own raw table/chains or native policy objects/marked blocks to `/var/backups/segmentra/` before applying
- Roll back to that backup on failure
- Work with nftables, iptables, firewalld, and UFW (see [Generated rules](#generated-firewall-rules) and [native managers](firewall-managers.md))
- Make the final state survive a reboot with the distribution's own service (see [Reboot persistence](#reboot-persistence))

---

## Advanced Features

### Firewall Learning (Traffic Discovery)

Learning/log-only sessions currently support raw nftables/iptables only. Native firewalld/UFW attempts are rejected before changing live or permanent ACLs. Ordinary host/gateway policy simulation and drift/compliance support native managers.

Firewall Learning is a powerful feature that helps administrators discover the correct firewall rules by observing actual network traffic patterns. This is particularly useful when deploying firewall policies to new systems or when you need to understand what traffic should be allowed without accidentally blocking legitimate communication.

#### How It Works

1. **Session Creation**: User selects one or more hosts and specifies a duration (e.g., 60 minutes)
2. **Backup**: Segmentra backs up its own state (`table inet segmentra`, or the `SEGMENTRA-*` chains and their jumps) to `/var/backups/segmentra/`; rules of other tools are not touched
3. **Log-Only Policy Deployment**: 
   - Compiles a log-only firewall policy that logs all traffic but doesn't block anything
   - The default for unmatched inbound traffic becomes accept (nft `input` chain policy `accept`; iptables `SEGMENTRA-IN` ends with `RETURN`)
   - Adds logging rules before each action to capture traffic details
   - Configures rsyslog to write FW-AUDIT logs to custom log file (`/var/log/segmentra-audit-*.log`)
4. **Traffic Collection**: System collects traffic logs for the specified duration
5. **Automatic Restore**: Background scheduler automatically restores original firewall rules when duration expires
6. **Log Retrieval & Parsing**: System retrieves log file, parses entries, and groups into communication flows
7. **Results Display**: User can view parsed communication flows showing:
   - Direction (IN/OUT)
   - Source and destination IPs
   - Protocol (TCP/UDP/ICMP)
   - Port numbers
   - Traffic counts
   - First and last seen timestamps

#### Technical Implementation

- **Compiler Enhancement**: `packages/compiler/src/compile.ts` supports `logOnlyMode` parameter
  - When enabled, unmatched traffic is accepted instead of dropped
  - Adds logging rules before each action
  - Includes catch-all logging rules for all remaining traffic
- **Executor Functions**: `packages/executor/src/audit-ssh.ts` provides:
  - `startAuditSession()` - Backs up rules and configures logging
  - `deployLogOnlyPolicy()` - Deploys log-only firewall policy
  - `restoreAuditSession()` - Restores original rules from backup
  - `retrieveAuditLogs()` - Copies log file from remote server
- **Log Parser**: `apps/api/src/services/log-parser.ts` parses firewall logs:
  - Supports both nftables and iptables log formats
  - Extracts IP addresses, ports, protocols, directions
  - Groups entries into communication flows with counts
- **Scheduler**: `apps/api/src/services/audit-scheduler.ts` processes expired sessions:
  - Runs every minute to check for sessions that need restoration
  - Automatically restores rules, retrieves logs, and parses results
- **Database**: `firewall_audit_sessions` table stores session state and parsed log data

#### Logging Configuration

- **nftables**: Configures rsyslog to capture kernel messages with "FW-AUDIT" prefix
- **iptables**: Configures rsyslog to capture LOG target messages with "FW-AUDIT" prefix
- Logs are written to `/var/log/segmentra-audit-<hostname>-<timestamp>.log` on remote servers
- rsyslog configuration is automatically cleaned up during restore

#### Usage

- **UI**: Navigate to Troubleshoot → Firewall Learning
  - Add hosts by hostname or IP address
  - Specify duration in minutes (1-1440, max 24 hours)
  - Click "Start Audit" to begin
  - View active sessions with countdown timers
  - After completion, select server from dropdown to view communication flows
- **API**: Use `/api/troubleshoot/audit/*` endpoints for programmatic access

#### Benefits

- **Zero-Risk Discovery**: Observe traffic without blocking anything
- **Automatic Restoration**: Original rules are automatically restored after duration
- **Multi-Server Support**: Run learning sessions on multiple servers simultaneously
- **Parsed Results**: Communication flows are automatically parsed and grouped
- **Session Persistence**: Sessions persist across page refreshes and API restarts
- **Manual Control**: Can manually cancel or restore sessions if needed

#### Limitations

- Requires SSH access and full sudo rights (with or without a sudo password) on target hosts
- Log file size depends on traffic volume (may be large for busy servers)
- Log parsing may be slow for very large log files
- rsyslog configuration changes require sudo access
- Background processes for log capture may not persist across system reboots (logs are written directly to file)

### Drift Detection & Configuration Compliance

Segmentra provides **agentless drift detection** by comparing current firewall rules on hosts against the last successfully deployed policy hash.

#### How It Works

1. **Baseline**: Right after a successful apply, the executor reads Segmentra's own live rules back from the host and stores their hash in `deployment_hosts.applied_live_hash`. (`applied_hash`, the hash of the compiled file, is not comparable with a live read.)

2. **Rule Reading**: The compliance check reads only Segmentra's own state over SSH (as root via `sudo sh -c`, passwordless or with the sudo password on stdin):
   - nftables: `table inet segmentra`
   - iptables: the `SEGMENTRA-IN` / `SEGMENTRA-OUT` chains (and `SEGMENTRA-FWD` when present) plus their jumps from `INPUT` / `OUTPUT` / `FORWARD`

   Rules of Docker, Kubernetes, fail2ban and other tools are not part of the hash.

3. **Normalization & Hashing**: The rules are normalized and hashed with SHA-256; the hash is prefixed with `v2:`.

4. **Comparison** with `applied_live_hash` of the last successful deployment:
   - **Compliant**: hashes match
   - **Drifted**: hashes differ, or Segmentra's table/chain or its jump is missing
   - **Unknown**: no successful deployment, the baseline was recorded by an older version (no `v2:` prefix; redeploy once), or the expiry `REMOVE` action removed the rules
   - **Error**: rules could not be read (SSH failure, sudo, etc.)

#### Usage

- **Per-Host Check**: Use the "Check Compliance" button in Inventory → Hosts
- **Bulk Check**: Select multiple hosts and use **Check Compliance** in the bulk actions
- **Status Display**: Compliance status is shown in the inventory table
- **API Access**: `GET /api/compliance/hosts/:hostId` or `POST /api/compliance/hosts/bulk`

#### Benefits

- **No Agent Required**: Uses existing SSH credentials
- **Real-time Detection**: Check compliance on-demand
- **Bulk Operations**: Check hundreds of hosts at once
- **Visual Indicators**: Color-coded status in UI

### Safety Guardrails

Segmentra includes pre-deployment safety checks to prevent administrators from locking themselves out.

#### Safety Check Process

Before allowing a deployment, the system:

1. **Compiles Policy**: Generates firewall ruleset for each target host
2. **Verifies SSH Access**: Checks that the compiled ruleset preserves SSH access from the management VLAN
3. **Validates Management CIDR**: Uses the configured management VLAN's subnet (from `system_settings.management_vlan_id`)
4. **Applies Mode-Specific Rules**:
   - **FULL mode**: **Blocks** deployment if SSH access would be blocked
   - **CANARY/PROGRESSIVE**: **Warns** but allows deployment (assumes canary/batch testing)

#### Implementation

- **Service**: `apps/api/src/services/safety-check.ts`
- **Integration**: Automatic check in `POST /deployments` endpoint
- **UI Feedback**: Visual warnings/errors in deployment creation form
- **Error Response**: Returns detailed safety check results with warnings/errors

#### Safety Check Result

```typescript
{
  safe: boolean;
  warnings: string[];
  errors: string[];
  sshAccessPreserved: boolean;
  blockingRules: Array<{ ruleIndex, action, source, protocol, ports?, comment? }>;
}
```

### High-Risk Policy Detection

Segmentra automatically flags potentially dangerous policy changes. A high-risk deployment needs a second person's approval before it can start.

#### How It Works

When a policy version is submitted for approval, the system automatically evaluates it against a set of heuristics to determine if it represents a high-risk change. The evaluation considers:

1. **Wide Interface Scope + Many Targets**:
   - Policy with `interface_scope_type = 'ALL_INTERFACES'` targeting 20+ hosts
   - Indicates a change that affects all network interfaces across many systems

2. **Very Broad Source Ranges to Sensitive Ports**:
   - Rules with `sourceType = 'CIDR'` and very broad CIDRs (0.0.0.0/0, /0-/8) that ALLOW access to sensitive ports:
     - SSH (22)
     - PostgreSQL (5432)
     - MySQL (3306)
     - SQL Server (1433)
     - RDP (3389)
   - Or wide port ranges (1-65535) combined with broad sources

3. **Management Access Beyond Management VLAN**:
   - ALLOW rules for TCP ports 22, 5432, 3306, 1433, 3389 from sources that are NOT the configured management VLAN CIDR
   - Prevents accidental opening of administrative access to untrusted networks

4. **"Any/Any" Style Rules**:
   - Rules with `protocol = 'any'` and wide port ranges (or no ports) combined with very broad CIDR sources
   - Represents extremely permissive firewall rules

#### Risk Evaluation Process

1. **On Submission**: When `POST /policy-versions/:id/submit-approval` is called, the system:
   - Loads the policy version and all its rules
   - Evaluates each heuristic against the policy
   - Sets `policy_versions.is_high_risk = true` if any heuristic triggers
   - Includes `isHighRisk` flag in audit metadata

2. **On Approval**: `POST /policy-versions/:id/approve` refuses every version (high-risk or not, even for admins) when the approver created, edited or submitted it. The `isHighRisk` flag is recorded in the audit event.

3. **On Deployment Creation**: `POST /deployments`:
   - Re-evaluates the risk with the actual target count and sets `is_high_risk` if it now triggers
   - Creates a high-risk deployment with `requires_approval = true`: it cannot be started (manually or by the scheduler) until an `approver`/`admin` other than its creator calls `POST /deployments/:id/approve`

#### Implementation

- **Service**: `apps/api/src/services/high-risk.ts`
- **Function**: `isPolicyVersionHighRisk(params: { policyVersionId: string, targetCount?: number }): Promise<boolean>`
- **Integration Points**:
  - Policy version submission (`POST /policy-versions/:id/submit-approval`)
  - Policy version approval (`POST /policy-versions/:id/approve`, audit metadata only)
  - Deployment creation (`POST /deployments`)

#### High-Risk Heuristics Details

```typescript
// Example heuristics (simplified)
- ALL_INTERFACES + targetCount >= 20 → high-risk
- CIDR source like 0.0.0.0/0 or /0-/8 + sensitive ports (22, 5432, etc.) → high-risk
- TCP port 22/5432/3306/1433/3389 + source NOT management VLAN → high-risk
- protocol='any' + wide ports + very broad CIDR → high-risk
```

#### Benefits

- **Prevents Accidents**: Catches dangerous configurations before deployment
- **Enforces Review**: Ensures high-risk changes receive proper scrutiny
- **Audit Compliance**: High-risk status is logged for compliance tracking
- **Configurable Thresholds**: Heuristic thresholds can be tuned (currently 20 hosts for wide scope)

#### Database Schema

The `policy_versions` table includes:
- `is_high_risk` (boolean, default false) — Set automatically during submission

#### API Behavior

- **Submission**: Automatically sets `is_high_risk` flag
- **Approval**: Self-approval is blocked for all versions; the flag is only recorded
- **Deployment**: Re-evaluates the flag with the actual scope; high-risk deployments require a second approval before they start

### Policy Impact Analysis

Before approving a policy version, reviewers can analyze the impact of changes. (The navigation entry **Policy Impact Analysis** is a different feature: on-device policy testing, see [On-Device Policy Testing](#on-device-policy-testing).)

#### Features

- **Semantic Diff**: Compares current deployed version vs. candidate version
- **Rule Categorization**: Identifies:
  - New allows (rules being added that allow traffic)
  - Removed allows (rules being removed that previously allowed traffic)
  - New denies (rules being added that block traffic)
  - Removed denies (rules being removed that previously blocked traffic)
- **Per-Host Analysis**: Shows impact for sample hosts (1-3 hosts)
- **Summary Counts**: Quick overview of total changes

#### Usage

- **In the Approvals page**: lists all versions pending approval (policy set, version, rule count, submitter, date, change summary, approve/reject). Under **Impact Analysis (Optional)** for a version:
  1. Choose the version to compare against
  2. Choose sample hosts
  3. Click **Analyze Impact**
- **API**: `POST /api/policy-versions/:candidateVersionId/impact-diff`

#### Benefits

- **Confidence**: Understand changes before deployment
- **Risk Assessment**: Identify potential connectivity issues
- **Documentation**: See exactly what will change

### Host Readiness Verification

Before deploying, verify that hosts are ready to receive firewall policies.

#### Checks Performed

1. **Firewall Backend Detection**:
   - Uses privileged SSH to check active firewalld/UFW first; two active managers are an error
   - Falls back to installed nftables, then iptables, only when no native manager is active
   - Native readiness verifies Python 3, systemd, manager capabilities, IPv6 requirements, and absence of an old raw Segmentra policy

2. **Version Detection**:
   - Reads `nft --version` if available
   - Reads `iptables --version` if available

3. **Sudo Access Verification** (with the credential's privilege escalation mode):
   - Runs `id -u` and `nft list ruleset` / `iptables-save` in one `sudo sh -c` — `sudo -n` for *sudo without password*, `sudo -k -S -p ''` with the password on stdin otherwise — and requires uid 0
   - Classifies sudo refusals (`sudoError`): `password_required`, `wrong_password`, `tty_required`, `not_permitted`
   - Verifies `iptables-restore` availability if needed

4. **Kernel Support**:
   - Checks for `nf_tables` kernel module (for nftables)

5. **Auto-Detection**:
   - If host `firewall_backend` is set to "auto", updates it based on detection

#### Usage

- **Per-Host**: Click "Check Readiness" button in Inventory → Hosts
- **API**: `POST /api/host-readiness/hosts/:hostId/check`

#### Result Format

```typescript
{
  hostname: string;
  ready: boolean;
  backend: 'nftables' | 'iptables' | 'firewalld' | 'ufw' | 'unknown';
  nftVersion?: string;
  iptablesVersion?: string;
  sudoAccess: boolean;
  sudoMode: 'nopasswd' | 'password';
  sudoError?: 'password_required' | 'wrong_password' | 'tty_required' | 'not_permitted';
  kernelSupport: boolean;
  errors: string[];      // Critical issues preventing deployment
  warnings: string[];   // Non-critical issues (may still work)
}
```

### SSH Credential Resolution

Every SSH connection to a managed host (readiness, deployments, backend detection, drift checks, policy expiry, Firewall Learning, policy tests, Ansible runs) picks the credential the same way (`EFFECTIVE_CREDENTIAL_LATERAL` in `apps/api/src/services/ssh-credentials.ts`):

1. the credential **explicitly assigned** to the host (`hosts.ssh_credential_id`; set by an admin in Inventory → edit host, or by discovery for the hosts it imports)
2. a credential with scope `HOST` for that host
3. a credential with scope `TAG` for one of the host's tags
4. a credential with scope `VLAN` for the host's VLAN
5. a `GLOBAL` credential

Within one level the highest `priority` wins, then the newest credential. `NONE` ("not assigned") credentials are never chosen automatically; they are used by discovery target sets and for hosts they are explicitly assigned to. There is no fallback: if the chosen credential fails, Segmentra does not try the next one. The result is exposed as `effective_credential` on `/api/hosts` and shown in the **SSH credential** column of Inventory → Hosts.

**Privilege escalation** (`sudo_mode`, migration 029): `NOPASSWD` (`sudo -n`), `LOGIN_PASSWORD` (the login password of a password credential) or `SUDO_PASSWORD` (a separate stored password). Passwords are sent to `sudo -k -S` on stdin. Every root step runs as `sudo sh -c '…'`, so the account needs full sudo rights (`ALL`); `requiretty`, `su`/`doas` and similar are not supported. Key credentials may be passphrase-protected: the passphrase is checked with `ssh-keygen -y` when saving and supplied at connect time through an OpenSSH askpass helper (`ssh-agent` in the Ansible runner). sudo refusals are classified as `password_required`, `wrong_password`, `tty_required` or `not_permitted` (see [Host Readiness Issues](#host-readiness-issues)).

### Inventory Discovery

Inventory → **Discovery** (`/api/discovery/*`, `services/discovery.ts`, migration 027):

- A **profile** has 1–20 **target sets** (SSH credential + IPv4 CIDRs and/or VLAN subnets + SSH port), an optional schedule (every N minutes; none = manual) and a tag for new hosts (default `new-server`). Profiles are managed by admins; operators can **Run Now**
- Limits: IPv4 only, each network at most /20 (4096 addresses), at most 8192 addresses per run; checked when saving and again at run time
- A run TCP-probes the SSH port, logs in with the target set's credential, collects read-only facts (hostname, OS, firewall tool) and imports hosts that are not yet in inventory (matched by management IP); existing hosts are left untouched
- An imported host gets the profile's tag and, unless scope resolution already picks the same credential, an explicit assignment of the credential that logged in (`hosts.ssh_credential_id`). Credentials added inline in the UI are stored with scope `NONE` (unless made global)
- Each run stores counters and per-address results (`discovery_runs`); at most one run per profile is `RUNNING`. The scheduler runs every minute; runs interrupted by an API restart are marked `FAILED` at startup
- A credential used by a target set cannot be deleted (`409`)

### Scheduled Deployments

Deployments can be scheduled for future execution, useful for maintenance windows.

#### Features

- **Simple Scheduling**: Specify `scheduledAt` when creating a deployment; it is created with status `SCHEDULED`
- **Automatic Start**: A background job runs every minute and starts deployments whose `scheduled_at <= now()` (up to 10 per run, each claimed atomically)
- **Approval First**: A high-risk deployment (`requires_approval`) is only started once it has been approved
- **Manual Start Still Possible**: `POST /deployments/:id/start` starts a scheduled deployment early
- **No Calendar Logic**: Simple "tonight at 02:00" style scheduling, no recurrence

#### Usage

- **UI**: Use datetime picker in deployment creation form
- **API**: Include `scheduledAt: "2026-01-10T02:00:00Z"` in deployment creation payload
- **Format**: ISO 8601 datetime string
- **Starting**: Automatic at the scheduled time; or call `POST /deployments/:id/start` earlier

#### Implementation

- **Database**: `deployments.scheduled_at` field (added in migration 007)
- **Background Job**: Runs every minute in `apps/api/src/index.ts`
- **Processing**: `processScheduledDeployments()` in `apps/api/src/routes/deployments.ts` claims each due deployment and runs it; a start error marks the deployment `FAILED`

#### Example

```json
{
  "policyVersionId": "...",
  "mode": "FULL",
  "targetQuery": { "hosts": ["..."] },
  "scheduledAt": "2026-01-10T02:00:00Z"
}
```

### Host Policy Visualization

Segmentra provides a visual diagram showing all firewall policies applied to a specific host, making it easy to understand network connectivity at a glance.

#### Features

- **Interactive SVG Diagram**: Host displayed in center with sources arranged in a circle
- **Color-Coded Connections**: 
  - Green arrows for ALLOW connections
  - Red arrows for DENY connections (when enabled)
- **Connection Details**: 
  - Port numbers displayed on arrows
  - Protocol badges (T=TCP, U=UDP, I=ICMP)
  - Source type icons (🌐 CIDR, 🏷️ TAG, 🔌 VLAN, 🖥️ HOST)
- **Direction Filtering**: Toggle between IN, OUT, or BOTH directions
- **Denied Connections Toggle**: Show or hide denied connections
- **Source Resolution**: Automatically resolves TAG/VLAN/HOST sources to display names

#### Usage

- **Access**: Click "View Visualization" button in Inventory → Hosts table
- **Modal Dialog**: Opens full-screen modal with interactive diagram
- **Controls**: 
  - Direction dropdown: Filter by IN/OUT/BOTH
  - Checkbox: Show/hide denied connections
  - Close button: Return to inventory

#### Visual Layout

The diagram uses a circular layout algorithm:
- Host icon (🖥️) positioned at center
- Sources arranged in a circle around the host
- Radius automatically adjusts based on number of sources
- Arrows connect sources to host, showing connection direction
- Port numbers and protocol badges displayed along arrows

#### Implementation

- **Component**: `apps/web/src/components/HostPolicyVisualization.tsx`
- **Data Source**: Uses existing `GET /api/troubleshoot/hosts/:hostId/policies` endpoint
- **Source Resolution**: Fetches tags, VLANs, and hosts for name resolution
- **Rendering**: Pure SVG using React SVG elements (no external dependencies)
- **Layout Algorithm**: Trigonometric calculations for circular positioning

#### Example Visual Structure

```
        [🌐 Network Icon]
        "192.168.1.0/24"
            ↓ (green, port 22)
    [🖥️ Host Name] ← (red, port 80) [🏷️ Tag Icon "web-servers"]
            ↑ (green, port 443)
        [🔌 VLAN Icon]
        "VLAN-10"
```

#### Benefits

- **Quick Understanding**: See all connections to/from a host at a glance
- **Visual Debugging**: Identify connectivity issues visually
- **Policy Review**: Understand what policies are actually applied
- **Documentation**: Visual representation of network security posture

### Auto-Tagging Rule Engine

The auto-tagging engine automatically assigns tags to hosts based on configurable criteria, replacing manual-only tag management.

#### How It Works

1. **Define Rules**: Create tag rules with conditions (hostname matches regex, IP in CIDR range, VLAN membership, OS family, etc.)
2. **Evaluation**: Rules evaluate against all hosts, supporting AND/OR logic across conditions
3. **Auto-Assignment**: Matching hosts automatically receive the target tag with `source='rule'`
4. **Source Tracking**: Tags track their origin (manual, rule, or integration) — rule engine never overwrites manual tags
5. **Background Job**: Rules auto-evaluate every 5 minutes; on-demand evaluation also available

#### Supported Criteria

| Field | Operators |
|-------|----------|
| hostname | equals, not_equals, matches (regex), contains |
| mgmt_ip | equals, in_cidr |
| vlan_id, vlan_tag | equals, not_equals |
| os_family, environment | equals, not_equals, matches, contains |
| firewall_backend | equals, not_equals |
| tag | has_tag |

### Policy Templates

Reusable policy blueprints that accelerate policy creation.

- **Template Rules**: Mirror policy_rules schema exactly — same fields, same validation
- **Instantiation**: Creates real policy_set + policy_version + policy_rules in DRAFT status
- **Auto-Apply**: When enabled, creates a DRAFT policy set (once per template and tag) when hosts gain the template's target tag, whether by manual tagging, CSV import, tag rules or discovery
- **Compiler Unchanged**: Templates produce standard policy objects, so the compiler needs zero changes

### Visual Topology Design

A network topology canvas for designing policies visually.

- **Nodes**: Represent tags, VLANs, or CIDR groups
- **Edges**: Represent allowed or denied flows (protocol, ports, direction)
- **Auto-Discovery**: Builds initial topology from existing inventory (tags with hosts, VLANs with hosts) and deployed policies
- **Policy Generation**: Decomposes visual flows into policy sets with bidirectional rules — a connection between TAG-A and TAG-B on port 443 produces OUT rules on TAG-A and IN rules on TAG-B

### Policy Auto-Recommendations

After a firewall audit/learning session completes, the recommendation engine analyzes traffic flows and suggests policy rules.

#### Pipeline

1. **Input**: `CommunicationFlow[]` from the audit session's parsed log data
2. **IP Resolution**: Look up each IP → host → tags/VLAN; prefer TAG-based rules over raw CIDRs
3. **Flow Grouping**: Consolidate flows by destination port; merge sources sharing the same tag
4. **Confidence Scoring**: Based on flow frequency, known service ports (80/443/22/53/3306/5432), and whether both endpoints are in inventory
5. **Deduplication**: Skip rules that already exist in deployed policies for the host
6. **Output**: Ranked list of recommended ALLOW rules with confidence scores

#### Workflow

- Generate recommendations from a completed audit session
- Review each recommendation (accept/reject)
- Apply accepted recommendations → creates DRAFT policy version through normal approval workflow

### Integrations Framework

Adapter-based integration system for external security tools.

| Type | Purpose |
|------|---------|
| SIEM | Forward audit events via syslog; **Test** sends a real syslog message |
| SOAR | Configuration only (placeholder) |
| Vulnerability DB | Configuration only (placeholder); `host_vulnerabilities` is not populated by a real scanner sync |
| Threat Intelligence | AbuseIPDB: **Sync** fetches the blocklist into `threat_intel_entries` with confidence and expiry |

- **Implemented today**: only the AbuseIPDB threat-intel sync and SIEM syslog forwarding do real work; other types/providers store configuration and return placeholder results on sync
- **SIEM scope**: every `audit_events` row is forwarded exactly once, however it was inserted. An `AFTER INSERT` trigger (migration 031) runs `pg_notify('segmentra_audit', id)`; `services/siem-audit-listener.ts` LISTENs on a dedicated connection (reconnects with backoff), claims the row via `audit_events.siem_forwarded_at` (so multiple API replicas don't duplicate) and sends it through `services/siem-forwarder.ts`. A sweep forwards unclaimed events of the last 60 minutes at startup, after reconnects and every minute. Do not call `forwardAuditToSiem` for audit events yourself
- **Secrets**: API keys and tokens live in the integration's `config` and are masked in API responses
- **Event Trail**: sync/test operations are logged in `integration_events`

### On-Device Policy Testing

Structured pre-enforcement testing that validates a policy against real traffic before enforcement.

#### How It Works (vs. Firewall Learning)

| | Firewall Learning | Policy Testing |
|---|---|---|
| **Purpose** | Discover unknown traffic | Validate known policy |
| **Input** | No policy (observe everything) | Specific policy version |
| **Output** | Communication flows | Gap analysis report |
| **Result** | "What traffic exists?" | "Does my policy cover all traffic?" |

#### Analysis Categories

- **Matched Flows** (green): Traffic that matches an ALLOW rule — expected behavior
- **Unexpected Blocks** (red): Traffic that matches a DENY rule — would break active connections
- **Unmatched Flows** (yellow): Traffic with no matching rule — default-deny would block it
- **Coverage %**: Percentage of observed flows covered by ALLOW rules

#### Technical Reuse

- Compiler: `compileHostPolicy()` with `logOnlyMode: true`
- Executor: `deployLogOnlyPolicy()`, `restoreAuditSession()`, `retrieveAuditLogs()` from audit-ssh.ts
- Log Parser: `parseFirewallLogs()`, `groupCommunicationFlows()`
- Background Job: Expired test sessions auto-stopped every 1 minute

### Docker Swarm and Docker-published ports

Swarm nodes are managed as ordinary hosts over SSH; there is no Docker API integration. Host columns `swarm_cluster`, `swarm_role`, `swarm_addr`, `swarm_encrypted_overlay` and `docker_published_ports` (migration 036) feed the compiler through `apps/api/src/services/swarm.ts` (`getDockerCompileInput`), which every `compileHostPolicy` call site spreads into its input: the peers are the other enabled hosts with the same swarm name, addressed by `swarm_addr` or the management IP.

- The compiler puts the Swarm cluster ports (2377/tcp on managers, 7946/tcp+udp, 4789/udp, optionally ESP) into the baseline of the input chain (`SEGMENTRA-IN`, or the nftables `input` chain), ahead of the policy rules.
- With `docker_published_ports` the forward chain (`SEGMENTRA-FWD`, or the nftables `forward` chain) gets the inbound rules again, matched on `conntrack --ctstate DNAT --ctorigdstport` (nft: `ct status dnat`, `ct original proto-dst`), then an exemption for Docker's own bridges and a default verdict. Docker publishes ports with NAT, so that traffic is forwarded and never reaches `INPUT`.
- The iptables script keeps a second jump `DOCKER-USER -> SEGMENTRA-FWD` (only when the fragment carries `segmentra:published_default`), because Docker re-inserts its own `DOCKER-USER` / `DOCKER-INGRESS` jumps at the top of `FORWARD` whenever a service publishes a port. Apply, remove, backup/restore and persistence (the saved file declares `DOCKER-USER`, since `iptables-restore` runs before Docker adopts it) manage that jump, and drift detection reports a missing jump as "not present".
- firewalld hosts reject both settings and UFW hosts reject published-port enforcement at compile time.

See [docker-swarm.md](docker-swarm.md) for settings, limitations and what is not tested, and `tests/swarm-lab/` for the Docker Desktop lab.

### Kubernetes Microsegmentation

Kubernetes NetworkPolicy management through the K8s API (`apps/api/src/services/k8s-client.ts`, a small HTTPS client without extra dependencies).

Current state (see also [kubernetes.md](kubernetes.md)):

- **Clusters**: cluster records (API server URL, auth type, CNI, namespace) with credentials stored encrypted in `secret_store` (types `K8S_CREDENTIALS`, `TLS_CA_CERT`, AES-256-GCM like SSH/LDAP secrets; never returned by the API). A kubeconfig is parsed in memory per call; file paths, exec plugins and auth providers are refused. API server addresses in the link-local/cloud-metadata ranges are blocked. **Test connection** checks the credentials; workload **Sync** (discovery) is not implemented (`501`). Workloads are registered by hand
- **Tag mapping**: workloads (namespace, kind, name, pod labels) are registered with `POST /k8s/clusters/:id/workloads` and mapped to Segmentra tags (`POST /k8s/workloads/:id/map-tag`). A TAG rule source yields `ipBlock` peers for the tag's hosts plus `namespaceSelector` + `podSelector` peers for its workloads
- **Generate NetworkPolicy**: `POST /k8s/clusters/:id/deploy-policy` translates an `APPROVED`/`DEPLOYED` policy version into an **Ingress-only** NetworkPolicy manifest (`ipBlock` sources, ports); DENY, FORWARD, ICMP and other rules that cannot be expressed are skipped with warnings. The manifest (labelled `app.kubernetes.io/managed-by: segmentra`) is stored in `k8s_network_policies` with its warnings. `POST /k8s/clusters/:id/network-policies/:npId/apply` (server-side apply, optional dry run), `/check` (drift: `IN_SYNC` / `DRIFTED` / `MISSING`) and `/remove` act on the cluster; rows move through `GENERATED`, `APPLIED`, `FAILED`, `REMOVED` and `SUPERSEDED` (older rows of the same name once a newer one is applied). Apply and remove refuse to touch a same-named policy that lacks the managed-by label

### OT/IoT Microsegmentation

Passive traffic discovery and upstream enforcement for devices that cannot run agents.

#### Architecture

```
┌─────────────────┐     NetFlow/sFlow     ┌──────────────────┐
│ Network Switches │ ──────────────────► │ Flow Collectors  │
│ (SPAN/Mirror)    │                      │ (Segmentra)      │
└─────────────────┘                      └────────┬─────────┘
                                                   │ Observed Flows
                                                   ▼
                                         ┌──────────────────┐
                                         │ IoT Asset        │
                                         │ Inventory        │
                                         │ + Fingerprinting │
                                         └────────┬─────────┘
                                                   │ Policy Rules
                                                   ▼
┌─────────────────┐     SSH (ACLs)       ┌──────────────────┐
│ IoT/OT Devices  │ ◄────────────────── │ Enforcement      │
│ (PLC, HMI, etc) │  (via switch/gw)    │ Points           │
└─────────────────┘                      └──────────────────┘
```

- **Separate from Hosts**: `iot_assets` table is distinct from `hosts` — fundamentally different devices
- **Zone Model**: Text field for Purdue levels, flexible for non-standard OT network layouts
- **Gateway enforcement (implemented)**: a Linux host in inventory (typically tagged `iot-gateway`) is assigned as the gateway of one or more assets (`iot_asset_gateways`). Policies for the gateway can contain `FORWARD` rules with an explicit destination (`destination_type` `CIDR|TAG|VLAN|HOST|IOT_ASSET`). On the gateway, forwarded traffic **to a protected asset** is dropped unless a `FORWARD` rule allows it; other routed traffic passes unchanged. See [Generated firewall rules](#generated-firewall-rules) and [iot.md](iot.md)
- **Flow collectors / enforcement points**: records and ACL texts can be stored; Segmentra does not run a NetFlow/sFlow listener or push ACLs to switches
- **Baseline**: Snapshot current traffic as "allowed" for anomaly detection

### Policy Expiry

Optional time-limited deployments that automatically expire after a specified date.

#### How It Works

1. When creating a deployment, optionally set **Expires At** and **On Expiry** action (`expiresAt`, `expiryAction`)
2. A background job (`services/deployment-expiry.ts`) runs every minute; each expired deployment is claimed atomically (`expired = false → true`) so it is processed once
3. The deployment's status becomes `EXPIRED`, the chosen action runs as "system" (no actor in the audit log), the result is stored in `deployments.expiry_outcome` (per host in `deployment_hosts.expiry_*`), and a `POLICY_EXPIRED` notification and audit event are written
4. A 24-hour warning notification (`POLICY_EXPIRING_SOON`) is sent before expiry (once per deployment)

#### Expiry Actions

| Action | Behavior |
|--------|----------|
| **Notify Only** (`NOTIFY_ONLY`) | Notification only; the rules stay active on the hosts. |
| **Remove** (`REMOVE`) | Over SSH, removes Segmentra's `table inet segmentra` or `SEGMENTRA-*` chains (and jumps) from every host that still runs this deployment's policy; other tools' rules are untouched. Hosts are then unmanaged (drift status `unknown`). |
| **Revert** (`REVERT`) | Creates and starts a new system deployment (`revert_of_deployment_id`) of the previous successfully deployed version of the same policy set, to the hosts that ran it. No new approval is needed, but that version must still be `APPROVED` or `DEPLOYED`. |

Failed REMOVE/REVERT actions are recorded and notified but not retried automatically.

#### Use Cases

- Temporary vendor access (30-day window)
- Maintenance window policies (remove restrictive rules after maintenance)
- Compliance-driven reviews (force policy expiry to ensure periodic review)

### Notification System

Multi-channel alerting for security events and operational changes.

#### Supported Channels

| Channel Type | Configuration | Example |
|-------------|---------------|---------|
| **Slack** | `{ "webhookUrl": "https://hooks.slack.com/services/..." }` | Posts formatted messages with color-coded severity |
| **Webhook** | `{ "url": "https://...", "authHeader": "Bearer ..." }` | POSTs JSON payload to any HTTP endpoint |
| **Email** | `{ "to": "admin@company.com" }` | Not implemented: delivery fails with an error and is logged as `FAILED` (no SMTP client) |

#### Event Types

| Event | Triggered When |
|-------|---------------|
| `POLICY_SUBMITTED` | Policy version submitted for approval |
| `POLICY_APPROVED` | Policy version approved |
| `POLICY_REJECTED` | Policy version rejected |
| `DEPLOYMENT_STARTED` | Deployment execution begins |
| `DEPLOYMENT_COMPLETED` | Deployment finishes successfully |
| `DEPLOYMENT_FAILED` | Deployment fails |
| `COMPLIANCE_DRIFT` | Host firewall rules don't match deployed policy |
| `POLICY_EXPIRING_SOON` | Deployment within 24 hours of expiry |
| `POLICY_EXPIRED` | Deployment has expired |
| `EXCESSIVE_RULES_DETECTED` | Security audit found critical/high findings |
| `AUDIT_RESTORE_FAILED` | A Firewall Learning session could not restore the host's rules |

`COMPLIANCE_DRIFT` can be subscribed to, but no code currently emits it (compliance checks are on demand and do not notify).

#### Design

- **Fire-and-forget**: Notification failures never block core operations (logged but not thrown)
- **Outbound URL checks**: webhook/Slack URLs that resolve to loopback, link-local or cloud metadata addresses are refused unless `SEGMENTRA_ALLOW_PRIVATE_WEBHOOKS=true`
- **Deduplication**: Expiry warnings are sent once per 24-hour period per deployment
- **Full log**: Every notification attempt is recorded in `notification_log` with status tracking
- **Rule filters**: `notification_rules.filter` is stored but not applied; a subscribed channel receives every event of that type

### Security Posture Audit

On-demand scanning of all deployed policies for excessive permissions and compliance risks.

#### What It Checks

| Category | Severity | What It Detects |
|----------|----------|----------------|
| Wide Open Sensitive Port | Critical | SSH, RDP, database ports open to 0.0.0.0/0 |
| Wide Open All Ports | Critical | All ports open to any source |
| Very Broad Source CIDR | High | Source ranges /0 to /8 (millions of IPs) |
| Any Protocol / Any Port | High | protocol=any with no port restriction |
| ALL_INTERFACES + Broad Source | High | Every interface exposed with wide-open rules |
| Duplicate Rules | Low | Same rule in multiple policy sets |
| Unmanaged Hosts | Medium | Enabled hosts with no successful deployment |
| Stale Policies | Medium | Deployments older than 90 days without update |

#### Auto-Notification

Scans run on demand (`POST /security-audit/scan`, `operator`/`admin`); each result is stored in `security_audit_results` and the latest one is shown to all roles. When the scan finds critical or high severity findings, it sends an `EXCESSIVE_RULES_DETECTED` notification to all subscribed channels.

### Role-Based Access Control (RBAC)

Segmentra enforces role-based access control at both the API level (backend) and the UI level (frontend).

#### Roles

| Role | Description |
|------|-------------|
| **viewer** | Read-only access to inventory, policies, deployments, troubleshooting lookups, IoT, Kubernetes, security audit results and the audit log. Cannot create, modify or deploy anything. |
| **operator** | Operational access: manage inventory, tags, tag rules and policies, run deployments, run discovery profiles, troubleshooting tools, Firewall Learning, policy tests, compliance/readiness checks, and manage IoT assets. |
| **approver** | Read access plus approve/reject policy versions and high-risk deployments, and run policy tests (Policy Impact Analysis). Cannot create policies, manage inventory or run deployments. |
| **admin** | Everything, including users, LDAP, SSH credentials and host credential assignment, discovery profiles, integrations, notifications, Kubernetes clusters, flow collectors, enforcement points and system settings. |

Users can hold several roles; permissions add up.

#### Permission Matrix

The API (`requireRole` calls) is authoritative; the UI hides what a role cannot use.

| Action | Viewer | Operator | Approver | Admin |
|--------|--------|----------|----------|-------|
| **View** dashboard, inventory, policies, deployments, templates | Yes | Yes | Yes | Yes |
| **View** troubleshoot lookups, IoT, K8s, topology (API), discovery profiles/runs | Yes | Yes | Yes | Yes |
| **View** security audit results and the audit log | Yes | Yes | Yes | Yes |
| **View** flow collectors | Yes | Yes | - | Yes |
| **View** pending approvals (Approvals page) | - | - | Yes | Yes |
| **Create/edit** hosts, tags, VLANs, interfaces, tag rules | - | Yes | - | Yes |
| **Assign** an SSH credential to a host (`sshCredentialId`) | - | - | - | Yes |
| **Create/edit** discovery profiles | - | - | - | Yes |
| **Run** discovery profiles | - | Yes | - | Yes |
| **Create/edit** policy sets, versions, rules, templates, topology views | - | Yes | - | Yes |
| **Submit** policy versions for approval | - | Yes | - | Yes |
| **Approve/reject** policy versions (not your own) | - | - | Yes | Yes |
| **Render** per-host ruleset preview | - | Yes | - | Yes |
| **Create/start/pause/resume/stop/retry** deployments | - | Yes | - | Yes |
| **Approve** high-risk deployments (not your own) | - | - | Yes | Yes |
| **Check** compliance (drift) and host readiness | - | Yes | - | Yes |
| **Run** Firewall Learning and communication simulation | - | Yes | - | Yes |
| **Run** policy tests (Policy Impact Analysis) | - | Yes | Yes | Yes |
| **Generate/apply** policy recommendations | - | Yes | - | Yes |
| **Manage** IoT assets and gateway assignments | - | Yes | - | Yes |
| **Sync** K8s clusters, map workloads, generate NetworkPolicy | - | Yes | - | Yes |
| **Record** ACLs on enforcement points | - | Yes | - | Yes |
| **Run** security audit scans | - | Yes | - | Yes |
| **Manage** K8s clusters, flow collectors, enforcement points | - | - | - | Yes |
| **Manage** users (create, edit, delete, reset password) | - | - | - | Yes |
| **Configure** LDAP/AD settings and AD group mapping | - | - | - | Yes |
| **Manage** SSH credentials | - | - | - | Yes |
| **Manage** integrations (SIEM, SOAR, etc.) | - | - | - | Yes |
| **Configure** notifications | - | - | - | Yes |
| **Configure** deployment executor, management VLAN | - | - | - | Yes |

#### Enforcement

- **API Level**: Routes use `requireAuth` (JWT validation) and `requireRole(...)` (on the route or the whole router). Unauthorized requests return 401 (no or invalid token) or 403 (insufficient role). Exceptions: `/health`, `/auth/login`, `/auth/logout` and `/admin/bootstrap` need no token; `/dashboard/stats` and `/auth/me` need only a valid token.
- **UI Level**: The sidebar navigation hides links the user cannot access. Route-level `RequireRole` components block direct URL access and show an "Access Denied" message.
- **Authentication**: JWT tokens (HS256, 12 h) are stored in browser localStorage (`segmentra_token`) and sent as `Authorization: Bearer <token>`. They contain `sub` (username) and `roles`, but `requireAuth` re-reads the user's roles and `is_active` from the database on every request: role changes apply immediately and a deactivated user is rejected while deactivated. Changing or resetting a password does not revoke existing tokens (they stay valid until they expire).
- **Separation of Duties**: Nobody (admins included) can approve a policy version they created, edited or submitted, or a high-risk deployment they created.

#### Local Users vs LDAP Users

| Feature | Local Users | LDAP Users |
|---------|------------|------------|
| **Created by** | Admin via Admin page | Automatically on first LDAP login |
| **Password stored** | bcrypt hash in `users.password_hash` | Not stored — authenticated against AD |
| **Roles assigned** | Manually by admin | Via AD group → role mappings |
| **Password reset** | Admin resets via UI | User resets in Active Directory |
| **Displayed as** | "Local" in user list | "LDAP" in user list |

---

## Firewall Backend Configuration

Segmentra supports multiple firewall backends to accommodate different Linux distributions and system configurations. Each host can be configured with a specific firewall backend, and the system automatically handles mixed environments during deployments.

### Firewall Backend Options

- **`auto`**: Detected over privileged SSH during the deployment's checking phase (same check as **Check Readiness**); active firewalld/UFW take precedence over installed nftables/iptables. The result is stored on the host. Detection failure fails the host's deployment; two active managers are an error. Hosts without a backend value are treated as `auto`.
- **`nftables`**: Uses nftables directly, with a dedicated Segmentra table.
- **`iptables`**: Uses iptables (legacy Linux firewall). Required for older systems that don't support nftables.
- **`firewalld`**: Uses permanent native policies and ordered rich rules, requiring the native policy API and nftables backend. Supports all-interface rules; unsupported interface scopes and learning mode fail before changing rules.
- **`ufw`**: Uses marked blocks in UFW's IPv4/IPv6 before-rules framework. Requires active UFW with IPv6 enabled; learning mode is rejected.

See [native firewall managers](firewall-managers.md) for permanent storage, boot-service verification, rollback/removal, drift handling, native verdict semantics, and test scope.

### How Mixed Backend Deployments Work

When deploying policies to multiple hosts with different firewall backends (e.g., 200 hosts where 10 use `iptables` and 190 use `nftables`), Segmentra handles this automatically:

1. **Individual Policy Compilation**: Each host's policy is compiled separately based on its configured `firewall_backend` field:
   - Hosts with `nftables` (or `auto` detected as nftables) → `.nft` file
   - Hosts with `iptables` → `.iptables` file (IPv4) plus `.ip6tables` (IPv6) when needed
   - Hosts with `firewalld` → `.firewalld.json` manifest containing permanent native policy XML
   - Hosts with `ufw` → `.ufw.json` manifest containing both family before-rule fragments

2. **Separate Policy Files**: Each host receives its own policy file with the appropriate format:
   - `hostname.nft` for nftables hosts
   - `hostname.iptables` for iptables hosts
   - `hostname.firewalld.json` / `hostname.ufw.json` for native-manager hosts

3. **Unified Deployment**: All hosts are included in a single deployment operation:
   - The Ansible inventory includes all hosts regardless of backend
   - Each host's inventory entry points to its specific policy file format
   - The playbook applies each host's file with the matching tool (`nft -f`, or `iptables-restore --noflush` / `ip6tables-restore --noflush`); the SSH Direct executor does the same per host
   - Native managers use the one-shot Python helper; Ansible delegates to `apply-manager.yml`, while SSH Direct uploads and executes the same native artifact

4. **Independent Status Tracking**: Each host's deployment status is tracked independently, so you can see which hosts succeeded or failed regardless of their firewall backend.

### Example: Mixed Environment Deployment

```
Deployment: Policy Set "Web Servers" v2
Target: 200 hosts (mixed backends)

Bundle Contents:
├── host_rules/
│   ├── web-01.nft          (nftables host)
│   ├── web-02.nft          (nftables host)
│   ├── web-03.iptables     (iptables host)
│   ├── web-04.nft          (nftables host)
│   └── ... (197 more files)

Ansible Inventory:
[all]
web-01 ansible_host=... segmentra_policy_file=/bundles/xxx/host_rules/web-01.nft
web-02 ansible_host=... segmentra_policy_file=/bundles/xxx/host_rules/web-02.nft
web-03 ansible_host=... segmentra_policy_file=/bundles/xxx/host_rules/web-03.iptables
web-04 ansible_host=... segmentra_policy_file=/bundles/xxx/host_rules/web-04.nft
...
```

**Result**: All 200 hosts receive the correct firewall rules for their backend type in a single deployment operation, with no conflicts or manual intervention required.

### Best Practices

- **Use `auto` for most hosts**: the backend is detected on the first deployment (or readiness check) and stored.
- **Set `iptables` explicitly**: Only when you know a host requires iptables (older systems, compatibility requirements).
- **Set `nftables` explicitly**: When you want to ensure nftables is used even if the system might support both.
- **Use native `firewalld`/`ufw` on manager-controlled hosts**: preserve native boot persistence instead of adding a conflicting raw boot service. Remove any old raw Segmentra policy before switching.

### Generated Firewall Rules

Segmentra only manages its own objects, so rules of Docker, Kubernetes, fail2ban or admins are left alone:

- **nftables**: one table, `table inet segmentra` (IPv4 + IPv6). Each apply deletes and recreates only that table. Chains: `input` (policy `drop`; loopback, established/related, the management SSH baseline and the policy rules accept), `output` (policy `accept`) and, only when the host has `FORWARD` rules or protected devices, `forward` (policy `accept`, traffic to protected devices is dropped unless a rule allows it). A drop in Segmentra's table is final; an accept does not override drops in other tables.
- **iptables**: an `iptables-restore --noflush` fragment that replaces only the chains `SEGMENTRA-IN`, `SEGMENTRA-OUT` and (when forwarding is filtered) `SEGMENTRA-FWD`; the executor inserts jumps at the top of `INPUT`, `OUTPUT` and `FORWARD`. "Allow" in these chains is `RETURN` (back to the built-in chain, so later rules of other tools still apply); only Segmentra's final `DROP` in `SEGMENTRA-IN` (and drops to protected devices in `SEGMENTRA-FWD`) is terminal. `SEGMENTRA-OUT` and `SEGMENTRA-FWD` end with `RETURN`. Built-in chain policies are not changed. IPv6 uses a separate `ip6tables` fragment.
- **Baseline**: loopback, established/related and SSH to the host's port from the management VLAN subnet (from anywhere if no management VLAN is set) are always allowed before policy rules.
- **Backups/restores** (rollback, lockout auto-revert, Firewall Learning, policy tests, `scripts/restore-previous-policy.sh`) cover only this table / these chains and jumps. Hosts last deployed by an older version that replaced the whole iptables `filter` table are restored that way once; redeploying moves them to the chain design.

### Reboot persistence

Native firewalld/UFW deployments use permanent manager configuration and require successful boot-service and live-state verification; persistence failure triggers rollback. The following distribution-specific shell-script behavior describes the raw nftables/iptables backends. See [native firewall managers](firewall-managers.md) for the native-manager paths.

Deployments load rules into the running kernel only; persistence uses the **distribution's own mechanism**, so nothing of Segmentra runs at boot. The host scripts (`segmentra-nft.sh` / `segmentra-iptables.sh`, modes `persist`, `unpersist`, `check`; shared shell in `packages/executor/src/persist-scripts.ts`) detect the distribution from `/etc/os-release` (`ID` / `ID_LIKE`) and copy Segmentra's **live** state into the boot configuration:

| | Debian / Ubuntu | RHEL family (RHEL, Rocky, Alma, CentOS Stream, Fedora) |
|---|---|---|
| nftables | `/etc/nftables.d/segmentra.nft` + one `include` line in `/etc/nftables.conf`; `systemctl enable nftables` | `/etc/nftables/segmentra.nft` + one `include` line in `/etc/sysconfig/nftables.conf`; `systemctl enable nftables` unless firewalld is active/enabled |
| iptables | Segmentra's lines merged into `/etc/iptables/rules.v4` / `rules.v6` (iptables-persistent); `systemctl enable netfilter-persistent` | merged into `/etc/sysconfig/iptables` / `ip6tables` (iptables-services); `systemctl enable iptables ip6tables` unless firewalld is active/enabled |

- The nft file is `nft -s list table inet segmentra` behind `add table inet segmentra` + `delete table inet segmentra`, so it can be loaded at boot or repeatedly. A missing `nftables.conf` is created with only a shebang and the include (no `flush ruleset`).
- The iptables merge replaces only `:SEGMENTRA-IN/OUT/FWD` declarations, `-A SEGMENTRA-*` rules and the `-A INPUT/OUTPUT/FORWARD -j SEGMENTRA-*` jumps in the `*filter` section (jumps first in their chains); every other line stays byte-identical. Docker/Kubernetes chains are never written by Segmentra.
- Services are only enabled, never started/restarted. Packages are never installed and firewalld is never disabled: missing pieces are reported as warnings (`firewalld_active`, `no_nftables_service`, `iptables_persistent_missing`, `iptables_services_missing`, `unsupported_distro`).
- **When:** SSH Direct persists after the reachability check and the cancelled auto-revert (the final state); the auto-revert, the apply-failure rollback, Firewall Learning / policy-test restores and `scripts/restore-previous-policy.sh` re-sync it to the restored state; expiry REMOVE removes it. Firewall Learning persists the enforced policy at session start, and a live log-only policy is never persisted, so a reboot during a session comes back enforced. The Ansible playbook runs the same `persist` step (and re-syncs in its `rescue`); the API then records the status with a read-only `check`.
- **Reporting:** `SshExecutionResult.persistence` → `deployment_hosts.persistence_*` ("Survives reboot" column on the deployment page); readiness returns `persistence: { distro, method, available, status, warnings, notes }`; compliance returns `persistence: { status, state: in_sync|differs|missing|none|learning, method, warnings }` and notes when the boot configuration differs from compliant running rules.

### Async Deployment Execution

Deployment execution is fully asynchronous with real-time progress tracking.

#### Flow

1. **POST /deployments/:id/start** returns `202 Accepted` immediately
2. Execution runs in the background via `setTimeout(async () => {...}, 0)`
3. Progress is tracked in `deployments.progress` (JSONB column)
4. UI polls `GET /deployments/:id` and displays a progress bar

#### Phases

| Phase | Description | Progress Bar Color |
|-------|------------|-------------------|
| `queued` | Reset by retry-failed, waiting for start | - |
| `starting` | Initializing deployment | - |
| `checking` | Pre-flight SSH checks (backend auto-detection) | Amber |
| `deploying` | Pushing firewall rules to hosts | Green |
| `complete` | All hosts processed | Green (100%) |
| `failed` | Execution error | Red |

#### Progress JSON Format

```json
{
  "phase": "checking",
  "checked": 5,
  "totalToCheck": 20,
  "deployed": 0,
  "totalToDeploy": 20,
  "currentHost": "web-prod-03.acme.corp",
  "warnings": []
}
```

#### Stop/Pause Behavior

The SSH executor checks between hosts whether it should continue. **Pause** stops before the next host and leaves the remaining hosts `PENDING` (deployed on **Resume**); **Stop** marks the remaining hosts `SKIPPED`. A host that is being deployed always finishes and records its real result. With the Ansible executor the playbook run is not interrupted.

#### Canary / Progressive Rollout (SSH Direct)

Hosts are deployed one by one in hostname order:

- **CANARY**: the first `canarySize` hosts (default 1) are the canary; if one of them fails, the remaining hosts are not deployed
- **PROGRESSIVE**: hosts go in batches of `batchSize` (default 5); if a host fails, the rollout stops at the end of that batch
- **FULL**: all hosts, no gate

Hosts not deployed because of a halted rollout are `SKIPPED` with a "Rollout halted:" message and are picked up again by `retry-failed`. The Ansible executor ignores these gates.

### Login Security

#### Rate Limiting

The login endpoint (`POST /api/auth/login`) implements in-memory rate limiting of **failed** attempts:
- **10 failed attempts** per client IP per **15-minute window** (a successful login resets the counter)
- After that: `429` with `too_many_attempts` ("Too many failed login attempts. Please try again in 15 minutes.")
- The client IP is `req.ip`; behind a reverse proxy set `TRUST_PROXY` so it is the real client address

#### Username Enumeration Prevention

All login failure cases return the same generic error response:
```json
{ "error": "invalid_credentials", "message": "Invalid username or password" }
```

This prevents attackers from distinguishing between:
- Non-existent username
- Disabled account
- Wrong password
- No roles assigned
- LDAP not configured

#### Token Storage

JWT tokens are stored in browser `localStorage`. This is a common pattern but means any XSS vulnerability could steal tokens. For high-security deployments, consider:
- Short token expiry (currently 12 hours, configurable in `apps/api/src/services/jwt.ts`)
- Content Security Policy (CSP) headers to mitigate XSS
- Regular security audits of frontend dependencies

---

## Troubleshooting

### Communication Simulation

`POST /troubleshoot/simulate-communication` (`operator`, `admin`; UI: **Troubleshoot**) predicts whether traffic between two IP addresses would be allowed by the policies currently enforced. It is a guidance tool, not a packet-level replay.

#### How Simulation Works

1. **Input**: `sourceIp`, `destIp` (IPv4 or IPv6), `protocol` (`tcp`, `udp`, `icmp`; default `tcp`), optional `destPort`
2. **Host resolution**: finds inventory hosts whose management IP equals the source / destination IP
3. **Enforced policy**: for each managed host, the version of its most recent successful deployment (`deployment_hosts.status = 'SUCCEEDED'`, version still `APPROVED`/`DEPLOYED`) — each deployment replaces Segmentra's whole table, so only that version counts
4. **Source host (outbound)**: `OUT`/`BOTH` rules are evaluated in `order_index` order, first match wins; default accept
5. **Destination host (inbound)**: the management SSH baseline is applied first (tcp to the host's SSH port from the management VLAN, or from anywhere if none is configured); then `IN`/`BOTH` rules, first match wins; default drop
6. **Gateway (forwarded)**: if the destination is an IoT asset assigned to a gateway host, that gateway's `FORWARD` rules are evaluated (first match wins) and traffic no rule allows is dropped. The simulator assumes the traffic is routed through the gateway
7. **Result**: blocked if any side denies, with the deciding rule, all matching rules and explanatory notes. Hosts that are not in inventory or have no deployed policy are treated as not filtering

Rule matching resolves `CIDR`, `TAG`, `VLAN` and `HOST` sources to addresses at simulation time. A rule with ports only matches when a destination port is given.

**Limitations**:
- Interface scoping is not modeled (rules are evaluated as if they applied to every interface)
- Connection state (established/related) and rules of other tools on the host are not modeled
- Only hosts whose management IP equals the given address are recognized

#### Use Cases

- **Pre-deployment Validation**: Test if a new policy would block critical communication paths
- **Connectivity Troubleshooting**: Determine why two hosts cannot communicate
- **Policy Audit**: Verify that deployed policies match intended security posture

### Compliance & Drift Detection Issues

#### Compliance Check Fails with SSH Error
**Symptom**: Compliance check returns "error" status with SSH connection failure

**Causes**:
- No SSH credential applies to the host (none assigned, none matching its host/tag/VLAN scope and no global credential)
- Host is unreachable or SSH port incorrect
- SSH key authentication failure
- Host firewall blocking SSH access

**Solutions**:
1. Check the host's **SSH credential** column in Inventory → Hosts (`effective_credential`) and the credentials in Admin → SSH Credentials
2. Test SSH manually: `ssh -i <key> user@host`
3. Check host `ssh_port` configuration matches actual port
4. Verify host is reachable: `ping <host_ip>`
5. Check host firewall isn't blocking SSH from Segmentra server

#### Compliance Shows "Unknown" Status
**Symptom**: Host shows "Unknown" compliance status

**Causes**:
- Host has never had a successful deployment
- The last successful deployment was made by an older version (baseline without the `v2:` prefix, or no `applied_live_hash`)
- The policy was removed by an expiry `REMOVE` action

**Solutions**:
1. Deploy (or redeploy) a policy to the host successfully
2. Check deployment history for the host

#### Compliance Shows "Drifted" Status
**Symptom**: Host shows "Drifted" status (hash mismatch)

**Causes**:
- Manual changes to `table inet segmentra` or the `SEGMENTRA-*` chains (or their jumps) on the host
- Segmentra's table/chain or jump was deleted (e.g. `nft flush ruleset`, firewall service restart)
- Policy was rolled back manually (e.g. `scripts/restore-previous-policy.sh`)

Rules other tools add outside Segmentra's table/chains do not cause drift.

**Solutions**:
1. Review current rules on host: `sudo nft list table inet segmentra` or `sudo iptables-save | grep SEGMENTRA`
2. Compare to expected policy: Use policy render endpoint
3. Redeploy the policy to restore compliance
4. Investigate what caused the drift (manual changes, other tools, etc.)

### Host Readiness Issues

#### Readiness Check Fails: sudo errors
**Symptom**: Readiness check shows `sudoAccess: false`; `sudoError` and the error text say why. The same messages appear on failed deployments ("sudo failed: …").

| `sudoError` | Error text (abridged) | Fix |
|---|---|---|
| `password_required` | sudo on this host requires a password for "user", but the SSH credential is set to "sudo without password" | Set the credential's *Privilege escalation* to *sudo with the login password* / *sudo with a separate password*, or give the account `NOPASSWD: ALL` |
| `wrong_password` | sudo rejected the configured sudo password (incorrect password) | Update the credential's sudo password (or the login password for *sudo with the login password*) |
| `tty_required` | sudo on this host requires a terminal (sudoers "Defaults requiretty") | Add `Defaults:<user> !requiretty` to a file in `/etc/sudoers.d/` |
| `not_permitted` | "user" is not allowed to run "sh" as root via sudo | Give the account full sudo rights (`ALL`); a list of firewall commands is not enough |

**Other checks**:
1. Verify on the host as the SSH user: `sudo -k -S -p '' sh -c 'id -u'` (enter the password; prints `0`) or `sudo -n sh -c 'id -u'` for passwordless sudo
2. Example sudoers entries (`/etc/sudoers.d/segmentra`): `segmentra_user ALL=(ALL) ALL` (sudo with password) or `segmentra_user ALL=(ALL) NOPASSWD: ALL`

#### Readiness Check Fails: "SSH connection failed: … Permission denied (publickey) (the key was rejected or its passphrase is wrong …)"
**Cause**: the key is not authorized for the user, or the stored key passphrase no longer matches (e.g. the key was re-encrypted). Passphrases are validated when a credential is saved; update it with `PUT /ssh-credentials/:id` `{ passphrase }`.

#### Readiness Check Shows "nf_tables kernel module not loaded"
**Symptom**: Warning about kernel module (but may still work)

**Causes**:
- Kernel module not loaded (but may load on demand)
- Older kernel without nftables support

**Solutions**:
1. Check if module loads automatically: `modprobe nf_tables`
2. If nftables works, this is just a warning (can be ignored)
3. If nftables doesn't work, use iptables backend instead

### Safety Check Issues

#### Deployment Blocked: "SSH access would be blocked"
**Symptom**: FULL mode deployment fails with safety check error

**Causes**:
- Policy rules don't include SSH allow rule from management VLAN
- Management VLAN not configured
- Policy has DENY rules that block management CIDR before ALLOW rules

**Solutions**:
1. Verify management VLAN is configured: `GET /api/admin/management-vlan-setting`
2. Review policy rules - ensure SSH allow rule exists for management CIDR
3. Check rule ordering - DENY rules before ALLOW rules will block
4. Use CANARY or PROGRESSIVE mode if you need to test (warns but allows)
5. Review compiled policy: `GET /api/policy-versions/:id/render/host/:hostId`

#### Safety Check Warning: "Your IP may be blocked"
**Symptom**: Warning that current user's IP would be blocked

**Causes**:
- Policy has DENY rules matching user's source IP
- User is deploying from outside management VLAN

**Solutions**:
1. Verify you're deploying from management network
2. Review DENY rules in the policy
3. Consider using CANARY mode to test safely
4. Ensure management VLAN CIDR includes your IP

### Scheduled Deployment Issues

#### Scheduled Deployment Not Starting
**Symptom**: Deployment with `scheduled_at` never starts

**Causes**:
- `scheduled_at` is still in the future (the UI sends the browser's local time)
- The deployment is high-risk and has not been approved yet (`requires_approval`)
- The API process is not running (the scheduler runs inside it)

**Solutions**:
1. Check API logs for `[Scheduled Deployments]` lines
2. Approve the deployment (`approver`/`admin`, not its creator)
3. Start it manually if needed: `POST /api/deployments/:id/start`

#### Scheduled Deployment Starts Immediately
**Symptom**: Deployment starts even though `scheduled_at` should be in the future

**Causes**:
- The time was interpreted in a different time zone than intended
- Someone used **Start** (`POST /deployments/:id/start` also starts `SCHEDULED` deployments)

**Solutions**:
1. Check `scheduled_at` in the deployment details
2. Check the audit log for `DEPLOYMENT_STARTED`

### Deployment Issues

#### Host Timeout
**Symptom**: Hosts show `FAILED` status with message "Deployment timeout: Host did not respond within 10 minutes"

**Causes**:
- Network connectivity issues
- SSH connection problems
- Host is overloaded or unresponsive
- Firewall blocking SSH access

**Solutions**:
1. Verify SSH connectivity: `ssh -i <key> user@host`
2. Check host is responsive: `ping <host_ip>`
3. Verify SSH credentials are correct
4. Check firewall rules on target host aren't blocking SSH
5. Review execution logs: `GET /executions/:executionId/logs`

#### Deployment Fails Immediately
**Symptom**: Deployment fails immediately with no host-level failures

**Causes**:
- No SSH credential applies to one of the hosts
- Ansible container not running (if using Ansible executor)
- Bundle generation failure
- Invalid policy version (not APPROVED or DEPLOYED)

**Solutions**:
1. Check the **SSH credential** column in Inventory → Hosts and Admin → SSH Credentials (a global credential is the fallback for every host)
2. Verify Ansible container is running: `docker ps | grep ansible-runner`
3. Check API logs for bundle generation errors
4. Verify policy version status is APPROVED or DEPLOYED

#### Partial Success (Some Hosts Fail)
**Symptom**: Deployment shows `PARTIAL` status with some hosts succeeded and some failed

**Causes**:
- Host-specific issues (SSH, permissions, firewall backend mismatch)
- Network issues affecting subset of hosts
- Host-specific configuration problems

**Solutions**:
1. Review individual host status in deployment details
2. Check host messages for specific error details
3. Verify SSH access to failed hosts
4. Check firewall backend configuration matches host capabilities
5. Review execution logs for specific hosts

### Policy Issues

#### Policy Won't Approve
**Symptom**: Policy version stuck in `PENDING_APPROVAL` or approval fails

**Causes**:
- The approver created, edited or submitted the version (separation of duties, `403 cannot_approve_own_changes`)
- User doesn't have approver/admin role

**Solutions**:
1. Verify approver has `approver` or `admin` role
2. Have someone who did not work on the version approve it
3. Review rejection reason if rejected

#### Policy Rules Not Applying
**Symptom**: Rules are defined but not appearing in rendered output

**Causes**:
- Interface scope mismatch
- Source type resolution issues
- Rule order/index problems

**Solutions**:
1. Use preview endpoint: `GET /policy-versions/:versionId/render/host/:hostId`
2. Verify interface scope matches host interfaces
3. Check source type values (tag/VLAN IDs, host IDs)
4. Verify rule order_index values

### Authentication Issues

#### LDAP Login Fails
**Symptom**: Cannot login with LDAP credentials

**Causes**:
- LDAP not enabled
- Incorrect LDAP URL or credentials
- AD group mapping not configured
- User filter not matching

**Solutions**:
1. Verify LDAP is enabled in Admin → LDAP / Active Directory Settings
2. Test LDAP connection with `ldapsearch` or similar tool
3. Check AD group mappings in Admin → AD Group → Role Mapping
4. Verify user filter matches your LDAP structure
5. Check API logs for LDAP connection errors

#### Local User Login Fails
**Symptom**: Cannot login with local user credentials

**Causes**:
- User doesn't exist
- Password incorrect
- User is inactive (`is_active=false`)

**Solutions**:
1. Verify user exists: Check `users` table
2. Reset the password in Admin → Local Users (or `POST /api/admin/users/:id/reset-password`)
3. Check `is_active` flag in database

### Database Issues

#### Migration Failures
**Symptom**: Database migrations fail on startup

**Causes**:
- Database connection issues
- Existing schema conflicts
- Migration version conflicts

**Solutions**:
1. Verify `DATABASE_URL` is correct
2. Check PostgreSQL is running and accessible
3. Review migration files in `packages/db/migrations/`
4. Check migration history: `SELECT * FROM pgmigrations;`
5. Local dev only: `SEGMENTRA_RESET_DB=1 ./start.sh dev` wipes the Docker volumes (data loss)

### Performance Issues

#### Slow Deployments
**Symptom**: Deployments take a long time to complete

**Causes**:
- Large number of hosts
- Network latency
- Sequential execution (SSH Direct executor)
- Host response time

**Solutions**:
1. Use the Ansible executor for parallel execution (no canary/progressive gates)
2. Use FULL mode or a larger batch size if rollout gates are not needed
3. Check network connectivity and latency
4. Monitor host resource usage
5. Consider canary deployments for large changes

---

## Configuration Details

### Environment Variables

The API validates these in `apps/api/src/lib/env.ts`:

- `NODE_ENV` — `production` enables strict checks (longer `JWT_SECRET`, unsafe defaults refused, generic error messages)
- `PORT` (default `8080`) — API server port
- `DATABASE_URL` (**required**) — PostgreSQL connection string
- `JWT_SECRET` (**required**; min 32 chars when `NODE_ENV=production`, 16 otherwise; known placeholder values are refused in production) — Secret for JWT token signing
- `SEGMENTRA_KEK_B64` (required in production by the API and container entrypoint) — Canonical base64 of a 32-byte key for AES-256-GCM secret encryption, validated at API startup. In development, if not provided, the key is derived from `JWT_SECRET`, so rotating `JWT_SECRET` breaks stored secrets. Set it before storing secrets.
- `SEGMENTRA_BOOTSTRAP_TOKEN` (optional) — Enables `POST /api/admin/bootstrap` for one-time admin creation
- `BUNDLES_DIR` (default `./data/bundles`; `/bundles` in Docker) — Directory where deployment bundles/logs are written
- `ANSIBLE_RUNNER_CONTAINER` (default `segmentra-ansible-runner`) — Name of the Ansible runner container
- `CORS_ORIGIN` (optional) — Comma-separated HTTP(S) browser origins without paths or wildcards. Empty grants no cross-origin access in production (same-origin nginx access works); development allows all origins.
- `TRUST_PROXY` (optional; `1` in docker-compose) — Express `trust proxy` value when running behind a reverse proxy

Read elsewhere:

- `SEGMENTRA_KNOWN_HOSTS` (`packages/executor`) — SSH known_hosts file (host keys accepted on first use, `accept-new`); default `~/.ssh/known_hosts`
- `SEGMENTRA_SSH_COMMAND_TIMEOUT_MS` (`packages/executor`) — overall per-command SSH timeout, default 300000 (5 minutes)
- `SEGMENTRA_ASKPASS_DIR` (`packages/executor`) — directory for the temporary askpass helper used for key passphrases / passwords (default: OS temp dir; it never contains a secret)
- `SEGMENTRA_ALLOW_PRIVATE_WEBHOOKS` (API) — `true` allows webhook/Slack URLs that resolve to loopback, link-local or cloud metadata addresses
- `SEGMENTRA_ADMIN_PASSWORD` (`packages/db/scripts/seed-roles.js`) — password for the initial `admin` user; in production no default admin is created without it
- `SEGMENTRA_SKIP_MIGRATIONS` (`infra/app/docker-entrypoint.sh`) — `1` skips migrations and seeding at container start

See [installation.md](installation.md#environment-variables) for the full table including the compose and launcher variables (`POSTGRES_PASSWORD`, `DB_PORT`, `API_BIND`, `WEB_PORT`, `DOCKER_GID`, `SEGMENTRA_RESET_DB`, ...).

### Background Jobs

Started in `apps/api/src/index.ts` when the API begins listening (all in-process `setInterval` timers):

| Job | Interval | What it does |
|-----|----------|--------------|
| Stale host timeout | 2 min | Marks hosts `RUNNING` for more than 10 minutes as `FAILED` and finalizes their deployments (`checkAndTimeoutStaleHosts`) |
| Scheduled deployments | 1 min | Starts due `SCHEDULED`/`QUEUED` deployments with `scheduled_at <= now()` that need no (or have) approval (`processScheduledDeployments`) |
| Firewall Learning sessions | 1 min | Restores hosts and collects/parses logs of expired learning sessions (`services/audit-scheduler.ts`) |
| Tag rules | 5 min | Re-evaluates all enabled auto-tagging rules (`services/tag-rule-engine.ts`) |
| Policy expiry | 1 min | Processes expired deployments (NOTIFY_ONLY / REMOVE / REVERT) and sends 24 h warnings (`services/deployment-expiry.ts`) |
| Inventory discovery | 1 min | Starts runs of due discovery profiles (claimed with `SKIP LOCKED`); at startup, runs left `RUNNING` by a previous process are marked `FAILED` (`services/discovery.ts`) |
| Policy test sessions | 1 min | Restores hosts and collects logs of expired policy test sessions; failed restores are retried |

The jobs run in every API process; claims in the database keep work from being done twice.

### Docker Compose Configuration

`docker-compose.yml` defines four services:

- **segmentra-db**: PostgreSQL 16, published on `127.0.0.1:${DB_PORT:-15432}`, with a healthcheck
- **segmentra-ansible-runner**: `container_name: segmentra-ansible-runner`, used by the Ansible executor via `docker exec`
- **segmentra-app**: API server (non-root, `NODE_ENV=production`, runs migrations + seed on start), published on `${API_BIND:-127.0.0.1}:${API_PORT:-8080}`, with the Docker socket mounted for the Ansible executor
- **segmentra-web**: nginx serving the UI and proxying `/api/`, published on `${WEB_PORT:-80}`
- **Volumes**: `segmentra_pgdata`, `segmentra_bundles` (`/bundles` in the API and runner), `segmentra_ansible_ssh`, `segmentra_ssh_known_hosts`

`docker-compose.hardened.yml` is an override for production (`docker compose -f docker-compose.yml -f docker-compose.hardened.yml up -d --build`): no Docker socket and no Ansible runner (SSH Direct only), read-only root filesystems, all capabilities dropped (a few added back per image), `no-new-privileges`, PID/memory limits, and only nginx published. See [security.md](security.md#hardening-a-production-install).

### Security Considerations

1. **Docker Socket Mount**: The app container mounts `/var/run/docker.sock` for the Ansible executor. This is root-equivalent on the Docker host; use the SSH Direct executor and the hardened compose override to avoid it.
2. **Secret Encryption**: SSH keys, key passphrases, SSH/sudo passwords and LDAP passwords are encrypted using AES-256-GCM. Store `SEGMENTRA_KEK_B64` securely.
3. **JWT Tokens**: Tokens expire after 12 hours. Store `JWT_SECRET` securely.
4. **SSH Credentials**: Use a dedicated account, not root, with full sudo rights — sudo with a password (stored encrypted, sent on stdin) or `NOPASSWD` (see [security.md](security.md)).
5. **LDAP**: Use LDAPS (port 636) for secure LDAP connections in production.

### Secret Storage & Encryption

Segmentra encrypts sensitive data stored in the database: SSH private keys, key passphrases, SSH login passwords, sudo passwords and LDAP bind passwords.

#### Encryption Architecture

**Storage Flow**:
- When creating an SSH credential or LDAP setting, sensitive data (private keys, passphrases, passwords) is passed to `createSecret()` service function
- `createSecret()` calls `encryptBlob()` which encrypts the data using **AES-256-GCM** (Galois/Counter Mode)
- The encrypted blob is stored in the `secret_store` table in the `encrypted_blob` column (bytea type)
- Reference tables (`ssh_credentials`, `ldap_settings`) only store UUID references (`private_key_secret_id`, `passphrase_secret_id`, `password_secret_id`, `sudo_password_secret_id`, `bind_password_secret_id`) to the encrypted secrets
- The actual sensitive data is never stored in plaintext in the database

**Encryption Algorithm**:
- **Algorithm**: AES-256-GCM (Advanced Encryption Standard, 256-bit key, Galois/Counter Mode)
- **Key Size**: 256 bits (32 bytes)
- **IV (Initialization Vector)**: 12-byte random IV generated for each encryption (ensures same plaintext produces different ciphertext)
- **Authentication Tag**: 16-byte authentication tag for integrity verification (prevents tampering)
- **Format**: `[1-byte version][12-byte IV][16-byte tag][ciphertext...]`
- **Implementation**: Uses Node.js `crypto.createCipheriv()` and `crypto.createDecipheriv()` with AES-256-GCM

**Key Encryption Key (KEK)**:
- **Primary Method**: Uses `SEGMENTRA_KEK_B64` environment variable
  - Must be a 32-byte (256-bit) key, base64-encoded
  - Example generation: `openssl rand -base64 32`
  - This is the **Key Encryption Key (KEK)** used to encrypt/decrypt all secrets
- **Development Fallback**: If `SEGMENTRA_KEK_B64` is not set, derives a key from `JWT_SECRET` using SHA-256
  - **Warning**: This fallback is less secure and should **never be used in production**
  - The derived key is deterministic (same JWT_SECRET = same encryption key), which reduces security
  - Intended only for development/testing environments

**Retrieval & Usage**:
- When secrets are needed (e.g., for SSH deployments), `readSecretPlaintext()` retrieves the encrypted blob from `secret_store`
- Calls `decryptBlob()` to decrypt using the same KEK
- Decrypted data is only held in memory temporarily
- For SSH operations, key files (as stored, so passphrase-protected keys stay encrypted) are written to a temporary directory in `os.tmpdir()` with mode 0600 and removed after use; passwords, passphrases and sudo passwords stay in memory and are passed via `sshpass`, an askpass helper or `sudo -S` on stdin, never on a command line
- Output returned from hosts is scrubbed of the credential's secrets before it is stored
- Keys are never logged or exposed in API responses

#### Security Features

- **Encryption at Rest**: All sensitive data is encrypted before being stored in the database
- **Strong Algorithm**: AES-256-GCM provides authenticated encryption (confidentiality + integrity)
- **Unique IVs**: Each encryption uses a random IV, ensuring identical plaintext produces different ciphertext
- **Key Separation**: The encryption key (KEK) is stored separately (environment variable), never in the database
- **Temporary File Handling**: Decrypted keys are only written to temporary files that are automatically cleaned up
- **No Plaintext Storage**: The database never contains unencrypted sensitive data
- **Immutable Keys**: a private key cannot be replaced via `PUT` (create a new credential instead); passwords, the sudo password and the key passphrase can be changed

#### Production Recommendations

1. **Set SEGMENTRA_KEK_B64**: Always set this environment variable in production
   ```bash
   # Generate a secure 32-byte key
   export SEGMENTRA_KEK_B64=$(openssl rand -base64 32)
   ```

2. **Secure Key Storage**: Store `SEGMENTRA_KEK_B64` securely:
   - Use a secrets management system (HashiCorp Vault, AWS Secrets Manager, etc.)
   - Never commit to version control
   - Rotate periodically (requires re-encrypting all secrets)

3. **Key Rotation**: To rotate the KEK:
   - Generate new KEK
   - Decrypt all secrets with old KEK
   - Re-encrypt with new KEK
   - Update `SEGMENTRA_KEK_B64` environment variable
   - Restart API server

4. **Database Security**: Ensure PostgreSQL database is:
   - Accessible only to the API server
   - Using encrypted connections (SSL/TLS)
   - Backed up securely (encrypted backups)
   - Protected by network firewalls

5. **Access Control**: Limit access to:
   - Database containing encrypted secrets
   - Environment variables containing KEK
   - API server that can decrypt secrets
   - Admin users who can create/manage SSH credentials

#### Implementation Details

- **Service**: `apps/api/src/services/secrets.ts` - Secret creation and retrieval
- **Crypto**: `apps/api/src/services/crypto.ts` - AES-256-GCM encryption/decryption
- **Database Table**: `secret_store` - Stores encrypted blobs
- **Reference Tables**: `ssh_credentials`, `ldap_settings` - Store UUID references to secrets

### Current v1 Limitations

- `CANARY` / `PROGRESSIVE` rollout gates only apply to the SSH Direct executor; the Ansible executor deploys all target hosts in one playbook run.
- Baseline management SSH access comes from the subnet of the VLAN in `system_settings.management_vlan_id` (`/admin/management-vlan-setting`). If no management VLAN is configured, the SSH port is allowed from any source so hosts cannot be locked out.
- SSH Direct runs sequentially (one host at a time); Ansible runs hosts in parallel.
- Deployment timeout is fixed at 10 minutes per host.
- No rollback button: rollback happens automatically on failure (and via the lockout auto-revert with SSH Direct); `scripts/restore-previous-policy.sh` restores a host manually.
- Firewall backend `auto` is detected over privileged SSH before compilation; active native managers take precedence. Detection failure fails the host instead of guessing. The detected backend is stored on the host.
- Drift detection requires SSH access and sudo. Hosts without an applicable SSH credential cannot be checked.
- Scheduled deployments use a simple datetime comparison: no recurrence or calendar rules.
- SSH credentials: no per-environment scope and no fallback to another credential when the chosen one fails (see [SSH credential resolution](#ssh-credential-resolution)).
- Kubernetes: no connection to real clusters (sync is a placeholder; NetworkPolicies are generated, not applied). Email notifications, SOAR and vulnerability integrations are not implemented.
- **High-risk policy detection**: see [High-Risk Policy Detection](#high-risk-policy-detection).

---

## Additional Resources

- **API Documentation**: See API endpoints section above
- **Database Schema**: See database schema section above
- **Deployment Flow**: See deployment executors section above
- **Policy Compilation**: See `packages/compiler/src/compile.ts` for policy rendering logic
- **Ansible Playbook**: See `infra/ansible-runner/playbooks/apply-firewall.yml` for deployment playbook
