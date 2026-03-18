# Segmentra Architecture Documentation

This document provides detailed technical information about Segmentra's architecture, API endpoints, database schema, file structure, and troubleshooting.

---

## Table of Contents

1. [File Structure](#file-structure)
2. [API Endpoints](#api-endpoints)
3. [Database Schema](#database-schema)
4. [Deployment Executors](#deployment-executors)
5. [Firewall Backend Configuration](#firewall-backend-configuration)
6. [Advanced Features](#advanced-features)
   - [Firewall Learning (Traffic Discovery)](#firewall-learning-traffic-discovery)
   - [Drift Detection & Configuration Compliance](#drift-detection--configuration-compliance)
   - [Safety Guardrails](#safety-guardrails)
   - [High-Risk Policy Detection](#high-risk-policy-detection)
   - [Policy Impact Analysis](#policy-impact-analysis)
   - [Host Readiness Verification](#host-readiness-verification)
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
   - [Async Deployment Execution](#async-deployment-execution)
   - [Login Security](#login-security)
7. [Troubleshooting](#troubleshooting)
8. [Configuration Details](#configuration-details)
   - [Environment Variables](#environment-variables)
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
      middleware/              # JWT auth + RBAC
      routes/                  # REST endpoints
        admin.ts
        audit.ts
        auth.ts
        compliance.ts          # Drift detection & compliance checking
        dashboard.ts
        deployments.ts
        health.ts
        host-readiness.ts      # Host capability verification
        inventory/             # Hosts, tags, VLANs, interfaces
          tag-rules.ts           # Auto-tagging rule engine
        policies/              # Policy sets, versions, rules
          templates.ts           # Policy templates
        ssh-credentials.ts
        troubleshoot.ts
        topology.ts              # Visual topology design
        recommendations.ts       # Policy auto-recommendations
        integrations.ts          # SIEM/SOAR/Vuln/ThreatIntel integrations
        policy-testing.ts        # On-device policy testing
        kubernetes.ts            # Kubernetes cluster management
        iot-assets.ts            # IoT/OT asset management
        flow-collectors.ts       # NetFlow/sFlow collectors
        enforcement-points.ts    # Switch/gateway enforcement
        notifications.ts         # Notification channel management
        security-audit.ts        # Security posture scanning
      services/                # LDAP, secrets crypto, JWT, audit, ...
        policy-diff.ts         # Policy version comparison
        safety-check.ts        # Pre-deployment safety validation
        high-risk.ts           # High-risk policy detection
        log-parser.ts          # Firewall log parsing for learning sessions
        audit-scheduler.ts     # Background job for expired audit sessions
        tag-rule-engine.ts       # Auto-tagging evaluation engine
        template-engine.ts       # Policy template instantiation
        recommendation-engine.ts # Audit-to-policy recommendations
        topology-to-policy.ts    # Visual topology → policy conversion
        policy-test-analyzer.ts  # Policy test gap analysis
        notifications.ts         # Multi-channel notification delivery
        excessive-rules-audit.ts # Security posture scanning engine
      lib/                     # Environment config
      index.ts                 # Express app entry point
  web/                         # React UI (Vite)
    src/
      components/              # App shell, auth gate, visualization
        HostPolicyVisualization.tsx  # Policy visualization diagram
      pages/                   # Dashboard/Inventory/Policies/...
        PolicyTemplatesPage.tsx  # Policy template management
        TopologyPage.tsx         # Visual topology designer
        IntegrationsPage.tsx     # Integration management
        PolicyTestPage.tsx       # On-device policy testing
        KubernetesPage.tsx       # Kubernetes management
        IoTPage.tsx              # OT/IoT asset management
        SecurityAuditPage.tsx    # Security posture audit
        NotificationsPage.tsx    # Notification management
      lib/                     # API client, auth helpers
infra/
  app/Dockerfile               # App container (installs docker client + openssh-client)
  ansible-runner/              # Ansible container + playbooks (only needed for Ansible executor)
    Dockerfile
    playbooks/
      apply-firewall.yml
packages/
  db/                          # node-pg-migrate migrations + seed scripts
    migrations/
      001_init.sql
      007_add_scheduled_deployments.sql
      008_add_firewall_audit_sessions.sql
      009_add_tag_rules.sql
      010_add_policy_templates.sql
      011_add_visual_topologies.sql
      012_add_policy_recommendations.sql
      013_add_integrations.sql
      014_add_policy_test_sessions.sql
      015_add_kubernetes_clusters.sql
      016_add_ot_iot.sql
      017_add_policy_expiry.sql
      018_add_notifications.sql
    scripts/
      seed-roles.js
  shared/                      # shared TS types
  compiler/                    # nftables/iptables rendering
    src/
      compile.ts               # Supports logOnlyMode for firewall learning
  executor/                    # Ansible CLI runner + SSH direct executor
    src/
      run-ansible.ts
      run-ssh.ts
      read-rules.ts            # SSH-based firewall rule reading
      check-host-readiness.ts  # Host capability verification
      audit-ssh.ts             # Firewall learning/audit session management
      types.ts                 # Shared executor types
docker-compose.yml             # Postgres + app + ansible-runner
```

---

## API Endpoints

Base URL: `http://localhost:8080/api`

### Authentication

- `POST /auth/login` — LDAP login. Body: `{ "username": "...", "password": "..." }`
- `POST /auth/logout` — stateless (client drops JWT)
- `GET /auth/me` — returns current user + roles (Bearer token required)
- `POST /auth/change-password` — Change password for current user

### Admin (Admin role required)

- `POST /admin/bootstrap` — one-time bootstrap admin user (enabled by `SEGMENTRA_BOOTSTRAP_TOKEN`)
- `GET /admin/roles`
- `GET /admin/ldap-settings`
- `PUT /admin/ldap-settings`
- `POST /admin/ad-group-role-map`
- `GET /admin/executor-setting` — Get deployment executor preference (ansible/ssh)
- `PUT /admin/executor-setting` — Set deployment executor preference
- `GET /admin/management-vlan-setting` — Get management VLAN setting
- `PUT /admin/management-vlan-setting` — Set management VLAN setting

### Inventory (Operator/Admin role required)

#### Hosts
- `GET /hosts?hostname=&tag=&vlan=&ip=&enabled=&page=&limit=` — Returns hosts with tags and VLAN info
- `POST /hosts` — Body: `{ hostname, mgmtIp?, vlanId?, tagIds[]?, sshPort?, firewallBackend?, ... }`
- `GET /hosts/:id` — Returns host with tags and VLAN info
- `PUT /hosts/:id` — Body: `{ hostname?, mgmtIp?, vlanId?, tagIds[]?, ... }`
- `DELETE /hosts/:id` (soft delete via `enabled=false`)
- `POST /hosts/bulk/delete` — Bulk delete hosts
- `POST /hosts/bulk/assign-vlan` — Bulk assign VLAN
- `POST /hosts/bulk/assign-tag` — Bulk assign tag
- `POST /hosts/bulk/set-enabled` — Bulk enable/disable hosts
- `POST /hosts/bulk/import` — Import hosts from CSV

#### Tags
- `GET /tags`
- `POST /tags` — Body: `{ name, description? }`
- `PUT /tags/:id` — Body: `{ name?, description? }`
- `DELETE /tags/:id`

#### VLANs
- `GET /vlans`
- `POST /vlans` — Body: `{ vlanTag, name, description?, subnet? }`
- `PUT /vlans/:id` — Body: `{ vlanTag?, name?, description?, subnet? }`
- `DELETE /vlans/:id`

### Interfaces (Operator/Admin role required)

- `GET /hosts/:id/interfaces`
- `POST /hosts/:id/interfaces` — Body: `{ name, role?, ipAddress?, cidr?, vlanId?, isPrimary?, enabled? }`
- `PUT /interfaces/:interfaceId` — Body: `{ name?, role?, ipAddress?, cidr?, vlanId?, isPrimary?, enabled? }`
- `DELETE /interfaces/:interfaceId`

### Policies + Approvals

#### Policy Sets
- `GET /policy-sets`
- `POST /policy-sets` — Body: `{ name, description?, scopeType, scopeTagId?, scopeVlanId? }`
- `GET /policy-sets/:id`
- `PUT /policy-sets/:id` — Body: `{ name?, description?, scopeType?, scopeTagId?, scopeVlanId? }`
- `DELETE /policy-sets/:id`

#### Policy Versions
- `GET /policy-sets/:id/versions`
- `POST /policy-sets/:id/versions` — Creates `DRAFT` version. Body: `{ changeSummary?, interfaceScopeType?, interfaceScopeRoles?, interfaceScopeNames? }`
- `GET /policy-versions/:versionId`
- `PUT /policy-versions/:versionId` — Only while `DRAFT`. Body: `{ changeSummary?, interfaceScopeType?, interfaceScopeRoles?, interfaceScopeNames? }`
- `POST /policy-versions/:versionId/submit-approval` — Changes status to `PENDING_APPROVAL`. Automatically evaluates and sets `is_high_risk` flag based on policy heuristics.
- `POST /policy-versions/:versionId/approve` — Approver/Admin role required; approver must differ from maker. High-risk policies cannot be self-approved (even by admins). Body: `{ changeSummary? }`
- `POST /policy-versions/:versionId/reject` — Approver/Admin role required. Body: `{ reason }`
- `POST /policy-versions/:versionId/clone` — Clone version as new DRAFT
- `GET /policy-versions/pending-approval` — Returns all policy versions with `PENDING_APPROVAL` status. Approver/Admin role required.

#### Policy Rules
- `GET /policy-versions/:versionId/rules`
- `POST /policy-versions/:versionId/rules` — Body: `{ direction, action, protocol, ports?, sourceType, sourceValue, logMode?, comment?, usePolicyInterfaceScope?, interfaceScopeType?, interfaceScopeRoles?, interfaceScopeNames? }`
- `PUT /policy-rules/:ruleId` — Body: `{ direction?, action?, protocol?, ports?, sourceType?, sourceValue?, logMode?, comment?, usePolicyInterfaceScope?, interfaceScopeType?, interfaceScopeRoles?, interfaceScopeNames? }`
- `DELETE /policy-rules/:ruleId`

#### Policy Utilities
- `GET /policy-versions/:versionId/diff?fromVersionId=...` — Compare two policy versions (basic rule list diff)
- `GET /policy-versions/:versionId/render/host/:hostId` — Per-host nft/iptables preview. Returns: `{ backend, sha256, text }`
- `POST /policy-versions/:candidateVersionId/impact-diff` — Semantic policy impact analysis
  - Body: `{ currentVersionId: string, hostIds: string[] }`
  - Returns: `{ diff: Array<{ hostId, hostname, changes: { newAllows, removedAllows, newDenies, removedDenies }, summary }> }`
  - Shows what rules were added/removed/modified between versions

### Deployments

- `POST /deployments` — Body: `{ policyVersionId, mode, targetQuery, canarySize?, batchSize?, scheduledAt? }` (policy version must be APPROVED)
  - `targetQuery`: `{ tags?: uuid[], vlans?: uuid[], hosts?: uuid[] }`
  - `scheduledAt`: Optional ISO 8601 datetime string for deferred execution
  - **Safety Check**: Automatically validates SSH access preservation before deployment
    - FULL mode: Blocks deployment if SSH access would be blocked
    - CANARY/PROGRESSIVE: Warns but allows deployment
- `GET /deployments` — Returns all deployments
- `GET /deployments/:deploymentId` — Returns deployment details
- `GET /deployments/:deploymentId/hosts` — Returns host-level deployment status
- `GET /deployments/:deploymentId/artifacts` — Returns deployment artifacts (bundles)
- `POST /deployments/:deploymentId/start` — Creates bundle + runs executor (Ansible or SSH Direct, based on admin setting)
- `POST /deployments/:deploymentId/pause` — Pause a running deployment (marks RUNNING hosts as PAUSED, leaves PENDING hosts for resume)
- `POST /deployments/:deploymentId/resume` — Resume a paused deployment (marks PAUSED hosts back to RUNNING)
- `POST /deployments/:deploymentId/stop` — Stop a running or paused deployment (marks all PENDING/RUNNING/PAUSED hosts as SKIPPED)

> **Note:** Pause, resume, and stop currently update the deployment status in the database but do not interrupt an in-progress SSH/Ansible execution. If a deployment is already running, the executor will complete its current work. These controls are most useful for managing queued deployments that haven't started yet.
- `POST /deployments/:deploymentId/cancel` — Best-effort cancellation (deprecated - use `/stop` instead)
- `POST /deployments/:deploymentId/retry-failed` — Retry failed hosts (v1 helper)
- `GET /executions/:executionId/logs` — Returns stdout and stderr from execution

**Note**: Host deployments automatically timeout after 10 minutes if they remain in `RUNNING` status. Timed-out hosts are marked as `FAILED` with the message "Deployment timeout: Host did not respond within 10 minutes". The timeout check runs automatically every 2 minutes and also when fetching deployments or deployment hosts.

### Dashboard

- `GET /dashboard/stats` — Returns dashboard statistics:
  - `totalDeployments`: Total number of deployments
  - `runningDeployments`: Number of currently running deployments
  - `successRate`: Percentage of successful deployments
  - `statusBreakdown`: Array of status counts
  - `topDeployers`: Array of most active users
  - `recentDeployments`: Last 10 deployments
  - `currentDeployments`: Currently running deployments with progress
  - `deploymentActivity`: Deployment activity over last 30 days

### Audit

- `GET /audit?actor=&action=&entityType=&from=&to=` — Returns last 500 audit events
  - `actor`: Filter by username
  - `action`: Filter by action (e.g., `DEPLOYMENT_CREATED`, `DEPLOYMENT_FINISHED`)
  - `entityType`: Filter by entity type (e.g., `DEPLOYMENT`, `POLICY_VERSION`)
  - `from`: Start timestamp (ISO format)
  - `to`: End timestamp (ISO format)

### Compliance & Drift Detection (Operator/Admin role required)

- `GET /compliance/hosts/:hostId` — Check compliance status for a specific host
  - Returns: `{ hostId, hostname, status: 'compliant'|'drifted'|'unknown'|'error', currentHash, expectedHash, backend, lastDeployment, error? }`
  - Reads current firewall rules via SSH and compares hash to `deployment_hosts.applied_hash`
- `POST /compliance/hosts/bulk` — Bulk compliance check for multiple hosts
  - Body: `{ hostIds: string[] }`
  - Returns: `{ results: Array<{ hostId, hostname, status, currentHash, expectedHash, error? }> }`

### Host Readiness (Operator/Admin role required)

- `POST /host-readiness/hosts/:hostId/check` — Check if a host is ready for deployments
  - Returns: `{ hostname, ready: boolean, backend: 'nftables'|'iptables'|'unknown', nftVersion?, iptablesVersion?, sudoAccess: boolean, kernelSupport: boolean, errors: string[], warnings: string[] }`
  - Verifies: nft/iptables availability, passwordless sudo access, kernel module support
  - Auto-updates `firewall_backend` if set to "auto"

### Troubleshoot

- `GET /troubleshoot/policies/by-ip?ip=...` — Find which policies apply to a specific IP
- `GET /troubleshoot/hosts/:hostId/policies` — Get all policies deployed to a host
- `GET /troubleshoot/policy-versions/:versionId/hosts` — Get all hosts with a specific policy version
- `POST /troubleshoot/simulate-communication` — Simulate communication between two IPs
  - Body: `{ sourceIp, sourcePort?, destIp, destPort?, protocol? }`
  - Returns: Analysis of whether communication would be blocked, matching rules, and host information

#### Firewall Learning (Audit Sessions)

- `POST /troubleshoot/audit/start` — Start firewall learning session(s) (Operator/Admin role required)
  - Body: `{ hosts: string[], durationMinutes: number }`
  - Creates audit sessions for specified hosts, backs up existing rules, deploys log-only policy
  - Returns: `{ sessions: Array<{ id, host_id, status, duration_minutes, scheduled_restore_at, ... }> }`
- `GET /troubleshoot/audit/sessions` — List all audit sessions
  - Returns: `{ sessions: Array<{ id, host_id, status, duration_minutes, started_at, restored_at, log_data?, ... }> }`
- `GET /troubleshoot/audit/sessions/:id` — Get audit session details
- `POST /troubleshoot/audit/sessions/:id/restore` — Manually trigger restore (Operator/Admin role required)
  - Restores original firewall rules and retrieves/parses logs
  - Returns: `{ success: boolean, flows: Array<{ direction, sourceIp, destinationIp, protocol, count, ... }>, entryCount: number }`
- `GET /troubleshoot/audit/sessions/:id/logs` — Get parsed log data
  - Returns: `{ logData: { entries: Array<...>, flows: Array<...> } }`
- `POST /troubleshoot/audit/sessions/:id/cancel` — Cancel running session (Operator/Admin role required)
  - Restores original rules and marks session as CANCELLED

### SSH Credentials (Admin role required)

- `GET /ssh-credentials` — List all SSH credentials
- `POST /ssh-credentials` — Create new SSH credential. Body: `{ name, username, privateKeyPem, passphrase?, scopeType, scopeId? }` (stores private key encrypted)
- `PUT /ssh-credentials/:id` — Update SSH credential metadata. Body: `{ name?, username?, scopeType?, scopeId? }`
  - **Note**: The `PUT` endpoint does **not** update the private key or passphrase. SSH keys are immutable for security reasons. To rotate SSH keys, create a new credential via `POST` and delete the old one.

### Tag Rules (Auto-Tagging) (Operator/Admin role required)

- `GET /tag-rules` — List all tag rules with match counts
- `GET /tag-rules/:id` — Get tag rule with matched hosts
- `POST /tag-rules` — Create tag rule. Body: `{ name, tagId, enabled?, priority?, criteria: { conditions: [{field, operator, value}], logic: 'AND'|'OR' } }`
- `PUT /tag-rules/:id` — Update tag rule
- `DELETE /tag-rules/:id` — Delete tag rule and remove auto-assigned tags
- `POST /tag-rules/:id/evaluate` — Evaluate single rule against all hosts
- `POST /tag-rules/evaluate-all` — Evaluate all enabled rules
- `POST /tag-rules/evaluate-host/:hostId` — Evaluate all rules for a specific host

### Policy Templates (Operator/Admin role required)

- `GET /policy-templates` — List templates with rule counts and instantiation counts
- `GET /policy-templates/categories` — List distinct template categories
- `GET /policy-templates/:id` — Get template with rules
- `POST /policy-templates` — Create template. Body: `{ name, category?, targetTagId?, autoApply?, interfaceScopeType?, ... }`
- `PUT /policy-templates/:id` — Update template
- `DELETE /policy-templates/:id` — Delete template
- `GET /policy-templates/:id/rules` — List template rules
- `POST /policy-templates/:id/rules` — Add rule to template
- `PUT /policy-templates/rules/:ruleId` — Update template rule
- `DELETE /policy-templates/rules/:ruleId` — Delete template rule
- `POST /policy-templates/:id/instantiate` — Create policy set + version + rules from template (DRAFT)
- `POST /policy-templates/:id/preview` — Preview what instantiation would create

### Visual Topology (Operator/Admin role required)

- `GET /topology/views` — List topology views
- `GET /topology/views/:id` — Get view with flows
- `POST /topology/views` — Create topology view
- `PUT /topology/views/:id` — Update view (layout, name)
- `DELETE /topology/views/:id` — Delete view
- `POST /topology/views/:id/flows` — Add flow connection
- `DELETE /topology/flows/:flowId` — Remove flow
- `POST /topology/views/:id/generate-policies` — Generate policy sets from topology flows (DRAFT)
- `GET /topology/auto-discover` — Auto-discover topology from existing inventory and deployed policies

### Policy Recommendations (Operator/Admin role required)

- `GET /recommendations` — List recommendations (filter by status, hostId)
- `GET /recommendations/:id` — Get recommendation details
- `POST /recommendations/generate` — Generate from audit session. Body: `{ auditSessionId, hostId }`
- `POST /recommendations/:id/accept` — Accept recommendation
- `POST /recommendations/:id/reject` — Reject recommendation
- `POST /recommendations/:id/apply` — Apply accepted recommendation as DRAFT policy version

### Integrations (Admin role required for write, Viewer+ for read)

- `GET /integrations` — List all integrations
- `GET /integrations/:id` — Get integration with recent events
- `POST /integrations` — Create integration. Body: `{ type: 'siem'|'soar'|'vulnerability_db'|'threat_intel', provider, name, config, ... }`
- `PUT /integrations/:id` — Update integration
- `DELETE /integrations/:id` — Delete integration
- `POST /integrations/:id/test` — Test connectivity
- `POST /integrations/:id/sync` — Trigger sync
- `GET /integrations/:id/events` — Get integration events
- `GET /integrations/vulnerabilities/by-host/:hostId` — Host vulnerabilities
- `GET /integrations/threat-intel` — Active threat intelligence entries

### Policy Testing (Operator/Admin role required)

- `GET /policy-test/sessions` — List test sessions (filter by hostId, status)
- `GET /policy-test/sessions/:id` — Get test session details with analysis results
- `POST /policy-test/start` — Start policy test. Body: `{ policyVersionId, hostId, durationMinutes? }`
- `POST /policy-test/sessions/:id/stop` — Stop running test session
- `POST /policy-test/sessions/:id/analyze` — Analyze collected traffic against policy rules

### Kubernetes (Admin for write, Viewer+ for read)

- `GET /k8s/clusters` — List K8s clusters
- `GET /k8s/clusters/:id` — Get cluster with workload summary
- `POST /k8s/clusters` — Add cluster. Body: `{ name, apiServerUrl, authType, ... }`
- `PUT /k8s/clusters/:id` — Update cluster
- `DELETE /k8s/clusters/:id` — Delete cluster
- `POST /k8s/clusters/:id/sync` — Sync workloads from cluster
- `GET /k8s/clusters/:id/workloads` — List workloads (filter by namespace, kind)
- `POST /k8s/workloads/:workloadId/map-tag` — Map workload to Segmentra tag
- `GET /k8s/clusters/:id/network-policies` — List deployed network policies
- `POST /k8s/clusters/:id/deploy-policy` — Deploy NetworkPolicy. Body: `{ policyVersionId, namespace, policyName }`

### OT/IoT Assets (Operator/Admin role required)

- `GET /iot-assets` — List IoT assets (filter by assetType, zone, vlanId)
- `GET /iot-assets/:id` — Get asset with observed flows and tags
- `POST /iot-assets` — Create asset. Body: `{ name, assetType, vendor?, ipAddress?, zone?, criticality, ... }`
- `PUT /iot-assets/:id` — Update asset
- `DELETE /iot-assets/:id` — Delete asset
- `POST /iot-assets/bulk-import` — Bulk import assets
- `POST /iot-assets/:id/tags` — Assign tag to asset
- `DELETE /iot-assets/:id/tags/:tagId` — Remove tag from asset
- `GET /iot-assets/:id/flows` — Get observed traffic flows
- `POST /iot-assets/:id/baseline` — Capture current traffic as baseline

### Flow Collectors (Admin role required)

- `GET /flow-collectors` — List flow collectors
- `GET /flow-collectors/:id` — Get collector with recent flows
- `POST /flow-collectors` — Create collector. Body: `{ name, type, listenAddress, listenPort, ... }`
- `PUT /flow-collectors/:id` — Update collector
- `DELETE /flow-collectors/:id` — Delete collector

### Enforcement Points (Admin role required)

- `GET /enforcement-points` — List enforcement points
- `GET /enforcement-points/:id` — Get enforcement point with ACLs
- `POST /enforcement-points` — Create. Body: `{ name, type, vendor?, mgmtIp, sshCredentialId?, ... }`
- `PUT /enforcement-points/:id` — Update
- `DELETE /enforcement-points/:id` — Delete
- `POST /enforcement-points/:id/deploy-acl` — Deploy ACL. Body: `{ policyVersionId, aclName, aclConfig }`
- `GET /enforcement-points/:id/acls` — List deployed ACLs

### Notifications (Admin role required)

- `GET /notifications/channels` — List notification channels with rule counts and failure stats
- `GET /notifications/channels/:id` — Get channel with rules and recent log
- `POST /notifications/channels` — Create channel. Body: `{ name, type: 'slack'|'webhook'|'email', config: {}, enabled? }`
- `PUT /notifications/channels/:id` — Update channel
- `DELETE /notifications/channels/:id` — Delete channel and rules
- `POST /notifications/channels/:id/test` — Send test notification
- `POST /notifications/channels/:id/rules` — Subscribe to event. Body: `{ eventType, enabled? }`
- `DELETE /notifications/rules/:ruleId` — Unsubscribe from event
- `GET /notifications/log` — View notification history (filter by status, limit)

### Security Posture Audit (All roles)

- `GET /security-audit/scan` — Run full audit scan, returns findings with severity
- `GET /security-audit/summary` — Get finding counts only (lighter)

---

## Database Schema

Migrations live in `packages/db/migrations/`.

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
- `type` (text) — `SSH_KEY|LDAP_BIND|TLS_CA_CERT`
- `encrypted_blob` (bytea)
- `created_at` (timestamptz)
- `rotated_at` (timestamptz, nullable)
- `is_active` (boolean)

### Inventory

#### `tags`
- `id` (uuid, PK)
- `name` (text, unique)
- `description` (text)

#### `vlans`
- `id` (uuid, PK)
- `vlan_tag` (int)
- `name` (text)
- `description` (text)
- `subnet` (cidr, nullable) — Used for management VLAN baseline SSH access

#### `hosts`
- `id` (uuid, PK)
- `hostname` (text, unique)
- `mgmt_ip` (inet)
- `ssh_port` (int, default 22) — SSH port for deployments
- `environment` (text)
- `os_family` (text)
- `firewall_backend` (text) — `auto|nftables|iptables`
- `vlan_id` (uuid, FK → vlans.id, nullable)
- `enabled` (boolean, default true) — Disabled hosts are skipped from deployments
- `created_at` (timestamptz)
- `updated_at` (timestamptz)

**Important Notes**:
- **SSH Port**: The `ssh_port` field (default: 22) specifies which SSH port to use when connecting to the host for deployments. Both Ansible and SSH Direct executors automatically use the configured port for each host.
- **Disabled Hosts**: Hosts with `enabled=false` are **automatically skipped** from all policy deployments. Disabled hosts will never receive firewall policies, even if they are included in deployment target queries (tags, VLANs, or direct host selection). They will be marked as `SKIPPED` in deployment status with the message "Host is disabled".

#### `host_tags`
- `host_id` (uuid, FK → hosts.id)
- `tag_id` (uuid, FK → tags.id)
- Primary key: `(host_id, tag_id)` — Many-to-many relationship

#### `host_interfaces`
- `id` (uuid, PK)
- `host_id` (uuid, FK → hosts.id)
- `name` (text) — Interface name (e.g., `eth0`, `ens3`)
- `role` (text) — Interface role (e.g., `data`, `management`)
- `ip_address` (inet, nullable)
- `cidr` (cidr, nullable)
- `vlan_id` (int, nullable) — VLAN tag number
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

#### `policy_set_hosts`
- `policy_set_id` (uuid, FK → policy_sets.id)
- `host_id` (uuid, FK → hosts.id)
- Primary key: `(policy_set_id, host_id)` — Only used when `scope_type=HOST_LIST`

#### `policy_versions`
- `id` (uuid, PK)
- `policy_set_id` (uuid, FK → policy_sets.id)
- `version_number` (int)
- `status` (text) — `DRAFT|PENDING_APPROVAL|APPROVED|REJECTED`
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

#### `policy_rules`
- `id` (uuid, PK)
- `policy_version_id` (uuid, FK → policy_versions.id)
- `order_index` (int)
- `direction` (text) — `IN|OUT|BOTH`
- `action` (text) — `ALLOW|DENY`
- `protocol` (text) — `tcp|udp|icmp|any`
- `ports` (text, nullable) — Normalized format: `"22"` or `"80,443"` or `"1000-2000"`
- `source_type` (text) — `CIDR|TAG|VLAN|HOST`
- `source_value` (text) — CIDR string OR tag_id/vlan_id/host_id serialized
- `log_mode` (text) — `NONE|LOG|LOG_RATE_LIMITED`
- `comment` (text)
- `use_policy_interface_scope` (boolean, default true)
- `interface_scope_type` (text, nullable) — Rule-level override
- `interface_scope_roles` (text[], nullable)
- `interface_scope_names` (text[], nullable)

### Deployments & Execution

#### `deployments`
- `id` (uuid, PK)
- `policy_version_id` (uuid, FK → policy_versions.id) — Must be APPROVED
- `mode` (text) — `CANARY|PROGRESSIVE|FULL`
- `target_query` (jsonb) — `{ tags: uuid[], vlans: uuid[], hosts: uuid[] }`
- `target_count` (int)
- `created_by` (uuid, FK → users.id)
- `created_at` (timestamptz)
- `started_at` (timestamptz, nullable)
- `finished_at` (timestamptz, nullable)
- `status` (text) — `QUEUED|RUNNING|SUCCEEDED|FAILED|PARTIAL|CANCELLED|PAUSED`
- `requires_approval` (boolean, default false)
- `approved_by` (uuid, FK → users.id, nullable)
- `approved_at` (timestamptz, nullable)
- `canary_size` (int, nullable)
- `batch_size` (int, nullable)
- `scheduled_at` (timestamptz, nullable) — For deferred/scheduled deployments

#### `deployment_hosts`
- `deployment_id` (uuid, FK → deployments.id)
- `host_id` (uuid, FK → hosts.id)
- `status` (text) — `PENDING|RUNNING|SUCCEEDED|FAILED|ROLLED_BACK|SKIPPED|PAUSED`
- `started_at` (timestamptz, nullable)
- `finished_at` (timestamptz, nullable)
- `message` (text, nullable)
- `applied_hash` (text, nullable) — SHA-256 hash of compiled policy text (for drift detection)
- `rollback_performed` (boolean, default false)
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
- `status` (text) — `RUNNING|DONE|ERROR`

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
- `private_key_secret_id` (uuid, FK → secret_store.id)
- `passphrase_secret_id` (uuid, FK → secret_store.id, nullable)
- `scope_type` (text) — `GLOBAL|TAG|VLAN|HOST`
- `scope_id` (uuid, nullable) — Tag/VLAN/Host ID when scope_type is not GLOBAL
- `created_at` (timestamptz)

### System Settings

#### `firewall_audit_sessions`
- `id` (uuid, PK)
- `host_id` (uuid, FK → hosts.id)
- `status` (text) — `RUNNING|COMPLETED|FAILED|CANCELLED`
- `duration_minutes` (integer)
- `started_at` (timestamptz)
- `scheduled_restore_at` (timestamptz)
- `restored_at` (timestamptz, nullable)
- `backup_path` (text) — Path to backup file on remote server
- `log_file_path` (text) — Path to log file on remote server
- `log_data` (jsonb, nullable) — Parsed log entries and communication flows
- `created_by` (uuid, FK → users.id)
- `created_at` (timestamptz)

#### `system_settings`
- `key` (text, PK) — e.g., `deployment_executor`, `management_vlan_id`
- `value` (text)
- `description` (text, nullable)
- `updated_at` (timestamptz)

### Policy Expiry

Added to existing `deployments` table:
- `expires_at` (timestamptz, nullable) — When the deployment expires
- `expiry_action` (text, default 'NOTIFY_ONLY') — What to do on expiry: NOTIFY_ONLY, REMOVE, REVERT
- `expired` (boolean, default false) — Whether the deployment has been processed as expired

### Notifications

#### `notification_channels`
- `id` (uuid, PK), `name`, `type` (slack/webhook/email), `config` (jsonb), `enabled`
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
- Mirrors `policy_rules` schema (order_index, direction, action, protocol, ports, source_type, source_value, log_mode, comment, interface scope overrides)
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
- `enabled`, `config` (jsonb), `credentials_secret_id` (FK → secret_store)
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
- `status` — `PENDING|DEPLOYING|RUNNING|COLLECTING|ANALYZING|COMPLETED|FAILED`
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
- `cluster_id` (FK), `policy_version_id` (FK), `namespace`, `policy_name`, `manifest` (jsonb), `status`, `deployed_hash`

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

---

## Deployment Executors

Segmentra supports two deployment executors, selectable in Admin settings:

### Ansible (Default, Recommended)

- Uses Ansible playbook for deployments
- Better error handling and automatic rollback
- Parallel execution across hosts
- Requires Ansible container (`segmentra-ansible-runner`)
- Uses `become: true` (sudo) for all privileged operations

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
   - The API container writes deployment bundles (inventory, policy files, SSH keys) to `/bundles/<deploymentId>/`
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

- Lightweight direct SSH/SCP execution
- No Ansible dependency
- Requires `ssh` and `scp` commands on the API host
- Uses `sudo` prefix for all privileged operations
- Suitable for simpler environments or when Ansible is not available
- Runs sequentially (one host at a time)

**Both executors:**
- Support sudo-capable accounts (not root)
- Create backups before applying rules
- Attempt rollback on failure
- Work with nftables and iptables

---

## Advanced Features

### Firewall Learning (Traffic Discovery)

Firewall Learning is a powerful feature that helps administrators discover the correct firewall rules by observing actual network traffic patterns. This is particularly useful when deploying firewall policies to new systems or when you need to understand what traffic should be allowed without accidentally blocking legitimate communication.

#### How It Works

1. **Session Creation**: User selects one or more hosts and specifies a duration (e.g., 60 minutes)
2. **Backup**: System automatically backs up existing firewall rules to `/var/backups/segmentra/`
3. **Log-Only Policy Deployment**: 
   - Compiles a log-only firewall policy that logs all traffic but doesn't block anything
   - Changes default policy from `DROP` to `ACCEPT` (nftables) or `DROP` to `ACCEPT` (iptables)
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
  - When enabled, changes default policies to ACCEPT
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

- Requires SSH access and passwordless sudo on target hosts
- Log file size depends on traffic volume (may be large for busy servers)
- Log parsing may be slow for very large log files
- rsyslog configuration changes require sudo access
- Background processes for log capture may not persist across system reboots (logs are written directly to file)

### Drift Detection & Configuration Compliance

Segmentra provides **agentless drift detection** by comparing current firewall rules on hosts against the last successfully deployed policy hash.

#### How It Works

1. **Policy Hash Storage**: When a deployment succeeds, the SHA-256 hash of the compiled policy text is stored in `deployment_hosts.applied_hash`.

2. **Rule Reading**: The compliance check uses SSH to read current firewall rules:
   - For nftables: `sudo -n nft list ruleset`
   - For iptables: `sudo -n iptables-save`

3. **Normalization & Hashing**: Rules are normalized (removing timestamps, comments) and hashed using SHA-256.

4. **Comparison**: The current hash is compared to `applied_hash`:
   - **Compliant**: Hashes match — host matches last deployed policy
   - **Drifted**: Hashes differ — manual changes or failed apply detected
   - **Unknown**: No successful deployment found (never deployed or hash missing)
   - **Error**: Unable to read rules (SSH failure, permissions, etc.)

#### Usage

- **Per-Host Check**: Use the "Check Compliance" button in Inventory → Hosts
- **Bulk Check**: Select multiple hosts and use bulk compliance check
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

Segmentra automatically detects potentially dangerous policy changes and enforces enhanced approval requirements to prevent accidental security breaches.

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

2. **On Approval**: When `POST /policy-versions/:id/approve` is called, the system:
   - Checks the `is_high_risk` flag
   - If high-risk and approver is the creator, blocks approval (even for admins)
   - Requires a different approver to review high-risk policies
   - Logs high-risk status in audit events

3. **On Deployment Creation**: When `POST /deployments` is called, the system:
   - Re-evaluates risk status with actual target count
   - Updates `is_high_risk` flag if risk level changes based on deployment scope
   - Allows deployment to proceed (flag is informational, not blocking)

#### Implementation

- **Service**: `apps/api/src/services/high-risk.ts`
- **Function**: `isPolicyVersionHighRisk(params: { policyVersionId: string, targetCount?: number }): Promise<boolean>`
- **Integration Points**:
  - Policy version submission (`POST /policy-versions/:id/submit-approval`)
  - Policy version approval (`POST /policy-versions/:id/approve`)
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
- **Approval**: Blocks self-approval for high-risk policies
- **Deployment**: Re-evaluates and updates flag based on actual deployment scope

### Policy Impact Analysis

Before approving a policy version, reviewers can analyze the impact of changes.

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

- **In Approvals Screen**: Displays a table of all pending approval versions with: policy set name, version number, rule count, submitted by, submitted date, change summary, approve/reject buttons, and impact analysis. When reviewing a specific policy version, select:
  1. Current deployed version ID
  2. Sample hosts to analyze
  3. Click "Analyze Impact"
- **API**: `POST /api/policy-versions/:candidateVersionId/impact-diff`

#### Benefits

- **Confidence**: Understand changes before deployment
- **Risk Assessment**: Identify potential connectivity issues
- **Documentation**: See exactly what will change

### Host Readiness Verification

Before deploying, verify that hosts are ready to receive firewall policies.

#### Checks Performed

1. **Firewall Backend Detection**:
   - Checks for `nft` command availability
   - Checks for `iptables` command availability
   - Determines preferred backend (nftables preferred)

2. **Version Detection**:
   - Reads `nft --version` if available
   - Reads `iptables --version` if available

3. **Sudo Access Verification**:
   - Tests passwordless sudo for `nft list ruleset`
   - Tests passwordless sudo for `iptables-save`
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
  backend: 'nftables' | 'iptables' | 'unknown';
  nftVersion?: string;
  iptablesVersion?: string;
  sudoAccess: boolean;
  kernelSupport: boolean;
  errors: string[];      // Critical issues preventing deployment
  warnings: string[];   // Non-critical issues (may still work)
}
```

### Scheduled Deployments

Deployments can be scheduled for future execution, useful for maintenance windows.

#### Features

- **Simple Scheduling**: Specify `scheduledAt` datetime when creating deployment
- **Background Processing**: Background job checks every minute for ready deployments
- **Queue Readiness**: When `scheduled_at <= now()`, the system clears `scheduled_at` and leaves the deployment in `QUEUED` status, ready to be started manually via the `/deployments/:id/start` endpoint
- **No Calendar Logic**: Simple "tonight at 02:00" style scheduling
- **Manual Start Required**: Scheduled deployments do not automatically start - they must be manually started via the start endpoint after the scheduled time has passed

#### Usage

- **UI**: Use datetime picker in deployment creation form
- **API**: Include `scheduledAt: "2026-01-10T02:00:00Z"` in deployment creation payload
- **Format**: ISO 8601 datetime string
- **Starting**: After the scheduled time, call `POST /deployments/:id/start` to begin the deployment

#### Implementation

- **Database**: `deployments.scheduled_at` field (added in migration 007)
- **Background Job**: Runs every minute in `apps/api/src/index.ts`
- **Processing**: `processScheduledDeployments()` function clears `scheduled_at` when `scheduled_at <= now()`, leaving deployments in `QUEUED` status for manual start

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
- **Auto-Apply**: When enabled, automatically creates DRAFT policies when hosts gain the template's target tag
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
| SIEM | Forward audit events via syslog/webhook |
| SOAR | Expose actions (isolate host, apply emergency policy) via webhooks |
| Vulnerability DB | Poll scanner API, populate host vulnerabilities, trigger auto-tagging for critical CVEs |
| Threat Intelligence | Poll threat feeds, maintain IP/CIDR blocklists with confidence and expiry |

- **Credentials**: Stored in existing `secret_store` with AES-256-GCM encryption
- **Event Trail**: All sync/webhook operations logged in `integration_events`
- **Auto-Block**: Threat intel auto-block is opt-in (admin configures confidence threshold)

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

### Kubernetes Microsegmentation

Agentless Kubernetes NetworkPolicy management via K8s API.

- **No Agent Required**: Connects to K8s API server directly — no sidecar, no service mesh dependency
- **Separate Package**: K8s logic is separate from SSH-focused `packages/executor`
- **Label Sync**: K8s labels synced to Segmentra tags for unified policy management across hosts and containers
- **NetworkPolicy Generation**: Translates Segmentra rules into K8s NetworkPolicy manifests (label selectors, not IP sets)
- **Credentials**: Supports kubeconfig, service account, and bearer token authentication — stored in `secret_store`

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
- **Enforcement**: Via existing SSH credential infrastructure to managed switches/gateways
- **Baseline**: Snapshot current traffic as "allowed" for anomaly detection

### Policy Expiry

Optional time-limited deployments that automatically expire after a specified date.

#### How It Works

1. When creating a deployment, optionally set **Expires At** and **On Expiry** action
2. A background job checks every minute for expired deployments
3. On expiry, the system:
   - Marks the deployment as `expired = true`
   - Sends a `POLICY_EXPIRED` notification
   - Logs an audit event
   - Executes the chosen action (notify only, remove rules, or revert to previous)
4. A 24-hour warning notification is sent before expiry (deduped to avoid spam)

#### Expiry Actions

| Action | Behavior |
|--------|----------|
| **Notify Only** | Alert is sent, but firewall rules remain active on hosts. Manual removal required. |
| **Remove** | Firewall rules are rolled back on all deployed hosts (restore from backup). |
| **Revert** | The previous policy version is automatically re-deployed to all affected hosts. |

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
| **Email** | `{ "to": "admin@company.com", "smtpHost": "..." }` | Sends email notifications (preview — requires SMTP implementation) |

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

#### Design

- **Fire-and-forget**: Notification failures never block core operations (logged but not thrown)
- **Deduplication**: Expiry warnings are sent once per 24-hour period per deployment
- **Full log**: Every notification attempt is recorded in `notification_log` with status tracking

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

When the scan finds critical or high severity findings, it automatically sends an `EXCESSIVE_RULES_DETECTED` notification to all subscribed channels.

### Role-Based Access Control (RBAC)

Segmentra enforces role-based access control at both the API level (backend) and the UI level (frontend).

#### Roles

| Role | Description |
|------|-------------|
| **viewer** | Read-only access to all data. Cannot create, modify, or deploy anything. |
| **operator** | Full operational access. Can manage inventory, create policies and rules, run deployments, use troubleshooting tools, and manage IoT assets. |
| **approver** | Can view everything and approve/reject policy versions. Cannot create policies, manage inventory, or run deployments. |
| **admin** | Full access to everything including user management, LDAP configuration, SSH credentials, integrations, notifications, and system settings. |

#### Permission Matrix

| Action | Viewer | Operator | Approver | Admin |
|--------|--------|----------|----------|-------|
| **View** dashboard, inventory, policies, deployments, approvals | Yes | Yes | Yes | Yes |
| **View** troubleshoot results, topology, IoT, K8s | Yes | Yes | Yes | Yes |
| **View** security audit results | Yes | Yes | Yes | Yes |
| **Create/edit** hosts, tags, VLANs, interfaces | - | Yes | - | Yes |
| **Create/edit** policy sets, versions, rules | - | Yes | - | Yes |
| **Create/edit** policy templates | - | Yes | - | Yes |
| **Create/edit** topology views and flows | - | Yes | - | Yes |
| **Create/start** deployments | - | Yes | - | Yes |
| **Submit** policy versions for approval | - | Yes | - | Yes |
| **Approve/reject** policy versions | - | - | Yes | Yes |
| **Run** firewall learning, policy testing | - | Yes | - | Yes |
| **Run** communication simulation | - | Yes | - | Yes |
| **Manage** IoT assets and gateway assignments | - | Yes | - | Yes |
| **Manage** K8s clusters and workloads | - | Yes | - | Yes |
| **Evaluate** tag rules | - | Yes | - | Yes |
| **Generate** policy recommendations | - | Yes | - | Yes |
| **Manage** users (create, edit, delete, reset password) | - | - | - | Yes |
| **Configure** LDAP/AD settings | - | - | - | Yes |
| **Manage** SSH credentials | - | - | - | Yes |
| **Manage** integrations (SIEM, SOAR, etc.) | - | - | - | Yes |
| **Configure** notifications | - | - | - | Yes |
| **View** audit log | - | - | - | Yes |
| **Configure** deployment executor, management VLAN | - | - | - | Yes |

#### Enforcement

- **API Level**: Every route has `requireAuth` (JWT validation) and `requireRole(...)` middleware. Unauthorized requests return 401 (no token) or 403 (insufficient role).
- **UI Level**: The sidebar navigation hides links the user cannot access. Route-level `RequireRole` components block direct URL access and show an "Access Denied" message.
- **Authentication**: JWT tokens stored in browser localStorage (`segmentra_token`). Tokens contain `sub` (username) and `roles` (array of role names). Token is sent as `Authorization: Bearer <token>` on every API request.
- **Separation of Duties**: Policy approvers must be different from policy creators. High-risk policies require a different approver even for admins.

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

- **`auto`** (default): Automatically uses `nftables` unless explicitly set to `iptables`. This is the recommended setting for most modern Linux systems.
- **`nftables`**: Uses nftables (modern Linux firewall, preferred). Used by default on RHEL 8+, Ubuntu 20.04+, and other modern distributions.
- **`iptables`**: Uses iptables (legacy Linux firewall). Required for older systems that don't support nftables.

### How Mixed Backend Deployments Work

When deploying policies to multiple hosts with different firewall backends (e.g., 200 hosts where 10 use `iptables` and 190 use `nftables`), Segmentra handles this automatically:

1. **Individual Policy Compilation**: Each host's policy is compiled separately based on its configured `firewall_backend` field:
   - Hosts with `nftables` or `auto` → generates `.nft` files (nftables format)
   - Hosts with `iptables` → generates `.iptables` files (iptables format)

2. **Separate Policy Files**: Each host receives its own policy file with the appropriate format:
   - `hostname.nft` for nftables hosts
   - `hostname.iptables` for iptables hosts

3. **Unified Deployment**: All hosts are included in a single deployment operation:
   - The Ansible inventory includes all hosts regardless of backend
   - Each host's inventory entry points to its specific policy file format
   - The Ansible playbook automatically detects the file extension and applies the correct firewall commands

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

- **Use `auto` for most hosts**: Modern Linux systems will automatically use nftables, which is preferred.
- **Set `iptables` explicitly**: Only when you know a host requires iptables (older systems, compatibility requirements).
- **Set `nftables` explicitly**: When you want to ensure nftables is used even if the system might support both.

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

The SSH executor checks a `shouldContinue()` callback between each host. When a deployment is stopped or paused via the API, remaining hosts are marked SKIPPED instead of being processed.

### Login Security

#### Rate Limiting

The login endpoint (`POST /api/auth/login`) implements in-memory rate limiting:
- **10 attempts** per IP address per **15-minute window**
- After exceeding the limit: `429 Too Many Requests` with message "Too many login attempts"
- The counter resets automatically after 15 minutes

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

The communication simulation feature (`POST /troubleshoot/simulate-communication`) provides a powerful analytical tool to predict whether network traffic between two IP addresses would be blocked by deployed firewall policies. This is particularly useful for troubleshooting connectivity issues and validating policy configurations before deployment.

#### How Simulation Works

The simulation engine performs a comprehensive analysis by:

1. **Host Resolution**: 
   - Queries the inventory to find hosts matching the source and destination IPs
   - Supports both exact IP matches and CIDR notation (e.g., `192.168.1.10` matches `192.168.1.10/32`)
   - Returns host information including hostname, management IP, and deployment status

2. **Policy Discovery**:
   - Retrieves all successfully deployed (`SUCCEEDED` status) and approved (`APPROVED` status) policy versions for both source and destination hosts
   - Only considers policies that have been successfully deployed to the hosts (not just created)
   - Filters out failed or cancelled deployments

3. **Rule Evaluation** (Source Host - OUT Direction):
   - For each policy deployed to the source host, evaluates rules with `OUT` or `BOTH` direction
   - Checks if the destination IP matches the rule's source specification:
     - **CIDR**: Uses CIDR matching algorithm to check if destination IP falls within the CIDR range
     - **HOST**: Resolves the host ID to its management IP and compares with destination IP
     - **TAG**: Resolves all hosts with the tag, extracts their management IPs, and checks if destination IP matches
     - **VLAN**: Resolves all hosts in the VLAN, extracts their management IPs, and checks if destination IP matches
   - Validates protocol match (rule protocol must be `any` or match the specified protocol)
   - Validates port match for TCP/UDP (supports single ports, comma-separated lists, and ranges like `1000-2000`)
   - If all conditions match, records the rule as either `ALLOW` or `DENY`

4. **Rule Evaluation** (Destination Host - IN Direction):
   - For each policy deployed to the destination host, evaluates rules with `IN` or `BOTH` direction
   - Checks if the source IP matches the rule's source specification (same resolution logic as above)
   - Validates protocol and port matches (same as source host evaluation)
   - Records matching rules

5. **Result Determination**:
   - Collects all matching rules from both source and destination hosts
   - Sorts rules by order index to determine precedence
   - Applies firewall rule evaluation logic:
     - **First DENY rule wins**: If any DENY rule matches before an ALLOW rule, communication is blocked
     - **ALLOW rules**: If an ALLOW rule matches and no DENY rule precedes it, communication is allowed
     - **Default DENY**: If no rules match, the default policy is DENY (typical firewall behavior)
   - Returns the blocking rule (if any) and all matching rules for review

#### Technical Implementation Details

The simulation uses simplified rule matching logic designed for quick analysis. **Important**: The simulation is intentionally approximate and should be used as a guidance tool, not as exact ground truth. Key implementation aspects:

- **CIDR Matching**: Implements bitwise AND operations with network masks for IPv4 CIDR range checking. **Note**: IPv6 is not supported in the simulation.
- **Port Parsing**: Handles port specifications including:
  - Single ports: `"80"`
  - Multiple ports: `"80,443"`
  - Port ranges: `"1000-2000"`
- **Source Type Resolution**: Dynamically resolves TAG, VLAN, and HOST source types to actual IP addresses at simulation time
- **Direction Handling**: Correctly evaluates both IN and OUT directions, understanding that:
  - Source host OUT rules control traffic leaving the source
  - Destination host IN rules control traffic arriving at the destination
- **Rule Ordering**: Attempts to respect the `order_index` field, but **simplified evaluation**:
  - For combined IN/OUT paths, the simulation builds separate lists of blocking and allowing rules
  - **Pessimistic DENY interpretation**: The simulation treats DENY rules pessimistically - if any DENY rule matches, it assumes communication is blocked, even though firewalls evaluate rules strictly in order (first-match wins)
  - This means the simulation may indicate blocking when an earlier ALLOW rule would actually permit the traffic
  - **Recommendation**: Use simulation results as guidance, but verify critical paths by reviewing actual compiled firewall rules or testing in a non-production environment

**Limitations**:
- Does not perform exact first-match rule evaluation like actual firewalls
- IPv6 addresses are not supported
- Does not account for interface scoping or interface-specific rules
- Does not model connection state (established/related) or other advanced firewall features
- User IP safety warnings use very simplified CIDR matching (first octet comparison) and may produce false positives/negatives

#### Use Cases

- **Pre-deployment Validation**: Test if a new policy would block critical communication paths
- **Connectivity Troubleshooting**: Determine why two hosts cannot communicate
- **Policy Audit**: Verify that deployed policies match intended security posture
- **Change Impact Analysis**: Understand the effect of policy changes on existing communication patterns

### Compliance & Drift Detection Issues

#### Compliance Check Fails with SSH Error
**Symptom**: Compliance check returns "error" status with SSH connection failure

**Causes**:
- SSH credentials not configured (no GLOBAL SSH credential)
- Host is unreachable or SSH port incorrect
- SSH key authentication failure
- Host firewall blocking SSH access

**Solutions**:
1. Verify SSH credentials exist: `GET /api/ssh-credentials`
2. Test SSH manually: `ssh -i <key> user@host`
3. Check host `ssh_port` configuration matches actual port
4. Verify host is reachable: `ping <host_ip>`
5. Check host firewall isn't blocking SSH from Segmentra server

#### Compliance Shows "Unknown" Status
**Symptom**: Host shows "Unknown" compliance status

**Causes**:
- Host has never had a successful deployment
- Last deployment failed (no `applied_hash` stored)
- Deployment was created but never started

**Solutions**:
1. Deploy a policy to the host successfully
2. Check deployment history for the host
3. Verify previous deployments completed with SUCCEEDED status

#### Compliance Shows "Drifted" Status
**Symptom**: Host shows "Drifted" status (hash mismatch)

**Causes**:
- Manual firewall rule changes on the host
- Failed deployment that partially applied
- Policy was rolled back manually
- Another tool modified firewall rules

**Solutions**:
1. Review current rules on host: `ssh host "sudo nft list ruleset"` or `ssh host "sudo iptables-save"`
2. Compare to expected policy: Use policy render endpoint
3. Redeploy the policy to restore compliance
4. Investigate what caused the drift (manual changes, other tools, etc.)

### Host Readiness Issues

#### Readiness Check Fails: "Passwordless sudo access required"
**Symptom**: Readiness check shows `sudoAccess: false` with error about passwordless sudo

**Causes**:
- SSH user doesn't have sudo access
- Sudo requires password (not passwordless)
- Sudoers configuration doesn't allow nft/iptables commands

**Solutions**:
1. Verify sudo access: `ssh user@host "sudo -n nft list ruleset"`
2. Configure passwordless sudo for firewall commands:
   ```bash
   # On the host, add to /etc/sudoers.d/segmentra:
   segmentra_user ALL=(ALL) NOPASSWD: /usr/sbin/nft, /usr/sbin/iptables, /usr/sbin/iptables-save, /usr/sbin/iptables-restore
   ```
3. Test: `sudo -n nft list ruleset` should work without password

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
- Background job not running
- `scheduled_at` is in the future
- API server was restarted and background job didn't restart
- Timezone mismatch

**Solutions**:
1. Check API logs for scheduled deployment processing
2. Verify `scheduled_at` timestamp is in the past
3. Use UTC timezone for `scheduled_at` to avoid timezone issues
4. Manually start deployment if needed: `POST /api/deployments/:id/start`

#### Scheduled Deployment Starts Immediately
**Symptom**: Deployment starts even though `scheduled_at` is in the future

**Causes**:
- Background job processes immediately (bug)
- `scheduled_at` parsing error

**Solutions**:
1. Verify `scheduled_at` format is correct ISO 8601
2. Check that deployment status is QUEUED (not RUNNING)
3. Review background job implementation

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
- Missing SSH credentials
- Ansible container not running (if using Ansible executor)
- Bundle generation failure
- Invalid policy version (not APPROVED)

**Solutions**:
1. Check Admin → SSH Credentials has a GLOBAL credential configured
2. Verify Ansible container is running: `docker ps | grep ansible-runner`
3. Check API logs for bundle generation errors
4. Verify policy version status is APPROVED

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
- Approver is the same user who created the policy (separation of duties)
- User doesn't have approver/admin role
- Policy version has validation errors

**Solutions**:
1. Verify approver has `approver` or `admin` role
2. Ensure approver is different from creator
3. Check policy version for validation errors
4. Review rejection reason if rejected

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
1. Verify LDAP is enabled in Admin → LDAP Settings
2. Test LDAP connection with `ldapsearch` or similar tool
3. Check AD group mappings in Admin → AD Group → Role map
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
2. Reset password via API or database
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
5. Reset database if needed: `SEGMENTRA_RESET_DB=1`

### Performance Issues

#### Slow Deployments
**Symptom**: Deployments take a long time to complete

**Causes**:
- Large number of hosts
- Network latency
- Sequential execution (SSH Direct executor)
- Host response time

**Solutions**:
1. Use Ansible executor for parallel execution
2. Reduce batch size for progressive deployments
3. Check network connectivity and latency
4. Monitor host resource usage
5. Consider canary deployments for large changes

---

## Configuration Details

### Environment Variables

The API reads env vars in `apps/api/src/lib/env.ts`:

- `PORT` (default `8080`) — API server port
- `DATABASE_URL` (**required**) — PostgreSQL connection string
- `JWT_SECRET` (**required**, min 16 chars) — Secret for JWT token signing
- `SEGMENTRA_KEK_B64` (optional) — Base64 of 32-byte key for AES-256-GCM secret encryption. If not provided, derives from JWT_SECRET (dev only).
- `SEGMENTRA_BOOTSTRAP_TOKEN` (optional) — Enables `POST /api/admin/bootstrap` endpoint for one-time admin creation
- `BUNDLES_DIR` (default `./data/bundles`) — Directory where deployment bundles/logs are written
- `ANSIBLE_RUNNER_CONTAINER` (default `segmentra-ansible-runner`) — Name of the Ansible runner container

### Docker Compose Configuration

The `docker-compose.yml` file defines:

- **PostgreSQL**: Database container on port 15432
- **App Container**: API server with Docker socket mount
- **Ansible Runner**: Optional container for Ansible executor
- **Volumes**: Shared bundle storage between containers

### Security Considerations

1. **Docker Socket Mount**: The app container mounts `/var/run/docker.sock` for Ansible executor. This gives full Docker access - treat as high trust.
2. **Secret Encryption**: SSH keys and LDAP passwords are encrypted using AES-256-GCM. Store `SEGMENTRA_KEK_B64` securely.
3. **JWT Tokens**: Tokens expire after 12 hours. Store `JWT_SECRET` securely.
4. **SSH Credentials**: Use sudo-capable accounts, not root. Ensure passwordless sudo for firewall commands.
5. **LDAP**: Use LDAPS (port 636) for secure LDAP connections in production.

### Secret Storage & Encryption

Segmentra implements robust encryption for sensitive data stored in the database, including SSH private keys, SSH key passphrases, and LDAP bind passwords.

#### Encryption Architecture

**Storage Flow**:
- When creating an SSH credential or LDAP setting, sensitive data (private keys, passphrases, passwords) is passed to `createSecret()` service function
- `createSecret()` calls `encryptBlob()` which encrypts the data using **AES-256-GCM** (Galois/Counter Mode)
- The encrypted blob is stored in the `secret_store` table in the `encrypted_blob` column (bytea type)
- Reference tables (e.g., `ssh_credentials`, `ldap_settings`) only store UUID references (`private_key_secret_id`, `passphrase_secret_id`, `bind_password_secret_id`) to the encrypted secrets
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
- For SSH operations, decrypted keys are written to temporary files in `os.tmpdir()` (system temporary directory)
- Temporary files are created with restrictive permissions (mode 0o600) and cleaned up immediately after use
- Keys are never logged or exposed in API responses

#### Security Features

- **Encryption at Rest**: All sensitive data is encrypted before being stored in the database
- **Strong Algorithm**: AES-256-GCM provides authenticated encryption (confidentiality + integrity)
- **Unique IVs**: Each encryption uses a random IV, ensuring identical plaintext produces different ciphertext
- **Key Separation**: The encryption key (KEK) is stored separately (environment variable), never in the database
- **Temporary File Handling**: Decrypted keys are only written to temporary files that are automatically cleaned up
- **No Plaintext Storage**: The database never contains unencrypted sensitive data
- **Immutable Secrets**: SSH keys cannot be updated via PUT endpoint - must create new credential and delete old one

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

- Canary/progressive orchestration and advanced guardrails are stubbed at the API level (basic deployment flow is implemented). The deployment modes (`CANARY`, `PROGRESSIVE`, `FULL`) are accepted and stored, but all selected hosts are processed immediately without host-by-host orchestration.
- Baseline mgmt SSH CIDR is configured via the management VLAN setting (`/admin/management-vlan-setting`). The system uses the `subnet` field from the VLAN referenced by `system_settings.management_vlan_id` to determine which CIDR ranges should have baseline SSH access. This is configurable per environment. If no management VLAN is configured, baseline SSH access is disabled (no hardcoded CIDR).
- SSH Direct executor runs sequentially (one host at a time); Ansible runs in parallel.
- Deployment timeout is fixed at 10 minutes per host.
- No built-in rollback UI (rollback happens automatically on failure).
- Firewall backend `auto` setting is now auto-detected before compilation via SSH. If auto-detection fails, it defaults to `nftables`. The detected backend is stored in the host record for future deployments. Executors validate that the compiled policy format matches the detected backend at runtime.
- Drift detection requires SSH access and passwordless sudo. Hosts without SSH credentials configured cannot be checked for compliance.
- Scheduled deployments use simple datetime comparison. When `scheduled_at <= now()`, the system clears `scheduled_at` and leaves the deployment in `QUEUED` status - manual start via `/deployments/:id/start` is still required. No support for recurring schedules, timezone handling, or complex scheduling rules.
- **High-risk policy detection**: The system automatically evaluates policy versions for high-risk patterns and sets the `is_high_risk` flag. High-risk policies require a different approver (no self-approval, even for admins). Risk evaluation considers interface scope, target count, source ranges, and sensitive ports. See [High-Risk Policy Detection](#high-risk-policy-detection) for details.

---

## Additional Resources

- **API Documentation**: See API endpoints section above
- **Database Schema**: See database schema section above
- **Deployment Flow**: See deployment executors section above
- **Policy Compilation**: See `packages/compiler/src/compile.ts` for policy rendering logic
- **Ansible Playbook**: See `infra/ansible-runner/playbooks/apply-firewall.yml` for deployment playbook
