import crypto from 'node:crypto';

import { pool } from '../db/pool.js';

/**
 * Compliance evidence reports (docs/compliance-reports.md).
 *
 * A report is a point-in-time snapshot of what Segmentra knows: inventory coverage, change control, deployments, drift,
 * access, credentials, audit trail, IoT, Kubernetes and Docker Swarm. The sections are mapped to controls of PCI DSS
 * v4.0, ISO/IEC 27001:2022, SOC 2 and the HIPAA Security Rule. The mapping is informational: it says which of
 * Segmentra's data supports a control and where attention is needed. It is not an audit opinion or a certification.
 */

export const REPORT_VERSION = 1;
export const FRAMEWORK_IDS = ['pci-dss-4', 'iso-27001-2022', 'soc2', 'hipaa'] as const;
export type FrameworkId = (typeof FRAMEWORK_IDS)[number];
const LIST_LIMIT = 500;

export type ReportParams = {
  frameworks: FrameworkId[];
  from: Date;
  to: Date;
  /** A managed host whose last successful deployment is older than this is "stale". */
  staleDays: number;
  /** A policy set without an approval for this long counts as not reviewed. */
  reviewDays: number;
  /** SSH credential secrets older than this are flagged for rotation. */
  credentialMaxAgeDays: number;
  /** Accounts without a login for this long are flagged. */
  inactiveUserDays: number;
  /** Also read every managed host over SSH and compare its live rules with the last deployment (slow). */
  liveDrift: boolean;
};

export const DEFAULT_PARAMS = { staleDays: 90, reviewDays: 180, credentialMaxAgeDays: 365, inactiveUserDays: 90 };

type MetricStatus = 'ok' | 'attention' | 'info';
export type Metric = { id: string; label: string; value: number | string | null; status: MetricStatus; detail?: string };

const days = (ms: number) => Math.floor(ms / 86_400_000);
const pct = (n: number, d: number) => (d === 0 ? 100 : Math.round((n / d) * 1000) / 10);
const cap = <T>(rows: T[]): { rows: T[]; truncated: boolean } => ({ rows: rows.slice(0, LIST_LIMIT), truncated: rows.length > LIST_LIMIT });

// ---- evidence collection ----------------------------------------------------------------------------------------

export async function collectEvidence(p: ReportParams, now = new Date()) {
  const q = async (sql: string, params: any[] = []) => (await pool.query(sql, params)).rows as any[];

  // Inventory and coverage
  const hosts = await q(`SELECT h.id, h.hostname, h.enabled, h.firewall_backend, h.swarm_cluster, h.docker_published_ports,
                                COALESCE((SELECT array_agg(t.name ORDER BY t.name) FROM host_tags ht JOIN tags t ON t.id = ht.tag_id WHERE ht.host_id = h.id), '{}') AS tags
                           FROM hosts h ORDER BY h.hostname`);
  const last = await q(
    `SELECT DISTINCT ON (dh.host_id) dh.host_id, COALESCE(dh.finished_at, d.finished_at, d.created_at) AS at, dh.expiry_status,
            pv.version_number, ps.name AS policy_set
       FROM deployment_hosts dh
       JOIN deployments d ON d.id = dh.deployment_id
       JOIN policy_versions pv ON pv.id = d.policy_version_id
       JOIN policy_sets ps ON ps.id = pv.policy_set_id
      WHERE dh.status = 'SUCCEEDED'
      ORDER BY dh.host_id, COALESCE(dh.finished_at, d.finished_at, d.created_at) DESC`
  );
  const lastBy = new Map(last.map((r) => [r.host_id, r]));
  const enabled = hosts.filter((h) => h.enabled);
  const hostRows = enabled.map((h) => {
    const l = lastBy.get(h.id);
    const removed = l?.expiry_status === 'REMOVED';
    const ageDays = l ? days(now.getTime() - new Date(l.at).getTime()) : null;
    const state = !l ? 'unmanaged' : removed ? 'unmanaged' : ageDays! > p.staleDays ? 'stale' : 'managed';
    return {
      hostname: h.hostname, backend: h.firewall_backend, tags: h.tags, state,
      reason: !l ? 'no successful deployment' : removed ? 'policy removed by the expiry action' : null,
      lastDeployedAt: l?.at ?? null, ageDays, policySet: l?.policy_set ?? null, policyVersion: l?.version_number ?? null,
    };
  });
  const managed = hostRows.filter((h) => h.state === 'managed' || h.state === 'stale');
  const unmanaged = hostRows.filter((h) => h.state === 'unmanaged');
  const stale = hostRows.filter((h) => h.state === 'stale');
  const byBackend: Record<string, number> = {};
  for (const h of enabled) byBackend[h.firewall_backend] = (byBackend[h.firewall_backend] ?? 0) + 1;

  // Policy sets and review
  const sets = await q(
    `SELECT ps.id, ps.name, ps.scope_type,
            (SELECT max(pv.approved_at) FROM policy_versions pv WHERE pv.policy_set_id = ps.id AND pv.approved_at IS NOT NULL) AS last_approved_at,
            (SELECT count(*)::int FROM policy_versions pv WHERE pv.policy_set_id = ps.id AND pv.status IN ('APPROVED','DEPLOYED')) AS approved_versions
       FROM policy_sets ps ORDER BY ps.name`
  );
  const notReviewed = sets
    .map((s) => ({ name: s.name, scope: s.scope_type, lastApprovedAt: s.last_approved_at, ageDays: s.last_approved_at ? days(now.getTime() - new Date(s.last_approved_at).getTime()) : null }))
    .filter((s) => s.ageDays === null || s.ageDays > p.reviewDays);
  const versionsByStatus = Object.fromEntries((await q(`SELECT status, count(*)::int AS n FROM policy_versions GROUP BY status`)).map((r) => [r.status, r.n]));

  // Change control in the period
  const changes = await q(
    `SELECT ps.name AS policy_set, pv.version_number, pv.status, pv.is_high_risk, pv.submitted_at, pv.approved_at, pv.rejected_at,
            su.username AS submitted_by, au.username AS approved_by, cu.username AS created_by,
            (pv.approved_by IS NOT NULL AND (pv.approved_by = pv.submitted_by OR pv.approved_by = pv.created_by
               OR EXISTS (SELECT 1 FROM policy_version_editors e WHERE e.policy_version_id = pv.id AND e.user_id = pv.approved_by))) AS self_approved
       FROM policy_versions pv
       JOIN policy_sets ps ON ps.id = pv.policy_set_id
       LEFT JOIN users su ON su.id = pv.submitted_by
       LEFT JOIN users au ON au.id = pv.approved_by
       LEFT JOIN users cu ON cu.id = pv.created_by
      WHERE (pv.submitted_at >= $1 AND pv.submitted_at <= $2) OR (pv.approved_at >= $1 AND pv.approved_at <= $2) OR (pv.rejected_at >= $1 AND pv.rejected_at <= $2)
      ORDER BY COALESCE(pv.approved_at, pv.submitted_at) DESC`,
    [p.from, p.to]
  );
  const approvedInPeriod = changes.filter((c) => c.approved_at && new Date(c.approved_at) >= p.from && new Date(c.approved_at) <= p.to);
  const latencies = approvedInPeriod.filter((c) => c.submitted_at).map((c) => (new Date(c.approved_at).getTime() - new Date(c.submitted_at).getTime()) / 3_600_000);
  const pendingNow = await q(`SELECT ps.name AS policy_set, pv.version_number, pv.submitted_at FROM policy_versions pv JOIN policy_sets ps ON ps.id = pv.policy_set_id WHERE pv.status = 'PENDING_APPROVAL' ORDER BY pv.submitted_at`);
  const pendingOld = pendingNow.filter((r) => r.submitted_at && days(now.getTime() - new Date(r.submitted_at).getTime()) >= 7);

  // Deployments in the period
  const deps = await q(
    `SELECT d.id, d.status, d.created_at, d.finished_at, d.requires_approval, d.approved_at, ps.name AS policy_set, pv.version_number, u.username AS created_by,
            (SELECT count(*)::int FROM deployment_hosts dh WHERE dh.deployment_id = d.id AND dh.status = 'FAILED') AS failed_hosts,
            (SELECT count(*)::int FROM deployment_hosts dh WHERE dh.deployment_id = d.id AND dh.rollback_performed) AS rollbacks
       FROM deployments d JOIN policy_versions pv ON pv.id = d.policy_version_id JOIN policy_sets ps ON ps.id = pv.policy_set_id LEFT JOIN users u ON u.id = d.created_by
      WHERE d.created_at >= $1 AND d.created_at <= $2 ORDER BY d.created_at DESC`,
    [p.from, p.to]
  );
  const depByStatus: Record<string, number> = {};
  for (const d of deps) depByStatus[d.status] = (depByStatus[d.status] ?? 0) + 1;
  const depFailures = deps.filter((d) => d.status !== 'SUCCEEDED' && ['FAILED', 'PARTIAL'].includes(d.status) || d.failed_hosts > 0);

  // Security audit (latest scan)
  const scan = (await q(`SELECT summary, created_at FROM security_audit_results ORDER BY created_at DESC LIMIT 1`))[0];
  const scanSummary = scan ? (typeof scan.summary === 'string' ? JSON.parse(scan.summary) : scan.summary) : null;

  // Audit trail
  const auditTotals = (await q(`SELECT count(*)::int AS events, count(DISTINCT actor_user_id)::int AS actors, min(timestamp) AS first_at, max(timestamp) AS last_at FROM audit_events WHERE timestamp >= $1 AND timestamp <= $2`, [p.from, p.to]))[0];
  const auditByAction = await q(`SELECT action, count(*)::int AS n FROM audit_events WHERE timestamp >= $1 AND timestamp <= $2 GROUP BY action ORDER BY n DESC, action LIMIT 60`, [p.from, p.to]);
  const privileged = (await q(
    `SELECT count(*)::int AS n FROM audit_events WHERE timestamp >= $1 AND timestamp <= $2 AND action ~ '^(USER_|SSH_CREDENTIAL_|LDAP|AD_|K8S_CLUSTER_|INTEGRATION_|NOTIFICATION_|SYSTEM_|EXECUTOR|MANAGEMENT)'`, [p.from, p.to]))[0].n;

  // Access
  const users = await q(
    `SELECT u.username, u.is_active, u.last_login_at, u.created_at, COALESCE((SELECT array_agg(r.name ORDER BY r.name) FROM user_roles ur JOIN roles r ON r.id = ur.role_id WHERE ur.user_id = u.id), '{}') AS roles
       FROM users u ORDER BY u.username`
  );
  const activeUsers = users.filter((u) => u.is_active);
  const inactiveUsers = activeUsers.filter((u) => {
    const ref = u.last_login_at ?? u.created_at;
    return days(now.getTime() - new Date(ref).getTime()) > p.inactiveUserDays;
  }).map((u) => ({ username: u.username, roles: u.roles, lastLoginAt: u.last_login_at, ageDays: days(now.getTime() - new Date(u.last_login_at ?? u.created_at).getTime()), neverLoggedIn: !u.last_login_at }));
  const roleCounts: Record<string, number> = {};
  for (const u of activeUsers) for (const r of u.roles) roleCounts[r] = (roleCounts[r] ?? 0) + 1;
  const ldap = (await q(`SELECT enabled FROM ldap_settings ORDER BY created_at DESC LIMIT 1`))[0];

  // Credentials
  const creds = await q(
    `SELECT c.name, c.auth_method, c.scope_type, c.created_at,
            GREATEST(c.created_at, COALESCE((SELECT max(COALESCE(s.rotated_at, s.created_at)) FROM secret_store s WHERE s.id IN (c.private_key_secret_id, c.password_secret_id)), c.created_at)) AS secret_at
       FROM ssh_credentials c ORDER BY c.name`
  );
  const credRows = creds.map((c) => ({ name: c.name, auth: c.auth_method, scope: c.scope_type, secretAt: c.secret_at, ageDays: days(now.getTime() - new Date(c.secret_at).getTime()) }));
  const oldCreds = credRows.filter((c) => c.ageDays > p.credentialMaxAgeDays);

  // IoT
  const assets = await q(
    `SELECT a.name, a.asset_type, a.criticality, a.zone, a.ip_address, a.enabled,
            (SELECT count(*)::int FROM iot_asset_gateways g WHERE g.asset_id = a.id) AS gateways
       FROM iot_assets a ORDER BY (a.criticality = 'critical') DESC, a.name`
  );
  const enabledAssets = assets.filter((a) => a.enabled);
  const unprotectedAssets = enabledAssets.filter((a) => a.gateways === 0);
  const gwCount = (await q(`SELECT count(DISTINCT ht.host_id)::int AS n FROM host_tags ht JOIN tags t ON t.id = ht.tag_id WHERE t.name = 'iot-gateway'`))[0].n;
  const assetsByCrit: Record<string, number> = {};
  for (const a of enabledAssets) assetsByCrit[a.criticality] = (assetsByCrit[a.criticality] ?? 0) + 1;

  // Kubernetes
  const clusters = await q(`SELECT name, cni, (credentials_secret_id IS NOT NULL) AS has_credentials, tls_skip_verify, enabled FROM k8s_clusters ORDER BY name`);
  const k8sPolicies = await q(
    `SELECT DISTINCT ON (cluster_id, namespace, policy_name) status, live_state FROM k8s_network_policies WHERE status <> 'SUPERSEDED' ORDER BY cluster_id, namespace, policy_name, created_at DESC`
  );
  const k8sByStatus: Record<string, number> = {};
  for (const r of k8sPolicies) k8sByStatus[r.status] = (k8sByStatus[r.status] ?? 0) + 1;

  // Docker / Swarm
  const swarmHosts = enabled.filter((h) => h.swarm_cluster);
  const swarmByCluster: Record<string, number> = {};
  for (const h of swarmHosts) swarmByCluster[h.swarm_cluster] = (swarmByCluster[h.swarm_cluster] ?? 0) + 1;

  // Optional live drift
  let drift: any = null;
  if (p.liveDrift) {
    const { runLiveDrift } = await import('./compliance-drift.js');
    drift = await runLiveDrift(enabled.filter((h) => lastBy.has(h.id)).map((h) => h.id));
  }

  return {
    inventory: { hostsTotal: hosts.length, hostsEnabled: enabled.length, managed: managed.length, unmanaged: unmanaged.length, stale: stale.length, byBackend, hosts: cap(hostRows) },
    policy: { policySets: sets.length, withApproved: sets.filter((s) => s.approved_versions > 0).length, versionsByStatus, notReviewed: cap(notReviewed), reviewDays: p.reviewDays },
    changes: {
      versionsTouched: changes.length, approvedInPeriod: approvedInPeriod.length,
      rejectedInPeriod: changes.filter((c) => c.rejected_at && new Date(c.rejected_at) >= p.from && new Date(c.rejected_at) <= p.to).length,
      highRiskApproved: approvedInPeriod.filter((c) => c.is_high_risk).length,
      selfApproved: changes.filter((c) => c.self_approved).length,
      avgApprovalHours: latencies.length ? Math.round((latencies.reduce((a, b) => a + b, 0) / latencies.length) * 10) / 10 : null,
      pendingNow: pendingNow.length, pendingOlderThan7d: pendingOld.length,
      rows: cap(changes.map((c) => ({ policySet: c.policy_set, version: c.version_number, status: c.status, highRisk: c.is_high_risk, createdBy: c.created_by, submittedBy: c.submitted_by, approvedBy: c.approved_by, submittedAt: c.submitted_at, approvedAt: c.approved_at, selfApproved: c.self_approved }))),
    },
    deployments: {
      total: deps.length, byStatus: depByStatus,
      withFailedHosts: deps.filter((d) => d.failed_hosts > 0).length, rollbacks: deps.reduce((n, d) => n + d.rollbacks, 0),
      requiringApproval: deps.filter((d) => d.requires_approval).length,
      failures: cap(depFailures.map((d) => ({ id: d.id, at: d.created_at, policySet: d.policy_set, version: d.version_number, status: d.status, failedHosts: d.failed_hosts, rollbacks: d.rollbacks, by: d.created_by }))),
    },
    posture: { lastScanAt: scan?.created_at ?? null, scanAgeDays: scan ? days(now.getTime() - new Date(scan.created_at).getTime()) : null, summary: scanSummary },
    audit: { events: auditTotals.events, actors: auditTotals.actors, firstAt: auditTotals.first_at, lastAt: auditTotals.last_at, privilegedEvents: privileged, byAction: auditByAction.map((r) => ({ action: r.action, count: r.n })) },
    access: { users: users.length, active: activeUsers.length, roleCounts, admins: roleCounts['admin'] ?? 0, ldapEnabled: !!ldap?.enabled, inactiveDays: p.inactiveUserDays, inactive: cap(inactiveUsers) },
    credentials: { ssh: credRows.length, maxAgeDays: p.credentialMaxAgeDays, older: cap(oldCreds), all: cap(credRows) },
    iot: { assets: enabledAssets.length, gateways: gwCount, byCriticality: assetsByCrit, unprotected: cap(unprotectedAssets.map((a) => ({ name: a.name, type: a.asset_type, criticality: a.criticality, zone: a.zone, ip: a.ip_address }))), all: cap(assets.map((a) => ({ name: a.name, type: a.asset_type, criticality: a.criticality, zone: a.zone, ip: a.ip_address, enabled: a.enabled, gateways: a.gateways }))) },
    kubernetes: { clusters: clusters.length, withCredentials: clusters.filter((c) => c.has_credentials).length, tlsNotVerified: clusters.filter((c) => c.tls_skip_verify).length, cniUnknown: clusters.filter((c) => c.cni === 'unknown').length, policiesByStatus: k8sByStatus, driftedPolicies: k8sPolicies.filter((r) => r.live_state === 'DRIFTED').length },
    swarm: { nodes: swarmHosts.length, clusters: swarmByCluster, withPublishedPortEnforcement: swarmHosts.filter((h) => h.docker_published_ports).length },
    drift,
  };
}

type Evidence = Awaited<ReturnType<typeof collectEvidence>>;

// ---- metrics ----------------------------------------------------------------------------------------------------

export function buildMetrics(e: Evidence, p: ReportParams): Record<string, Metric> {
  const m: Record<string, Metric> = {};
  const add = (id: string, label: string, value: number | string | null, status: MetricStatus, detail?: string) => { m[id] = { id, label, value, status, detail }; };
  const covered = e.inventory.managed;
  add('coverage', 'Enabled hosts under a deployed Segmentra policy (%)', pct(covered, e.inventory.hostsEnabled), e.inventory.unmanaged === 0 ? 'ok' : 'attention',
    `${covered} of ${e.inventory.hostsEnabled} enabled hosts (${e.inventory.unmanaged} without a successful deployment)`);
  add('stale_hosts', `Hosts not deployed for more than ${p.staleDays} days`, e.inventory.stale, e.inventory.stale === 0 ? 'ok' : 'attention');
  add('policy_sets_reviewed', `Policy sets approved within ${p.reviewDays} days`, e.policy.policySets - e.policy.notReviewed.rows.length, e.policy.notReviewed.rows.length === 0 ? 'ok' : 'attention',
    `${e.policy.notReviewed.rows.length}${e.policy.notReviewed.truncated ? '+' : ''} of ${e.policy.policySets} policy sets have no approval in that time`);
  add('changes_approved', 'Policy versions approved in the period', e.changes.approvedInPeriod, 'info');
  add('self_approvals', 'Versions approved by someone who edited or submitted them', e.changes.selfApproved, e.changes.selfApproved === 0 ? 'ok' : 'attention', 'Segmentra refuses these; any number above zero needs explaining');
  add('pending_old', 'Approvals waiting more than 7 days', e.changes.pendingOlderThan7d, e.changes.pendingOlderThan7d === 0 ? 'ok' : 'attention');
  add('high_risk_approved', 'High-risk versions approved in the period', e.changes.highRiskApproved, 'info');
  add('deployments_failed', 'Deployments with failed hosts in the period', e.deployments.withFailedHosts, e.deployments.withFailedHosts === 0 ? 'ok' : 'attention', `${e.deployments.total} deployments, ${e.deployments.rollbacks} automatic rollbacks`);
  add('security_scan_age', 'Days since the last security audit scan', e.posture.scanAgeDays, e.posture.scanAgeDays === null ? 'attention' : e.posture.scanAgeDays <= 30 ? 'ok' : 'attention',
    e.posture.summary ? `latest findings: ${e.posture.summary.critical ?? 0} critical, ${e.posture.summary.high ?? 0} high, ${e.posture.summary.medium ?? 0} medium` : 'no scan recorded');
  add('security_critical', 'Critical or high findings in the latest scan', e.posture.summary ? (e.posture.summary.critical ?? 0) + (e.posture.summary.high ?? 0) : null, !e.posture.summary ? 'attention' : (e.posture.summary.critical ?? 0) + (e.posture.summary.high ?? 0) === 0 ? 'ok' : 'attention');
  add('audit_events', 'Audit events recorded in the period', e.audit.events, e.audit.events > 0 ? 'ok' : 'attention', `${e.audit.actors} distinct users; ${e.audit.privilegedEvents} administrative or credential events`);
  add('active_users', 'Active user accounts', e.access.active, 'info', Object.entries(e.access.roleCounts).map(([r, n]) => `${r}: ${n}`).join(', '));
  add('admins', 'Active administrator accounts', e.access.admins, e.access.admins <= 5 ? 'ok' : 'attention');
  add('inactive_users', `Active accounts without login for more than ${p.inactiveUserDays} days`, e.access.inactive.rows.length, e.access.inactive.rows.length === 0 ? 'ok' : 'attention');
  add('old_credentials', `SSH credentials not rotated for more than ${p.credentialMaxAgeDays} days`, e.credentials.older.rows.length, e.credentials.older.rows.length === 0 ? 'ok' : 'attention', `${e.credentials.ssh} SSH credentials`);
  add('iot_unprotected', 'Enabled IoT/OT assets without a protecting gateway', e.iot.unprotected.rows.length, e.iot.assets === 0 ? 'info' : e.iot.unprotected.rows.length === 0 ? 'ok' : 'attention', `${e.iot.assets} assets, ${e.iot.gateways} gateways`);
  add('k8s_tls', 'Kubernetes clusters with TLS verification disabled', e.kubernetes.tlsNotVerified, e.kubernetes.tlsNotVerified === 0 ? 'ok' : 'attention', `${e.kubernetes.clusters} clusters`);
  add('k8s_drift', 'Kubernetes policies that drifted from Segmentra\'s manifest (last check)', e.kubernetes.driftedPolicies, e.kubernetes.driftedPolicies === 0 ? 'ok' : 'attention');
  add('swarm_nodes', 'Docker Swarm nodes managed', e.swarm.nodes, 'info', e.swarm.nodes ? `${e.swarm.withPublishedPortEnforcement} with published-port enforcement` : undefined);
  if (e.drift) {
    const c = e.drift.counts;
    add('drift', 'Hosts whose live rules differ from the last deployment', c.drifted ?? 0, (c.drifted ?? 0) === 0 && (c.error ?? 0) === 0 ? 'ok' : 'attention',
      `checked ${e.drift.checked} hosts over SSH: ${c.compliant ?? 0} match, ${c.drifted ?? 0} drifted, ${c.unknown ?? 0} unknown, ${c.error ?? 0} unreachable`);
  } else {
    add('drift', 'Live drift check', null, 'info', 'not run for this report (enable the live drift check to read every host over SSH)');
  }
  return m;
}

// ---- frameworks ---------------------------------------------------------------------------------------------------

type ControlDef = { id: string; title: string; note: string; metrics: string[]; gap?: string };
type FrameworkDef = { id: FrameworkId; name: string; version: string; controls: ControlDef[] };

export const FRAMEWORKS: FrameworkDef[] = [
  {
    id: 'pci-dss-4', name: 'PCI DSS', version: 'v4.0',
    controls: [
      { id: '1.2.1', title: 'Configuration standards for network security controls are defined and maintained', note: 'Approved, versioned policy sets deployed to the hosts', metrics: ['coverage', 'policy_sets_reviewed'] },
      { id: '1.2.2', title: 'Changes to network connections and security control configurations are approved and managed', note: 'Approval workflow with separation of duties; deployments and rollbacks recorded', metrics: ['changes_approved', 'self_approvals', 'pending_old', 'high_risk_approved'] },
      { id: '1.2.7', title: 'Network security control configurations are reviewed at least once every six months', note: 'Policy sets without a recent approval are listed', metrics: ['policy_sets_reviewed'] },
      { id: '1.3.1', title: 'Inbound traffic to the cardholder data environment is restricted', note: 'Default-deny inbound firewall on the managed hosts; drift check when run', metrics: ['coverage', 'stale_hosts', 'drift'] },
      { id: '1.3.2', title: 'Outbound traffic from the cardholder data environment is restricted', note: '', metrics: [], gap: 'Segmentra enforces inbound default-deny. Outbound traffic is allowed unless explicit OUT rules exist, and there is no outbound default-deny.' },
      { id: '6.5.1', title: 'Changes to system components follow change-control procedures', note: 'Same evidence as 1.2.2', metrics: ['changes_approved', 'self_approvals', 'deployments_failed'] },
      { id: '8.2.6', title: 'Inactive user accounts are removed or disabled', note: 'Accounts without a recent login are listed', metrics: ['inactive_users'] },
      { id: '10.2.1', title: 'Audit logs capture user access and administrative actions', note: 'Audit trail of changes, approvals, deployments and credential changes', metrics: ['audit_events'] },
    ],
  },
  {
    id: 'iso-27001-2022', name: 'ISO/IEC 27001', version: '2022 (Annex A)',
    controls: [
      { id: 'A.8.20', title: 'Networks security', note: 'Host firewall policies deployed and verified', metrics: ['coverage', 'stale_hosts', 'drift'] },
      { id: 'A.8.22', title: 'Segregation of networks', note: 'Policies scoped by tag or VLAN; IoT/OT assets behind gateways; Kubernetes NetworkPolicies', metrics: ['coverage', 'iot_unprotected', 'k8s_drift'] },
      { id: 'A.8.9', title: 'Configuration management', note: 'Versioned configuration, drift detection, staleness', metrics: ['stale_hosts', 'drift', 'k8s_drift'] },
      { id: 'A.8.32', title: 'Change management', note: 'Approvals, separation of duties, deployment outcomes', metrics: ['changes_approved', 'self_approvals', 'pending_old', 'deployments_failed'] },
      { id: 'A.5.3', title: 'Segregation of duties', note: 'The author of a version cannot approve it', metrics: ['self_approvals'] },
      { id: 'A.8.2', title: 'Privileged access rights', note: 'Administrator accounts and credential rotation', metrics: ['admins', 'old_credentials', 'inactive_users'] },
      { id: 'A.8.15', title: 'Logging', note: 'Audit trail of administrative actions', metrics: ['audit_events'] },
      { id: 'A.8.16', title: 'Monitoring activities', note: '', metrics: [], gap: 'Segmentra records changes, not network traffic. Continuous monitoring of allowed and blocked connections is not provided (firewall learning runs on demand only).' },
    ],
  },
  {
    id: 'soc2', name: 'SOC 2', version: 'Trust Services Criteria (2017, rev. 2022)',
    controls: [
      { id: 'CC6.1', title: 'Logical access security measures protect information assets', note: 'Role-based access, account hygiene, credential rotation', metrics: ['active_users', 'admins', 'inactive_users', 'old_credentials'] },
      { id: 'CC6.3', title: 'Access is granted, modified and removed using role-based, least-privilege principles', note: 'Roles viewer, operator, approver, admin; inactive accounts listed', metrics: ['active_users', 'inactive_users'] },
      { id: 'CC6.6', title: 'Boundary protection against threats from outside the system', note: 'Default-deny host firewalls; IoT and Kubernetes segmentation', metrics: ['coverage', 'iot_unprotected', 'k8s_tls'] },
      { id: 'CC7.2', title: 'Components are monitored for anomalies and security events', note: 'Security audit scans of the policy set and drift detection (not traffic monitoring)', metrics: ['security_scan_age', 'security_critical', 'drift'] },
      { id: 'CC8.1', title: 'Changes are authorised, designed, tested, approved and implemented', note: 'Approval workflow, impact analysis, canary deployments, rollbacks', metrics: ['changes_approved', 'self_approvals', 'high_risk_approved', 'deployments_failed'] },
    ],
  },
  {
    id: 'hipaa', name: 'HIPAA Security Rule', version: '45 CFR 164.3xx',
    controls: [
      { id: '164.312(a)(1)', title: 'Access control: technical policies for access to systems holding ePHI', note: 'Role-based access to the firewall management and host firewall policies', metrics: ['coverage', 'active_users', 'inactive_users'] },
      { id: '164.312(b)', title: 'Audit controls: record and examine activity in systems', note: 'Audit trail with actor, time and details', metrics: ['audit_events'] },
      { id: '164.312(c)(1)', title: 'Integrity: protect information from improper alteration', note: 'Configuration integrity of the firewall rules (drift detection)', metrics: ['drift', 'stale_hosts'] },
      { id: '164.308(a)(1)(ii)(D)', title: 'Information system activity review', note: 'Security audit scans and audit events can be reviewed', metrics: ['security_scan_age', 'audit_events'] },
      { id: '164.308(a)(4)', title: 'Information access management', note: 'Roles, approvals, separation of duties', metrics: ['active_users', 'self_approvals', 'inactive_users'] },
      { id: '164.312(e)(1)', title: 'Transmission security', note: '', metrics: [], gap: 'Segmentra restricts who can connect, it does not encrypt or inspect traffic. Transmission security needs other controls.' },
    ],
  },
];

export type ControlResult = { id: string; title: string; status: 'evidence' | 'attention' | 'gap'; note: string; metrics: Metric[]; gap?: string };

export function evaluateFramework(def: FrameworkDef, metrics: Record<string, Metric>) {
  const controls: ControlResult[] = def.controls.map((c) => {
    if (c.gap) return { id: c.id, title: c.title, status: 'gap', note: c.note, metrics: [], gap: c.gap };
    const ms = c.metrics.map((id) => metrics[id]).filter(Boolean);
    const status = ms.some((x) => x.status === 'attention') ? 'attention' : 'evidence';
    return { id: c.id, title: c.title, status, note: c.note, metrics: ms };
  });
  return {
    id: def.id, name: def.name, version: def.version, controls,
    summary: { evidence: controls.filter((c) => c.status === 'evidence').length, attention: controls.filter((c) => c.status === 'attention').length, gap: controls.filter((c) => c.status === 'gap').length },
  };
}

export const DISCLAIMER =
  'This report is evidence generated from the data Segmentra holds at the time it was created. The mapping to framework controls shows which of that data supports a control ' +
  'and where attention is needed; it is not an audit opinion, an assessment or a certification, and it does not cover controls outside Segmentra (physical, personnel, ' +
  'encryption, outbound filtering and so on). Confirm the mapping with your assessor.';

export async function buildReport(p: ReportParams, who: { username: string }, now = new Date()) {
  const evidence = await collectEvidence(p, now);
  const metrics = buildMetrics(evidence, p);
  const frameworks = FRAMEWORKS.filter((f) => p.frameworks.includes(f.id)).map((f) => evaluateFramework(f, metrics));
  const content = {
    reportVersion: REPORT_VERSION,
    generatedAt: now.toISOString(),
    generatedBy: who.username,
    period: { from: p.from.toISOString(), to: p.to.toISOString() },
    parameters: { staleDays: p.staleDays, reviewDays: p.reviewDays, credentialMaxAgeDays: p.credentialMaxAgeDays, inactiveUserDays: p.inactiveUserDays, liveDrift: p.liveDrift },
    disclaimer: DISCLAIMER,
    metrics: Object.values(metrics),
    frameworks,
    evidence,
  };
  const summary = {
    frameworks: frameworks.map((f) => ({ id: f.id, name: f.name, ...f.summary })),
    attentionMetrics: Object.values(metrics).filter((x) => x.status === 'attention').length,
    hosts: { enabled: evidence.inventory.hostsEnabled, managed: evidence.inventory.managed, unmanaged: evidence.inventory.unmanaged, stale: evidence.inventory.stale },
  };
  return { content, summary, sha256: contentHash(content) };
}

// ---- integrity ----------------------------------------------------------------------------------------------------

export function canonicalJson(v: unknown): string {
  if (v === undefined) return 'null';
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(',')}]`;
  if (v && typeof v === 'object') {
    return `{${Object.keys(v as object).sort().map((k) => `${JSON.stringify(k)}:${canonicalJson((v as any)[k])}`).join(',')}}`;
  }
  return JSON.stringify(v);
}
export const contentHash = (content: unknown) => crypto.createHash('sha256').update(canonicalJson(JSON.parse(JSON.stringify(content))), 'utf8').digest('hex');

// ---- CSV ----------------------------------------------------------------------------------------------------------

/** Cells starting with = + - @ are prefixed so spreadsheet programs do not evaluate them. */
function csvCell(v: unknown): string {
  let s = v === null || v === undefined ? '' : v instanceof Date ? v.toISOString() : typeof v === 'object' ? JSON.stringify(v) : String(v);
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}
export function toCsv(columns: string[], rows: Array<Record<string, unknown>>): string {
  return [columns.join(','), ...rows.map((r) => columns.map((c) => csvCell(r[c])).join(','))].join('\r\n') + '\r\n';
}

export const CSV_DATASETS = ['controls', 'metrics', 'hosts', 'changes', 'deployment_failures', 'users_inactive', 'credentials', 'iot_assets', 'audit_events'] as const;

export async function csvDataset(content: any, dataset: string, reportRow: { period_from: Date; period_to: Date }): Promise<string | null> {
  const ev = content.evidence;
  switch (dataset) {
    case 'controls':
      return toCsv(['framework', 'control', 'title', 'status', 'evidence', 'gap'], content.frameworks.flatMap((f: any) => f.controls.map((c: any) => ({
        framework: `${f.name} ${f.version}`, control: c.id, title: c.title, status: c.status,
        evidence: c.metrics.map((m: Metric) => `${m.label}: ${m.value ?? 'n/a'}${m.detail ? ` (${m.detail})` : ''}`).join(' | '), gap: c.gap ?? '',
      }))));
    case 'metrics':
      return toCsv(['id', 'label', 'value', 'status', 'detail'], content.metrics);
    case 'hosts':
      return toCsv(['hostname', 'backend', 'tags', 'state', 'reason', 'lastDeployedAt', 'ageDays', 'policySet', 'policyVersion'], ev.inventory.hosts.rows.map((h: any) => ({ ...h, tags: (h.tags ?? []).join(';') })));
    case 'changes':
      return toCsv(['policySet', 'version', 'status', 'highRisk', 'createdBy', 'submittedBy', 'approvedBy', 'submittedAt', 'approvedAt', 'selfApproved'], ev.changes.rows.rows);
    case 'deployment_failures':
      return toCsv(['id', 'at', 'policySet', 'version', 'status', 'failedHosts', 'rollbacks', 'by'], ev.deployments.failures.rows);
    case 'users_inactive':
      return toCsv(['username', 'roles', 'lastLoginAt', 'ageDays', 'neverLoggedIn'], ev.access.inactive.rows.map((u: any) => ({ ...u, roles: u.roles.join(';') })));
    case 'credentials':
      return toCsv(['name', 'auth', 'scope', 'secretAt', 'ageDays'], ev.credentials.all.rows);
    case 'iot_assets':
      return toCsv(['name', 'type', 'criticality', 'zone', 'ip', 'enabled', 'gateways'], ev.iot.all.rows);
    case 'audit_events': {
      // Regenerated from the append-only audit log for the report's period (the report stores aggregates only).
      const { rows } = await pool.query(
        `SELECT a.timestamp, u.username AS actor, a.action, a.entity_type, a.entity_id, a.ip_address::text AS ip, a.metadata
           FROM audit_events a LEFT JOIN users u ON u.id = a.actor_user_id
          WHERE a.timestamp >= $1 AND a.timestamp <= $2 ORDER BY a.timestamp LIMIT 20000`,
        [reportRow.period_from, reportRow.period_to]
      );
      return toCsv(['timestamp', 'actor', 'action', 'entity_type', 'entity_id', 'ip', 'metadata'], rows);
    }
    default:
      return null;
  }
}

// ---- HTML ---------------------------------------------------------------------------------------------------------

const esc = (v: unknown) => String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!));
const fmtDate = (v: unknown) => (v ? esc(new Date(String(v)).toISOString().replace('T', ' ').slice(0, 16) + ' UTC') : '-');

export function renderHtml(r: { id: string; title: string; content_sha256: string; created_at: Date }, content: any, intact: boolean): string {
  const table = (cols: Array<[string, (row: any) => unknown]>, rows: any[], max = 50, emptyText = 'None') =>
    rows.length === 0
      ? `<p class="muted">${esc(emptyText)}</p>`
      : `<table><thead><tr>${cols.map(([h]) => `<th>${esc(h)}</th>`).join('')}</tr></thead><tbody>${rows.slice(0, max).map((row) => `<tr>${cols.map(([, f]) => `<td>${esc(f(row))}</td>`).join('')}</tr>`).join('')}</tbody></table>${rows.length > max ? `<p class="muted">${rows.length - max} more rows: see the CSV dataset.</p>` : ''}`;
  const ev = content.evidence;
  const badge = (s: string) => `<span class="b ${esc(s)}">${esc({ evidence: 'Evidence', attention: 'Attention', gap: 'Not covered', ok: 'OK', info: 'Info' }[s] ?? s)}</span>`;
  const fw = content.frameworks.map((f: any) => `
    <h2>${esc(f.name)} <small>${esc(f.version)}</small></h2>
    <p class="muted">${f.summary.evidence} with supporting evidence, ${f.summary.attention} need attention, ${f.summary.gap} not covered by Segmentra.</p>
    <table><thead><tr><th>Control</th><th>Requirement (summary)</th><th>Status</th><th>Segmentra evidence</th></tr></thead><tbody>
    ${f.controls.map((c: any) => `<tr><td class="nowrap">${esc(c.id)}</td><td>${esc(c.title)}</td><td>${badge(c.status)}</td><td>${
      c.gap ? esc(c.gap) : `${esc(c.note)}<ul>${c.metrics.map((m: Metric) => `<li>${badge(m.status)} ${esc(m.label)}: <strong>${esc(m.value ?? 'n/a')}</strong>${m.detail ? ` <span class="muted">(${esc(m.detail)})</span>` : ''}</li>`).join('')}</ul>`}</td></tr>`).join('')}
    </tbody></table>`).join('');
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(r.title)}</title>
<style>
 :root{color-scheme:light dark;--bg:#fdfcf9;--fg:#2b2118;--mut:#78644e;--line:#e0d6c6;--ok:#3f5a26;--att:#a63d2f;--gap:#6b5a45;--card:#f7f4ef}
 @media (prefers-color-scheme:dark){:root{--bg:#1d1913;--fg:#efe7da;--mut:#b6a58d;--line:#3a3226;--ok:#9bc27a;--att:#e58a7c;--gap:#c9b79c;--card:#27221a}}
 body{background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,sans-serif;margin:0;padding:24px;max-width:1100px;margin-inline:auto}
 h1{font-size:24px;margin:0 0 4px} h2{font-size:18px;margin:28px 0 6px;border-bottom:1px solid var(--line);padding-bottom:4px} small{color:var(--mut);font-weight:normal}
 table{border-collapse:collapse;width:100%;margin:8px 0 12px} th,td{border:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top} th{background:var(--card)}
 .muted{color:var(--mut)} .nowrap{white-space:nowrap} ul{margin:4px 0 0 18px;padding:0}
 .b{display:inline-block;padding:0 6px;border-radius:4px;font-size:12px;border:1px solid var(--line)} .b.evidence,.b.ok{color:var(--ok)} .b.attention{color:var(--att)} .b.gap{color:var(--gap)}
 .cards{display:flex;flex-wrap:wrap;gap:10px;margin:12px 0}.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:8px 12px;min-width:150px}.card strong{display:block;font-size:20px}
 .note{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 12px}
 @media print{body{padding:0} h2{break-after:avoid} tr{break-inside:avoid}}
</style></head><body>
<h1>${esc(r.title)}</h1>
<p class="muted">Period ${fmtDate(content.period.from)} to ${fmtDate(content.period.to)} · generated ${fmtDate(content.generatedAt)} by ${esc(content.generatedBy)} · report ${esc(r.id)}<br>
SHA-256 <code>${esc(r.content_sha256)}</code> · integrity ${intact ? '<span class="b ok">verified</span>' : '<span class="b attention">MISMATCH: the stored report was altered</span>'}</p>
<div class="note">${esc(content.disclaimer)}</div>
<div class="cards">
 <div class="card"><strong>${ev.inventory.managed}/${ev.inventory.hostsEnabled}</strong>hosts under a deployed policy</div>
 <div class="card"><strong>${ev.changes.approvedInPeriod}</strong>versions approved in the period</div>
 <div class="card"><strong>${ev.changes.selfApproved}</strong>self-approvals</div>
 <div class="card"><strong>${ev.audit.events}</strong>audit events</div>
 <div class="card"><strong>${ev.iot.unprotected.rows.length}/${ev.iot.assets}</strong>IoT assets without a gateway</div>
</div>
${fw}
<h2>Measurements</h2>
${table([['Measurement', (m) => m.label], ['Value', (m) => m.value ?? 'n/a'], ['Status', (m) => m.status], ['Detail', (m) => m.detail ?? '']], content.metrics, 100)}
<h2>Hosts without a deployed policy</h2>
${table([['Host', (h) => h.hostname], ['Backend', (h) => h.backend], ['Reason', (h) => h.reason]], ev.inventory.hosts.rows.filter((h: any) => h.state === 'unmanaged'), 50, 'Every enabled host has a successful deployment.')}
<h2>Stale hosts</h2>
${table([['Host', (h) => h.hostname], ['Last deployed', (h) => fmtDate(h.lastDeployedAt)], ['Days', (h) => h.ageDays], ['Policy', (h) => `${h.policySet} v${h.policyVersion}`]], ev.inventory.hosts.rows.filter((h: any) => h.state === 'stale'), 50, `No host is older than ${content.parameters.staleDays} days.`)}
<h2>Policy sets not approved recently</h2>
${table([['Policy set', (s) => s.name], ['Last approved', (s) => fmtDate(s.lastApprovedAt)], ['Days', (s) => s.ageDays ?? 'never']], ev.policy.notReviewed.rows, 50, `All policy sets were approved within ${content.parameters.reviewDays} days.`)}
<h2>Changes in the period</h2>
<p class="muted">${ev.changes.versionsTouched} versions submitted, approved or rejected; ${ev.changes.approvedInPeriod} approved (average ${ev.changes.avgApprovalHours ?? 'n/a'} h from submission); ${ev.changes.highRiskApproved} high-risk; ${ev.changes.pendingNow} waiting now.</p>
${table([['Policy set', (c) => c.policySet], ['Ver.', (c) => c.version], ['Status', (c) => c.status], ['Submitted by', (c) => c.submittedBy], ['Approved by', (c) => c.approvedBy], ['Approved', (c) => fmtDate(c.approvedAt)], ['High risk', (c) => (c.highRisk ? 'yes' : '')], ['Self-approved', (c) => (c.selfApproved ? 'YES' : '')]], ev.changes.rows.rows, 40)}
<h2>Deployments with failures</h2>
<p class="muted">${ev.deployments.total} deployments in the period (${Object.entries(ev.deployments.byStatus).map(([k, v]) => `${esc(k)}: ${v}`).join(', ') || 'none'}); ${ev.deployments.rollbacks} automatic rollbacks.</p>
${table([['When', (d) => fmtDate(d.at)], ['Policy', (d) => `${d.policySet} v${d.version}`], ['Status', (d) => d.status], ['Failed hosts', (d) => d.failedHosts], ['Rollbacks', (d) => d.rollbacks], ['By', (d) => d.by]], ev.deployments.failures.rows, 40, 'No failed deployments in the period.')}
<h2>IoT / OT assets without a protecting gateway</h2>
${table([['Asset', (a) => a.name], ['Type', (a) => a.type], ['Criticality', (a) => a.criticality], ['Zone', (a) => a.zone], ['IP', (a) => a.ip]], ev.iot.unprotected.rows, 50, ev.iot.assets === 0 ? 'No IoT assets are registered.' : 'Every enabled IoT asset has a gateway.')}
<h2>Access and credentials</h2>
<p class="muted">${ev.access.active} active accounts (${Object.entries(ev.access.roleCounts).map(([k, v]) => `${esc(k)}: ${v}`).join(', ')}); directory login ${ev.access.ldapEnabled ? 'enabled' : 'not enabled'}; ${ev.credentials.ssh} SSH credentials.</p>
${table([['Account', (u) => u.username], ['Roles', (u) => (u.roles ?? []).join(', ')], ['Last login', (u) => (u.neverLoggedIn ? 'never' : fmtDate(u.lastLoginAt))], ['Days', (u) => u.ageDays]], ev.access.inactive.rows, 30, `No active account is inactive for more than ${content.parameters.inactiveUserDays} days.`)}
${table([['SSH credential', (c) => c.name], ['Method', (c) => c.auth], ['Scope', (c) => c.scope], ['Secret age (days)', (c) => c.ageDays]], ev.credentials.older.rows, 30, `No SSH credential is older than ${content.parameters.credentialMaxAgeDays} days.`)}
<h2>Kubernetes and Docker Swarm</h2>
<p class="muted">${ev.kubernetes.clusters} Kubernetes clusters (${ev.kubernetes.withCredentials} with stored credentials, ${ev.kubernetes.tlsNotVerified} with TLS verification disabled, ${ev.kubernetes.cniUnknown} with an unknown CNI); policies: ${Object.entries(ev.kubernetes.policiesByStatus).map(([k, v]) => `${esc(k)} ${v}`).join(', ') || 'none'}; ${ev.kubernetes.driftedPolicies} drifted at the last check.<br>
${ev.swarm.nodes} Docker Swarm nodes${ev.swarm.nodes ? ` (${ev.swarm.withPublishedPortEnforcement} enforcing policy on published ports)` : ''}.</p>
${ev.drift ? `<h2>Live drift check</h2><p class="muted">${esc(ev.drift.checked)} hosts read over SSH: ${Object.entries(ev.drift.counts).map(([k, v]) => `${esc(k)} ${v}`).join(', ')}.</p>${table([['Host', (d) => d.hostname], ['Status', (d) => d.status], ['Message', (d) => d.message ?? d.error ?? '']], ev.drift.hosts.filter((d: any) => d.status !== 'compliant'), 50, 'Every checked host matches its last deployment.')}` : ''}
<h2>Audit trail</h2>
<p class="muted">${ev.audit.events} events by ${ev.audit.actors} users between ${fmtDate(ev.audit.firstAt)} and ${fmtDate(ev.audit.lastAt)}; ${ev.audit.privilegedEvents} administrative or credential events. The full list is the <code>audit_events</code> CSV dataset.</p>
${table([['Action', (a) => a.action], ['Events', (a) => a.count]], ev.audit.byAction, 30)}
<p class="muted">Generated by Segmentra. Save as PDF from the browser's print dialog.</p>
</body></html>`;
}
