import { Router } from 'express';
import { z } from 'zod';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

import { pool } from '../db/pool.js';
import { requireAuth, requireRole } from '../middleware/auth.js';
import { analyzePolicyTest } from '../services/policy-test-analyzer.js';
import { compileHostPolicy, type RuleDirection } from '@segmentra/compiler';
import { addDestinationSets, compilerDestination, getProtectedDestinations } from '../services/forward-rules.js';
import { getDockerCompileInput } from '../services/swarm.js';
import { startAuditSession, deployLogOnlyPolicy, restoreAuditSession, retrieveAuditLogs } from '@segmentra/executor';
import { parseFirewallLogs, groupCommunicationFlows } from '../services/log-parser.js';
import { getSshCredentialForHost, type MaterializedSshCredential } from '../services/ssh-credentials.js';
import { createAuditEvent } from '../services/audit.js';
import {
  ACTIVE_TEST_SESSION_STATUSES,
  buildAuditHost,
  markRestoreFailed,
  restoreAndCollectSession
} from '../lib/policy-test-session.js';

export const policyTestingRouter = Router();
policyTestingRouter.use(requireAuth);

// List test sessions
policyTestingRouter.get('/sessions', requireRole('viewer', 'operator', 'approver', 'admin'), async (req, res) => {
  const hostId = req.query.hostId ? String(req.query.hostId) : null;
  const status = req.query.status ? String(req.query.status) : null;

  let query = `SELECT pts.*, h.hostname, h.mgmt_ip,
    pv.version_number, ps.name as policy_set_name
   FROM policy_test_sessions pts
   JOIN hosts h ON h.id = pts.host_id
   JOIN policy_versions pv ON pv.id = pts.policy_version_id
   JOIN policy_sets ps ON ps.id = pv.policy_set_id
   WHERE 1=1`;
  const params: any[] = [];
  let idx = 1;

  if (hostId) {
    query += ` AND pts.host_id = $${idx++}`;
    params.push(hostId);
  }
  if (status) {
    query += ` AND pts.status = $${idx++}`;
    params.push(status);
  }
  query += ` ORDER BY pts.created_at DESC`;

  const { rows } = await pool.query(query, params);
  res.json({ sessions: rows });
});

// Get single test session
policyTestingRouter.get('/sessions/:id', requireRole('viewer', 'operator', 'approver', 'admin'), async (req, res) => {
  const { rows } = await pool.query(
    `SELECT pts.*, h.hostname, h.mgmt_ip, h.firewall_backend,
      pv.version_number, ps.name as policy_set_name
     FROM policy_test_sessions pts
     JOIN hosts h ON h.id = pts.host_id
     JOIN policy_versions pv ON pv.id = pts.policy_version_id
     JOIN policy_sets ps ON ps.id = pv.policy_set_id
     WHERE pts.id = $1`,
    [req.params.id]
  );
  if (!rows[0]) return res.status(404).json({ error: 'not_found' });
  res.json({ session: rows[0] });
});

// Start a policy test — compiles policy in log-only mode, SSHes into the host,
// backs up current rules, deploys the log-only policy, and waits for traffic.
policyTestingRouter.post('/start', requireRole('operator', 'approver', 'admin'), async (req, res) => {
  const bodySchema = z.object({
    policyVersionId: z.string().uuid(),
    hostId: z.string().uuid(),
    durationMinutes: z.number().int().min(1).max(1440).default(30),
  });
  const parsed = bodySchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body', details: parsed.error.issues });
  const b = parsed.data;

  const userId = req.auth!.userId;
  const roles = req.auth!.roles;

  // Check host exists
  const { rows: hosts } = await pool.query(
    `SELECT h.*, v.vlan_tag, v.subnet as vlan_subnet,
       (SELECT array_agg(json_build_object('name', hi.name, 'role', hi.role, 'enabled', hi.enabled))
        FROM host_interfaces hi WHERE hi.host_id = h.id) as interfaces
     FROM hosts h LEFT JOIN vlans v ON h.vlan_id = v.id WHERE h.id = $1`,
    [b.hostId]
  );
  if (!hosts[0]) return res.status(404).json({ error: 'host_not_found' });
  const host = hosts[0];

  // Check policy version exists
  const { rows: versions } = await pool.query(
    `SELECT pv.*, ps.scope_type, ps.scope_tag_id, ps.scope_vlan_id
     FROM policy_versions pv JOIN policy_sets ps ON ps.id = pv.policy_set_id WHERE pv.id = $1`,
    [b.policyVersionId]
  );
  if (!versions[0]) return res.status(404).json({ error: 'policy_version_not_found' });

  // Testing pushes rules to a real host: operators may only test reviewed (APPROVED/DEPLOYED) versions;
  // unreviewed versions (DRAFT, PENDING_APPROVAL, ...) may only be tested by approvers/admins.
  const versionReviewed = ['APPROVED', 'DEPLOYED'].includes(versions[0].status);
  const canTestUnreviewed = roles.includes('approver') || roles.includes('admin');
  if (!versionReviewed && !canTestUnreviewed) {
    return res.status(403).json({
      error: 'version_not_approved',
      message: `Only approvers or admins can test a ${versions[0].status} policy version. Operators can test APPROVED or DEPLOYED versions.`
    });
  }

  // Create the test session record, refusing if another test is already active on this host.
  const scheduledEnd = new Date(Date.now() + b.durationMinutes * 60 * 1000);
  let session: any;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(`SELECT pg_advisory_xact_lock(hashtext($1::text))`, [b.hostId]);
    const active = await client.query(
      `SELECT id, status FROM policy_test_sessions WHERE host_id = $1 AND status = ANY($2::text[]) LIMIT 1`,
      [b.hostId, ACTIVE_TEST_SESSION_STATUSES]
    );
    if (active.rows[0]) {
      await client.query('ROLLBACK');
      return res.status(409).json({
        error: 'test_already_running',
        message: `Another policy test (${active.rows[0].id}, ${active.rows[0].status}) is already active on ${host.hostname}. Stop it before starting a new one.`,
        sessionId: active.rows[0].id
      });
    }
    const { rows: sessionRows } = await client.query(
      `INSERT INTO policy_test_sessions
        (policy_version_id, host_id, status, duration_minutes, started_at, scheduled_end_at, created_by)
       VALUES ($1, $2, 'DEPLOYING', $3, now(), $4, $5) RETURNING *`,
      [b.policyVersionId, b.hostId, b.durationMinutes, scheduledEnd, userId]
    );
    await client.query('COMMIT');
    session = sessionRows[0];
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    throw e;
  } finally {
    client.release();
  }

  const logFilePath = `/var/log/segmentra-test-${host.hostname}-${Date.now()}.log`;
  let cred: MaterializedSshCredential | null = null;
  let backupPath: string | null = null;
  let policyFilePath: string | null = null;

  try {
    cred = await getSshCredentialForHost(host.id);
    const auditHost = buildAuditHost(host, cred);
    const backend = auditHost.backend;

    // Step 1: SSH into host — backup current rules and configure logging
    const startResult = await startAuditSession(auditHost, logFilePath);
    if (!startResult.success) {
      throw new Error(`Failed to backup rules on ${host.hostname}: ${startResult.stderr}`);
    }
    backupPath = startResult.backupPath ?? null;

    // Persist the backup location immediately so a later failure (or a crash) can still restore.
    await pool.query(
      `UPDATE policy_test_sessions SET backup_path = $2, log_file_path = $3 WHERE id = $1`,
      [session.id, backupPath, logFilePath]
    );

    // Step 2: Compile the SPECIFIC policy version in log-only mode
    const { rows: rules } = await pool.query(
      `SELECT * FROM policy_rules WHERE policy_version_id = $1 ORDER BY order_index ASC`,
      [b.policyVersionId]
    );

    // Get management VLAN for baseline
    const { rows: mgmtSetting } = await pool.query(
      `SELECT value FROM system_settings WHERE key = 'management_vlan_id'`
    );
    let mgmtCidrs: string[] = [];
    if (mgmtSetting[0]?.value) {
      const { rows: mgmtVlan } = await pool.query(`SELECT subnet FROM vlans WHERE id = $1`, [mgmtSetting[0].value]);
      if (mgmtVlan[0]?.subnet) mgmtCidrs = [mgmtVlan[0].subnet];
    }

    // Resolve TAG/VLAN/HOST sources to IP sets (same pattern as render.ts)
    const sets: Record<string, string[]> = {};
    async function resolveRemote(ruleRow: any): Promise<{ kind: 'CIDR' } | { kind: 'SET'; setName: string }> {
      if (ruleRow.source_type === 'CIDR') return { kind: 'CIDR' };
      const setName = `src_${ruleRow.source_type.toLowerCase()}_${String(ruleRow.source_value).replace(/-/g, '')}`;
      if (sets[setName]) return { kind: 'SET', setName };
      let ips: string[] = [];
      if (ruleRow.source_type === 'HOST') {
        const h = await pool.query(`SELECT mgmt_ip FROM hosts WHERE id=$1`, [ruleRow.source_value]);
        if (h.rows[0]?.mgmt_ip) ips = [String(h.rows[0].mgmt_ip)];
      } else if (ruleRow.source_type === 'TAG') {
        const q = await pool.query(
          `SELECT h.mgmt_ip FROM hosts h JOIN host_tags ht ON ht.host_id=h.id WHERE ht.tag_id=$1 AND h.mgmt_ip IS NOT NULL AND h.enabled=true`,
          [ruleRow.source_value]
        );
        ips = q.rows.map((x: any) => String(x.mgmt_ip));
      } else if (ruleRow.source_type === 'VLAN') {
        const q = await pool.query(
          `SELECT mgmt_ip FROM hosts WHERE vlan_id=$1 AND mgmt_ip IS NOT NULL AND enabled=true`,
          [ruleRow.source_value]
        );
        ips = q.rows.map((x: any) => String(x.mgmt_ip));
      }
      if (ips.length === 0) ips = ['0.0.0.0/32'];
      sets[setName] = ips;
      return { kind: 'SET', setName };
    }

    const v = versions[0];
    const policyInterfaceScope =
      v.interface_scope_type === 'ALL_INTERFACES'
        ? { type: 'ALL_INTERFACES' as const }
        : v.interface_scope_type === 'INTERFACE_NAME'
          ? { type: 'INTERFACE_NAME' as const, names: (v.interface_scope_names ?? []) as string[] }
          : { type: 'INTERFACE_ROLE' as const, roles: (v.interface_scope_roles ?? []) as string[] };

    const compiledRules = await Promise.all(
      rules.map(async (r: any) => {
        const ruleScope =
          r.interface_scope_type === 'ALL_INTERFACES'
            ? { type: 'ALL_INTERFACES' as const }
            : r.interface_scope_type === 'INTERFACE_NAME'
              ? { type: 'INTERFACE_NAME' as const, names: (r.interface_scope_names ?? []) as string[] }
              : r.interface_scope_type === 'INTERFACE_ROLE'
                ? { type: 'INTERFACE_ROLE' as const, roles: (r.interface_scope_roles ?? []) as string[] }
                : undefined;
        const remote = await resolveRemote(r);
        return {
          orderIndex: Number(r.order_index),
          direction: (r.direction ?? 'IN') as RuleDirection,
          action: r.action,
          protocol: r.protocol,
          ports: r.ports,
          sourceType: r.source_type,
          sourceValue: r.source_value,
          logMode: r.log_mode,
          comment: r.comment,
          usePolicyInterfaceScope: Boolean(r.use_policy_interface_scope),
          interfaceScope: ruleScope,
          remote,
          ...compilerDestination(r),
        };
      })
    );
    await addDestinationSets(rules, sets);
    const protectedDestinations = await getProtectedDestinations(host.id);

    let compiled;
    try {
      compiled = compileHostPolicy({
        host: {
          id: host.id,
          hostname: host.hostname,
          mgmtIp: host.mgmt_ip ? String(host.mgmt_ip) : null,
          sshPort: host.ssh_port ? Number(host.ssh_port) : undefined,
          firewallBackend: backend,
          interfaces: (host.interfaces || []).map((i: any) => ({ name: i.name, role: i.role, enabled: i.enabled })),
        },
        policyInterfaceScope,
        rules: compiledRules,
        sets,
        baseline: { mgmtSshCidrs: mgmtCidrs },
        logOnlyMode: true,
        protectedDestinations,
        ...(await getDockerCompileInput(host.id)),
      });
    } catch (ce: any) {
      if (ce?.name === 'CompileError') throw new Error(`Policy failed to compile for ${host.hostname}: ${ce.message}`);
      throw ce;
    }

    // Step 3: Deploy the log-only policy to the host via SSH
    policyFilePath = path.join(os.tmpdir(), `policy_test_${session.id}_${Date.now()}.${compiled.backend === 'nftables' ? 'nft' : 'iptables'}`);
    const deployResult = await deployLogOnlyPolicy(auditHost, compiled.text, policyFilePath);

    if (!deployResult.success) {
      throw new Error(`Failed to deploy log-only policy on ${host.hostname}: ${deployResult.stderr}`);
    }

    // Success — update session to RUNNING
    await pool.query(`UPDATE policy_test_sessions SET status = 'RUNNING' WHERE id = $1`, [session.id]);

    await pool.query(
      `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
       VALUES ($1, 'POLICY_TEST_START', 'policy_test_session', $2, $3)`,
      [userId, session.id, JSON.stringify({
        hostId: b.hostId,
        hostname: host.hostname,
        policyVersionId: b.policyVersionId,
        policyVersionStatus: versions[0].status,
        durationMinutes: b.durationMinutes,
        backend: compiled.backend,
        rulesCount: compiledRules.length
      })]
    );

    res.status(201).json({
      session: { ...session, status: 'RUNNING', backup_path: backupPath, log_file_path: logFilePath },
      message: `Log-only policy deployed to ${host.hostname}. Traffic is being captured for ${b.durationMinutes} minutes. Original rules will be restored automatically when the test ends.`,
      compiled: { backend: compiled.backend, sha256: compiled.sha256, rulesCount: compiledRules.length }
    });
  } catch (e: any) {
    const message = e?.message ?? String(e);
    let restoreError: string | null = null;

    // If the backup was taken, the host's rules may have been modified: restore using the in-memory path.
    if (backupPath && cred) {
      try {
        const restore = await restoreAuditSession(buildAuditHost(host, cred), backupPath);
        if (!restore.success) restoreError = (restore.stderr || restore.stdout || `exit code ${restore.exitCode}`).trim();
      } catch (re: any) {
        restoreError = re?.message ?? String(re);
      }
    }

    if (restoreError) {
      // Keep the session RUNNING so the expiry job keeps retrying the restore; flag it as a failed start.
      await markRestoreFailed(session.id, `Restore after failed start: ${restoreError}`, { start_failed: true, start_error: message });
      return res.status(500).json({
        error: 'test_start_failed',
        message: `${message}. WARNING: restoring the original rules on ${host.hostname} also failed (${restoreError}); it will be retried automatically.`,
        restoreFailed: true
      });
    }

    await pool.query(
      `UPDATE policy_test_sessions
         SET status = 'FAILED', completed_at = now(),
             raw_log_data = COALESCE(raw_log_data, '{}'::jsonb) || jsonb_build_object('start_error', $2::text)
       WHERE id = $1`,
      [session.id, message.slice(0, 4000)]
    );

    if (message === 'missing_ssh_credential') {
      return res.status(400).json({ error: 'missing_ssh_credential', message: 'SSH credentials are required. Configure them in Admin → SSH Credentials.' });
    }
    if (message.startsWith('Policy failed to compile')) {
      return res.status(400).json({ error: 'policy_compile_failed', message });
    }
    res.status(500).json({ error: 'test_start_failed', message });
  } finally {
    if (policyFilePath && fs.existsSync(policyFilePath)) { try { fs.unlinkSync(policyFilePath); } catch { /* ignore */ } }
    cred?.cleanup();
  }
});

// Stop a running test — SSH into host, restore original rules, retrieve logs
policyTestingRouter.post('/sessions/:id/stop', requireRole('operator', 'approver', 'admin'), async (req, res) => {
  const { rows: sessions } = await pool.query(
    `SELECT pts.*, h.hostname, h.mgmt_ip, h.ssh_port, h.firewall_backend
     FROM policy_test_sessions pts
     JOIN hosts h ON h.id = pts.host_id
     WHERE pts.id = $1 AND pts.status = 'RUNNING'`,
    [req.params.id]
  );
  if (!sessions[0]) return res.status(404).json({ error: 'not_found_or_not_running' });
  const session = sessions[0];

  const result = await restoreAndCollectSession(session);
  await createAuditEvent({
    actorUserId: req.auth!.userId ?? null,
    action: result.ok ? 'POLICY_TEST_STOP' : 'POLICY_TEST_RESTORE_FAILED',
    entityType: 'policy_test_session',
    entityId: session.id,
    ipAddress: req.ip,
    metadata: result.ok ? { hostname: session.hostname, entryCount: result.entryCount, flowCount: result.flowCount } : { hostname: session.hostname, error: result.error }
  });
  if (!result.ok) {
    return res.status(502).json({
      error: 'restore_failed',
      message: `${result.error}. The session remains RUNNING and the restore will be retried automatically.`
    });
  }

  if (result.startFailed) {
    return res.json({
      session: { ...session, status: 'FAILED' },
      message: `Original rules restored on ${session.hostname}. This test had failed to start, so no traffic was collected.`,
      flowCount: 0,
      entryCount: 0
    });
  }

  res.json({
    session: { ...session, status: 'COLLECTING' },
    message: `Original rules restored on ${session.hostname}. ${result.entryCount} log entries collected, ${result.flowCount} unique flows identified. Click "Analyze" to compare against policy rules.`,
    flowCount: result.flowCount,
    entryCount: result.entryCount
  });
});

// Collect logs from a running session WITHOUT stopping it
policyTestingRouter.post('/sessions/:id/collect-logs', requireRole('operator', 'approver', 'admin'), async (req, res) => {
  const { rows: sessions } = await pool.query(
    `SELECT pts.*, h.hostname, h.mgmt_ip, h.ssh_port, h.firewall_backend
     FROM policy_test_sessions pts
     JOIN hosts h ON h.id = pts.host_id
     WHERE pts.id = $1 AND pts.status = 'RUNNING'`,
    [req.params.id]
  );
  if (!sessions[0]) return res.status(404).json({ error: 'not_found_or_not_running' });
  const session = sessions[0];

  let cred: MaterializedSshCredential | null = null;
  try {
    try {
      cred = await getSshCredentialForHost(session.host_id);
    } catch (e: any) {
      if (e?.message === 'missing_ssh_credential') return res.status(400).json({ error: 'missing_ssh_credential' });
      throw e;
    }
    const auditHost = buildAuditHost(session, cred);

    // Retrieve logs without restoring rules (test keeps running)
    let logContent = '';
    if (session.log_file_path) {
      const localLogPath = path.join(os.tmpdir(), `policy_test_peek_${session.id}_${Date.now()}.log`);
      try {
        const retrieveResult = await retrieveAuditLogs(auditHost, session.log_file_path, localLogPath);
        if (retrieveResult.success && fs.existsSync(localLogPath)) {
          logContent = fs.readFileSync(localLogPath, 'utf8');
        }
      } finally {
        if (fs.existsSync(localLogPath)) { try { fs.unlinkSync(localLogPath); } catch { /* ignore */ } }
      }
    }

    const parsedEntries = parseFirewallLogs(logContent);
    const flows = groupCommunicationFlows(parsedEntries);

    // Update raw_log_data with latest snapshot (preserve any restore bookkeeping keys)
    await pool.query(
      `UPDATE policy_test_sessions
         SET raw_log_data = COALESCE(raw_log_data, '{}'::jsonb) || $2::jsonb
       WHERE id = $1`,
      [session.id, JSON.stringify({ entries: parsedEntries, flows })]
    );

    res.json({
      message: `Collected ${parsedEntries.length} log entries, ${flows.length} unique flows from ${session.hostname}. Test is still running.`,
      flowCount: flows.length,
      entryCount: parsedEntries.length,
      flows
    });
  } catch (e: any) {
    res.status(500).json({ error: 'collect_failed', message: e.message });
  } finally {
    cred?.cleanup();
  }
});

// Analyze: compare collected traffic flows against the policy rules
policyTestingRouter.post('/sessions/:id/analyze', requireRole('operator', 'approver', 'admin'), async (req, res) => {
  try {
    const result = await analyzePolicyTest(req.params.id);
    res.json({
      analysis: result,
      message: result.summary.totalFlows === 0
        ? 'Analysis complete, but no traffic was captured during the test, so the policy could not be validated. Check that the host logs kernel firewall messages (rsyslog/journald) and that traffic occurred during the test window.'
        : `Analysis complete. Coverage: ${result.summary.coveragePercent}%. ${result.summary.matched} flows matched, ${result.summary.unexpectedAllows} would be blocked by default-deny, ${result.summary.unexpectedBlocks} hit DENY rules.`
    });
  } catch (e: any) {
    res.status(400).json({ error: e.message });
  }
});
