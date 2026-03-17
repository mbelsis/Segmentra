import { Router } from 'express';
import { z } from 'zod';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

import { pool } from '../db/pool.js';
import { requireAuth, requireRole } from '../middleware/auth.js';
import { analyzePolicyTest } from '../services/policy-test-analyzer.js';
import { compileHostPolicy } from '@segmentra/compiler';
import { startAuditSession, deployLogOnlyPolicy, restoreAuditSession, retrieveAuditLogs, type AuditSshHost } from '@segmentra/executor';
import { readSecretPlaintext } from '../services/secrets.js';
import { parseFirewallLogs, groupCommunicationFlows } from '../services/log-parser.js';

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
policyTestingRouter.post('/start', requireRole('operator', 'admin'), async (req, res) => {
  const bodySchema = z.object({
    policyVersionId: z.string().uuid(),
    hostId: z.string().uuid(),
    durationMinutes: z.number().int().min(1).max(1440).default(30),
  });
  const parsed = bodySchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body', details: parsed.error.issues });
  const b = parsed.data;

  const userRes = await pool.query(`SELECT id FROM users WHERE username=$1 LIMIT 1`, [req.auth!.username]);
  const userId = userRes.rows[0]?.id ?? null;

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

  // Get SSH credentials
  const credRes = await pool.query(
    `SELECT * FROM ssh_credentials WHERE scope_type='GLOBAL' ORDER BY created_at DESC LIMIT 1`
  );
  const cred = credRes.rows[0];
  if (!cred) {
    return res.status(400).json({ error: 'missing_ssh_credential', message: 'SSH credentials are required. Configure them in Admin → SSH Credentials.' });
  }

  // Create test session record
  const scheduledEnd = new Date(Date.now() + b.durationMinutes * 60 * 1000);
  const { rows: sessionRows } = await pool.query(
    `INSERT INTO policy_test_sessions
      (policy_version_id, host_id, status, duration_minutes, started_at, scheduled_end_at, created_by)
     VALUES ($1, $2, 'DEPLOYING', $3, now(), $4, $5) RETURNING *`,
    [b.policyVersionId, b.hostId, b.durationMinutes, scheduledEnd, userId]
  );
  const session = sessionRows[0];

  const keyPem = (await readSecretPlaintext(cred.private_key_secret_id)).toString('utf8');
  const tempKeyPath = path.join(os.tmpdir(), `policy_test_key_${session.id}_${Date.now()}`);
  const logFilePath = `/var/log/segmentra-test-${host.hostname}-${Date.now()}.log`;

  try {
    // Write SSH key to temp file
    fs.writeFileSync(tempKeyPath, keyPem, { encoding: 'utf8', mode: 0o600 });

    const backendRaw = String(host.firewall_backend ?? 'auto');
    const backend = backendRaw === 'iptables' ? 'iptables' : 'nftables';

    const auditHost: AuditSshHost = {
      hostname: host.hostname,
      ip: String(host.mgmt_ip),
      port: host.ssh_port || 22,
      username: cred.username,
      privateKeyPath: tempKeyPath,
      backend
    };

    // Step 1: SSH into host — backup current rules and configure logging
    const startResult = await startAuditSession(auditHost, logFilePath);
    if (!startResult.success) {
      throw new Error(`Failed to backup rules on ${host.hostname}: ${startResult.stderr}`);
    }

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
          direction: (r.direction ?? 'IN') as 'IN' | 'OUT' | 'BOTH',
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
        };
      })
    );

    const compiled = compileHostPolicy({
      host: {
        id: host.id,
        hostname: host.hostname,
        mgmtIp: host.mgmt_ip ? String(host.mgmt_ip) : null,
        firewallBackend: backend,
        interfaces: (host.interfaces || []).map((i: any) => ({ name: i.name, role: i.role, enabled: i.enabled })),
      },
      policyInterfaceScope,
      rules: compiledRules,
      sets,
      baseline: { mgmtSshCidrs: mgmtCidrs },
      logOnlyMode: true,
    });

    // Step 3: Deploy the log-only policy to the host via SSH
    const policyFilePath = path.join(os.tmpdir(), `policy_test_${session.id}_${Date.now()}.${compiled.backend === 'nftables' ? 'nft' : 'iptables'}`);
    const deployResult = await deployLogOnlyPolicy(auditHost, compiled.text, policyFilePath);

    if (!deployResult.success) {
      throw new Error(`Failed to deploy log-only policy on ${host.hostname}: ${deployResult.stderr}`);
    }

    // Success — update session to RUNNING
    await pool.query(
      `UPDATE policy_test_sessions
       SET status = 'RUNNING', backup_path = $2, log_file_path = $3
       WHERE id = $1`,
      [session.id, startResult.backupPath, logFilePath]
    );

    await pool.query(
      `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
       VALUES ($1, 'POLICY_TEST_START', 'policy_test_session', $2, $3)`,
      [userId, session.id, JSON.stringify({
        hostId: b.hostId,
        hostname: host.hostname,
        policyVersionId: b.policyVersionId,
        durationMinutes: b.durationMinutes,
        backend: compiled.backend,
        rulesCount: compiledRules.length
      })]
    );

    // Clean up local temp files
    if (fs.existsSync(policyFilePath)) fs.unlinkSync(policyFilePath);
    if (fs.existsSync(tempKeyPath)) fs.unlinkSync(tempKeyPath);

    res.status(201).json({
      session: { ...session, status: 'RUNNING', backup_path: startResult.backupPath, log_file_path: logFilePath },
      message: `Log-only policy deployed to ${host.hostname}. Traffic is being captured for ${b.durationMinutes} minutes. Original rules will be restored automatically when the test ends.`,
      compiled: { backend: compiled.backend, sha256: compiled.sha256, rulesCount: compiledRules.length }
    });
  } catch (e: any) {
    // On failure, try to restore original rules if we have a backup
    try {
      if (fs.existsSync(tempKeyPath)) {
        const auditHost: AuditSshHost = {
          hostname: host.hostname,
          ip: String(host.mgmt_ip),
          port: host.ssh_port || 22,
          username: cred.username,
          privateKeyPath: tempKeyPath,
          backend: (host.firewall_backend === 'iptables' ? 'iptables' : 'nftables') as 'nftables' | 'iptables'
        };
        // Best-effort restore
        const backupRes = await pool.query(`SELECT backup_path FROM policy_test_sessions WHERE id = $1`, [session.id]);
        if (backupRes.rows[0]?.backup_path) {
          await restoreAuditSession(auditHost, backupRes.rows[0].backup_path);
        }
      }
    } catch { /* best effort */ }

    await pool.query(
      `UPDATE policy_test_sessions SET status = 'FAILED' WHERE id = $1`,
      [session.id]
    );

    // Clean up temp files
    if (fs.existsSync(tempKeyPath)) { try { fs.unlinkSync(tempKeyPath); } catch {} }

    res.status(500).json({ error: 'test_start_failed', message: e.message });
  }
});

// Stop a running test — SSH into host, restore original rules, retrieve logs
policyTestingRouter.post('/sessions/:id/stop', requireRole('operator', 'admin'), async (req, res) => {
  const { rows: sessions } = await pool.query(
    `SELECT pts.*, h.hostname, h.mgmt_ip, h.ssh_port, h.firewall_backend
     FROM policy_test_sessions pts
     JOIN hosts h ON h.id = pts.host_id
     WHERE pts.id = $1 AND pts.status = 'RUNNING'`,
    [req.params.id]
  );
  if (!sessions[0]) return res.status(404).json({ error: 'not_found_or_not_running' });
  const session = sessions[0];

  // Get SSH credentials
  const credRes = await pool.query(
    `SELECT * FROM ssh_credentials WHERE scope_type='GLOBAL' ORDER BY created_at DESC LIMIT 1`
  );
  const cred = credRes.rows[0];
  if (!cred) return res.status(400).json({ error: 'missing_ssh_credential' });

  const keyPem = (await readSecretPlaintext(cred.private_key_secret_id)).toString('utf8');
  const tempKeyPath = path.join(os.tmpdir(), `policy_test_stop_${session.id}_${Date.now()}`);

  try {
    fs.writeFileSync(tempKeyPath, keyPem, { encoding: 'utf8', mode: 0o600 });

    const auditHost: AuditSshHost = {
      hostname: session.hostname,
      ip: String(session.mgmt_ip),
      port: session.ssh_port || 22,
      username: cred.username,
      privateKeyPath: tempKeyPath,
      backend: session.firewall_backend === 'iptables' ? 'iptables' : 'nftables'
    };

    // Restore original firewall rules
    await restoreAuditSession(auditHost, session.backup_path);

    // Retrieve traffic logs from host
    let logContent = '';
    if (session.log_file_path) {
      const localLogPath = path.join(os.tmpdir(), `policy_test_log_${session.id}_${Date.now()}.log`);
      const retrieveResult = await retrieveAuditLogs(auditHost, session.log_file_path, localLogPath);
      if (retrieveResult.success && fs.existsSync(localLogPath)) {
        logContent = fs.readFileSync(localLogPath, 'utf8');
        fs.unlinkSync(localLogPath);
      }
    }

    // Parse logs into structured flows
    const parsedEntries = parseFirewallLogs(logContent);
    const flows = groupCommunicationFlows(parsedEntries);

    // Update session with raw log data
    await pool.query(
      `UPDATE policy_test_sessions
       SET status = 'COLLECTING', completed_at = now(),
           raw_log_data = $2
       WHERE id = $1`,
      [session.id, JSON.stringify({ entries: parsedEntries, flows })]
    );

    res.json({
      session: { ...session, status: 'COLLECTING' },
      message: `Original rules restored on ${session.hostname}. ${parsedEntries.length} log entries collected, ${flows.length} unique flows identified. Click "Analyze" to compare against policy rules.`,
      flowCount: flows.length,
      entryCount: parsedEntries.length
    });
  } catch (e: any) {
    res.status(500).json({ error: 'stop_failed', message: e.message });
  } finally {
    if (fs.existsSync(tempKeyPath)) { try { fs.unlinkSync(tempKeyPath); } catch {} }
  }
});

// Collect logs from a running session WITHOUT stopping it
policyTestingRouter.post('/sessions/:id/collect-logs', requireRole('operator', 'admin'), async (req, res) => {
  const { rows: sessions } = await pool.query(
    `SELECT pts.*, h.hostname, h.mgmt_ip, h.ssh_port, h.firewall_backend
     FROM policy_test_sessions pts
     JOIN hosts h ON h.id = pts.host_id
     WHERE pts.id = $1 AND pts.status = 'RUNNING'`,
    [req.params.id]
  );
  if (!sessions[0]) return res.status(404).json({ error: 'not_found_or_not_running' });
  const session = sessions[0];

  const credRes = await pool.query(
    `SELECT * FROM ssh_credentials WHERE scope_type='GLOBAL' ORDER BY created_at DESC LIMIT 1`
  );
  const cred = credRes.rows[0];
  if (!cred) return res.status(400).json({ error: 'missing_ssh_credential' });

  const keyPem = (await readSecretPlaintext(cred.private_key_secret_id)).toString('utf8');
  const tempKeyPath = path.join(os.tmpdir(), `policy_test_peek_${session.id}_${Date.now()}`);

  try {
    fs.writeFileSync(tempKeyPath, keyPem, { encoding: 'utf8', mode: 0o600 });

    const auditHost: AuditSshHost = {
      hostname: session.hostname,
      ip: String(session.mgmt_ip),
      port: session.ssh_port || 22,
      username: cred.username,
      privateKeyPath: tempKeyPath,
      backend: session.firewall_backend === 'iptables' ? 'iptables' : 'nftables'
    };

    // Retrieve logs without restoring rules (test keeps running)
    let logContent = '';
    if (session.log_file_path) {
      const localLogPath = path.join(os.tmpdir(), `policy_test_peek_${session.id}_${Date.now()}.log`);
      const retrieveResult = await retrieveAuditLogs(auditHost, session.log_file_path, localLogPath);
      if (retrieveResult.success && fs.existsSync(localLogPath)) {
        logContent = fs.readFileSync(localLogPath, 'utf8');
        fs.unlinkSync(localLogPath);
      }
    }

    const parsedEntries = parseFirewallLogs(logContent);
    const flows = groupCommunicationFlows(parsedEntries);

    // Update raw_log_data with latest snapshot
    await pool.query(
      `UPDATE policy_test_sessions SET raw_log_data = $2 WHERE id = $1`,
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
    if (fs.existsSync(tempKeyPath)) { try { fs.unlinkSync(tempKeyPath); } catch {} }
  }
});

// Analyze: compare collected traffic flows against the policy rules
policyTestingRouter.post('/sessions/:id/analyze', requireRole('operator', 'admin'), async (req, res) => {
  try {
    const result = await analyzePolicyTest(req.params.id);
    res.json({
      analysis: result,
      message: `Analysis complete. Coverage: ${result.summary.coveragePercent}%. ${result.summary.matched} flows matched, ${result.summary.unexpectedAllows} would be blocked by default-deny, ${result.summary.unexpectedBlocks} hit DENY rules.`
    });
  } catch (e: any) {
    res.status(400).json({ error: e.message });
  }
});
