import { Router } from 'express';
import { z } from 'zod';

import { pool } from '../db/pool.js';
import { requireAuth, requireRole } from '../middleware/auth.js';
import { analyzePolicyTest } from '../services/policy-test-analyzer.js';
import { compileHostPolicy } from '@segmentra/compiler';

export const policyTestingRouter = Router();
policyTestingRouter.use(requireAuth);

// List test sessions
policyTestingRouter.get('/sessions', requireRole('viewer', 'operator', 'admin'), async (req, res) => {
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
policyTestingRouter.get('/sessions/:id', requireRole('viewer', 'operator', 'admin'), async (req, res) => {
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

// Start a policy test
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

  // Check host exists and get SSH info
  const { rows: hosts } = await pool.query(
    `SELECT h.*, v.vlan_tag, v.subnet as vlan_subnet FROM hosts h LEFT JOIN vlans v ON h.vlan_id = v.id WHERE h.id = $1`,
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

  // Create test session
  const scheduledEnd = new Date(Date.now() + b.durationMinutes * 60 * 1000);
  const { rows: sessionRows } = await pool.query(
    `INSERT INTO policy_test_sessions
      (policy_version_id, host_id, status, duration_minutes, started_at, scheduled_end_at, created_by)
     VALUES ($1, $2, 'DEPLOYING', $3, now(), $4, $5) RETURNING *`,
    [b.policyVersionId, b.hostId, b.durationMinutes, scheduledEnd, userId]
  );
  const session = sessionRows[0];

  // Compile policy in log-only mode
  try {
    const { rows: rules } = await pool.query(
      `SELECT * FROM policy_rules WHERE policy_version_id = $1 ORDER BY order_index ASC`,
      [b.policyVersionId]
    );

    // Get host interfaces
    const { rows: interfaces } = await pool.query(
      `SELECT * FROM host_interfaces WHERE host_id = $1 AND enabled = true`,
      [b.hostId]
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

    // Build sets for TAG/VLAN/HOST resolution (same pattern as render.ts)
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
      if (ips.length === 0) ips = ['0.0.0.0/32']; // fallback to avoid empty set error
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

    const backendRaw = String(host.firewall_backend ?? 'auto');
    const backend = backendRaw === 'iptables' ? 'iptables' : 'nftables';

    const compiled = compileHostPolicy({
      host: {
        id: host.id,
        hostname: host.hostname,
        mgmtIp: host.mgmt_ip ? String(host.mgmt_ip) : null,
        firewallBackend: backend,
        interfaces: interfaces.map((i: any) => ({ name: i.name, role: i.role, enabled: i.enabled })),
      },
      policyInterfaceScope,
      rules: compiledRules,
      sets,
      baseline: { mgmtSshCidrs: mgmtCidrs },
      logOnlyMode: true,
    });

    // Update session status
    await pool.query(
      `UPDATE policy_test_sessions SET status = 'RUNNING' WHERE id = $1`,
      [session.id]
    );

    await pool.query(
      `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
       VALUES ($1, 'POLICY_TEST_START', 'policy_test_session', $2, $3)`,
      [userId, session.id, JSON.stringify({ hostId: b.hostId, policyVersionId: b.policyVersionId, durationMinutes: b.durationMinutes })]
    );

    res.status(201).json({ session: { ...session, status: 'RUNNING' }, compiled: { backend: compiled.backend, sha256: compiled.sha256 } });
  } catch (e: any) {
    await pool.query(
      `UPDATE policy_test_sessions SET status = 'FAILED' WHERE id = $1`,
      [session.id]
    );
    res.status(500).json({ error: 'test_start_failed', message: e.message });
  }
});

// Stop a test session early
policyTestingRouter.post('/sessions/:id/stop', requireRole('operator', 'admin'), async (req, res) => {
  const { rows } = await pool.query(
    `UPDATE policy_test_sessions SET status = 'COLLECTING', completed_at = now()
     WHERE id = $1 AND status = 'RUNNING' RETURNING *`,
    [req.params.id]
  );
  if (!rows[0]) return res.status(404).json({ error: 'not_found_or_not_running' });
  res.json({ session: rows[0] });
});

// Analyze test results
policyTestingRouter.post('/sessions/:id/analyze', requireRole('operator', 'admin'), async (req, res) => {
  try {
    const result = await analyzePolicyTest(req.params.id);
    res.json({ analysis: result });
  } catch (e: any) {
    res.status(400).json({ error: e.message });
  }
});
