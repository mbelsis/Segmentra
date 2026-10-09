import { Router } from 'express';

import { compileHostPolicy, firewallBackend, type RuleDirection } from '@segmentra/compiler';

import { pool } from '../../db/pool.js';
import { requireAuth, requireRole } from '../../middleware/auth.js';
import { addDestinationSets, compilerDestination, getProtectedDestinations } from '../../services/forward-rules.js';

export const policyRenderRouter = Router();
policyRenderRouter.use(requireAuth);

policyRenderRouter.get('/policy-versions/:versionId/render/host/:hostId', requireRole('operator', 'admin'), async (req, res) => {
  const { versionId, hostId } = req.params;

  const [hostRes, ifRes, vRes, rRes] = await Promise.all([
    pool.query(`SELECT id, hostname, mgmt_ip, ssh_port, firewall_backend FROM hosts WHERE id=$1`, [hostId]),
    pool.query(`SELECT name, role, enabled FROM host_interfaces WHERE host_id=$1`, [hostId]),
    pool.query(
      `SELECT interface_scope_type, interface_scope_roles, interface_scope_names
       FROM policy_versions WHERE id=$1`,
      [versionId]
    ),
    pool.query(
      `SELECT order_index, action, protocol, ports, source_type, source_value, log_mode, comment,
              use_policy_interface_scope, interface_scope_type, interface_scope_roles, interface_scope_names, direction,
              destination_type, destination_value
       FROM policy_rules
       WHERE policy_version_id=$1
       ORDER BY order_index ASC`,
      [versionId]
    )
  ]);

  if (!hostRes.rows[0] || !vRes.rows[0]) return res.status(404).json({ error: 'not_found' });

  const backendRaw = String(hostRes.rows[0].firewall_backend ?? 'auto');
  const backend = firewallBackend(backendRaw);

  const v = vRes.rows[0];
  const policyInterfaceScope =
    v.interface_scope_type === 'ALL_INTERFACES'
      ? { type: 'ALL_INTERFACES' as const }
      : v.interface_scope_type === 'INTERFACE_NAME'
        ? { type: 'INTERFACE_NAME' as const, names: (v.interface_scope_names ?? []) as string[] }
        : { type: 'INTERFACE_ROLE' as const, roles: (v.interface_scope_roles ?? []) as string[] };

  // Resolve TAG/VLAN/HOST to concrete IP lists and compile to nft sets (per-host bundle later)
  const sets: Record<string, string[]> = {};
  async function resolveRemote(ruleRow: any): Promise<{ kind: 'CIDR' } | { kind: 'SET'; setName: string }> {
    if (ruleRow.source_type === 'CIDR') return { kind: 'CIDR' };

    const key = `${ruleRow.source_type}:${ruleRow.source_value}`;
    const setName = `src_${ruleRow.source_type.toLowerCase()}_${String(ruleRow.source_value).replace(/-/g, '')}`;
    if (sets[setName]) return { kind: 'SET', setName };

    let ips: string[] = [];
    if (ruleRow.source_type === 'HOST') {
      const h = await pool.query(`SELECT mgmt_ip FROM hosts WHERE id=$1`, [ruleRow.source_value]);
      if (h.rows[0]?.mgmt_ip) ips = [String(h.rows[0].mgmt_ip)];
    } else if (ruleRow.source_type === 'TAG') {
      const q = await pool.query(
        `SELECT h.mgmt_ip FROM hosts h
         JOIN host_tags ht ON ht.host_id=h.id
         WHERE ht.tag_id=$1 AND h.mgmt_ip IS NOT NULL AND h.enabled=true`,
        [ruleRow.source_value]
      );
      ips = q.rows.map((x) => String(x.mgmt_ip));
    } else if (ruleRow.source_type === 'VLAN') {
      const q = await pool.query(
        `SELECT mgmt_ip FROM hosts WHERE vlan_id=$1 AND mgmt_ip IS NOT NULL AND enabled=true`,
        [ruleRow.source_value]
      );
      ips = q.rows.map((x) => String(x.mgmt_ip));
    }

    if (ips.length === 0) throw new Error(`empty_selector:${key}`);
    sets[setName] = ips;
    return { kind: 'SET', setName };
  }

  const rules = await Promise.all(
    rRes.rows.map(async (r) => {
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
      ...compilerDestination(r)
    };
  })
  );
  await addDestinationSets(rRes.rows, sets);
  const protectedDestinations = await getProtectedDestinations(hostId);

  // Get management VLAN setting
  const mgmtVlanRes = await pool.query(
    `SELECT value FROM system_settings WHERE key='management_vlan_id'`
  );
  const mgmtVlanId = mgmtVlanRes.rows[0]?.value || null;
  
  let mgmtSshCidrs: string[] = [];
  if (mgmtVlanId) {
    const vlanRes = await pool.query(`SELECT subnet FROM vlans WHERE id=$1`, [mgmtVlanId]);
    if (vlanRes.rows[0]?.subnet) {
      mgmtSshCidrs = [vlanRes.rows[0].subnet];
    }
  }

  const compiled = compileHostPolicy({
    host: {
      id: hostRes.rows[0].id,
      hostname: hostRes.rows[0].hostname,
      mgmtIp: hostRes.rows[0].mgmt_ip ? String(hostRes.rows[0].mgmt_ip) : null,
      sshPort: hostRes.rows[0].ssh_port ? Number(hostRes.rows[0].ssh_port) : undefined,
      firewallBackend: backend,
      interfaces: ifRes.rows.map((i) => ({ name: i.name, role: i.role, enabled: i.enabled }))
    },
    policyInterfaceScope,
    rules,
    sets,
    baseline: { mgmtSshCidrs },
    protectedDestinations
  });

  res.json({ backend: compiled.backend, sha256: compiled.sha256, text: compiled.text });
});

