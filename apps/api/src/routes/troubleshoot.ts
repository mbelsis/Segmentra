import { Router } from 'express';
import { z } from 'zod';
import { pool } from '../db/pool.js';
import { requireAuth, requireRole } from '../middleware/auth.js';
import { compileHostPolicy } from '@segmentra/compiler';
import { startAuditSession, deployLogOnlyPolicy } from '@segmentra/executor';
import { buildAuditHost, restoreAuditSessionById } from '../services/audit-scheduler.js';
import { cidrContains, isValidCidr, isValidIp, portSpecIncludes } from '../services/ip-utils.js';
import { createSourceResolver } from '../services/source-resolver.js';
import { createDestinationResolver, gatewaysProtecting, getProtectedDestinations } from '../services/forward-rules.js';
import { getSshCredentialForHost, type MaterializedSshCredential } from '../services/ssh-credentials.js';
import { createAuditEvent } from '../services/audit.js';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

export const troubleshootRouter = Router();
troubleshootRouter.use(requireAuth, requireRole('viewer', 'operator', 'approver', 'admin'));

// Helper function to check if an IP matches a CIDR (IPv4/IPv6; "any" matches everything)
function ipMatchesCidr(ip: string, cidr: string): boolean {
  const target = String(ip).split('/')[0];
  return String(cidr ?? '')
    .split(',')
    .map((c) => c.trim())
    .some((c) => (/^(any|\*)$/i.test(c) ? true : cidrContains(c, target)));
}

// Search policies by IP address
troubleshootRouter.get('/policies/by-ip', async (req, res) => {
  const ip = String(req.query.ip ?? '').trim();
  if (!ip) {
    return res.status(400).json({ error: 'ip_required', message: 'IP address query parameter is required' });
  }

  // Find rules with CIDR source_type that match the IP
  const cidrRules = await pool.query(
    `SELECT pr.*, pv.id as version_id, pv.version_number, pv.status as version_status,
            ps.id as policy_set_id, ps.name as policy_set_name
     FROM policy_rules pr
     JOIN policy_versions pv ON pv.id = pr.policy_version_id
     JOIN policy_sets ps ON ps.id = pv.policy_set_id
     WHERE pr.source_type = 'CIDR'`,
    []
  );

  const matchingRules: any[] = [];
  for (const rule of cidrRules.rows) {
    if (ipMatchesCidr(ip, rule.source_value)) {
      matchingRules.push(rule);
    }
  }

  // Find rules with TAG/VLAN/HOST source types and resolve them
  const tagVlanHostRules = await pool.query(
    `SELECT pr.*, pv.id as version_id, pv.version_number, pv.status as version_status,
            ps.id as policy_set_id, ps.name as policy_set_name
     FROM policy_rules pr
     JOIN policy_versions pv ON pv.id = pr.policy_version_id
     JOIN policy_sets ps ON ps.id = pv.policy_set_id
     WHERE pr.source_type IN ('TAG', 'VLAN', 'HOST')`,
    []
  );

  for (const rule of tagVlanHostRules.rows) {
    let matches = false;
    
    if (rule.source_type === 'HOST') {
      const hostRes = await pool.query(`SELECT mgmt_ip FROM hosts WHERE id=$1`, [rule.source_value]);
      if (hostRes.rows[0]?.mgmt_ip) {
        const hostIp = String(hostRes.rows[0].mgmt_ip).split('/')[0]; // Remove CIDR if present
        if (hostIp === ip) matches = true;
      }
    } else if (rule.source_type === 'TAG') {
      const hostsRes = await pool.query(
        `SELECT DISTINCT h.mgmt_ip
         FROM hosts h
         JOIN host_tags ht ON ht.host_id = h.id
         WHERE ht.tag_id = $1 AND h.mgmt_ip IS NOT NULL`,
        [rule.source_value]
      );
      for (const host of hostsRes.rows) {
        const hostIp = String(host.mgmt_ip).split('/')[0];
        if (hostIp === ip) {
          matches = true;
          break;
        }
      }
    } else if (rule.source_type === 'VLAN') {
      const hostsRes = await pool.query(
        `SELECT mgmt_ip FROM hosts WHERE vlan_id = $1 AND mgmt_ip IS NOT NULL`,
        [rule.source_value]
      );
      for (const host of hostsRes.rows) {
        const hostIp = String(host.mgmt_ip).split('/')[0];
        if (hostIp === ip) {
          matches = true;
          break;
        }
      }
    }
    
    if (matches) {
      matchingRules.push(rule);
    }
  }

  // For each matching rule, find which hosts have this policy deployed
  const results = await Promise.all(matchingRules.map(async (rule) => {
    // Hosts where this version is the one currently active: each host's latest successful
    // deployment (a deploy replaces the host's whole Segmentra ruleset), not removed by expiry.
    const deploymentsRes = await pool.query(
      `SELECT * FROM (
         SELECT DISTINCT ON (dh.host_id)
                d.id, d.status, d.created_at, d.started_at, d.finished_at, d.policy_version_id,
                dh.host_id, h.hostname, h.mgmt_ip, dh.status AS host_status, dh.expiry_status
           FROM deployment_hosts dh
           JOIN deployments d ON d.id = dh.deployment_id
           JOIN hosts h ON h.id = dh.host_id
          WHERE dh.status = 'SUCCEEDED' AND h.enabled = true
            AND dh.host_id IN (SELECT dh2.host_id FROM deployment_hosts dh2 JOIN deployments d2 ON d2.id = dh2.deployment_id WHERE d2.policy_version_id = $1)
          ORDER BY dh.host_id, COALESCE(dh.finished_at, d.finished_at, d.created_at) DESC
       ) cur
       WHERE cur.policy_version_id = $1 AND cur.expiry_status IS DISTINCT FROM 'REMOVED'
       ORDER BY cur.hostname`,
      [rule.version_id]
    );

    return {
      rule: {
        id: rule.id,
        orderIndex: rule.order_index,
        action: rule.action,
        protocol: rule.protocol,
        ports: rule.ports,
        sourceType: rule.source_type,
        sourceValue: rule.source_value,
        destinationType: rule.destination_type ?? null,
        destinationValue: rule.destination_value ?? null,
        direction: rule.direction,
        comment: rule.comment
      },
      policyVersion: {
        id: rule.version_id,
        versionNumber: rule.version_number,
        status: rule.version_status,
        policySetName: rule.policy_set_name
      },
      deployedHosts: deploymentsRes.rows.map((d: any) => ({
        hostId: d.host_id,
        hostname: d.hostname,
        mgmtIp: d.mgmt_ip,
        deploymentId: d.id,
        deploymentStatus: d.status,
        hostDeploymentStatus: d.host_status,
        deployedAt: d.created_at
      }))
    };
  }));

  res.json({ ip, results });
});

// Get policies deployed to a specific host
troubleshootRouter.get('/hosts/:hostId/policies', async (req, res) => {
  const hostId = req.params.hostId;

  // Verify host exists
  const hostRes = await pool.query(`SELECT * FROM hosts WHERE id=$1`, [hostId]);
  if (!hostRes.rows[0]) {
    return res.status(404).json({ error: 'host_not_found' });
  }
  const host = hostRes.rows[0];

  // Find all deployments that include this host
  const deploymentsRes = await pool.query(
    `SELECT DISTINCT d.*, pv.version_number, pv.status as version_status,
            ps.id as policy_set_id, ps.name as policy_set_name,
            dh.status as host_deployment_status, dh.started_at, dh.finished_at, dh.message,
            dh.expiry_status, dh.finished_at AS host_finished_at
     FROM deployments d
     JOIN deployment_hosts dh ON dh.deployment_id = d.id
     JOIN policy_versions pv ON pv.id = d.policy_version_id
     JOIN policy_sets ps ON ps.id = pv.policy_set_id
     WHERE dh.host_id = $1
     ORDER BY d.created_at DESC`,
    [hostId]
  );

  // The host's active policy is its latest successful deployment (each deploy replaces the whole
  // Segmentra ruleset), unless the expiry REMOVE action stripped it afterwards.
  const latestOk = deploymentsRes.rows
    .filter((d: any) => d.host_deployment_status === 'SUCCEEDED')
    .sort((a: any, b: any) => new Date(b.host_finished_at ?? b.finished_at ?? b.created_at).getTime() - new Date(a.host_finished_at ?? a.finished_at ?? a.created_at).getTime())[0];
  const currentDeploymentId = latestOk && latestOk.expiry_status !== 'REMOVED' ? latestOk.id : null;

  // Get rules for each policy version
  const results = await Promise.all(deploymentsRes.rows.map(async (dep: any) => {
    const rulesRes = await pool.query(
      `SELECT * FROM policy_rules WHERE policy_version_id = $1 ORDER BY order_index ASC`,
      [dep.policy_version_id]
    );

    return {
      deployment: {
        id: dep.id,
        status: dep.status,
        mode: dep.mode,
        createdAt: dep.created_at,
        startedAt: dep.started_at,
        finishedAt: dep.finished_at
      },
      policyVersion: {
        id: dep.policy_version_id,
        versionNumber: dep.version_number,
        status: dep.version_status,
        policySetName: dep.policy_set_name
      },
      hostDeploymentStatus: dep.host_deployment_status,
      hostDeploymentMessage: dep.message,
      current: dep.id === currentDeploymentId,
      rules: rulesRes.rows.map((r: any) => ({
        id: r.id,
        orderIndex: r.order_index,
        action: r.action,
        protocol: r.protocol,
        ports: r.ports,
        sourceType: r.source_type,
        sourceValue: r.source_value,
        destinationType: r.destination_type ?? null,
        destinationValue: r.destination_value ?? null,
        direction: r.direction,
        comment: r.comment
      }))
    };
  }));

  res.json({ host: { id: host.id, hostname: host.hostname, mgmtIp: host.mgmt_ip }, policies: results });
});

// Get hosts that have a specific policy version deployed
troubleshootRouter.get('/policy-versions/:versionId/hosts', async (req, res) => {
  const versionId = req.params.versionId;

  // Verify policy version exists
  const versionRes = await pool.query(
    `SELECT pv.*, ps.name as policy_set_name
     FROM policy_versions pv
     JOIN policy_sets ps ON ps.id = pv.policy_set_id
     WHERE pv.id = $1`,
    [versionId]
  );
  if (!versionRes.rows[0]) {
    return res.status(404).json({ error: 'policy_version_not_found' });
  }
  const version = versionRes.rows[0];

  // Find all deployments of this policy version
  const deploymentsRes = await pool.query(
    `SELECT d.id, d.status, d.created_at, d.started_at, d.finished_at,
            dh.host_id, h.hostname, h.mgmt_ip, dh.status as host_status, dh.message
     FROM deployments d
     JOIN deployment_hosts dh ON dh.deployment_id = d.id
     JOIN hosts h ON h.id = dh.host_id
     WHERE d.policy_version_id = $1 AND h.enabled = true
     ORDER BY h.hostname ASC`,
    [versionId]
  );

  // Group by host (a host might appear in multiple deployments)
  const hostMap = new Map();
  for (const row of deploymentsRes.rows) {
    if (!hostMap.has(row.host_id)) {
      hostMap.set(row.host_id, {
        host: {
          id: row.host_id,
          hostname: row.hostname,
          mgmtIp: row.mgmt_ip
        },
        deployments: []
      });
    }
    hostMap.get(row.host_id).deployments.push({
      deploymentId: row.id,
      deploymentStatus: row.status,
      hostDeploymentStatus: row.host_status,
      message: row.message,
      createdAt: row.created_at,
      startedAt: row.started_at,
      finishedAt: row.finished_at
    });
  }

  res.json({
    policyVersion: {
      id: version.id,
      versionNumber: version.version_number,
      status: version.status,
      policySetName: version.policy_set_name
    },
    hosts: Array.from(hostMap.values())
  });
});

type SimRule = {
  id: string;
  order_index: number;
  direction: string;
  action: 'ALLOW' | 'DENY';
  protocol: string;
  ports: string | null;
  source_type: string;
  source_value: string;
  destination_type?: string | null;
  destination_value?: string | null;
  comment: string | null;
};

/** The policy actually enforced on a host: its most recent successful deployment
 *  (each deployment replaces the whole Segmentra table). */
async function effectivePolicyForHost(hostId: string) {
  const { rows } = await pool.query(
    `SELECT d.policy_version_id, d.id AS deployment_id, d.status AS deployment_status,
            pv.version_number, pv.status AS version_status, ps.name AS policy_set_name
       FROM deployments d
       JOIN deployment_hosts dh ON dh.deployment_id = d.id
       JOIN policy_versions pv ON pv.id = d.policy_version_id
       JOIN policy_sets ps ON ps.id = pv.policy_set_id
      WHERE dh.host_id = $1 AND dh.status = 'SUCCEEDED' AND pv.status IN ('APPROVED','DEPLOYED')
      ORDER BY COALESCE(dh.finished_at, d.finished_at, d.created_at) DESC
      LIMIT 1`,
    [hostId]
  );
  if (!rows[0]) return null;
  const rulesRes = await pool.query(
    `SELECT * FROM policy_rules WHERE policy_version_id = $1 ORDER BY order_index ASC, id ASC`,
    [rows[0].policy_version_id]
  );
  return { policy: rows[0], rules: rulesRes.rows as SimRule[] };
}

async function managementCidrs(): Promise<string[]> {
  const mgmtVlanRes = await pool.query(`SELECT value FROM system_settings WHERE key='management_vlan_id'`);
  const mgmtVlanId = mgmtVlanRes.rows[0]?.value || null;
  if (!mgmtVlanId) return [];
  const vlanRes = await pool.query(`SELECT subnet FROM vlans WHERE id=$1`, [mgmtVlanId]);
  const subnet = vlanRes.rows[0]?.subnet ? String(vlanRes.rows[0].subnet) : null;
  return subnet && isValidCidr(subnet) ? [subnet] : [];
}

// Simulate communication between two IPs.
// Mirrors the compiled firewall: rules are evaluated in order_index order and the FIRST match
// wins. Inbound on the destination: management SSH baseline first, default DROP. Outbound on
// the source: default ACCEPT. A host without a deployed policy does not filter traffic.
troubleshootRouter.post('/simulate-communication', requireRole('operator', 'admin'), async (req, res) => {
  const sourceIp = String(req.body.sourceIp ?? '').trim();
  const sourcePort = req.body.sourcePort ? parseInt(String(req.body.sourcePort), 10) : null;
  const destIp = String(req.body.destIp ?? '').trim();
  const destPortRaw = req.body.destPort ? parseInt(String(req.body.destPort), 10) : null;
  const destPort = destPortRaw !== null && Number.isFinite(destPortRaw) ? destPortRaw : null;
  const protocol = String(req.body.protocol ?? 'tcp').toLowerCase();

  if (!sourceIp || !destIp) {
    return res.status(400).json({ error: 'source_ip_and_dest_ip_required', message: 'Source IP and destination IP are required' });
  }
  if (!isValidIp(sourceIp) || !isValidIp(destIp)) {
    return res.status(400).json({ error: 'invalid_ip', message: 'Source and destination must be valid IP addresses' });
  }
  if (!['tcp', 'udp', 'icmp'].includes(protocol)) {
    return res.status(400).json({ error: 'invalid_protocol', message: 'protocol must be tcp, udp or icmp' });
  }
  if (destPort !== null && (destPort < 1 || destPort > 65535)) {
    return res.status(400).json({ error: 'invalid_port' });
  }

  const findHost = async (ip: string) =>
    (await pool.query(
      `SELECT id, hostname, mgmt_ip, ssh_port FROM hosts WHERE host(mgmt_ip) = $1 ORDER BY enabled DESC, hostname LIMIT 1`,
      [ip]
    )).rows[0] ?? null;
  const sourceHost = await findHost(sourceIp);
  const destHost = await findHost(destIp);

  const resolve = createSourceResolver();
  const notes: string[] = [];

  const ruleMatches = async (rule: SimRule, remoteIp: string): Promise<boolean> => {
    if (rule.protocol !== 'any' && rule.protocol !== protocol) return false;
    if (rule.ports && String(rule.ports).trim()) {
      if (protocol !== 'tcp' && protocol !== 'udp') return false;
      if (destPort === null) {
        notes.push(`Rule #${rule.order_index} restricts ports (${rule.ports}); no destination port given, so it was treated as not matching`);
        return false;
      }
      if (!portSpecIncludes(rule.ports, destPort)) return false;
    }
    const addrs = await resolve(rule.source_type, rule.source_value);
    return addrs.some((a) => cidrContains(a, remoteIp));
  };

  const ruleInfoOf = (rule: SimRule, policy: any, host: any, appliesTo: 'source' | 'destination' | 'gateway') => ({
    rule: {
      id: rule.id,
      orderIndex: rule.order_index,
      action: rule.action,
      protocol: rule.protocol,
      ports: rule.ports,
      sourceType: rule.source_type,
      sourceValue: rule.source_value,
      destinationType: rule.destination_type ?? null,
      destinationValue: rule.destination_value ?? null,
      direction: rule.direction,
      comment: rule.comment
    },
    policyVersion: {
      id: policy.policy_version_id,
      versionNumber: policy.version_number,
      status: policy.version_status,
      policySetName: policy.policy_set_name
    },
    host: { id: host.id, hostname: host.hostname, mgmtIp: host.mgmt_ip },
    appliesTo,
    direction: appliesTo === 'source' ? 'OUT' : appliesTo === 'gateway' ? 'FORWARD' : 'IN'
  });

  const blockingRules: any[] = [];
  const allowingRules: any[] = [];
  const allRules: any[] = [];

  type SideResult = {
    managed: boolean;
    decision: 'ALLOW' | 'DENY';
    decidedBy: 'rule' | 'baseline' | 'default_policy' | 'no_policy';
    defaultAction: 'ACCEPT' | 'DROP' | null;
    matchedRule: any | null;
    policyVersion: any | null;
  };

  // Outbound on the source host (default ACCEPT).
  let sourceSide: SideResult = { managed: false, decision: 'ALLOW', decidedBy: 'no_policy', defaultAction: null, matchedRule: null, policyVersion: null };
  if (sourceHost) {
    const eff = await effectivePolicyForHost(sourceHost.id);
    if (eff) {
      sourceSide = { managed: true, decision: 'ALLOW', decidedBy: 'default_policy', defaultAction: 'ACCEPT', matchedRule: null, policyVersion: eff.policy };
      for (const rule of eff.rules) {
        if (rule.direction !== 'OUT' && rule.direction !== 'BOTH') continue;
        if (!(await ruleMatches(rule, destIp))) continue;
        const info = ruleInfoOf(rule, eff.policy, sourceHost, 'source');
        allRules.push(info);
        (rule.action === 'DENY' ? blockingRules : allowingRules).push(info);
        if (!sourceSide.matchedRule) {
          sourceSide = { ...sourceSide, decision: rule.action, decidedBy: 'rule', matchedRule: info };
        }
      }
    }
  }

  // Inbound on the destination host (baseline first, default DROP).
  let destSide: SideResult = { managed: false, decision: 'ALLOW', decidedBy: 'no_policy', defaultAction: null, matchedRule: null, policyVersion: null };
  if (destHost) {
    const eff = await effectivePolicyForHost(destHost.id);
    if (eff) {
      destSide = { managed: true, decision: 'DENY', decidedBy: 'default_policy', defaultAction: 'DROP', matchedRule: null, policyVersion: eff.policy };
      const sshPort = Number(destHost.ssh_port) || 22;
      const mgmt = await managementCidrs();
      const baselineSsh =
        protocol === 'tcp' && destPort === sshPort && (mgmt.length === 0 || mgmt.some((c) => cidrContains(c, sourceIp)));
      if (baselineSsh) {
        destSide = { ...destSide, decision: 'ALLOW', decidedBy: 'baseline' };
        notes.push(`Management SSH baseline (tcp/${sshPort}) accepts this traffic before any policy rule`);
      }
      for (const rule of eff.rules) {
        if (rule.direction !== 'IN' && rule.direction !== 'BOTH') continue;
        if (!(await ruleMatches(rule, sourceIp))) continue;
        const info = ruleInfoOf(rule, eff.policy, destHost, 'destination');
        allRules.push(info);
        (rule.action === 'DENY' ? blockingRules : allowingRules).push(info);
        if (destSide.decidedBy !== 'baseline' && !destSide.matchedRule) {
          destSide = { ...destSide, decision: rule.action, decidedBy: 'rule', matchedRule: info };
        }
      }
    }
  }

  // Forwarded through a managed gateway: when the destination is an IoT device assigned to a
  // gateway, that gateway's FORWARD rules are evaluated in order (first match wins) and traffic
  // no rule allows is dropped (protected-device default deny). The simulator assumes the traffic
  // is actually routed through the gateway.
  const resolveDst = createDestinationResolver();
  type GatewayResult = SideResult & { gateway: { id: string; hostname: string; mgmtIp: string | null }; protectedAsset: { id: string; name: string } };
  const gatewayResults: GatewayResult[] = [];
  for (const gw of await gatewaysProtecting(destIp)) {
    const eff = await effectivePolicyForHost(gw.id);
    const gwHost = { id: gw.id, hostname: gw.hostname, mgmt_ip: gw.mgmt_ip };
    let r: GatewayResult = {
      managed: !!eff,
      decision: eff ? 'DENY' : 'ALLOW',
      decidedBy: eff ? 'default_policy' : 'no_policy',
      defaultAction: eff ? 'DROP' : null,
      matchedRule: null,
      policyVersion: eff?.policy ?? null,
      gateway: { id: gw.id, hostname: gw.hostname, mgmtIp: gw.mgmt_ip },
      protectedAsset: { id: gw.asset_id, name: gw.asset_name }
    };
    if (eff) {
      for (const rule of eff.rules) {
        if (rule.direction !== 'FORWARD' || !rule.destination_type) continue;
        if (!(await ruleMatches(rule, sourceIp))) continue;
        const dsts = await resolveDst(rule.destination_type, String(rule.destination_value ?? ''));
        if (!dsts.some((a) => cidrContains(a, destIp))) continue;
        const info = ruleInfoOf(rule, eff.policy, gwHost, 'gateway');
        allRules.push(info);
        (rule.action === 'DENY' ? blockingRules : allowingRules).push(info);
        if (!r.matchedRule) r = { ...r, decision: rule.action, decidedBy: 'rule', matchedRule: info };
      }
      notes.push(
        `${destIp} is protected IoT device "${gw.asset_name}" behind gateway ${gw.hostname}: forwarded traffic to it is denied unless a FORWARD rule allows it ` +
          '(assumes the traffic is routed through the gateway and the gateway was deployed after the device was assigned)'
      );
    } else {
      notes.push(`${destIp} is IoT device "${gw.asset_name}" assigned to gateway ${gw.hostname}, but no policy is deployed on that gateway: forwarded traffic is not filtered`);
    }
    gatewayResults.push(r);
  }
  const gatewayDeny = gatewayResults.find((g) => g.decision === 'DENY') ?? null;

  const wouldBlock = sourceSide.decision === 'DENY' || destSide.decision === 'DENY' || !!gatewayDeny;
  let blockingRule: any = null;
  let reason: string;
  if (!sourceSide.managed && !destSide.managed && !gatewayResults.some((g) => g.managed)) {
    reason = 'allowed (no policy)';
  } else if (sourceSide.decision === 'DENY') {
    blockingRule = sourceSide.matchedRule;
    reason = `blocked outbound on ${sourceHost.hostname} by rule #${sourceSide.matchedRule?.rule.orderIndex}`;
  } else if (destSide.decision === 'DENY') {
    blockingRule = destSide.matchedRule;
    reason = destSide.decidedBy === 'rule'
      ? `blocked inbound on ${destHost.hostname} by rule #${destSide.matchedRule?.rule.orderIndex}`
      : `blocked inbound on ${destHost.hostname} by the default DROP policy (no rule matched)`;
  } else if (gatewayDeny) {
    blockingRule = gatewayDeny.matchedRule;
    reason = gatewayDeny.decidedBy === 'rule'
      ? `blocked while forwarded through gateway ${gatewayDeny.gateway.hostname} by FORWARD rule #${gatewayDeny.matchedRule?.rule.orderIndex}`
      : `blocked while forwarded through gateway ${gatewayDeny.gateway.hostname}: ${destIp} is a protected device and no FORWARD rule allows this traffic`;
  } else {
    reason = 'allowed';
  }
  if (sourceHost || destHost) notes.push('Interface scopes are not considered by the simulator');

  res.json({
    sourceIp,
    sourcePort,
    destIp,
    destPort,
    protocol,
    sourceHost: sourceHost ? { id: sourceHost.id, hostname: sourceHost.hostname, mgmtIp: sourceHost.mgmt_ip } : null,
    destHost: destHost ? { id: destHost.id, hostname: destHost.hostname, mgmtIp: destHost.mgmt_ip } : null,
    wouldBlock,
    verdict: wouldBlock ? 'blocked' : 'allowed',
    reason,
    blockingRule,
    source: sourceSide,
    destination: destSide,
    gateways: gatewayResults,
    blockingRules,
    allowingRules,
    allRules,
    notes: Array.from(new Set(notes))
  });
});

// Firewall Audit Endpoints

const startAuditSchema = z.object({
  hosts: z.array(z.string().uuid()).min(1),
  durationMinutes: z.number().int().min(1).max(1440) // Max 24 hours
});

type AuditStartResult = {
  hostId: string;
  hostname: string | null;
  status: 'RUNNING' | 'FAILED' | 'RESTORE_PENDING';
  sessionId: string | null;
  error?: string;
};

// Start audit session(s). Every host is processed independently; the response lists the
// outcome per host (HTTP 201 if all started, 207 if any failed).
troubleshootRouter.post('/audit/start', requireRole('operator', 'admin'), async (req, res) => {
  const parsed = startAuditSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: 'invalid_body', message: parsed.error.message });
  }
  const { hosts: hostIds, durationMinutes } = parsed.data;
  const userId = req.auth!.userId ?? null;

  const hostRes = await pool.query(
    `SELECT h.*,
            (SELECT array_agg(json_build_object('name', hi.name, 'role', hi.role, 'enabled', hi.enabled))
             FROM host_interfaces hi WHERE hi.host_id = h.id) as interfaces
     FROM hosts h
     WHERE h.id = ANY($1::uuid[]) AND h.enabled = true`,
    [hostIds]
  );

  const results: AuditStartResult[] = [];
  const found = new Set(hostRes.rows.map((h: any) => h.id));
  for (const id of new Set(hostIds)) {
    if (!found.has(id)) results.push({ hostId: id, hostname: null, status: 'FAILED', sessionId: null, error: 'host not found or disabled' });
  }

  const busy = await pool.query(
    `SELECT DISTINCT host_id FROM firewall_audit_sessions WHERE host_id = ANY($1::uuid[]) AND status IN ('PENDING','RUNNING')`,
    [hostIds]
  );
  const busyHosts = new Set(busy.rows.map((r: any) => r.host_id));

  const sessions: any[] = [];
  const scheduledRestoreAt = new Date(Date.now() + durationMinutes * 60 * 1000);
  const mgmtSshCidrs = await managementCidrs();

  for (const host of hostRes.rows) {
    if (busyHosts.has(host.id)) {
      results.push({ hostId: host.id, hostname: host.hostname, status: 'FAILED', sessionId: null, error: 'an audit session is already active for this host' });
      continue;
    }
    if (!host.mgmt_ip) {
      results.push({ hostId: host.id, hostname: host.hostname, status: 'FAILED', sessionId: null, error: 'host has no management IP' });
      continue;
    }

    const logFilePath = `/var/log/segmentra-audit-${host.hostname}-${Date.now()}.log`;

    // Create DB record FIRST so the scheduler can restore if we crash mid-way
    const sessionRes = await pool.query(
      `INSERT INTO firewall_audit_sessions
       (host_id, status, duration_minutes, started_at, scheduled_restore_at, backup_path, log_file_path, created_by)
       VALUES ($1, 'PENDING', $2, now(), $3, NULL, $4, $5)
       RETURNING *`,
      [host.id, durationMinutes, scheduledRestoreAt, logFilePath, userId]
    );
    const sessionId = sessionRes.rows[0].id;
    let cred: MaterializedSshCredential | null = null;
    let backupPath: string | null = null;
    let policyFilePath: string | null = null;

    try {
      cred = await getSshCredentialForHost(host.id);
      const auditHost = buildAuditHost(host, cred);

      // Start audit session (backup rules, configure logging)
      const startResult = await startAuditSession(auditHost, logFilePath);
      if (startResult.backupPath) {
        backupPath = startResult.backupPath;
        await pool.query(`UPDATE firewall_audit_sessions SET backup_path = $2 WHERE id = $1`, [sessionId, backupPath]);
      }
      if (!startResult.success) {
        throw new Error(`Failed to start audit: ${(startResult.stderr || '').trim()}`);
      }

      // Compile log-only policy
      const compiled = compileHostPolicy({
        host: {
          id: host.id,
          hostname: host.hostname,
          mgmtIp: String(host.mgmt_ip),
          firewallBackend: auditHost.backend,
          interfaces: (host.interfaces || []).map((i: any) => ({ name: i.name, role: i.role, enabled: i.enabled })),
          sshPort: Number(host.ssh_port) || 22
        },
        policyInterfaceScope: { type: 'ALL_INTERFACES' as const },
        rules: [],
        sets: {},
        baseline: { mgmtSshCidrs },
        logOnlyMode: true,
        // Gateways: log forwarded traffic to their protected devices (accepted while learning)
        protectedDestinations: await getProtectedDestinations(host.id)
      });

      policyFilePath = path.join(os.tmpdir(), `audit_policy_${host.id}_${Date.now()}.${compiled.backend === 'nftables' ? 'nft' : 'iptables'}`);
      const deployResult = await deployLogOnlyPolicy(auditHost, compiled.text, policyFilePath);
      if (!deployResult.success) {
        throw new Error(`Failed to deploy log-only policy: ${(deployResult.stderr || '').trim()}`);
      }

      await pool.query(`UPDATE firewall_audit_sessions SET status = 'RUNNING' WHERE id = $1`, [sessionId]);
      sessions.push({ ...sessionRes.rows[0], status: 'RUNNING', backup_path: backupPath });
      results.push({ hostId: host.id, hostname: host.hostname, status: 'RUNNING', sessionId });
    } catch (error: any) {
      const message = error?.message ?? String(error);
      if (backupPath) {
        // The host may already be modified: hand the session to the restore path. If the
        // immediate restore fails, the session stays RUNNING and the scheduler retries.
        await pool.query(`UPDATE firewall_audit_sessions SET status = 'RUNNING', scheduled_restore_at = now() WHERE id = $1`, [sessionId]);
        const outcome = await restoreAuditSessionById(sessionId, { finalStatus: 'CANCELLED', collectLogs: false });
        if (outcome?.success) {
          await pool.query(
            `UPDATE firewall_audit_sessions
                SET status = 'FAILED', log_data = COALESCE(log_data, '{}'::jsonb) || jsonb_build_object('error', $2::text)
              WHERE id = $1`,
            [sessionId, message]
          );
          results.push({ hostId: host.id, hostname: host.hostname, status: 'FAILED', sessionId, error: `${message} (original rules restored)` });
        } else {
          results.push({
            hostId: host.id,
            hostname: host.hostname,
            status: 'RESTORE_PENDING',
            sessionId,
            error: `${message}; immediate restore failed (${outcome && !outcome.success ? outcome.error : 'session busy'}) — the scheduler will keep retrying`
          });
        }
      } else {
        // Nothing was changed on the host.
        await pool.query(
          `UPDATE firewall_audit_sessions
              SET status = 'FAILED', log_data = COALESCE(log_data, '{}'::jsonb) || jsonb_build_object('error', $2::text)
            WHERE id = $1`,
          [sessionId, message]
        );
        results.push({ hostId: host.id, hostname: host.hostname, status: 'FAILED', sessionId, error: message });
      }
    } finally {
      cred?.cleanup();
      if (policyFilePath) {
        try { if (fs.existsSync(policyFilePath)) fs.unlinkSync(policyFilePath); } catch { /* ignore */ }
      }
    }
  }

  // Firewall learning puts hosts into log-only (allow-all) mode, so every start is audited.
  for (const r of results) {
    if (!r.sessionId) continue;
    await createAuditEvent({
      actorUserId: userId,
      action: r.status === 'RUNNING' ? 'FIREWALL_LEARNING_START' : 'FIREWALL_LEARNING_START_FAILED',
      entityType: 'firewall_audit_session',
      entityId: r.sessionId,
      ipAddress: req.ip,
      metadata: { hostId: r.hostId, hostname: r.hostname, durationMinutes, status: r.status, error: r.error }
    });
  }

  const failed = results.filter((r) => r.status !== 'RUNNING').length;
  res.status(failed === 0 ? 201 : 207).json({
    sessions,
    results,
    summary: { requested: new Set(hostIds).size, started: results.length - failed, failed }
  });
});

// List all audit sessions
troubleshootRouter.get('/audit/sessions', async (req, res) => {
  const { rows } = await pool.query(
    `SELECT fas.*, h.hostname, h.mgmt_ip
     FROM firewall_audit_sessions fas
     JOIN hosts h ON h.id = fas.host_id
     ORDER BY fas.created_at DESC
     LIMIT 100`
  );
  res.json({ sessions: rows });
});

// Get audit session details
troubleshootRouter.get('/audit/sessions/:id', async (req, res) => {
  const { rows } = await pool.query(
    `SELECT fas.*, h.hostname, h.mgmt_ip, h.firewall_backend
     FROM firewall_audit_sessions fas
     JOIN hosts h ON h.id = fas.host_id
     WHERE fas.id = $1`,
    [req.params.id]
  );
  if (!rows[0]) {
    return res.status(404).json({ error: 'not_found' });
  }
  res.json({ session: rows[0] });
});

// Manually trigger restore
troubleshootRouter.post('/audit/sessions/:id/restore', requireRole('operator', 'admin'), async (req, res) => {
  const outcome = await restoreAuditSessionById(req.params.id, { finalStatus: 'COMPLETED', collectLogs: true });
  if (!outcome) {
    return res.status(404).json({ error: 'not_found', message: 'Session not found or not running' });
  }
  await createAuditEvent({
    actorUserId: req.auth!.userId ?? null,
    action: outcome.success ? 'FIREWALL_LEARNING_RESTORE' : 'FIREWALL_LEARNING_RESTORE_FAILED',
    entityType: 'firewall_audit_session',
    entityId: req.params.id,
    ipAddress: req.ip,
    metadata: outcome.success ? { entryCount: outcome.entryCount } : { error: outcome.error }
  });
  if (!outcome.success) {
    return res.status(502).json({
      error: 'restore_failed',
      message: `${outcome.error}. The session remains RUNNING and will be retried automatically.`,
      attempts: outcome.attempts,
      nextAttemptAt: outcome.nextAttemptAt
    });
  }
  res.json({ success: true, flows: outcome.flows, entryCount: outcome.entryCount });
});

// Get parsed log data
troubleshootRouter.get('/audit/sessions/:id/logs', async (req, res) => {
  const { rows } = await pool.query(
    `SELECT log_data FROM firewall_audit_sessions WHERE id = $1`,
    [req.params.id]
  );
  if (!rows[0]) {
    return res.status(404).json({ error: 'not_found' });
  }
  res.json({ logData: rows[0].log_data });
});

// Cancel running session
troubleshootRouter.post('/audit/sessions/:id/cancel', requireRole('operator', 'admin'), async (req, res) => {
  const outcome = await restoreAuditSessionById(req.params.id, { finalStatus: 'CANCELLED', collectLogs: false });
  if (!outcome) {
    return res.status(404).json({ error: 'not_found', message: 'Session not found or not running' });
  }
  await createAuditEvent({
    actorUserId: req.auth!.userId ?? null,
    action: outcome.success ? 'FIREWALL_LEARNING_CANCEL' : 'FIREWALL_LEARNING_CANCEL_FAILED',
    entityType: 'firewall_audit_session',
    entityId: req.params.id,
    ipAddress: req.ip,
    metadata: outcome.success ? {} : { error: outcome.error }
  });
  if (!outcome.success) {
    return res.status(502).json({
      error: 'cancel_failed',
      message: `Could not restore the original firewall rules: ${outcome.error}. The session remains RUNNING and the restore will be retried automatically.`,
      attempts: outcome.attempts,
      nextAttemptAt: outcome.nextAttemptAt
    });
  }
  res.json({ success: true });
});
