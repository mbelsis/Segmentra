import { Router } from 'express';
import { z } from 'zod';
import { pool } from '../db/pool.js';
import { requireAuth, requireRole } from '../middleware/auth.js';
import { compileHostPolicy } from '@segmentra/compiler';
import { startAuditSession, deployLogOnlyPolicy, restoreAuditSession, retrieveAuditLogs, type AuditSshHost } from '@segmentra/executor';
import { readSecretPlaintext } from '../services/secrets.js';
import { parseFirewallLogs, groupCommunicationFlows } from '../services/log-parser.js';
import { processExpiredAuditSessions } from '../services/audit-scheduler.js';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

export const troubleshootRouter = Router();
troubleshootRouter.use(requireAuth, requireRole('viewer', 'operator', 'approver', 'admin'));

// Helper function to check if an IP matches a CIDR
function ipMatchesCidr(ip: string, cidr: string): boolean {
  try {
    // Remove CIDR notation if present in IP
    const cleanIp = ip.split('/')[0];
    
    const [cidrIp, prefix] = cidr.split('/');
    const prefixLen = prefix ? parseInt(prefix, 10) : 32;
    
    if (prefixLen < 0 || prefixLen > 32) return false;
    
    // Simple CIDR matching (for IPv4)
    const ipParts = cleanIp.split('.').map(Number);
    const cidrParts = cidrIp.split('.').map(Number);
    
    if (ipParts.length !== 4 || cidrParts.length !== 4) return false;
    if (ipParts.some(p => isNaN(p) || p < 0 || p > 255)) return false;
    if (cidrParts.some(p => isNaN(p) || p < 0 || p > 255)) return false;
    
    const mask = prefixLen === 0 ? 0 : (0xFFFFFFFF << (32 - prefixLen)) >>> 0;
    const ipNum = (ipParts[0] << 24) + (ipParts[1] << 16) + (ipParts[2] << 8) + ipParts[3];
    const cidrNum = (cidrParts[0] << 24) + (cidrParts[1] << 16) + (cidrParts[2] << 8) + cidrParts[3];
    
    return (ipNum & mask) === (cidrNum & mask);
  } catch {
    return false;
  }
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
    const deploymentsRes = await pool.query(
      `SELECT d.id, d.status, d.created_at, d.started_at, d.finished_at,
              dh.host_id, h.hostname, h.mgmt_ip, dh.status as host_status
       FROM deployments d
       JOIN deployment_hosts dh ON dh.deployment_id = d.id
       JOIN hosts h ON h.id = dh.host_id
       WHERE d.policy_version_id = $1 AND h.enabled = true
       ORDER BY d.created_at DESC`,
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
            dh.status as host_deployment_status, dh.started_at, dh.finished_at, dh.message
     FROM deployments d
     JOIN deployment_hosts dh ON dh.deployment_id = d.id
     JOIN policy_versions pv ON pv.id = d.policy_version_id
     JOIN policy_sets ps ON ps.id = pv.policy_set_id
     WHERE dh.host_id = $1
     ORDER BY d.created_at DESC`,
    [hostId]
  );

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
      rules: rulesRes.rows.map((r: any) => ({
        id: r.id,
        orderIndex: r.order_index,
        action: r.action,
        protocol: r.protocol,
        ports: r.ports,
        sourceType: r.source_type,
        sourceValue: r.source_value,
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

// Helper function to check if a port matches a port specification
function portMatches(port: number | null, portSpec: string | null): boolean {
  if (!portSpec || port === null) return true; // No port filter means match all
  
  const parts = portSpec.split(',');
  for (const part of parts) {
    const trimmed = part.trim();
    if (trimmed.includes('-')) {
      // Port range
      const [start, end] = trimmed.split('-').map(p => parseInt(p.trim(), 10));
      if (!isNaN(start) && !isNaN(end) && port >= start && port <= end) {
        return true;
      }
    } else {
      // Single port
      const portNum = parseInt(trimmed, 10);
      if (!isNaN(portNum) && port === portNum) {
        return true;
      }
    }
  }
  return false;
}

// Simulate communication between two IPs
troubleshootRouter.post('/simulate-communication', requireRole('operator', 'admin'), async (req, res) => {
  const sourceIp = String(req.body.sourceIp ?? '').trim();
  const sourcePort = req.body.sourcePort ? parseInt(String(req.body.sourcePort), 10) : null;
  const destIp = String(req.body.destIp ?? '').trim();
  const destPort = req.body.destPort ? parseInt(String(req.body.destPort), 10) : null;
  const protocol = String(req.body.protocol ?? 'tcp').toLowerCase();

  if (!sourceIp || !destIp) {
    return res.status(400).json({ error: 'source_ip_and_dest_ip_required', message: 'Source IP and destination IP are required' });
  }

  // Find hosts for source and destination IPs
  const sourceHostRes = await pool.query(
    `SELECT id, hostname, mgmt_ip FROM hosts WHERE mgmt_ip::text = $1 OR mgmt_ip::text LIKE $2`,
    [sourceIp, `${sourceIp}/%`]
  );
  const sourceHost = sourceHostRes.rows[0];

  const destHostRes = await pool.query(
    `SELECT id, hostname, mgmt_ip FROM hosts WHERE mgmt_ip::text = $1 OR mgmt_ip::text LIKE $2`,
    [destIp, `${destIp}/%`]
  );
  const destHost = destHostRes.rows[0];

  // Get all deployed policies for source host (if exists)
  const sourcePolicies: any[] = [];
  if (sourceHost) {
    const sourceDeploymentsRes = await pool.query(
      `SELECT DISTINCT d.policy_version_id, d.id as deployment_id, d.status as deployment_status,
              pv.version_number, pv.status as version_status, ps.name as policy_set_name
       FROM deployments d
       JOIN deployment_hosts dh ON dh.deployment_id = d.id
       JOIN policy_versions pv ON pv.id = d.policy_version_id
       JOIN policy_sets ps ON ps.id = pv.policy_set_id
       WHERE dh.host_id = $1 AND dh.status = 'SUCCEEDED' AND pv.status = 'APPROVED'
       ORDER BY d.created_at DESC`,
      [sourceHost.id]
    );
    sourcePolicies.push(...sourceDeploymentsRes.rows);
  }

  // Get all deployed policies for destination host (if exists)
  const destPolicies: any[] = [];
  if (destHost) {
    const destDeploymentsRes = await pool.query(
      `SELECT DISTINCT d.policy_version_id, d.id as deployment_id, d.status as deployment_status,
              pv.version_number, pv.status as version_status, ps.name as policy_set_name
       FROM deployments d
       JOIN deployment_hosts dh ON dh.deployment_id = d.id
       JOIN policy_versions pv ON pv.id = d.policy_version_id
       JOIN policy_sets ps ON ps.id = pv.policy_set_id
       WHERE dh.host_id = $1 AND dh.status = 'SUCCEEDED' AND pv.status = 'APPROVED'
       ORDER BY d.created_at DESC`,
      [destHost.id]
    );
    destPolicies.push(...destDeploymentsRes.rows);
  }

  // Check rules that would affect this communication
  const blockingRules: any[] = [];
  const allowingRules: any[] = [];

  // Check source host policies (OUT direction)
  for (const policy of sourcePolicies) {
    const rulesRes = await pool.query(
      `SELECT * FROM policy_rules WHERE policy_version_id = $1 ORDER BY order_index ASC`,
      [policy.policy_version_id]
    );

    for (const rule of rulesRes.rows) {
      // Check if rule applies to OUT direction (source host sending to destination)
      if (rule.direction === 'OUT' || rule.direction === 'BOTH') {
        // Check if destination IP matches rule source
        let sourceMatches = false;
        
        if (rule.source_type === 'CIDR') {
          sourceMatches = ipMatchesCidr(destIp, rule.source_value);
        } else if (rule.source_type === 'HOST') {
          const hostRes = await pool.query(`SELECT mgmt_ip FROM hosts WHERE id=$1`, [rule.source_value]);
          if (hostRes.rows[0]?.mgmt_ip) {
            const hostIp = String(hostRes.rows[0].mgmt_ip).split('/')[0];
            sourceMatches = hostIp === destIp;
          }
        } else if (rule.source_type === 'TAG') {
          const hostsRes = await pool.query(
            `SELECT DISTINCT h.mgmt_ip FROM hosts h
             JOIN host_tags ht ON ht.host_id = h.id
             WHERE ht.tag_id = $1 AND h.mgmt_ip IS NOT NULL`,
            [rule.source_value]
          );
          for (const host of hostsRes.rows) {
            const hostIp = String(host.mgmt_ip).split('/')[0];
            if (hostIp === destIp) {
              sourceMatches = true;
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
            if (hostIp === destIp) {
              sourceMatches = true;
              break;
            }
          }
        }

        if (sourceMatches) {
          // Check protocol match
          const protocolMatch = rule.protocol === 'any' || rule.protocol === protocol;
          
          // Check port match (for TCP/UDP)
          const portMatch = (protocol === 'tcp' || protocol === 'udp') 
            ? portMatches(destPort, rule.ports) 
            : true;

          if (protocolMatch && portMatch) {
            const ruleInfo = {
              rule: {
                id: rule.id,
                orderIndex: rule.order_index,
                action: rule.action,
                protocol: rule.protocol,
                ports: rule.ports,
                sourceType: rule.source_type,
                sourceValue: rule.source_value,
                direction: rule.direction,
                comment: rule.comment
              },
              policyVersion: {
                id: policy.policy_version_id,
                versionNumber: policy.version_number,
                status: policy.version_status,
                policySetName: policy.policy_set_name
              },
              host: {
                id: sourceHost.id,
                hostname: sourceHost.hostname,
                mgmtIp: sourceHost.mgmt_ip
              },
              appliesTo: 'source',
              direction: 'OUT'
            };

            if (rule.action === 'DENY') {
              blockingRules.push(ruleInfo);
            } else {
              allowingRules.push(ruleInfo);
            }
          }
        }
      }
    }
  }

  // Check destination host policies (IN direction)
  for (const policy of destPolicies) {
    const rulesRes = await pool.query(
      `SELECT * FROM policy_rules WHERE policy_version_id = $1 ORDER BY order_index ASC`,
      [policy.policy_version_id]
    );

    for (const rule of rulesRes.rows) {
      // Check if rule applies to IN direction (destination host receiving from source)
      if (rule.direction === 'IN' || rule.direction === 'BOTH') {
        // Check if source IP matches rule source
        let sourceMatches = false;
        
        if (rule.source_type === 'CIDR') {
          sourceMatches = ipMatchesCidr(sourceIp, rule.source_value);
        } else if (rule.source_type === 'HOST') {
          const hostRes = await pool.query(`SELECT mgmt_ip FROM hosts WHERE id=$1`, [rule.source_value]);
          if (hostRes.rows[0]?.mgmt_ip) {
            const hostIp = String(hostRes.rows[0].mgmt_ip).split('/')[0];
            sourceMatches = hostIp === sourceIp;
          }
        } else if (rule.source_type === 'TAG') {
          const hostsRes = await pool.query(
            `SELECT DISTINCT h.mgmt_ip FROM hosts h
             JOIN host_tags ht ON ht.host_id = h.id
             WHERE ht.tag_id = $1 AND h.mgmt_ip IS NOT NULL`,
            [rule.source_value]
          );
          for (const host of hostsRes.rows) {
            const hostIp = String(host.mgmt_ip).split('/')[0];
            if (hostIp === sourceIp) {
              sourceMatches = true;
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
            if (hostIp === sourceIp) {
              sourceMatches = true;
              break;
            }
          }
        }

        if (sourceMatches) {
          // Check protocol match
          const protocolMatch = rule.protocol === 'any' || rule.protocol === protocol;
          
          // Check port match (for TCP/UDP)
          const portMatch = (protocol === 'tcp' || protocol === 'udp') 
            ? portMatches(destPort, rule.ports) 
            : true;

          if (protocolMatch && portMatch) {
            const ruleInfo = {
              rule: {
                id: rule.id,
                orderIndex: rule.order_index,
                action: rule.action,
                protocol: rule.protocol,
                ports: rule.ports,
                sourceType: rule.source_type,
                sourceValue: rule.source_value,
                direction: rule.direction,
                comment: rule.comment
              },
              policyVersion: {
                id: policy.policy_version_id,
                versionNumber: policy.version_number,
                status: policy.version_status,
                policySetName: policy.policy_set_name
              },
              host: {
                id: destHost.id,
                hostname: destHost.hostname,
                mgmtIp: destHost.mgmt_ip
              },
              appliesTo: 'destination',
              direction: 'IN'
            };

            if (rule.action === 'DENY') {
              blockingRules.push(ruleInfo);
            } else {
              allowingRules.push(ruleInfo);
            }
          }
        }
      }
    }
  }

  // Determine final result: blocked if any DENY rule comes before ALLOW rules
  // Sort by order index to determine precedence
  const allRules = [...blockingRules, ...allowingRules].sort((a, b) => {
    // If rules are on different hosts, check both
    if (a.host.id !== b.host.id) {
      // Source host rules (OUT) are checked first, then destination (IN)
      if (a.appliesTo === 'source' && b.appliesTo === 'destination') return -1;
      if (a.appliesTo === 'destination' && b.appliesTo === 'source') return 1;
    }
    return a.rule.orderIndex - b.rule.orderIndex;
  });

  let wouldBlock = false;
  let blockingRule: any = null;
  
  // Check if any DENY rule comes before an ALLOW rule
  for (const ruleInfo of allRules) {
    if (ruleInfo.rule.action === 'DENY') {
      wouldBlock = true;
      blockingRule = ruleInfo;
      break; // First DENY rule blocks
    } else if (ruleInfo.rule.action === 'ALLOW') {
      // If we find an ALLOW before any DENY, communication is allowed
      // But we need to check if there's a DENY later that would override
      // For simplicity, we'll say if there's any DENY rule, it blocks
      // (In reality, firewall rules are evaluated in order)
    }
  }

  // If no rules match, default is typically DENY (default policy)
  if (allRules.length === 0) {
    wouldBlock = true; // Default deny policy
  }

  res.json({
    sourceIp,
    sourcePort,
    destIp,
    destPort,
    protocol,
    sourceHost: sourceHost ? {
      id: sourceHost.id,
      hostname: sourceHost.hostname,
      mgmtIp: sourceHost.mgmt_ip
    } : null,
    destHost: destHost ? {
      id: destHost.id,
      hostname: destHost.hostname,
      mgmtIp: destHost.mgmt_ip
    } : null,
    wouldBlock,
    blockingRule,
    blockingRules,
    allowingRules,
    allRules
  });
});

// Firewall Audit Endpoints

const startAuditSchema = z.object({
  hosts: z.array(z.string().uuid()),
  durationMinutes: z.number().int().min(1).max(1440) // Max 24 hours
});

// Start audit session(s)
troubleshootRouter.post('/audit/start', requireRole('operator', 'admin'), async (req, res) => {
  const parsed = startAuditSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: 'invalid_body', message: parsed.error.message });
  }
  const { hosts: hostIds, durationMinutes } = parsed.data;

  // Get user ID
  const userRes = await pool.query(`SELECT id FROM users WHERE username=$1 LIMIT 1`, [req.auth!.username]);
  const userId = userRes.rows[0]?.id || null;

  // Get SSH credentials
  const credRes = await pool.query(
    `SELECT * FROM ssh_credentials WHERE scope_type='GLOBAL' ORDER BY created_at DESC LIMIT 1`
  );
  const cred = credRes.rows[0];
  if (!cred) {
    return res.status(400).json({ error: 'missing_ssh_credential', message: 'SSH credentials are required' });
  }

  const keyPem = (await readSecretPlaintext(cred.private_key_secret_id)).toString('utf8');

  // Get hosts
  const hostRes = await pool.query(
    `SELECT h.*, 
            (SELECT array_agg(json_build_object('name', hi.name, 'role', hi.role, 'enabled', hi.enabled))
             FROM host_interfaces hi WHERE hi.host_id = h.id) as interfaces
     FROM hosts h
     WHERE h.id = ANY($1::uuid[]) AND h.enabled = true`,
    [hostIds]
  );

  if (hostRes.rows.length === 0) {
    return res.status(400).json({ error: 'no_hosts_found', message: 'No enabled hosts found' });
  }

  const sessions = [];
  const scheduledRestoreAt = new Date(Date.now() + durationMinutes * 60 * 1000);

  // Get management VLAN CIDRs for baseline
  const mgmtVlanRes = await pool.query(
    `SELECT value FROM system_settings WHERE key='management_vlan_id'`
  );
  const mgmtVlanId = mgmtVlanRes.rows[0]?.value || null;
  const mgmtSshCidrs: string[] = [];
  if (mgmtVlanId) {
    const vlanRes = await pool.query(`SELECT subnet FROM vlans WHERE id=$1`, [mgmtVlanId]);
    if (vlanRes.rows[0]?.subnet) {
      mgmtSshCidrs.push(vlanRes.rows[0].subnet);
    }
  }

  for (const host of hostRes.rows) {
    const tempKeyPath = path.join(os.tmpdir(), `audit_key_${host.id}_${Date.now()}`);
    const logFilePath = `/var/log/segmentra-audit-${host.hostname}-${Date.now()}.log`;

    try {
      fs.writeFileSync(tempKeyPath, keyPem, { encoding: 'utf8', mode: 0o600 });

      const auditHost: AuditSshHost = {
        hostname: host.hostname,
        ip: String(host.mgmt_ip),
        port: host.ssh_port || 22,
        username: cred.username,
        privateKeyPath: tempKeyPath,
        backend: host.firewall_backend === 'iptables' ? 'iptables' : 'nftables'
      };

      // Start audit session (backup rules, configure logging)
      const startResult = await startAuditSession(auditHost, logFilePath);
      
      if (!startResult.success) {
        throw new Error(`Failed to start audit: ${startResult.stderr}`);
      }

      // Create empty policy rules for log-only mode (we want to log everything)
      const emptyRules: any[] = [];
      const policyInterfaceScope = { type: 'ALL_INTERFACES' as const };

      // Compile log-only policy
      const compiled = compileHostPolicy({
        host: {
          id: host.id,
          hostname: host.hostname,
          mgmtIp: host.mgmt_ip ? String(host.mgmt_ip) : null,
          firewallBackend: auditHost.backend,
          interfaces: (host.interfaces || []).map((i: any) => ({
            name: i.name,
            role: i.role,
            enabled: i.enabled
          }))
        },
        policyInterfaceScope,
        rules: emptyRules,
        sets: {},
        baseline: { mgmtSshCidrs },
        logOnlyMode: true
      });

      // Deploy log-only policy
      const policyFilePath = path.join(os.tmpdir(), `audit_policy_${host.id}_${Date.now()}.${compiled.backend === 'nftables' ? 'nft' : 'iptables'}`);
      const deployResult = await deployLogOnlyPolicy(auditHost, compiled.text, policyFilePath);

      if (!deployResult.success) {
        throw new Error(`Failed to deploy log-only policy: ${deployResult.stderr}`);
      }

      // Create database record
      const sessionRes = await pool.query(
        `INSERT INTO firewall_audit_sessions 
         (host_id, status, duration_minutes, started_at, scheduled_restore_at, backup_path, log_file_path, created_by)
         VALUES ($1, $2, $3, now(), $4, $5, $6, $7)
         RETURNING *`,
        [host.id, 'RUNNING', durationMinutes, scheduledRestoreAt, startResult.backupPath, logFilePath, userId]
      );

      sessions.push(sessionRes.rows[0]);

      // Clean up temp files
      if (fs.existsSync(tempKeyPath)) fs.unlinkSync(tempKeyPath);
      if (fs.existsSync(policyFilePath)) fs.unlinkSync(policyFilePath);

    } catch (error: any) {
      // Clean up temp files on error
      const tempKeyPath = path.join(os.tmpdir(), `audit_key_${host.id}_${Date.now()}`);
      if (fs.existsSync(tempKeyPath)) {
        try { fs.unlinkSync(tempKeyPath); } catch {}
      }

      return res.status(500).json({
        error: 'audit_start_failed',
        message: `Failed to start audit for ${host.hostname}: ${error.message}`
      });
    }
  }

  res.status(201).json({ sessions });
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
  const sessionRes = await pool.query(
    `SELECT fas.*, h.hostname, h.mgmt_ip, h.ssh_port, h.firewall_backend
     FROM firewall_audit_sessions fas
     JOIN hosts h ON h.id = fas.host_id
     WHERE fas.id = $1 AND fas.status = 'RUNNING'`,
    [req.params.id]
  );

  if (!sessionRes.rows[0]) {
    return res.status(404).json({ error: 'not_found', message: 'Session not found or not running' });
  }

  const session = sessionRes.rows[0];

  // Get SSH credentials
  const credRes = await pool.query(
    `SELECT * FROM ssh_credentials WHERE scope_type='GLOBAL' ORDER BY created_at DESC LIMIT 1`
  );
  const cred = credRes.rows[0];
  if (!cred) {
    return res.status(400).json({ error: 'missing_ssh_credential' });
  }

  const keyPem = (await readSecretPlaintext(cred.private_key_secret_id)).toString('utf8');
  const tempKeyPath = path.join(os.tmpdir(), `audit_restore_${session.id}_${Date.now()}`);

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

    // Restore original rules
    const restoreResult = await restoreAuditSession(auditHost, session.backup_path);

    if (!restoreResult.success) {
      throw new Error(`Restore failed: ${restoreResult.stderr}`);
    }

    // Retrieve and parse logs
    let logContent = '';
    if (session.log_file_path) {
      const localLogPath = path.join(os.tmpdir(), `audit_log_${session.id}_${Date.now()}.log`);
      const retrieveResult = await retrieveAuditLogs(auditHost, session.log_file_path, localLogPath);
      
      if (retrieveResult.success && fs.existsSync(localLogPath)) {
        logContent = fs.readFileSync(localLogPath, 'utf8');
        fs.unlinkSync(localLogPath);
      }
    }

    const parsedEntries = parseFirewallLogs(logContent);
    const flows = groupCommunicationFlows(parsedEntries);

    // Update session
    await pool.query(
      `UPDATE firewall_audit_sessions 
       SET status = 'COMPLETED', restored_at = now(), log_data = $1
       WHERE id = $2`,
      [JSON.stringify({ entries: parsedEntries, flows }), session.id]
    );

    res.json({ success: true, flows, entryCount: parsedEntries.length });

  } catch (error: any) {
    res.status(500).json({ error: 'restore_failed', message: error.message });
  } finally {
    if (fs.existsSync(tempKeyPath)) {
      try { fs.unlinkSync(tempKeyPath); } catch {}
    }
  }
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
  const sessionRes = await pool.query(
    `SELECT fas.*, h.hostname, h.mgmt_ip, h.ssh_port, h.firewall_backend
     FROM firewall_audit_sessions fas
     JOIN hosts h ON h.id = fas.host_id
     WHERE fas.id = $1 AND fas.status = 'RUNNING'`,
    [req.params.id]
  );

  if (!sessionRes.rows[0]) {
    return res.status(404).json({ error: 'not_found', message: 'Session not found or not running' });
  }

  const session = sessionRes.rows[0];

  // Get SSH credentials
  const credRes = await pool.query(
    `SELECT * FROM ssh_credentials WHERE scope_type='GLOBAL' ORDER BY created_at DESC LIMIT 1`
  );
  const cred = credRes.rows[0];
  if (!cred) {
    return res.status(400).json({ error: 'missing_ssh_credential' });
  }

  const keyPem = (await readSecretPlaintext(cred.private_key_secret_id)).toString('utf8');
  const tempKeyPath = path.join(os.tmpdir(), `audit_cancel_${session.id}_${Date.now()}`);

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

    // Restore original rules
    await restoreAuditSession(auditHost, session.backup_path);

    // Update session status
    await pool.query(
      `UPDATE firewall_audit_sessions SET status = 'CANCELLED' WHERE id = $1`,
      [session.id]
    );

    res.json({ success: true });

  } catch (error: any) {
    res.status(500).json({ error: 'cancel_failed', message: error.message });
  } finally {
    if (fs.existsSync(tempKeyPath)) {
      try { fs.unlinkSync(tempKeyPath); } catch {}
    }
  }
});

