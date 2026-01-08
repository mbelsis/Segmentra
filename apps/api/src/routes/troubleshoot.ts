import { Router } from 'express';
import { z } from 'zod';
import { pool } from '../db/pool.js';
import { requireAuth, requireRole } from '../middleware/auth.js';

export const troubleshootRouter = Router();
troubleshootRouter.use(requireAuth, requireRole('operator', 'admin', 'viewer'));

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

