import { Router } from 'express';
import { z } from 'zod';
import { LIVE_HASH_VERSION_PREFIX, checkHostPersistence, readHostFirewallRules, type SshHostInfo } from '@segmentra/executor';
import { pool } from '../db/pool.js';
import { requireAuth, requireRole } from '../middleware/auth.js';
import { getSshCredentialForHost, sshAuthFields, type MaterializedSshCredential } from '../services/ssh-credentials.js';

const complianceRouter = Router();
complianceRouter.use(requireAuth, requireRole('operator', 'admin'));

type ComplianceStatus = 'compliant' | 'drifted' | 'unknown' | 'error';

const NO_LIVE_BASELINE_MESSAGE = 'no live baseline recorded; redeploy to enable drift detection';
const OLD_BASELINE_MESSAGE = 'baseline recorded by an older version; redeploy to enable drift detection';

function sshHostInfo(host: any, cred: MaterializedSshCredential): SshHostInfo {
  return {
    hostname: host.hostname,
    ip: String(host.mgmt_ip).split('/')[0],
    port: Number(host.ssh_port) || 22,
    ...sshAuthFields(cred),
    backend: host.firewall_backend || 'auto'
  };
}

/**
 * Drift is detected by comparing the hash of Segmentra's own LIVE state read from the host
 * (nft: table inet segmentra; iptables: SEGMENTRA-IN/OUT chains + INPUT/OUTPUT jumps) with the
 * live hash recorded right after the last successful deployment (deployment_hosts.applied_live_hash,
 * same read + normalization as readHostFirewallRules().rulesHash). Rules of other tools (Docker,
 * Kubernetes, fail2ban) are not part of the hash. applied_hash is the hash of the compiled artifact
 * and is NOT comparable with a live read. Hashes recorded by older versions covered the whole
 * ruleset and lack the "v2:" prefix; they cannot be compared.
 */
function compareHashes(
  currentHash: string | undefined | null,
  lastDeployment: any,
  segmentraPresent?: boolean
): { status: ComplianceStatus; message?: string } {
  if (!lastDeployment) return { status: 'unknown', message: 'no successful deployment recorded for this host' };
  // The expiry REMOVE action deliberately stripped Segmentra's rules; a missing table/chain is expected.
  if (lastDeployment.expiry_status === 'REMOVED') {
    return { status: 'unknown', message: 'Segmentra policy was removed by the deployment expiry REMOVE action; host is currently unmanaged' };
  }
  const baseline = lastDeployment.applied_live_hash ? String(lastDeployment.applied_live_hash) : null;
  // Checked first: hosts deployed by older versions (legacy full-table iptables design) have no
  // SEGMENTRA chains at all, which must not be reported as drift.
  if (baseline && !baseline.startsWith(LIVE_HASH_VERSION_PREFIX)) return { status: 'unknown', message: OLD_BASELINE_MESSAGE };
  if (segmentraPresent === false) {
    return { status: 'drifted', message: 'Segmentra firewall table/chain or its INPUT/OUTPUT jump is missing on the host' };
  }
  if (!baseline) return { status: 'unknown', message: NO_LIVE_BASELINE_MESSAGE };
  if (!currentHash) return { status: 'error', message: 'could not compute live ruleset hash' };
  return currentHash === baseline
    ? { status: 'compliant' }
    : { status: 'drifted', message: 'live Segmentra rules differ from the last deployed ruleset' };
}

function lastDeploymentInfo(d: any) {
  return d
    ? {
        hash: d.applied_hash,
        liveHash: d.applied_live_hash ?? null,
        createdAt: d.created_at,
        policyVersion: d.version_number,
        policySetName: d.policy_set_name
      }
    : null;
}

/** Latest successful deployment per host (one query for any number of hosts). */
async function lastDeployments(hostIds: string[]): Promise<Map<string, any>> {
  const { rows } = await pool.query(
    `SELECT DISTINCT ON (dh.host_id)
            dh.host_id, dh.applied_hash, dh.applied_live_hash, dh.expiry_status, d.created_at, pv.version_number,
            ps.name AS policy_set_name
       FROM deployment_hosts dh
       JOIN deployments d ON d.id = dh.deployment_id
       JOIN policy_versions pv ON pv.id = d.policy_version_id
       JOIN policy_sets ps ON ps.id = pv.policy_set_id
      WHERE dh.host_id = ANY($1::uuid[]) AND dh.status = 'SUCCEEDED'
      ORDER BY dh.host_id, COALESCE(dh.finished_at, d.finished_at, d.created_at) DESC`,
    [hostIds]
  );
  return new Map(rows.map((r: any) => [r.host_id, r]));
}

async function checkHost(host: any, lastDeployment: any) {
  let cred: MaterializedSshCredential | null = null;
  try {
    if (!host.mgmt_ip) throw new Error('host has no management IP');
    cred = await getSshCredentialForHost(host.id);
    const readResult = await readHostFirewallRules(sshHostInfo(host, cred));
    if (!readResult.success) {
      return {
        hostId: host.id,
        hostname: host.hostname,
        status: 'error' as ComplianceStatus,
        error: readResult.error,
        currentHash: null,
        expectedHash: lastDeployment?.applied_live_hash ?? null,
        lastDeployment: lastDeploymentInfo(lastDeployment)
      };
    }
    const cmp = compareHashes(readResult.rulesHash, lastDeployment, readResult.segmentraPresent);
    // Reboot persistence: does the distribution's boot configuration hold the same Segmentra
    // state as the running rules? (read-only; does not change the compliance status)
    const p = await checkHostPersistence(sshHostInfo(host, cred), readResult.backend);
    const persistence = {
      status: p.status,
      state: p.state,
      method: p.method,
      warnings: p.warnings,
      error: p.error ?? null
    };
    if (cmp.status === 'compliant' && (p.state === 'differs' || p.state === 'missing')) {
      cmp.message = `running rules match the last deployment, but the boot configuration ${p.state === 'differs' ? 'differs from them' : 'does not contain them'} (they would not come back as deployed after a reboot)`;
    }
    return {
      persistence,
      hostId: host.id,
      hostname: host.hostname,
      status: cmp.status,
      message: cmp.message ?? null,
      currentHash: readResult.rulesHash,
      expectedHash: lastDeployment?.applied_live_hash ?? null,
      backend: readResult.backend,
      error: null,
      lastDeployment: lastDeploymentInfo(lastDeployment)
    };
  } catch (error: any) {
    const msg = error?.message ?? String(error);
    return {
      hostId: host.id,
      hostname: host.hostname,
      status: 'error' as ComplianceStatus,
      error: msg === 'missing_ssh_credential' ? 'No SSH credential configured for this host' : msg,
      currentHash: null,
      expectedHash: lastDeployment?.applied_live_hash ?? null,
      lastDeployment: lastDeploymentInfo(lastDeployment)
    };
  } finally {
    cred?.cleanup();
  }
}

/**
 * Check compliance status for a specific host
 * GET /compliance/hosts/:hostId
 */
complianceRouter.get('/hosts/:hostId', async (req, res) => {
  const hostId = req.params.hostId;

  const hostRes = await pool.query(
    `SELECT h.id, h.hostname, h.mgmt_ip, h.ssh_port, h.firewall_backend
     FROM hosts h
     WHERE h.id=$1 AND h.enabled=true`,
    [hostId]
  );
  if (!hostRes.rows[0]) {
    return res.status(404).json({ error: 'host_not_found' });
  }

  const deployments = await lastDeployments([hostId]);
  const result = await checkHost(hostRes.rows[0], deployments.get(hostId));
  return res.json(result);
});

/**
 * Check compliance for multiple hosts (bulk)
 * POST /compliance/hosts/bulk
 * Body: { hostIds: string[] }
 */
complianceRouter.post('/hosts/bulk', async (req, res) => {
  const parsed = z.object({ hostIds: z.array(z.string().uuid()).min(1).max(1000) }).safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: 'invalid_body', details: parsed.error.issues });
  }
  const { hostIds } = parsed.data;

  const hostsRes = await pool.query(
    `SELECT h.id, h.hostname, h.mgmt_ip, h.ssh_port, h.firewall_backend
     FROM hosts h
     WHERE h.id = ANY($1::uuid[]) AND h.enabled=true`,
    [hostIds]
  );

  const deployments = await lastDeployments(hostIds);
  const results = [];
  for (const host of hostsRes.rows) {
    results.push(await checkHost(host, deployments.get(host.id)));
  }

  return res.json({ results });
});

/** Live compliance check of one enabled host by id (used by compliance reports); null-safe for missing hosts. */
export async function checkHostCompliance(hostId: string): Promise<any> {
  const hostRes = await pool.query(
    `SELECT h.id, h.hostname, h.mgmt_ip, h.ssh_port, h.firewall_backend FROM hosts h WHERE h.id=$1 AND h.enabled=true`,
    [hostId]
  );
  if (!hostRes.rows[0]) return { hostId, hostname: hostId, status: 'error', error: 'host_not_found' };
  const deployments = await lastDeployments([hostId]);
  return checkHost(hostRes.rows[0], deployments.get(hostId));
}

export default complianceRouter;
