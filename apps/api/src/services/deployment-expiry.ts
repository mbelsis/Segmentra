import { acquireHostLock } from './host-lock.js';
import { removeSegmentraPolicy, type SshHostInfo } from '@segmentra/executor';
import { firewallBackend } from '@segmentra/compiler';

import { pool } from '../db/pool.js';
import { claimDeploymentForStart, runDeploymentInBackground } from '../routes/deployments.js';
import { createAuditEvent } from './audit.js';
import { sendNotification } from './notifications.js';
import { getSshCredentialForHost, sshAuthFields, type MaterializedSshCredential } from './ssh-credentials.js';

/**
 * Policy expiry processor (runs every minute from index.ts).
 *
 * Each expired deployment is claimed atomically (expired=false -> true) before anything is done,
 * so concurrent ticks / API instances never process one twice. The expiry action was authorised
 * when the original deployment was created/approved, so automatic actions run as "system"
 * (actor NULL in the audit log):
 *
 *  - NOTIFY_ONLY: mark EXPIRED + notify.
 *  - REMOVE:      remove Segmentra's nft table / iptables chains from every host that still runs
 *                 this deployment's policy; per-host result in deployment_hosts.expiry_*.
 *  - REVERT:      redeploy the previous successfully deployed version of the same policy set to
 *                 the hosts that ran it, as a new system-created deployment (no new approval, but
 *                 the version must still be APPROVED or DEPLOYED).
 *
 * The outcome is stored in deployments.expiry_outcome (jsonb).
 */

const DEPLOYABLE_VERSION_STATUSES = ['APPROVED', 'DEPLOYED'];

/**
 * Deployments whose rules may be on hosts and so must expire: SUCCEEDED/PARTIAL, and CANCELLED ones that got at least
 * one host deployed before the stop (their rules stay enforced otherwise). REMOVE/REVERT only act on SUCCEEDED hosts.
 */
const EXPIRABLE_SQL = (alias: string) =>
  `(${alias}.status IN ('SUCCEEDED', 'PARTIAL')
    OR (${alias}.status = 'CANCELLED'
        AND EXISTS (SELECT 1 FROM deployment_hosts edh WHERE edh.deployment_id = ${alias}.id AND edh.status = 'SUCCEEDED')))`;
const REMOVE_SSH_TIMEOUT_MS = 2 * 60 * 1000;
const MAX_PER_TICK = 20;

let tickRunning = false;

type ExpiryOutcome = {
  action: string;
  result: string;
  processedAt: string;
  message: string;
  revertDeploymentId?: string;
  revertToVersionId?: string;
  revertToVersionNumber?: number | null;
  revertSourceDeploymentId?: string;
  hostCounts?: Record<string, number>;
};

interface ExpiringHost {
  host_id: string;
  status: string;
  hostname: string;
  mgmt_ip: string | null;
  ssh_port: number | null;
  firewall_backend: string | null;
  superseded_by: string | null;
}

function truncate(msg: string, max = 500): string {
  const m = String(msg ?? '').trim();
  return m.length > max ? `${m.slice(0, max)}…` : m;
}

async function setHostExpiry(deploymentId: string, hostId: string, status: string, message: string) {
  await pool.query(
    `UPDATE deployment_hosts SET expiry_status=$3, expiry_message=$4, expiry_processed_at=now()
     WHERE deployment_id=$1 AND host_id=$2`,
    [deploymentId, hostId, status, truncate(message)]
  );
}

async function saveOutcome(deploymentId: string, outcome: ExpiryOutcome) {
  await pool.query(`UPDATE deployments SET expiry_outcome=$2::jsonb WHERE id=$1`, [deploymentId, JSON.stringify(outcome)]);
}

/** When a deployment's rules reached a host (deployment_hosts row `x`, deployments row `y`). */
const appliedAt = (x: string, y: string) => `COALESCE(${x}.finished_at, ${y}.finished_at, ${y}.created_at)`;

/**
 * Correlated subquery (needs `dh` = the expiring deployment's host row, `d` = its deployment): the newest other deployment
 * whose rules replaced it on that host. Ordered by when the rules were APPLIED, not when the deployment was created: an
 * older deployment that is started (scheduled, resumed, retried) after a newer one is what the host runs now.
 *   - succeeded on the host after `dh` was applied (also when its own deployment later failed partially or expired);
 *   - being applied right now;
 *   - queued in an active deployment created after this one (kept from before: it will land after these rules).
 */
const SUPERSEDING_SQL = `
  SELECT d2.id FROM deployment_hosts dh2
    JOIN deployments d2 ON d2.id = dh2.deployment_id
   WHERE dh2.host_id = dh.host_id AND dh2.deployment_id <> dh.deployment_id
     AND (
       (dh2.status = 'SUCCEEDED' AND ${appliedAt('dh2', 'd2')} > ${appliedAt('dh', 'd')})
       OR (dh2.status = 'RUNNING' AND d2.status IN ('RUNNING', 'PAUSED'))
       OR (dh2.status = 'PENDING' AND d2.status IN ('RUNNING', 'PAUSED') AND d2.created_at > d.created_at)
     )
   ORDER BY CASE WHEN dh2.status = 'SUCCEEDED' THEN ${appliedAt('dh2', 'd2')} ELSE now() END DESC
   LIMIT 1`;

/** Hosts of the deployment, with the newest other deployment that replaced its rules (if any). */
async function loadHosts(dep: any): Promise<ExpiringHost[]> {
  const { rows } = await pool.query(
    `SELECT dh.host_id, dh.status, h.hostname, h.mgmt_ip, h.ssh_port, h.firewall_backend,
            (${SUPERSEDING_SQL}) AS superseded_by
     FROM deployment_hosts dh
     JOIN deployments d ON d.id = dh.deployment_id
     JOIN hosts h ON h.id = dh.host_id
     WHERE dh.deployment_id = $1
     ORDER BY h.hostname ASC`,
    [dep.id]
  );
  return rows as ExpiringHost[];
}

async function notifyExpiry(dep: any, outcome: ExpiryOutcome, extra: Record<string, unknown> = {}) {
  const label = `${dep.policy_set_name} v${dep.version_number}`;
  const subjects: Record<string, string> = {
    NOTIFIED: `Policy expired: ${label}`,
    REMOVED: `Policy expired and removed from all hosts: ${label}`,
    REMOVE_PARTIAL: `Policy expired — removal FAILED on some hosts: ${label}`,
    REMOVE_FAILED: `Policy expired — automatic removal FAILED: ${label}`,
    NOTHING_TO_REMOVE: `Policy expired — no hosts needed removal: ${label}`,
    REVERT_STARTED: `Policy expired — reverting to v${outcome.revertToVersionNumber ?? '?'}: ${label}`,
    NO_PREVIOUS_VERSION: `Policy expired — no previous version to revert to: ${label}`,
    REVERT_NOT_DEPLOYABLE: `Policy expired — previous version is not deployable, revert skipped: ${label}`,
    REVERT_NOT_STARTED: `Policy expired — automatic revert could not start: ${label}`,
    NO_HOSTS: `Policy expired — no hosts still run this policy: ${label}`,
    ERROR: `Policy expired — automatic ${outcome.action} action failed: ${label}`,
  };
  await sendNotification({
    eventType: 'POLICY_EXPIRED',
    subject: subjects[outcome.result] ?? `Policy expired: ${label}`,
    body: {
      deploymentId: dep.id,
      policySetName: dep.policy_set_name,
      versionNumber: dep.version_number,
      expiryAction: outcome.action,
      expiredAt: dep.expires_at,
      result: outcome.result,
      message: outcome.message,
      ...(outcome.revertDeploymentId ? { revertDeploymentId: outcome.revertDeploymentId } : {}),
      ...(outcome.hostCounts ? { hostCounts: outcome.hostCounts } : {}),
      ...extra,
    },
  });
}

/** Id of the newest other deployment that replaced the rules of `dep` on the host, if any. */
async function findSupersedingDeployment(dep: any, hostId: string): Promise<string | null> {
  const { rows } = await pool.query(
    `SELECT (${SUPERSEDING_SQL}) AS id
       FROM deployment_hosts dh JOIN deployments d ON d.id = dh.deployment_id
      WHERE dh.deployment_id = $1 AND dh.host_id = $2`,
    [dep.id, hostId]
  );
  return rows[0]?.id ?? null;
}

async function handleRemove(dep: any, hosts: ExpiringHost[]): Promise<{ outcome: ExpiryOutcome; details: Record<string, unknown> }> {
  const counts = { removed: 0, failed: 0, skipped: 0 };
  const failures: string[] = [];

  for (const h of hosts) {
    if (h.status !== 'SUCCEEDED') {
      counts.skipped++;
      await setHostExpiry(dep.id, h.host_id, 'SKIPPED', `Policy was not applied to this host (host status ${h.status})`);
      continue;
    }
    if (h.superseded_by) {
      counts.skipped++;
      await setHostExpiry(dep.id, h.host_id, 'SKIPPED', `Rules were replaced by later deployment ${h.superseded_by}; not removed`);
      continue;
    }

    // Serialize with deployments and learning/test sessions on this host (see host-lock.ts), and look again for a
    // deployment that replaced these rules while we waited: removing the table would then remove the newer policy.
    // A lock timeout (another long deployment/session on the host) fails just this host: the deployment is already
    // marked EXPIRED, so aborting here would leave the remaining hosts unprocessed with no per-host record.
    let releaseHostLock: () => Promise<void>;
    try {
      releaseHostLock = await acquireHostLock(h.host_id);
    } catch (e: any) {
      const message = truncate(`Removal not attempted: ${e?.message ?? String(e)}`);
      counts.failed++;
      failures.push(`${h.hostname}: ${truncate(message, 200)}`);
      await setHostExpiry(dep.id, h.host_id, 'FAILED', message);
      await createAuditEvent({
        actorUserId: null,
        action: 'POLICY_EXPIRY_REMOVE_FAILED',
        entityType: 'DEPLOYMENT',
        entityId: dep.id,
        metadata: { automatic: true, hostId: h.host_id, hostname: h.hostname, policySetName: dep.policy_set_name, versionNumber: dep.version_number, exitCode: null, message },
      });
      continue;
    }
    try {
    const supersedingNow = await findSupersedingDeployment(dep, h.host_id);
    if (supersedingNow) {
      counts.skipped++;
      await setHostExpiry(dep.id, h.host_id, 'SKIPPED', `Rules were replaced by later deployment ${supersedingNow}; not removed`);
      continue;
    }

    let cred: MaterializedSshCredential | null = null;
    let success = false;
    let message: string;
    let exitCode: number | null = null;
    try {
      if (!h.mgmt_ip) throw new Error('host has no management IP');
      cred = await getSshCredentialForHost(h.host_id);
      const sshHost: SshHostInfo = {
        hostname: h.hostname,
        ip: String(h.mgmt_ip),
        port: Number(h.ssh_port) || 22,
        ...sshAuthFields(cred),
        backend: h.firewall_backend && h.firewall_backend !== 'auto' ? firewallBackend(h.firewall_backend) : 'auto',
      };
      const r = await removeSegmentraPolicy(sshHost, { timeoutMs: REMOVE_SSH_TIMEOUT_MS });
      success = r.success;
      exitCode = r.exitCode;
      const lastErr = String(r.stderr || '').trim().split('\n').filter(Boolean).pop() ?? '';
      message = r.success ? 'Segmentra rules removed' : `Removal failed (exit ${r.exitCode})${lastErr ? `: ${lastErr}` : ''}`;
      if (r.success && r.persistence && r.persistence.status !== 'unknown') {
        // Segmentra's part of the distribution's boot configuration is removed as well.
        const pw = [...r.persistence.warnings.filter((w) => !w.startsWith('unsupported_distro'))];
        if (r.persistence.status === 'removed') message += ' (also removed from the boot configuration)';
        else if (pw.length) message += ` (boot configuration: ${pw.join('; ')})`;
        await pool.query(
          `UPDATE deployment_hosts SET persistence_status='removed', persistence_message=$3
           WHERE deployment_id=$1 AND host_id=$2`,
          [dep.id, h.host_id, truncate(`Removed by the expiry REMOVE action; the rules do not come back after a reboot`, 2000)]
        );
      }
    } catch (e: any) {
      message = `Removal failed: ${e?.message ?? String(e)}`;
    } finally {
      cred?.cleanup();
    }

    if (success) counts.removed++;
    else {
      counts.failed++;
      failures.push(`${h.hostname}: ${truncate(message, 200)}`);
    }
    await setHostExpiry(dep.id, h.host_id, success ? 'REMOVED' : 'FAILED', message);
    await createAuditEvent({
      actorUserId: null,
      action: success ? 'POLICY_EXPIRY_RULES_REMOVED' : 'POLICY_EXPIRY_REMOVE_FAILED',
      entityType: 'DEPLOYMENT',
      entityId: dep.id,
      metadata: {
        automatic: true,
        hostId: h.host_id,
        hostname: h.hostname,
        policySetName: dep.policy_set_name,
        versionNumber: dep.version_number,
        exitCode,
        message: truncate(message),
      },
    });
    } finally {
      await releaseHostLock();
    }
  }

  const attempted = counts.removed + counts.failed;
  const result = attempted === 0 ? 'NOTHING_TO_REMOVE'
    : counts.failed === 0 ? 'REMOVED'
    : counts.removed === 0 ? 'REMOVE_FAILED'
    : 'REMOVE_PARTIAL';
  const message = attempted === 0
    ? 'No host still ran this policy; nothing was removed.'
    : `Removed Segmentra rules from ${counts.removed}/${attempted} host(s)${counts.skipped ? `, ${counts.skipped} skipped` : ''}.` +
      (counts.failed ? ' Hosts where removal failed still enforce the expired policy and need manual cleanup.' : '');
  return {
    outcome: { action: 'REMOVE', result, processedAt: new Date().toISOString(), message, hostCounts: { total: hosts.length, ...counts } },
    details: failures.length ? { failures } : {},
  };
}

async function handleRevert(dep: any, hosts: ExpiringHost[]): Promise<{ outcome: ExpiryOutcome; details: Record<string, unknown> }> {
  const now = () => new Date().toISOString();
  const candidates = hosts.filter((h) => h.status === 'SUCCEEDED' && !h.superseded_by);
  for (const h of hosts) {
    if (h.status !== 'SUCCEEDED') {
      await setHostExpiry(dep.id, h.host_id, 'SKIPPED', `Policy was not applied to this host (host status ${h.status})`);
    } else if (h.superseded_by) {
      await setHostExpiry(dep.id, h.host_id, 'SKIPPED', `Rules were replaced by later deployment ${h.superseded_by}; not reverted`);
    }
  }
  if (candidates.length === 0) {
    return { outcome: { action: 'REVERT', result: 'NO_HOSTS', processedAt: now(), message: 'No host still runs this policy; nothing to revert.' }, details: {} };
  }

  // Most recent earlier deployment of the same policy set, of a different version, that
  // succeeded on at least one of these hosts.
  const candidateIds = candidates.map((h) => h.host_id);
  const prevRes = await pool.query(
    // "Earlier" = its rules reached one of these hosts before the expiring deployment's rules did (applied time, not
    // creation time: see SUPERSEDING_SQL).
    `SELECT d.id, d.policy_version_id, pv.version_number, pv.status AS version_status,
            MAX(${appliedAt('dhp', 'd')}) AS applied_at
     FROM deployments d
     JOIN policy_versions pv ON pv.id = d.policy_version_id
     JOIN deployment_hosts dhp ON dhp.deployment_id = d.id AND dhp.status = 'SUCCEEDED' AND dhp.host_id = ANY($4::uuid[])
     JOIN deployment_hosts dhe ON dhe.deployment_id = $2 AND dhe.host_id = dhp.host_id
     JOIN deployments de ON de.id = dhe.deployment_id
     WHERE pv.policy_set_id = $1
       AND d.id <> $2
       AND d.policy_version_id <> $3
       AND d.status IN ('SUCCEEDED', 'PARTIAL')
       AND ${appliedAt('dhp', 'd')} < ${appliedAt('dhe', 'de')}
     GROUP BY d.id, d.policy_version_id, pv.version_number, pv.status
     ORDER BY applied_at DESC
     LIMIT 1`,
    [dep.policy_set_id, dep.id, dep.policy_version_id, candidateIds]
  );
  const prev = prevRes.rows[0];
  if (!prev) {
    for (const h of candidates) await setHostExpiry(dep.id, h.host_id, 'SKIPPED', 'No previous version to revert to; expired policy is still enforced');
    return {
      outcome: {
        action: 'REVERT', result: 'NO_PREVIOUS_VERSION', processedAt: now(),
        message: 'No previous version to revert to. The expired policy is still enforced on its hosts; deploy or remove a policy manually.',
      },
      details: {},
    };
  }
  if (!DEPLOYABLE_VERSION_STATUSES.includes(prev.version_status)) {
    for (const h of candidates) await setHostExpiry(dep.id, h.host_id, 'SKIPPED', `Previous version v${prev.version_number} is ${prev.version_status}; not reverted`);
    return {
      outcome: {
        action: 'REVERT', result: 'REVERT_NOT_DEPLOYABLE', processedAt: now(),
        revertToVersionId: prev.policy_version_id, revertToVersionNumber: prev.version_number, revertSourceDeploymentId: prev.id,
        message: `Previous version v${prev.version_number} is ${prev.version_status} (must be APPROVED or DEPLOYED); revert skipped. The expired policy is still enforced.`,
      },
      details: {},
    };
  }

  // Only hosts that actually ran the previous version get it back.
  const prevHostsRes = await pool.query(
    `SELECT host_id FROM deployment_hosts WHERE deployment_id=$1 AND status='SUCCEEDED' AND host_id = ANY($2::uuid[])`,
    [prev.id, candidateIds]
  );
  const revertHostIds = new Set<string>(prevHostsRes.rows.map((r: any) => r.host_id));
  const revertHosts = candidates.filter((h) => revertHostIds.has(h.host_id));
  const notCovered = candidates.filter((h) => !revertHostIds.has(h.host_id));

  const notes = `Automatic revert: deployment ${dep.id} expired`;
  const client = await pool.connect();
  let revertDep: any;
  try {
    await client.query('BEGIN');
    const ins = await client.query(
      `INSERT INTO deployments (policy_version_id, mode, target_query, target_count, created_by, status,
                                requires_approval, notes, revert_of_deployment_id, expiry_action)
       VALUES ($1, 'FULL', $2, $3, $4, 'QUEUED', false, $5, $6, 'NOTIFY_ONLY')
       RETURNING *`,
      [prev.policy_version_id, { tags: [], vlans: [], hosts: revertHosts.map((h) => h.host_id) }, revertHosts.length, dep.created_by ?? null, notes, dep.id]
    );
    revertDep = ins.rows[0];
    await client.query(
      `INSERT INTO deployment_hosts (deployment_id, host_id) SELECT $1, unnest($2::uuid[]) ON CONFLICT DO NOTHING`,
      [revertDep.id, revertHosts.map((h) => h.host_id)]
    );
    await client.query(
      `UPDATE deployment_hosts SET expiry_status='REVERT_QUEUED', expiry_message=$3, expiry_processed_at=now()
       WHERE deployment_id=$1 AND host_id = ANY($2::uuid[])`,
      [dep.id, revertHosts.map((h) => h.host_id), `Reverting to v${prev.version_number} via deployment ${revertDep.id}`]
    );
    if (notCovered.length) {
      await client.query(
        `UPDATE deployment_hosts SET expiry_status='SKIPPED', expiry_message=$3, expiry_processed_at=now()
         WHERE deployment_id=$1 AND host_id = ANY($2::uuid[])`,
        [dep.id, notCovered.map((h) => h.host_id), `v${prev.version_number} was never deployed to this host; expired policy is still enforced`]
      );
    }
    await client.query('COMMIT');
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    throw e;
  } finally {
    client.release();
  }

  await createAuditEvent({
    actorUserId: null,
    action: 'DEPLOYMENT_CREATED',
    entityType: 'DEPLOYMENT',
    entityId: revertDep.id,
    metadata: {
      automatic: true,
      reason: notes,
      revertOfDeploymentId: dep.id,
      policySetName: dep.policy_set_name,
      policyVersionNumber: prev.version_number,
      deploymentMode: 'FULL',
      targetType: 'Hosts',
      targetHosts: revertHosts.map((h) => h.hostname),
      targetCount: revertHosts.length,
      onBehalfOfUserId: dep.created_by ?? null,
    },
  });

  // Pre-authorised by the original deployment: start without a new approval.
  const claimed = await claimDeploymentForStart(revertDep.id, ['QUEUED']);
  if (!claimed) {
    return {
      outcome: {
        action: 'REVERT', result: 'REVERT_NOT_STARTED', processedAt: now(),
        revertDeploymentId: revertDep.id, revertToVersionId: prev.policy_version_id, revertToVersionNumber: prev.version_number, revertSourceDeploymentId: prev.id,
        message: `Revert deployment ${revertDep.id} was created but could not be started automatically; start it manually.`,
      },
      details: {},
    };
  }
  runDeploymentInBackground(revertDep.id, undefined, '[Policy Expiry Revert]');

  return {
    outcome: {
      action: 'REVERT', result: 'REVERT_STARTED', processedAt: now(),
      revertDeploymentId: revertDep.id, revertToVersionId: prev.policy_version_id, revertToVersionNumber: prev.version_number, revertSourceDeploymentId: prev.id,
      hostCounts: { total: hosts.length, reverting: revertHosts.length, skipped: hosts.length - revertHosts.length },
      message: `Redeploying v${prev.version_number} to ${revertHosts.length} host(s) via deployment ${revertDep.id}.` +
        (notCovered.length ? ` ${notCovered.length} host(s) never ran v${prev.version_number} and keep the expired policy.` : ''),
    },
    details: notCovered.length ? { hostsWithoutPreviousVersion: notCovered.map((h) => h.hostname) } : {},
  };
}

/** Claim + process one expired deployment. Returns false if someone else claimed it first. */
export async function processExpiredDeployment(deploymentId: string): Promise<boolean> {
  const claim = await pool.query(
    `UPDATE deployments SET expired=true, status='EXPIRED'
     WHERE id=$1 AND expired=false AND ${EXPIRABLE_SQL('deployments')}
       AND expires_at IS NOT NULL AND expires_at <= now()
     RETURNING id`,
    [deploymentId]
  );
  if (!claim.rows[0]) return false;

  const { rows } = await pool.query(
    `SELECT d.*, pv.version_number, pv.policy_set_id, ps.name AS policy_set_name
     FROM deployments d
     JOIN policy_versions pv ON pv.id = d.policy_version_id
     JOIN policy_sets ps ON ps.id = pv.policy_set_id
     WHERE d.id=$1`,
    [deploymentId]
  );
  const dep = rows[0];
  const action: string = dep?.expiry_action || 'NOTIFY_ONLY';

  let outcome: ExpiryOutcome;
  let details: Record<string, unknown> = {};
  try {
    if (action === 'REMOVE' || action === 'REVERT') {
      const hosts = await loadHosts(dep);
      ({ outcome, details } = action === 'REMOVE' ? await handleRemove(dep, hosts) : await handleRevert(dep, hosts));
    } else {
      outcome = { action, result: 'NOTIFIED', processedAt: new Date().toISOString(), message: 'Deployment expired. The policy is still enforced on its hosts (notify-only).' };
    }
  } catch (e: any) {
    outcome = { action, result: 'ERROR', processedAt: new Date().toISOString(), message: truncate(`Automatic ${action} failed: ${e?.message ?? String(e)}`) };
    // eslint-disable-next-line no-console
    console.error(`[Policy Expiry] ${action} for deployment ${deploymentId} failed:`, e);
  }

  await saveOutcome(deploymentId, outcome);
  await createAuditEvent({
    actorUserId: null,
    action: 'POLICY_EXPIRED',
    entityType: 'DEPLOYMENT',
    entityId: deploymentId,
    metadata: {
      automatic: true,
      policySetName: dep?.policy_set_name,
      versionNumber: dep?.version_number,
      expiryAction: action,
      result: outcome.result,
      message: outcome.message,
      ...(outcome.revertDeploymentId ? { revertDeploymentId: outcome.revertDeploymentId } : {}),
      ...(outcome.hostCounts ? { hostCounts: outcome.hostCounts } : {}),
    },
  });
  await notifyExpiry(dep, outcome, details);
  // eslint-disable-next-line no-console
  console.log(`[Policy Expiry] Deployment ${deploymentId} (${dep?.policy_set_name} v${dep?.version_number}) expired: ${action} -> ${outcome.result}`);
  return true;
}

/** Send "expiring soon" warnings (24 hours before expiry), at most once per 24h per deployment. */
async function sendExpiringSoonWarnings() {
  const { rows: expiringSoon } = await pool.query(
    `SELECT d.id, d.expires_at, d.expiry_action, pv.version_number, ps.name as policy_set_name
     FROM deployments d
     JOIN policy_versions pv ON pv.id = d.policy_version_id
     JOIN policy_sets ps ON ps.id = pv.policy_set_id
     WHERE d.expires_at IS NOT NULL
       AND d.expires_at > now()
       AND d.expires_at <= now() + interval '24 hours'
       AND d.expired = false
       AND ${EXPIRABLE_SQL('d')}
       AND NOT EXISTS (
         SELECT 1 FROM notification_log nl
         WHERE nl.event_type = 'POLICY_EXPIRING_SOON'
           AND nl.payload::text LIKE '%' || d.id::text || '%'
           AND nl.created_at > now() - interval '24 hours'
       )`
  );

  for (const dep of expiringSoon) {
    const hoursLeft = Math.round((new Date(dep.expires_at).getTime() - Date.now()) / 3600000);
    await sendNotification({
      eventType: 'POLICY_EXPIRING_SOON',
      subject: `Policy expiring ${hoursLeft < 1 ? 'in under an hour' : `in ${hoursLeft}h`}: ${dep.policy_set_name} v${dep.version_number}`,
      body: {
        deploymentId: dep.id,
        policySetName: dep.policy_set_name,
        versionNumber: dep.version_number,
        expiresAt: dep.expires_at,
        expiryAction: dep.expiry_action,
        hoursRemaining: hoursLeft,
      },
    });
  }
}

/** One tick of the expiry job. Errors in one deployment never stop the others. */
export async function processExpiredDeployments(): Promise<number> {
  if (tickRunning) return 0; // a slow REMOVE run is still going; the claim makes overlap safe anyway
  tickRunning = true;
  let processed = 0;
  try {
    const { rows } = await pool.query(
      `SELECT id FROM deployments
       WHERE expires_at IS NOT NULL AND expires_at <= now() AND expired = false
         AND ${EXPIRABLE_SQL('deployments')}
       ORDER BY expires_at ASC
       LIMIT ${MAX_PER_TICK}`
    );
    for (const row of rows) {
      try {
        if (await processExpiredDeployment(row.id)) processed++;
      } catch (e) {
        // eslint-disable-next-line no-console
        console.error(`[Policy Expiry] Error processing deployment ${row.id}:`, e);
      }
    }
    try {
      await sendExpiringSoonWarnings();
    } catch (e) {
      // eslint-disable-next-line no-console
      console.error('[Policy Expiry] Error sending expiring-soon warnings:', e);
    }
  } finally {
    tickRunning = false;
  }
  return processed;
}
