import { randomUUID } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { firewallBackend } from '@segmentra/compiler';

import { restoreAuditSession, retrieveAuditLogs, type AuditSshHost } from '@segmentra/executor';

import { HOST_LOCK_TIMEOUT_MS, acquireHostLock, deploymentSucceededSince, tryAcquireHostLock, type HostLockRelease } from './host-lock.js';
import { pool } from '../db/pool.js';
import { groupCommunicationFlows, parseFirewallLogs } from './log-parser.js';
import { sendNotification } from './notifications.js';
import { getSshCredentialForHost, sshAuthFields, type MaterializedSshCredential } from './ssh-credentials.js';

/**
 * Firewall audit session lifecycle (firewall_audit_sessions.status has no CHECK constraint):
 *   PENDING   – row created, host not yet switched to log-only mode
 *   RUNNING   – log-only policy active; the scheduler restores it at scheduled_restore_at.
 *               A failed restore keeps the session RUNNING and pushes scheduled_restore_at
 *               out with exponential backoff; attempt bookkeeping lives in log_data.restore.
 *   COMPLETED / CANCELLED – original rules restored
 *   FAILED    – audit never changed the host (no backup taken) or could not be started
 *
 * Restores are claimed with a lease (restore_lease_token / restore_lease_until, migration 041) so the scheduler does
 * not queue the same session again while a run is waiting for the host lock or restoring, and then re-checked under
 * the host lock: a run proceeds only if the session is still PENDING/RUNNING and its lease token is still the one it
 * claimed. Every restore holds the host lock until its final status write, so two runs can never overlap.
 */

const envMs = (name: string, def: number, min: number) => {
  const n = Number(process.env[name]);
  return Number.isFinite(n) && n >= min ? Math.floor(n) : def;
};
const SSH_COMMAND_TIMEOUT_MS = envMs('SEGMENTRA_SSH_COMMAND_TIMEOUT_MS', 5 * 60 * 1000, 1000);

/**
 * Restore lease: longer than the longest wait for the host lock plus the restore itself (credential lookup, restore,
 * log retrieval with its kernel-log fallbacks: a few SSH commands, each bounded by the SSH command timeout) plus a
 * margin, so a lease never runs out while its run is still legitimately in progress.
 */
export function auditRestoreLeaseMs(lockTimeoutMs = HOST_LOCK_TIMEOUT_MS, sshCommandTimeoutMs = SSH_COMMAND_TIMEOUT_MS): number {
  return lockTimeoutMs + 4 * sshCommandTimeoutMs + 5 * 60 * 1000;
}
const LEASE_MS = auditRestoreLeaseMs();
const MAX_BACKOFF_MINUTES = 60;
const NOTIFY_AFTER_ATTEMPTS = 3;
const STALE_PENDING_MINUTES = 15;

export type RestoreOutcome =
  | { success: true; flows: unknown[]; entryCount: number }
  | { success: false; error: string; attempts: number; nextAttemptAt: string | null };

export function buildAuditHost(
  host: { hostname: string; mgmt_ip: unknown; ssh_port?: number | null; firewall_backend?: string | null },
  cred: MaterializedSshCredential
): AuditSshHost {
  const ip = host.mgmt_ip ? String(host.mgmt_ip).split('/')[0] : '';
  if (!ip) throw new Error(`host ${host.hostname} has no management IP`);
  return {
    hostname: host.hostname,
    ip,
    port: Number(host.ssh_port) || 22,
    ...sshAuthFields(cred),
    backend: firewallBackend(host.firewall_backend)
  };
}

function restoreState(session: any): { attempts: number } {
  const ld = typeof session.log_data === 'string' ? safeJson(session.log_data) : session.log_data;
  return { attempts: Number(ld?.restore?.attempts ?? 0) };
}

function safeJson(s: string): any {
  try {
    return JSON.parse(s);
  } catch {
    return null;
  }
}

/**
 * Record a failed restore: session stays RUNNING, next attempt is scheduled with exponential
 * backoff, and a notification is sent once the failure repeats.
 */
async function recordRestoreFailure(session: any, error: string, leaseToken: string | null): Promise<{ attempts: number; nextAttemptAt: string }> {
  const attempts = restoreState(session).attempts + 1;
  const backoffMinutes = Math.min(2 ** Math.min(attempts, 6), MAX_BACKOFF_MINUTES);
  const nextAttemptAt = new Date(Date.now() + backoffMinutes * 60_000);

  await pool.query(
    `UPDATE firewall_audit_sessions
        SET status = 'RUNNING',
            scheduled_restore_at = $2,
            log_data = COALESCE(log_data, '{}'::jsonb) || jsonb_build_object('restore', $3::jsonb),
            restore_lease_until = CASE WHEN restore_lease_token = $4 THEN NULL ELSE restore_lease_until END,
            restore_lease_token = CASE WHEN restore_lease_token = $4 THEN NULL ELSE restore_lease_token END
      WHERE id = $1 AND status IN ('PENDING', 'RUNNING')`,
    [
      session.id,
      nextAttemptAt,
      JSON.stringify({
        attempts,
        lastError: error.slice(0, 2000),
        lastAttemptAt: new Date().toISOString(),
        nextAttemptAt: nextAttemptAt.toISOString()
      }),
      leaseToken
    ]
  );

  // eslint-disable-next-line no-console
  console.error(
    `[Audit] Restore of session ${session.id} (${session.hostname}) failed (attempt ${attempts}); retrying at ${nextAttemptAt.toISOString()}: ${error}`
  );

  if (attempts === NOTIFY_AFTER_ATTEMPTS || (attempts > NOTIFY_AFTER_ATTEMPTS && attempts % 10 === 0)) {
    void sendNotification({
      eventType: 'AUDIT_RESTORE_FAILED',
      subject: `Firewall audit restore failing on ${session.hostname} (${attempts} attempts)`,
      body: {
        host: session.hostname,
        sessionId: session.id,
        attempts,
        lastError: error.slice(0, 500),
        nextAttemptAt: nextAttemptAt.toISOString(),
        impact: 'Host is still running the log-only (allow-all) audit policy'
      }
    }).catch((e) => {
      // eslint-disable-next-line no-console
      console.error('[Audit] Failed to send restore-failure notification:', e);
    });
  }

  return { attempts, nextAttemptAt: nextAttemptAt.toISOString() };
}

/**
 * Claim a session for restoring: sets a fresh lease token. The scheduler (onlyIfDue) only claims a due session whose
 * lease is free; an explicit API call (restore/cancel, failed start) takes the lease over, and an earlier claimer that
 * is still waiting for the host lock then backs off when it sees the token changed. Returns the claimed row or null.
 */
async function claimSession(sessionId: string, opts: { onlyIfDue: boolean }): Promise<{ row: any; token: string } | null> {
  const token = randomUUID();
  const { rows } = await pool.query(
    `UPDATE firewall_audit_sessions fas
        SET restore_lease_token = $2,
            restore_lease_until = now() + ($3::bigint * interval '1 millisecond')
       FROM hosts h
      WHERE fas.id = $1
        AND h.id = fas.host_id
        AND (fas.status = 'RUNNING' OR (fas.status = 'PENDING' AND fas.backup_path IS NOT NULL))
        AND (
          $4::boolean = false
          OR (
            (fas.restore_lease_until IS NULL OR fas.restore_lease_until <= now())
            AND (
              (fas.status = 'RUNNING' AND fas.scheduled_restore_at <= now())
              OR (fas.status = 'PENDING' AND fas.started_at < now() - ($5::int * interval '1 minute'))
            )
          )
        )
      RETURNING fas.*, h.hostname, h.mgmt_ip, h.ssh_port, h.firewall_backend`,
    [sessionId, token, LEASE_MS, opts.onlyIfDue, STALE_PENDING_MINUTES]
  );
  return rows[0] ? { row: rows[0], token } : null;
}

/** Give up a lease without changing anything else (only if it is still ours). */
async function releaseLease(sessionId: string, token: string): Promise<void> {
  await pool.query(
    `UPDATE firewall_audit_sessions SET restore_lease_token = NULL, restore_lease_until = NULL
      WHERE id = $1 AND restore_lease_token = $2`,
    [sessionId, token]
  );
}

const entryCount = (logData: any): number => {
  const ld = typeof logData === 'string' ? safeJson(logData) : logData;
  return Array.isArray(ld?.entries) ? ld.entries.length : 0;
};

/**
 * The log_data written when a restore succeeds. Logs already stored with more entries than this run collected (an
 * earlier collection, or a run whose retrieval came back short) are kept rather than replaced by fewer.
 */
export function finalAuditLogData(
  existing: any,
  collected: { entries: unknown[]; flows: unknown[] },
  extra: Record<string, unknown> = {}
): Record<string, unknown> {
  const prev = typeof existing === 'string' ? safeJson(existing) : existing;
  const keepPrevious = entryCount(prev) > collected.entries.length;
  return {
    entries: keepPrevious ? prev.entries : collected.entries,
    flows: keepPrevious ? (Array.isArray(prev.flows) ? prev.flows : []) : collected.flows,
    ...extra
  };
}

/**
 * Restore the original firewall rules of an audit session and (optionally) collect its logs.
 * Never throws for SSH/restore failures: those are recorded and retried by the scheduler.
 * Returns null when the session is not (or no longer) restorable by this call: not found, not due, already restored,
 * claimed by another run, or (lockMode 'try') its host lock is taken.
 */
export async function restoreAuditSessionById(
  sessionId: string,
  opts: { finalStatus: 'COMPLETED' | 'CANCELLED'; collectLogs: boolean; onlyIfDue?: boolean; hostLockHeld?: boolean; lockMode?: 'wait' | 'try' }
): Promise<RestoreOutcome | null> {
  const claim = await claimSession(sessionId, { onlyIfDue: opts.onlyIfDue ?? false });
  if (!claim) return null;
  const { token } = claim;
  let session = claim.row;

  // Firewall changes on one host are serialized with deployments and other sessions (see host-lock.ts).
  let releaseHostLock: HostLockRelease;
  if (opts.hostLockHeld) {
    releaseHostLock = async () => {};
  } else if (opts.lockMode === 'try') {
    const r = await tryAcquireHostLock(session.host_id);
    if (!r) {
      await releaseLease(session.id, token);
      return null;
    }
    releaseHostLock = r;
  } else {
    try {
      releaseHostLock = await acquireHostLock(session.host_id);
    } catch (e: any) {
      const error = e?.message ?? String(e);
      const f = await recordRestoreFailure(session, error, token);
      return { success: false, error, ...f };
    }
  }
  let cred: MaterializedSshCredential | null = null;
  try {
    // Re-check under the host lock: another run may have restored it (or taken the claim over) while we waited.
    const fresh = await pool.query(
      `SELECT fas.*, h.hostname, h.mgmt_ip, h.ssh_port, h.firewall_backend
         FROM firewall_audit_sessions fas JOIN hosts h ON h.id = fas.host_id
        WHERE fas.id = $1 AND fas.restore_lease_token = $2
          AND (fas.status = 'RUNNING' OR (fas.status = 'PENDING' AND fas.backup_path IS NOT NULL))`,
      [session.id, token]
    );
    if (!fresh.rows[0]) return null;
    session = fresh.rows[0];

    cred = await getSshCredentialForHost(session.host_id);
    const host = buildAuditHost(session, cred);

    // The backup is the state from before this session started. If a deployment succeeded on the host since,
    // that deployment already replaced the log-only rules; putting the backup back would silently undo it.
    const replacedByDeployment = await deploymentSucceededSince(session.host_id, session.started_at);
    if (!replacedByDeployment) {
      const restoreResult = await restoreAuditSession(host, session.backup_path);
      if (!restoreResult.success) {
        const error = (restoreResult.stderr || restoreResult.stdout || 'restore failed').trim();
        const f = await recordRestoreFailure(session, error, token);
        return { success: false, error, ...f };
      }
    }

    let logContent = '';
    if (opts.collectLogs && session.log_file_path) {
      const localLogPath = path.join(os.tmpdir(), `audit_log_${session.id}_${Date.now()}.log`);
      try {
        const retrieveResult = await retrieveAuditLogs(host, session.log_file_path, localLogPath);
        if (retrieveResult.success && fs.existsSync(localLogPath)) {
          logContent = fs.readFileSync(localLogPath, 'utf8');
        }
      } catch (e: any) {
        // Rules are restored; log retrieval failure must not undo that.
        // eslint-disable-next-line no-console
        console.error(`[Audit] Could not retrieve logs for session ${session.id}:`, e?.message);
      } finally {
        try {
          if (fs.existsSync(localLogPath)) fs.unlinkSync(localLogPath);
        } catch {
          // ignore
        }
      }
    }

    const parsedEntries = parseFirewallLogs(logContent);
    const flows = groupCommunicationFlows(parsedEntries);
    const prev = restoreState(session);
    const logData = finalAuditLogData(session.log_data, { entries: parsedEntries, flows }, {
      ...(replacedByDeployment ? { restoreSkipped: 'A deployment succeeded on this host after the session started and replaced the audit rules; the original rules were not restored over it.' } : {}),
      ...(prev.attempts > 0 ? { restore: { attempts: prev.attempts + 1, succeededAt: new Date().toISOString() } } : {})
    });

    // Still under the host lock and conditional on the claim: a session another run finished is never written again.
    const written = await pool.query(
      `UPDATE firewall_audit_sessions
          SET status = $3, restored_at = now(), log_data = $1, restore_lease_token = NULL, restore_lease_until = NULL
        WHERE id = $2 AND status IN ('PENDING', 'RUNNING')
        RETURNING id`,
      [JSON.stringify(logData), session.id, opts.finalStatus]
    );
    if (!written.rows[0]) return null;

    const storedFlows = logData.flows as unknown[];
    return { success: true, flows: storedFlows, entryCount: (logData.entries as unknown[]).length };
  } catch (e: any) {
    const error = e?.message ?? String(e);
    const f = await recordRestoreFailure(session, error, token);
    return { success: false, error, ...f };
  } finally {
    cred?.cleanup();
    await releaseHostLock();
  }
}

/**
 * Check for expired audit sessions and restore them.
 * Called periodically (every minute). Failed restores are retried with backoff.
 */
let auditTickRunning = false;

export async function processExpiredAuditSessions(): Promise<void> {
  // A pass can take longer than the 1-minute interval (several hosts, slow SSH): never run two at once.
  if (auditTickRunning) return;
  auditTickRunning = true;
  try {
    await processExpiredAuditSessionsOnce();
  } finally {
    auditTickRunning = false;
  }
}

async function processExpiredAuditSessionsOnce(): Promise<void> {
  // Sessions that never got a backup and were abandoned mid-start changed nothing: mark FAILED.
  await pool.query(
    `UPDATE firewall_audit_sessions
        SET status = 'FAILED',
            log_data = COALESCE(log_data, '{}'::jsonb) || '{"error":"audit start did not complete"}'::jsonb
      WHERE status = 'PENDING' AND backup_path IS NULL
        AND started_at < now() - ($1::int * interval '1 minute')`,
    [STALE_PENDING_MINUTES]
  );

  const { rows } = await pool.query(
    `SELECT id FROM firewall_audit_sessions
      WHERE ((status = 'RUNNING' AND scheduled_restore_at <= now())
             OR (status = 'PENDING' AND backup_path IS NOT NULL
                 AND started_at < now() - ($1::int * interval '1 minute')))
        AND (restore_lease_until IS NULL OR restore_lease_until <= now())
      ORDER BY scheduled_restore_at ASC`,
    [STALE_PENDING_MINUTES]
  );

  for (const row of rows) {
    try {
      // Hosts whose lock is taken (a deployment, a manual restore) are skipped and retried on the next pass.
      await restoreAuditSessionById(row.id, { finalStatus: 'COMPLETED', collectLogs: true, onlyIfDue: true, lockMode: 'try' });
    } catch (error: any) {
      // Unexpected (e.g. DB) error: leave the session RUNNING so the next tick retries.
      // eslint-disable-next-line no-console
      console.error(`[Audit Scheduler] Error restoring session ${row.id}:`, error?.message ?? error);
    }
  }
}
