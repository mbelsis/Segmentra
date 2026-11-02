import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { firewallBackend } from '@segmentra/compiler';

import { restoreAuditSession, retrieveAuditLogs, type AuditLogSource, type AuditSshHost } from '@segmentra/executor';

import { pool } from '../db/pool.js';
import { ACTIVE_TEST_SESSION_STATUSES, acquireHostLock, deploymentSucceededSince, tryAcquireHostLock, type HostLockRelease } from '../services/host-lock.js';
import { parseFirewallLogs, groupCommunicationFlows } from '../services/log-parser.js';
import { getSshCredentialForHost, sshAuthFields, type MaterializedSshCredential } from '../services/ssh-credentials.js';

/** Statuses of a policy test session that still own the host's firewall (defined with the learning ones in host-lock.ts). */
export { ACTIVE_TEST_SESSION_STATUSES };

export function buildAuditHost(
  host: { hostname: string; mgmt_ip: unknown; ssh_port?: number | null; firewall_backend?: string | null },
  cred: MaterializedSshCredential
): AuditSshHost {
  return {
    hostname: host.hostname,
    ip: String(host.mgmt_ip),
    port: host.ssh_port || 22,
    ...sshAuthFields(cred),
    backend: firewallBackend(host.firewall_backend)
  };
}

/**
 * Record a restore failure while leaving the session in RUNNING so the expiry job retries it.
 * scheduled_end_at is pulled forward so the retry happens on the next tick.
 * The error is stored inside raw_log_data (no dedicated error column exists).
 */
export async function markRestoreFailed(sessionId: string, error: string, extra: Record<string, unknown> = {}) {
  // Only a session that still owns the host's firewall: a duplicate or late run must never move a COLLECTING /
  // COMPLETED / FAILED session back to RUNNING.
  await pool.query(
    `UPDATE policy_test_sessions
       SET status = 'RUNNING',
           scheduled_end_at = LEAST(COALESCE(scheduled_end_at, now()), now()),
           raw_log_data = COALESCE(raw_log_data, '{}'::jsonb)
             || jsonb_build_object('restore_error', $2::text, 'restore_failed_at', now()::text)
             || $3::jsonb
     WHERE id = $1 AND status = ANY($4::text[])`,
    [sessionId, error.slice(0, 4000), JSON.stringify(extra), ACTIVE_TEST_SESSION_STATUSES]
  );
}

export type RestoreAndCollectResult =
  | { ok: true; entryCount: number; flowCount: number; startFailed: boolean; logSource?: AuditLogSource }
  /** notActive: another run (Stop, expiry, recovery) already restored it; busy: lockMode 'try' and the host lock is taken. */
  | { ok: false; error: string; notActive?: boolean; busy?: boolean; status?: string };

const SESSION_WITH_HOST = `SELECT pts.*, h.hostname, h.mgmt_ip, h.ssh_port, h.firewall_backend
                             FROM policy_test_sessions pts JOIN hosts h ON h.id = pts.host_id`;

/**
 * Restore a host's original rules for a test session, then retrieve and parse logs.
 * On restore failure the session is kept RUNNING (with the error recorded) so the
 * background expiry job retries; it is never reported as finished.
 *
 * Stop, the expiry job and interrupted-start recovery all come through here, and the claim is the host lock plus a
 * re-read of the row once it is held: only a session still in `expectStatuses` is restored, and every status write is
 * conditional on it. A second caller that waited for the lock therefore sees COLLECTING/FAILED/COMPLETED and returns
 * `notActive` instead of putting the backup back again, re-pulling logs and overwriting raw_log_data.
 *
 * `session` needs at least `id`; the row is re-read under the lock.
 */
export async function restoreAndCollectSession(
  session: { id: string; host_id: string; hostname?: string },
  opts: { hostLockHeld?: boolean; lockMode?: 'wait' | 'try'; expectStatuses?: readonly string[] } = {}
): Promise<RestoreAndCollectResult> {
  const expect = [...(opts.expectStatuses ?? ['RUNNING'])];
  // Serialized with deployments and audit sessions on the same host (see services/host-lock.ts).
  let releaseHostLock: HostLockRelease;
  if (opts.hostLockHeld) {
    releaseHostLock = async () => {};
  } else if (opts.lockMode === 'try') {
    const r = await tryAcquireHostLock(session.host_id);
    if (!r) return { ok: false, busy: true, error: `host ${session.hostname ?? session.host_id} is busy (another firewall operation holds its lock)` };
    releaseHostLock = r;
  } else {
    try {
      releaseHostLock = await acquireHostLock(session.host_id);
    } catch (e: any) {
      const msg = `Failed to restore session on ${session.hostname ?? session.host_id}: ${e?.message ?? String(e)}`;
      await markRestoreFailed(session.id, msg);
      return { ok: false, error: msg };
    }
  }
  const held: { cred: MaterializedSshCredential | null } = { cred: null };
  try {
    const { rows } = await pool.query(`${SESSION_WITH_HOST} WHERE pts.id = $1`, [session.id]);
    const current = rows[0];
    if (!current || !expect.includes(current.status)) {
      return { ok: false, notActive: true, status: current?.status, error: `session is no longer ${expect.join('/')}${current ? ` (it is ${current.status})` : ''}` };
    }
    session = current;
    return await restoreLocked(current, expect, (c) => { held.cred = c; });
  } catch (e: any) {
    const msg = `Failed to restore session on ${session.hostname}: ${e?.message ?? String(e)}`;
    await markRestoreFailed(session.id, msg);
    return { ok: false, error: msg };
  } finally {
    held.cred?.cleanup();
    await releaseHostLock();
  }
}

/** The restore itself; the caller holds the host lock and has checked that the session is in `expect`. */
async function restoreLocked(session: any, expect: string[], onCred: (c: MaterializedSshCredential) => void): Promise<RestoreAndCollectResult> {
  const cred = await getSshCredentialForHost(session.host_id);
  onCred(cred);
  const auditHost = buildAuditHost(session, cred);

  // A deployment that succeeded after the test started already replaced the test rules; the backup is older
  // than it, so restoring would silently undo that deployment.
  const replacedByDeployment = await deploymentSucceededSince(session.host_id, session.started_at);
  if (session.backup_path && !replacedByDeployment) {
    const restore = await restoreAuditSession(auditHost, session.backup_path);
    if (!restore.success) {
      const msg = `Failed to restore original rules on ${session.hostname}: ${(restore.stderr || restore.stdout || `exit code ${restore.exitCode}`).trim()}`;
      await markRestoreFailed(session.id, msg);
      return { ok: false, error: msg };
    }
  }

  const startFailed = Boolean(session.raw_log_data?.start_failed);

  let logContent = '';
  let logSource: AuditLogSource | undefined;
  if (session.log_file_path && !startFailed) {
    const localLogPath = path.join(os.tmpdir(), `policy_test_log_${session.id}_${Date.now()}.log`);
    try {
      const retrieveResult = await retrieveAuditLogs(auditHost, session.log_file_path, localLogPath);
      logSource = retrieveResult.logSource;
      if (retrieveResult.success && fs.existsSync(localLogPath)) {
        logContent = fs.readFileSync(localLogPath, 'utf8');
      }
    } finally {
      if (fs.existsSync(localLogPath)) { try { fs.unlinkSync(localLogPath); } catch { /* ignore */ } }
    }
  }

  if (startFailed) {
    // The test never started successfully; rules are now restored, so close it out as FAILED.
    await pool.query(
      `UPDATE policy_test_sessions
         SET status = 'FAILED', completed_at = now(),
             raw_log_data = (COALESCE(raw_log_data, '{}'::jsonb) - 'restore_error') || jsonb_build_object('restored_at', now()::text)
       WHERE id = $1 AND status = ANY($2::text[])`,
      [session.id, expect]
    );
    return { ok: true, entryCount: 0, flowCount: 0, startFailed: true };
  }

  const parsedEntries = parseFirewallLogs(logContent);
  const flows = groupCommunicationFlows(parsedEntries);

  await pool.query(
    `UPDATE policy_test_sessions
       SET status = 'COLLECTING', completed_at = now(), raw_log_data = $2
     WHERE id = $1 AND status = ANY($3::text[])`,
    [session.id, JSON.stringify({ entries: parsedEntries, flows, ...(logSource ? { log_source: logSource } : {}) }), expect]
  );
  return { ok: true, entryCount: parsedEntries.length, flowCount: flows.length, startFailed: false, logSource };
}

export type InterruptedRecovery =
  | { outcome: 'busy' }          // the start is still running (it holds the host lock)
  | { outcome: 'not_interrupted' } // no longer DEPLOYING/PENDING once we had the lock
  | { outcome: 'failed_no_changes' } // no backup was recorded: the host's rules were not replaced
  | { outcome: 'restored' }
  | { outcome: 'restore_failed'; error: string }; // left RUNNING + start_failed: the expiry job keeps retrying

/**
 * A policy test is DEPLOYING (or PENDING) only while its start request runs, and that request holds the host lock from
 * before the row is inserted until it is RUNNING or FAILED. So a DEPLOYING session whose host lock is free was abandoned:
 * the API stopped in the middle of the start, possibly after the log-only (allow-all) policy reached the host. Restore
 * its backup like a failed start; without a backup the rules were never replaced and the session is simply FAILED.
 */
export async function recoverInterruptedTestSession(sessionId: string, reason = 'the API stopped while the test was starting'): Promise<InterruptedRecovery> {
  const first = await pool.query(`SELECT host_id FROM policy_test_sessions WHERE id = $1`, [sessionId]);
  if (!first.rows[0]) return { outcome: 'not_interrupted' };
  const release = await tryAcquireHostLock(first.rows[0].host_id);
  if (!release) return { outcome: 'busy' };
  try {
    const { rows } = await pool.query(`${SESSION_WITH_HOST} WHERE pts.id = $1 AND pts.status IN ('PENDING', 'DEPLOYING')`, [sessionId]);
    const session = rows[0];
    if (!session) return { outcome: 'not_interrupted' };
    if (!session.backup_path) {
      await pool.query(
        `UPDATE policy_test_sessions
            SET status = 'FAILED', completed_at = now(),
                raw_log_data = COALESCE(raw_log_data, '{}'::jsonb) || jsonb_build_object('start_error', $2::text, 'interrupted', true)
          WHERE id = $1`,
        [session.id, `Start interrupted (${reason}) before the host's rules were backed up; nothing was changed`]
      );
      return { outcome: 'failed_no_changes' };
    }
    const flagged = await pool.query(
      `UPDATE policy_test_sessions
          SET raw_log_data = COALESCE(raw_log_data, '{}'::jsonb)
                || jsonb_build_object('start_failed', true, 'interrupted', true, 'start_error', $2::text)
        WHERE id = $1 RETURNING raw_log_data`,
      [session.id, `Start interrupted (${reason}); restoring the backup taken at start`]
    );
    session.raw_log_data = flagged.rows[0]?.raw_log_data ?? { start_failed: true };
    const result = await restoreAndCollectSession(session, { hostLockHeld: true, expectStatuses: ['PENDING', 'DEPLOYING'] });
    return result.ok ? { outcome: 'restored' } : { outcome: 'restore_failed', error: result.error };
  } finally {
    await release();
  }
}

/** Find and recover every abandoned DEPLOYING/PENDING test (run at startup and by the expiry job). */
export async function recoverInterruptedTestSessions(): Promise<Array<{ id: string; hostname: string; result: InterruptedRecovery }>> {
  const { rows } = await pool.query(`${SESSION_WITH_HOST} WHERE pts.status IN ('PENDING', 'DEPLOYING') ORDER BY pts.started_at`);
  const out: Array<{ id: string; hostname: string; result: InterruptedRecovery }> = [];
  for (const s of rows) {
    const result = await recoverInterruptedTestSession(s.id);
    if (result.outcome !== 'busy' && result.outcome !== 'not_interrupted') out.push({ id: s.id, hostname: s.hostname, result });
  }
  return out;
}

let expiryTickRunning = false;

/**
 * One pass of the policy-test expiry job (startup and every minute): recover interrupted starts, then restore every
 * RUNNING session past its scheduled end (failed restores keep scheduled_end_at pulled forward, so they are retried
 * here). Passes never overlap in this process: a restore can take longer than the interval. Hosts whose lock is taken
 * are skipped and retried on the next pass instead of blocking the job; across processes the claim in
 * restoreAndCollectSession (host lock + status re-check) keeps a session from being restored twice.
 * Returns false when skipped because the previous pass is still running.
 */
export async function processExpiredTestSessions(): Promise<boolean> {
  if (expiryTickRunning) return false;
  expiryTickRunning = true;
  try {
    try {
      for (const r of await recoverInterruptedTestSessions()) {
        // eslint-disable-next-line no-console
        console.log(`[Policy Test] Interrupted start of session ${r.id} (${r.hostname}): ${r.result.outcome}${'error' in r.result ? ` — ${r.result.error}` : ''}`);
      }
    } catch (e) {
      // eslint-disable-next-line no-console
      console.error('[Policy Test] Error recovering interrupted test sessions:', e);
    }
    const { rows } = await pool.query(
      `SELECT pts.id, pts.host_id, h.hostname
         FROM policy_test_sessions pts JOIN hosts h ON h.id = pts.host_id
        WHERE pts.status = 'RUNNING' AND pts.scheduled_end_at <= now()
        ORDER BY pts.scheduled_end_at`
    );
    for (const session of rows) {
      const result = await restoreAndCollectSession(session, { lockMode: 'try' });
      if (result.ok) {
        // eslint-disable-next-line no-console
        console.log(`[Policy Test] Auto-restored ${session.hostname}, collected ${result.entryCount} entries, ${result.flowCount} flows`);
      } else if (!result.busy && !result.notActive) {
        // eslint-disable-next-line no-console
        console.error(`[Policy Test] Restore failed for session ${session.id} (${session.hostname}); will retry: ${result.error}`);
      }
    }
    return true;
  } finally {
    expiryTickRunning = false;
  }
}
