import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { firewallBackend } from '@segmentra/compiler';

import { restoreAuditSession, retrieveAuditLogs, type AuditSshHost } from '@segmentra/executor';

import { pool } from '../db/pool.js';
import { ACTIVE_TEST_SESSION_STATUSES, acquireHostLock, deploymentSucceededSince, tryAcquireHostLock } from '../services/host-lock.js';
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
  await pool.query(
    `UPDATE policy_test_sessions
       SET status = 'RUNNING',
           scheduled_end_at = LEAST(COALESCE(scheduled_end_at, now()), now()),
           raw_log_data = COALESCE(raw_log_data, '{}'::jsonb)
             || jsonb_build_object('restore_error', $2::text, 'restore_failed_at', now()::text)
             || $3::jsonb
     WHERE id = $1`,
    [sessionId, error.slice(0, 4000), JSON.stringify(extra)]
  );
}

export type RestoreAndCollectResult =
  | { ok: true; entryCount: number; flowCount: number; startFailed: boolean }
  | { ok: false; error: string };

/**
 * Restore a host's original rules for a test session, then retrieve and parse logs.
 * On restore failure the session is kept RUNNING (with the error recorded) so the
 * background expiry job retries; it is never reported as finished.
 *
 * `session` must include host columns: host_id, hostname, mgmt_ip, ssh_port, firewall_backend.
 */
export async function restoreAndCollectSession(session: any, opts: { hostLockHeld?: boolean } = {}): Promise<RestoreAndCollectResult> {
  // Serialized with deployments and audit sessions on the same host (see services/host-lock.ts).
  const releaseHostLock = opts.hostLockHeld ? async () => {} : await acquireHostLock(session.host_id);
  let cred: MaterializedSshCredential | null = null;
  try {
    cred = await getSshCredentialForHost(session.host_id);
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
    if (session.log_file_path && !startFailed) {
      const localLogPath = path.join(os.tmpdir(), `policy_test_log_${session.id}_${Date.now()}.log`);
      try {
        const retrieveResult = await retrieveAuditLogs(auditHost, session.log_file_path, localLogPath);
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
         WHERE id = $1`,
        [session.id]
      );
      return { ok: true, entryCount: 0, flowCount: 0, startFailed: true };
    }

    const parsedEntries = parseFirewallLogs(logContent);
    const flows = groupCommunicationFlows(parsedEntries);

    await pool.query(
      `UPDATE policy_test_sessions
         SET status = 'COLLECTING', completed_at = now(), raw_log_data = $2
       WHERE id = $1`,
      [session.id, JSON.stringify({ entries: parsedEntries, flows })]
    );
    return { ok: true, entryCount: parsedEntries.length, flowCount: flows.length, startFailed: false };
  } catch (e: any) {
    const msg = `Failed to restore session on ${session.hostname}: ${e?.message ?? String(e)}`;
    await markRestoreFailed(session.id, msg);
    return { ok: false, error: msg };
  } finally {
    cred?.cleanup();
    await releaseHostLock();
  }
}

const SESSION_WITH_HOST = `SELECT pts.*, h.hostname, h.mgmt_ip, h.ssh_port, h.firewall_backend
                             FROM policy_test_sessions pts JOIN hosts h ON h.id = pts.host_id`;

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
    const result = await restoreAndCollectSession(session, { hostLockHeld: true });
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
