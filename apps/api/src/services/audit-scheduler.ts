import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { firewallBackend } from '@segmentra/compiler';

import { restoreAuditSession, retrieveAuditLogs, type AuditSshHost } from '@segmentra/executor';

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
 */

const LEASE_MINUTES = 10; // claim window so the scheduler and API calls don't restore concurrently
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
async function recordRestoreFailure(session: any, error: string): Promise<{ attempts: number; nextAttemptAt: string }> {
  const attempts = restoreState(session).attempts + 1;
  const backoffMinutes = Math.min(2 ** Math.min(attempts, 6), MAX_BACKOFF_MINUTES);
  const nextAttemptAt = new Date(Date.now() + backoffMinutes * 60_000);

  await pool.query(
    `UPDATE firewall_audit_sessions
        SET status = 'RUNNING',
            scheduled_restore_at = $2,
            log_data = COALESCE(log_data, '{}'::jsonb) || jsonb_build_object('restore', $3::jsonb)
      WHERE id = $1`,
    [
      session.id,
      nextAttemptAt,
      JSON.stringify({
        attempts,
        lastError: error.slice(0, 2000),
        lastAttemptAt: new Date().toISOString(),
        nextAttemptAt: nextAttemptAt.toISOString()
      })
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
 * Claim a session for restoring (prevents the scheduler and an API call from running the
 * restore at the same time). Returns the claimed row or null.
 */
async function claimSession(sessionId: string, opts: { onlyIfDue: boolean }): Promise<any | null> {
  const { rows } = await pool.query(
    `UPDATE firewall_audit_sessions fas
        SET scheduled_restore_at = now() + ($2::int * interval '1 minute')
       FROM hosts h
      WHERE fas.id = $1
        AND h.id = fas.host_id
        AND (fas.status = 'RUNNING' OR (fas.status = 'PENDING' AND fas.backup_path IS NOT NULL))
        AND ($3::boolean = false OR fas.scheduled_restore_at <= now() OR fas.status = 'PENDING')
      RETURNING fas.*, h.hostname, h.mgmt_ip, h.ssh_port, h.firewall_backend`,
    [sessionId, LEASE_MINUTES, opts.onlyIfDue]
  );
  return rows[0] ?? null;
}

/**
 * Restore the original firewall rules of an audit session and (optionally) collect its logs.
 * Never throws for SSH/restore failures: those are recorded and retried by the scheduler.
 */
export async function restoreAuditSessionById(
  sessionId: string,
  opts: { finalStatus: 'COMPLETED' | 'CANCELLED'; collectLogs: boolean; onlyIfDue?: boolean }
): Promise<RestoreOutcome | null> {
  const session = await claimSession(sessionId, { onlyIfDue: opts.onlyIfDue ?? false });
  if (!session) return null;

  let cred: MaterializedSshCredential | null = null;
  try {
    cred = await getSshCredentialForHost(session.host_id);
    const host = buildAuditHost(session, cred);

    const restoreResult = await restoreAuditSession(host, session.backup_path);
    if (!restoreResult.success) {
      const error = (restoreResult.stderr || restoreResult.stdout || 'restore failed').trim();
      const f = await recordRestoreFailure(session, error);
      return { success: false, error, ...f };
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

    await pool.query(
      `UPDATE firewall_audit_sessions
          SET status = $3, restored_at = now(), log_data = $1
        WHERE id = $2`,
      [
        JSON.stringify({
          entries: parsedEntries,
          flows,
          ...(prev.attempts > 0 ? { restore: { attempts: prev.attempts + 1, succeededAt: new Date().toISOString() } } : {})
        }),
        session.id,
        opts.finalStatus
      ]
    );

    return { success: true, flows, entryCount: parsedEntries.length };
  } catch (e: any) {
    const error = e?.message ?? String(e);
    const f = await recordRestoreFailure(session, error);
    return { success: false, error, ...f };
  } finally {
    cred?.cleanup();
  }
}

/**
 * Check for expired audit sessions and restore them.
 * Called periodically (every minute). Failed restores are retried with backoff.
 */
export async function processExpiredAuditSessions(): Promise<void> {
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
      WHERE (status = 'RUNNING' AND scheduled_restore_at <= now())
         OR (status = 'PENDING' AND backup_path IS NOT NULL
             AND started_at < now() - ($1::int * interval '1 minute'))
      ORDER BY scheduled_restore_at ASC`,
    [STALE_PENDING_MINUTES]
  );

  for (const row of rows) {
    try {
      await restoreAuditSessionById(row.id, { finalStatus: 'COMPLETED', collectLogs: true, onlyIfDue: true });
    } catch (error: any) {
      // Unexpected (e.g. DB) error: leave the session RUNNING so the next tick retries.
      // eslint-disable-next-line no-console
      console.error(`[Audit Scheduler] Error restoring session ${row.id}:`, error?.message ?? error);
    }
  }
}
