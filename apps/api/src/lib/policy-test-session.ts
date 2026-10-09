import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { firewallBackend } from '@segmentra/compiler';

import { restoreAuditSession, retrieveAuditLogs, type AuditSshHost } from '@segmentra/executor';

import { pool } from '../db/pool.js';
import { parseFirewallLogs, groupCommunicationFlows } from '../services/log-parser.js';
import { getSshCredentialForHost, sshAuthFields, type MaterializedSshCredential } from '../services/ssh-credentials.js';

/** Statuses of a policy test session that still own the host's firewall. */
export const ACTIVE_TEST_SESSION_STATUSES = ['PENDING', 'DEPLOYING', 'RUNNING'] as const;

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
export async function restoreAndCollectSession(session: any): Promise<RestoreAndCollectResult> {
  let cred: MaterializedSshCredential | null = null;
  try {
    cred = await getSshCredentialForHost(session.host_id);
    const auditHost = buildAuditHost(session, cred);

    if (session.backup_path) {
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
  }
}
