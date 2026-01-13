import { pool } from '../db/pool.js';
import { restoreAuditSession, retrieveAuditLogs, type AuditSshHost } from '@segmentra/executor';
import { parseFirewallLogs, groupCommunicationFlows } from './log-parser.js';
import { readSecretPlaintext } from './secrets.js';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

/**
 * Check for expired audit sessions and restore them
 * This should be called periodically (e.g., every minute)
 */
export async function processExpiredAuditSessions(): Promise<void> {
  const now = new Date();
  
  // Find all running sessions that should be restored
  const { rows } = await pool.query(
    `SELECT fas.*, h.hostname, h.mgmt_ip, h.ssh_port, h.firewall_backend
     FROM firewall_audit_sessions fas
     JOIN hosts h ON h.id = fas.host_id
     WHERE fas.status = 'RUNNING' 
     AND fas.scheduled_restore_at <= $1
     ORDER BY fas.scheduled_restore_at ASC`,
    [now]
  );

  for (const session of rows) {
    try {
      await restoreAuditSessionForHost(session);
    } catch (error: any) {
      // Log error but continue processing other sessions
      console.error(`[Audit Scheduler] Error restoring session ${session.id}:`, error.message);
      await pool.query(
        `UPDATE firewall_audit_sessions 
         SET status = 'FAILED' 
         WHERE id = $1`,
        [session.id]
      );
    }
  }
}

/**
 * Restore audit session for a specific host
 */
async function restoreAuditSessionForHost(session: any): Promise<void> {
  // Get SSH credentials
  const credRes = await pool.query(
    `SELECT * FROM ssh_credentials WHERE scope_type='GLOBAL' ORDER BY created_at DESC LIMIT 1`
  );
  const cred = credRes.rows[0];
  if (!cred) {
    throw new Error('missing_ssh_credential');
  }

  const keyPem = (await readSecretPlaintext(cred.private_key_secret_id)).toString('utf8');
  const tempKeyPath = path.join(os.tmpdir(), `audit_key_${session.id}_${Date.now()}`);
  
  try {
    fs.writeFileSync(tempKeyPath, keyPem, { encoding: 'utf8', mode: 0o600 });

    const host: AuditSshHost = {
      hostname: session.hostname,
      ip: String(session.mgmt_ip),
      port: session.ssh_port || 22,
      username: cred.username,
      privateKeyPath: tempKeyPath,
      backend: session.firewall_backend === 'iptables' ? 'iptables' : 'nftables'
    };

    // Restore original firewall rules
    const restoreResult = await restoreAuditSession(host, session.backup_path);
    
    if (!restoreResult.success) {
      throw new Error(`Restore failed: ${restoreResult.stderr}`);
    }

    // Retrieve log file
    let logContent = '';
    if (session.log_file_path) {
      const localLogPath = path.join(os.tmpdir(), `audit_log_${session.id}_${Date.now()}.log`);
      const retrieveResult = await retrieveAuditLogs(host, session.log_file_path, localLogPath);
      
      if (retrieveResult.success && fs.existsSync(localLogPath)) {
        logContent = fs.readFileSync(localLogPath, 'utf8');
        // Clean up local log file
        fs.unlinkSync(localLogPath);
      }
    }

    // Parse logs
    const parsedEntries = parseFirewallLogs(logContent);
    const flows = groupCommunicationFlows(parsedEntries);

    // Update session status
    await pool.query(
      `UPDATE firewall_audit_sessions 
       SET status = 'COMPLETED', 
           restored_at = now(),
           log_data = $1
       WHERE id = $2`,
      [JSON.stringify({ entries: parsedEntries, flows }), session.id]
    );

  } finally {
    // Clean up temp key file
    if (fs.existsSync(tempKeyPath)) {
      try {
        fs.unlinkSync(tempKeyPath);
      } catch (e) {
        // Ignore cleanup errors
      }
    }
  }
}
