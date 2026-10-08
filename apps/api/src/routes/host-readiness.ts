import { Router } from 'express';
import { checkHostReadiness, type SshHostInfo } from '@segmentra/executor';
import { pool } from '../db/pool.js';
import { requireAuth, requireRole } from '../middleware/auth.js';
import { getSshCredentialForHost, sshAuthFields, type MaterializedSshCredential } from '../services/ssh-credentials.js';

const hostReadinessRouter = Router();
hostReadinessRouter.use(requireAuth, requireRole('operator', 'admin'));

/**
 * Check readiness for a specific host
 * POST /host-readiness/hosts/:hostId/check
 */
hostReadinessRouter.post('/hosts/:hostId/check', async (req, res) => {
  const hostId = req.params.hostId;

  // Get host info
  const hostRes = await pool.query(
    `SELECT h.id, h.hostname, h.mgmt_ip, h.ssh_port, h.firewall_backend
     FROM hosts h
     WHERE h.id=$1 AND h.enabled=true`,
    [hostId]
  );

  if (!hostRes.rows[0]) {
    return res.status(404).json({ error: 'host_not_found' });
  }

  const host = hostRes.rows[0];

  if (!host.mgmt_ip) {
    return res.status(400).json({ error: 'missing_mgmt_ip', message: 'Host has no management IP' });
  }

  let cred: MaterializedSshCredential;
  try {
    cred = await getSshCredentialForHost(hostId);
  } catch (e: any) {
    if (e?.message === 'missing_ssh_credential') return res.status(400).json({ error: 'missing_ssh_credential' });
    throw e;
  }

  try {
    const sshHostInfo: SshHostInfo = {
      hostname: host.hostname,
      ip: String(host.mgmt_ip).split('/')[0],
      port: Number(host.ssh_port) || 22,
      ...sshAuthFields(cred),
      backend: host.firewall_backend === 'iptables' || host.firewall_backend === 'nftables' ? host.firewall_backend : 'auto'
    };

    const result = await checkHostReadiness(sshHostInfo);

    // Update host firewall_backend if auto-detected
    if (result.backend !== 'unknown' && host.firewall_backend === 'auto') {
      await pool.query(
        `UPDATE hosts SET firewall_backend=$1, updated_at=now() WHERE id=$2`,
        [result.backend, hostId]
      );
    }

    return res.json(result);
  } catch (error: any) {
    return res.status(502).json({ error: 'check_failed', message: error.message });
  } finally {
    cred.cleanup();
  }
});

export default hostReadinessRouter;
