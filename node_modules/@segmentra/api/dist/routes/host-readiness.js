import { Router } from 'express';
import { checkHostReadiness } from '@segmentra/executor';
import { pool } from '../db/pool.js';
import { requireAuth, requireRole } from '../middleware/auth.js';
import { readSecretPlaintext } from '../services/secrets.js';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
const hostReadinessRouter = Router();
hostReadinessRouter.use(requireAuth, requireRole('operator', 'admin'));
/**
 * Check readiness for a specific host
 * POST /host-readiness/hosts/:hostId/check
 */
hostReadinessRouter.post('/hosts/:hostId/check', async (req, res) => {
    const hostId = req.params.hostId;
    // Get host info
    const hostRes = await pool.query(`SELECT h.id, h.hostname, h.mgmt_ip, h.ssh_port, h.firewall_backend
     FROM hosts h
     WHERE h.id=$1 AND h.enabled=true`, [hostId]);
    if (!hostRes.rows[0]) {
        return res.status(404).json({ error: 'host_not_found' });
    }
    const host = hostRes.rows[0];
    // Get SSH credential
    const credRes = await pool.query(`SELECT * FROM ssh_credentials WHERE scope_type='GLOBAL' ORDER BY created_at DESC LIMIT 1`);
    const cred = credRes.rows[0];
    if (!cred) {
        return res.status(400).json({ error: 'missing_ssh_credential' });
    }
    const keyPem = (await readSecretPlaintext(cred.private_key_secret_id)).toString('utf8');
    // Use os.tmpdir() for temporary keys to avoid dependency on BUNDLES_DIR existing
    const tempKeyPath = path.join(os.tmpdir(), `segmentra_readiness_key_${hostId}_${Date.now()}`);
    fs.writeFileSync(tempKeyPath, keyPem, { encoding: 'utf8', mode: 0o600 });
    try {
        const sshHostInfo = {
            hostname: host.hostname,
            ip: String(host.mgmt_ip),
            port: host.ssh_port || 22,
            username: cred.username,
            privateKeyPath: tempKeyPath
        };
        const result = await checkHostReadiness(sshHostInfo);
        // Update host firewall_backend if auto-detected
        if (result.backend !== 'unknown' && host.firewall_backend === 'auto') {
            await pool.query(`UPDATE hosts SET firewall_backend=$1 WHERE id=$2`, [result.backend, hostId]);
        }
        return res.json(result);
    }
    catch (error) {
        return res.status(500).json({ error: 'check_failed', message: error.message });
    }
    finally {
        // Clean up temp key file
        if (fs.existsSync(tempKeyPath)) {
            fs.unlinkSync(tempKeyPath);
        }
    }
});
export default hostReadinessRouter;
