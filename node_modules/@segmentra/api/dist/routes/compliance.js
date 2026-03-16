import { Router } from 'express';
import { readHostFirewallRules } from '@segmentra/executor';
import { pool } from '../db/pool.js';
import { requireAuth, requireRole } from '../middleware/auth.js';
import { readSecretPlaintext } from '../services/secrets.js';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
const complianceRouter = Router();
complianceRouter.use(requireAuth, requireRole('operator', 'admin'));
/**
 * Check compliance status for a specific host
 * GET /compliance/hosts/:hostId
 */
complianceRouter.get('/hosts/:hostId', async (req, res) => {
    const hostId = req.params.hostId;
    // Get host info
    const hostRes = await pool.query(`SELECT h.id, h.hostname, h.mgmt_ip, h.ssh_port, h.firewall_backend
     FROM hosts h
     WHERE h.id=$1 AND h.enabled=true`, [hostId]);
    if (!hostRes.rows[0]) {
        return res.status(404).json({ error: 'host_not_found' });
    }
    const host = hostRes.rows[0];
    // Get last successful deployment hash
    const lastDeploymentRes = await pool.query(`SELECT dh.applied_hash, d.created_at, pv.version_number, ps.name as policy_set_name
     FROM deployment_hosts dh
     JOIN deployments d ON d.id = dh.deployment_id
     JOIN policy_versions pv ON pv.id = d.policy_version_id
     JOIN policy_sets ps ON ps.id = pv.policy_set_id
     WHERE dh.host_id=$1 AND dh.status='SUCCEEDED' AND dh.applied_hash IS NOT NULL
     ORDER BY d.created_at DESC
     LIMIT 1`, [hostId]);
    const lastDeployment = lastDeploymentRes.rows[0];
    // Get SSH credential
    const credRes = await pool.query(`SELECT * FROM ssh_credentials WHERE scope_type='GLOBAL' ORDER BY created_at DESC LIMIT 1`);
    const cred = credRes.rows[0];
    if (!cred) {
        return res.status(400).json({ error: 'missing_ssh_credential' });
    }
    const keyPem = (await readSecretPlaintext(cred.private_key_secret_id)).toString('utf8');
    // Use os.tmpdir() for temporary keys to avoid dependency on BUNDLES_DIR existing
    const tempKeyPath = path.join(os.tmpdir(), `segmentra_compliance_key_${hostId}_${Date.now()}`);
    fs.writeFileSync(tempKeyPath, keyPem, { encoding: 'utf8', mode: 0o600 });
    try {
        // Read current rules from host
        const sshHostInfo = {
            hostname: host.hostname,
            ip: String(host.mgmt_ip),
            port: host.ssh_port || 22,
            username: cred.username,
            privateKeyPath: tempKeyPath,
            backend: host.firewall_backend || 'auto'
        };
        const readResult = await readHostFirewallRules(sshHostInfo);
        if (!readResult.success) {
            return res.json({
                hostId,
                hostname: host.hostname,
                status: 'error',
                error: readResult.error,
                lastDeployment: lastDeployment ? {
                    hash: lastDeployment.applied_hash,
                    createdAt: lastDeployment.created_at,
                    policyVersion: lastDeployment.version_number,
                    policySetName: lastDeployment.policy_set_name
                } : null
            });
        }
        // Compare hashes
        let complianceStatus;
        if (!lastDeployment) {
            complianceStatus = 'unknown';
        }
        else if (readResult.rulesHash === lastDeployment.applied_hash) {
            complianceStatus = 'compliant';
        }
        else {
            complianceStatus = 'drifted';
        }
        return res.json({
            hostId,
            hostname: host.hostname,
            status: complianceStatus,
            currentHash: readResult.rulesHash,
            expectedHash: lastDeployment?.applied_hash || null,
            backend: readResult.backend,
            lastDeployment: lastDeployment ? {
                hash: lastDeployment.applied_hash,
                createdAt: lastDeployment.created_at,
                policyVersion: lastDeployment.version_number,
                policySetName: lastDeployment.policy_set_name
            } : null
        });
    }
    finally {
        // Clean up temp key file
        if (fs.existsSync(tempKeyPath)) {
            fs.unlinkSync(tempKeyPath);
        }
    }
});
/**
 * Check compliance for multiple hosts (bulk)
 * POST /compliance/hosts/bulk
 * Body: { hostIds: string[] }
 */
complianceRouter.post('/hosts/bulk', async (req, res) => {
    const { hostIds } = req.body;
    if (!Array.isArray(hostIds) || hostIds.length === 0) {
        return res.status(400).json({ error: 'invalid_body' });
    }
    // Get hosts
    const hostsRes = await pool.query(`SELECT h.id, h.hostname, h.mgmt_ip, h.ssh_port, h.firewall_backend
     FROM hosts h
     WHERE h.id = ANY($1::uuid[]) AND h.enabled=true`, [hostIds]);
    // Get SSH credential
    const credRes = await pool.query(`SELECT * FROM ssh_credentials WHERE scope_type='GLOBAL' ORDER BY created_at DESC LIMIT 1`);
    const cred = credRes.rows[0];
    if (!cred) {
        return res.status(400).json({ error: 'missing_ssh_credential' });
    }
    const keyPem = (await readSecretPlaintext(cred.private_key_secret_id)).toString('utf8');
    // Use os.tmpdir() for temporary keys to avoid dependency on BUNDLES_DIR existing
    const tempKeyPath = path.join(os.tmpdir(), `segmentra_compliance_bulk_key_${Date.now()}`);
    fs.writeFileSync(tempKeyPath, keyPem, { encoding: 'utf8', mode: 0o600 });
    try {
        // Get last deployment hashes for all hosts
        const lastDeploymentsRes = await pool.query(`SELECT dh.host_id, dh.applied_hash, d.created_at, pv.version_number, ps.name as policy_set_name
       FROM deployment_hosts dh
       JOIN deployments d ON d.id = dh.deployment_id
       JOIN policy_versions pv ON pv.id = d.policy_version_id
       JOIN policy_sets ps ON ps.id = pv.policy_set_id
       WHERE dh.host_id = ANY($1::uuid[]) AND dh.status='SUCCEEDED' AND dh.applied_hash IS NOT NULL
       AND (dh.host_id, d.created_at) IN (
         SELECT host_id, MAX(d.created_at)
         FROM deployment_hosts dh2
         JOIN deployments d ON d.id = dh2.deployment_id
         WHERE dh2.host_id = ANY($1::uuid[]) AND dh2.status='SUCCEEDED' AND dh2.applied_hash IS NOT NULL
         GROUP BY dh2.host_id
       )`, [hostIds]);
        const lastDeploymentsMap = new Map();
        for (const row of lastDeploymentsRes.rows) {
            lastDeploymentsMap.set(row.host_id, row);
        }
        const results = [];
        for (const host of hostsRes.rows) {
            const sshHostInfo = {
                hostname: host.hostname,
                ip: String(host.mgmt_ip),
                port: host.ssh_port || 22,
                username: cred.username,
                privateKeyPath: tempKeyPath,
                backend: host.firewall_backend || 'auto'
            };
            try {
                const readResult = await readHostFirewallRules(sshHostInfo);
                const lastDeployment = lastDeploymentsMap.get(host.id);
                let complianceStatus;
                if (!readResult.success) {
                    complianceStatus = 'error';
                }
                else if (!lastDeployment) {
                    complianceStatus = 'unknown';
                }
                else if (readResult.rulesHash === lastDeployment.applied_hash) {
                    complianceStatus = 'compliant';
                }
                else {
                    complianceStatus = 'drifted';
                }
                results.push({
                    hostId: host.id,
                    hostname: host.hostname,
                    status: complianceStatus,
                    currentHash: readResult.success ? readResult.rulesHash : null,
                    expectedHash: lastDeployment?.applied_hash || null,
                    error: readResult.success ? null : readResult.error
                });
            }
            catch (error) {
                results.push({
                    hostId: host.id,
                    hostname: host.hostname,
                    status: 'error',
                    error: error.message
                });
            }
        }
        return res.json({ results });
    }
    finally {
        // Clean up temp key file
        if (fs.existsSync(tempKeyPath)) {
            fs.unlinkSync(tempKeyPath);
        }
    }
});
export default complianceRouter;
