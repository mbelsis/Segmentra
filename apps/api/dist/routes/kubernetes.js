import { Router } from 'express';
import { z } from 'zod';
import { pool } from '../db/pool.js';
import { requireAuth, requireRole } from '../middleware/auth.js';
export const kubernetesRouter = Router();
kubernetesRouter.use(requireAuth);
// List clusters
kubernetesRouter.get('/clusters', requireRole('viewer', 'operator', 'approver', 'admin'), async (_req, res) => {
    const { rows } = await pool.query(`SELECT id, name, description, api_server_url, auth_type, default_namespace, last_sync_at, last_sync_status, enabled, created_at
     FROM k8s_clusters ORDER BY name ASC`);
    res.json({ clusters: rows });
});
// Get single cluster with workload summary
kubernetesRouter.get('/clusters/:id', requireRole('viewer', 'operator', 'approver', 'admin'), async (req, res) => {
    const { rows } = await pool.query(`SELECT id, name, description, api_server_url, auth_type, default_namespace, last_sync_at, last_sync_status, enabled, created_at
     FROM k8s_clusters WHERE id = $1`, [req.params.id]);
    if (!rows[0])
        return res.status(404).json({ error: 'not_found' });
    const { rows: workloadCounts } = await pool.query(`SELECT kind, COUNT(*)::int as count FROM k8s_workloads WHERE cluster_id = $1 GROUP BY kind`, [req.params.id]);
    const { rows: namespaceCounts } = await pool.query(`SELECT namespace, COUNT(*)::int as count FROM k8s_workloads WHERE cluster_id = $1 GROUP BY namespace ORDER BY namespace`, [req.params.id]);
    res.json({ cluster: rows[0], workloadSummary: workloadCounts, namespaces: namespaceCounts });
});
const clusterSchema = z.object({
    name: z.string().min(1),
    description: z.string().optional(),
    apiServerUrl: z.string().min(1),
    authType: z.enum(['kubeconfig', 'service_account', 'token']).default('kubeconfig'),
    credentialsSecretId: z.string().uuid().optional().nullable(),
    caCertSecretId: z.string().uuid().optional().nullable(),
    defaultNamespace: z.string().default('default'),
    enabled: z.boolean().default(true),
});
// Create cluster
kubernetesRouter.post('/clusters', requireRole('admin'), async (req, res) => {
    const parsed = clusterSchema.safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ error: 'invalid_body', details: parsed.error.issues });
    const b = parsed.data;
    const userRes = await pool.query(`SELECT id FROM users WHERE username=$1 LIMIT 1`, [req.auth.username]);
    const userId = userRes.rows[0]?.id ?? null;
    const { rows } = await pool.query(`INSERT INTO k8s_clusters (name, description, api_server_url, auth_type, credentials_secret_id, ca_cert_secret_id, default_namespace, enabled, created_by)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *`, [b.name, b.description ?? null, b.apiServerUrl, b.authType, b.credentialsSecretId ?? null,
        b.caCertSecretId ?? null, b.defaultNamespace, b.enabled, userId]);
    await pool.query(`INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
     VALUES ($1, 'K8S_CLUSTER_CREATE', 'k8s_cluster', $2, $3)`, [userId, rows[0].id, JSON.stringify({ name: b.name, apiServerUrl: b.apiServerUrl })]);
    res.status(201).json({ cluster: rows[0] });
});
// Update cluster
kubernetesRouter.put('/clusters/:id', requireRole('admin'), async (req, res) => {
    const parsed = clusterSchema.partial().safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ error: 'invalid_body' });
    const b = parsed.data;
    const { rows } = await pool.query(`UPDATE k8s_clusters
     SET name = COALESCE($2, name),
         description = COALESCE($3, description),
         api_server_url = COALESCE($4, api_server_url),
         auth_type = COALESCE($5, auth_type),
         credentials_secret_id = COALESCE($6, credentials_secret_id),
         ca_cert_secret_id = COALESCE($7, ca_cert_secret_id),
         default_namespace = COALESCE($8, default_namespace),
         enabled = COALESCE($9, enabled),
         updated_at = now()
     WHERE id = $1 RETURNING *`, [req.params.id, b.name ?? null, b.description ?? null, b.apiServerUrl ?? null,
        b.authType ?? null, b.credentialsSecretId ?? null, b.caCertSecretId ?? null,
        b.defaultNamespace ?? null, b.enabled ?? null]);
    if (!rows[0])
        return res.status(404).json({ error: 'not_found' });
    await pool.query(`INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
     VALUES ((SELECT id FROM users WHERE username=$1 LIMIT 1), $2, $3, $4, $5)`, [req.auth.username, 'K8S_CLUSTER_UPDATE', 'k8s_cluster', req.params.id, JSON.stringify({ name: rows[0].name })]);
    res.json({ cluster: rows[0] });
});
// Delete cluster
kubernetesRouter.delete('/clusters/:id', requireRole('admin'), async (req, res) => {
    const { rowCount } = await pool.query(`DELETE FROM k8s_clusters WHERE id = $1`, [req.params.id]);
    if (!rowCount)
        return res.status(404).json({ error: 'not_found' });
    await pool.query(`INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
     VALUES ((SELECT id FROM users WHERE username=$1 LIMIT 1), $2, $3, $4, $5)`, [req.auth.username, 'K8S_CLUSTER_DELETE', 'k8s_cluster', req.params.id, JSON.stringify({ clusterId: req.params.id })]);
    res.json({ ok: true });
});
// Sync cluster workloads (discovery)
kubernetesRouter.post('/clusters/:id/sync', requireRole('operator', 'admin'), async (req, res) => {
    const { rows } = await pool.query(`SELECT * FROM k8s_clusters WHERE id = $1`, [req.params.id]);
    if (!rows[0])
        return res.status(404).json({ error: 'not_found' });
    // Placeholder sync — in production this would call k8s API
    await pool.query(`UPDATE k8s_clusters SET last_sync_at = now(), last_sync_status = 'synced' WHERE id = $1`, [req.params.id]);
    await pool.query(`INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
     VALUES ((SELECT id FROM users WHERE username=$1 LIMIT 1), $2, $3, $4, $5)`, [req.auth.username, 'K8S_CLUSTER_SYNC', 'k8s_cluster', req.params.id, JSON.stringify({ clusterId: req.params.id })]);
    res.json({ success: true, message: 'Cluster sync initiated' });
});
// List workloads
kubernetesRouter.get('/clusters/:id/workloads', requireRole('viewer', 'operator', 'approver', 'admin'), async (req, res) => {
    const namespace = req.query.namespace ? String(req.query.namespace) : null;
    const kind = req.query.kind ? String(req.query.kind) : null;
    let query = `SELECT w.*,
    (SELECT array_agg(t.name) FROM k8s_workload_tags wt JOIN tags t ON t.id = wt.tag_id WHERE wt.workload_id = w.id) as tag_names
   FROM k8s_workloads w WHERE w.cluster_id = $1`;
    const params = [req.params.id];
    let idx = 2;
    if (namespace) {
        query += ` AND w.namespace = $${idx++}`;
        params.push(namespace);
    }
    if (kind) {
        query += ` AND w.kind = $${idx++}`;
        params.push(kind);
    }
    query += ` ORDER BY w.namespace, w.kind, w.name`;
    const { rows } = await pool.query(query, params);
    res.json({ workloads: rows });
});
// Map workload labels to tags
kubernetesRouter.post('/workloads/:workloadId/map-tag', requireRole('operator', 'admin'), async (req, res) => {
    const bodySchema = z.object({ tagId: z.string().uuid() });
    const parsed = bodySchema.safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ error: 'invalid_body' });
    await pool.query(`INSERT INTO k8s_workload_tags (workload_id, tag_id, source) VALUES ($1, $2, 'manual')
     ON CONFLICT (workload_id, tag_id) DO NOTHING`, [req.params.workloadId, parsed.data.tagId]);
    res.json({ ok: true });
});
// List network policies for cluster
kubernetesRouter.get('/clusters/:id/network-policies', requireRole('viewer', 'operator', 'approver', 'admin'), async (req, res) => {
    const { rows } = await pool.query(`SELECT np.*, pv.version_number, ps.name as policy_set_name
     FROM k8s_network_policies np
     LEFT JOIN policy_versions pv ON pv.id = np.policy_version_id
     LEFT JOIN policy_sets ps ON ps.id = pv.policy_set_id
     WHERE np.cluster_id = $1 ORDER BY np.namespace, np.policy_name`, [req.params.id]);
    res.json({ networkPolicies: rows });
});
// Deploy policy to cluster
kubernetesRouter.post('/clusters/:id/deploy-policy', requireRole('operator', 'admin'), async (req, res) => {
    const bodySchema = z.object({
        policyVersionId: z.string().uuid(),
        namespace: z.string().min(1),
        policyName: z.string().min(1),
    });
    const parsed = bodySchema.safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ error: 'invalid_body' });
    const b = parsed.data;
    // Get policy rules
    const { rows: rules } = await pool.query(`SELECT * FROM policy_rules WHERE policy_version_id = $1 ORDER BY order_index ASC`, [b.policyVersionId]);
    // Build NetworkPolicy manifest (simplified)
    const ingressRules = [];
    const egressRules = [];
    for (const rule of rules) {
        const policyRule = {};
        if (rule.ports) {
            policyRule.ports = rule.ports.split(',').map((p) => ({
                port: parseInt(p.trim()),
                protocol: rule.protocol === 'any' ? 'TCP' : rule.protocol.toUpperCase(),
            }));
        }
        if (rule.direction === 'IN' || rule.direction === 'BOTH') {
            if (rule.action === 'ALLOW') {
                ingressRules.push({ ...policyRule, from: [{ ipBlock: { cidr: rule.source_type === 'CIDR' ? rule.source_value : '0.0.0.0/0' } }] });
            }
        }
        if (rule.direction === 'OUT' || rule.direction === 'BOTH') {
            if (rule.action === 'ALLOW') {
                egressRules.push({ ...policyRule, to: [{ ipBlock: { cidr: rule.source_type === 'CIDR' ? rule.source_value : '0.0.0.0/0' } }] });
            }
        }
    }
    const manifest = {
        apiVersion: 'networking.k8s.io/v1',
        kind: 'NetworkPolicy',
        metadata: { name: b.policyName, namespace: b.namespace },
        spec: {
            podSelector: {},
            policyTypes: ['Ingress', 'Egress'],
            ingress: ingressRules,
            egress: egressRules,
        },
    };
    const crypto = await import('node:crypto');
    const hash = crypto.createHash('sha256').update(JSON.stringify(manifest)).digest('hex');
    const { rows } = await pool.query(`INSERT INTO k8s_network_policies (cluster_id, policy_version_id, namespace, policy_name, manifest, status, deployed_hash, deployed_at)
     VALUES ($1, $2, $3, $4, $5, 'DEPLOYED', $6, now()) RETURNING *`, [req.params.id, b.policyVersionId, b.namespace, b.policyName, JSON.stringify(manifest), hash]);
    const userRes = await pool.query(`SELECT id FROM users WHERE username=$1 LIMIT 1`, [req.auth.username]);
    const userId = userRes.rows[0]?.id ?? null;
    await pool.query(`INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
     VALUES ($1, 'K8S_POLICY_DEPLOY', 'k8s_network_policy', $2, $3)`, [userId, rows[0].id, JSON.stringify({ clusterId: req.params.id, namespace: b.namespace, policyName: b.policyName })]);
    res.status(201).json({ networkPolicy: rows[0] });
});
