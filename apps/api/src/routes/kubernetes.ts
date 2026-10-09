import { Router } from 'express';
import { z } from 'zod';

import { pool } from '../db/pool.js';
import { requireAuth, requireRole } from '../middleware/auth.js';
import { parseCidr, parsePortSpec } from '../services/ip-utils.js';
import { encryptBlob } from '../services/crypto.js';
import {
  K8sError, MANAGED_BY_LABEL, MANAGED_BY_VALUE, applyNetworkPolicy, canListNetworkPolicies, canonicalJson, deleteNetworkPolicy,
  getNetworkPolicy, getVersion, isManagedBySegmentra, loadConnection, validateClusterUrl, validateCredentials,
} from '../services/k8s-client.js';
import { createSecret } from '../services/secrets.js';
import { createSourceResolver } from '../services/source-resolver.js';

export const kubernetesRouter = Router();
kubernetesRouter.use(requireAuth);

const CLUSTER_COLUMNS = `id, name, description, api_server_url, auth_type, cni, default_namespace, last_sync_at, last_sync_status, enabled, created_at,
     tls_skip_verify, (credentials_secret_id IS NOT NULL) AS has_credentials, (ca_cert_secret_id IS NOT NULL) AS has_ca_cert`;

// List clusters. Secret ids are never returned; has_credentials / has_ca_cert say whether they exist.
kubernetesRouter.get('/clusters', requireRole('viewer', 'operator', 'approver', 'admin'), async (_req, res) => {
  const { rows } = await pool.query(`SELECT ${CLUSTER_COLUMNS} FROM k8s_clusters ORDER BY name ASC`);
  res.json({ clusters: rows });
});

// Get single cluster with workload summary
kubernetesRouter.get('/clusters/:id', requireRole('viewer', 'operator', 'approver', 'admin'), async (req, res) => {
  const { rows } = await pool.query(`SELECT ${CLUSTER_COLUMNS} FROM k8s_clusters WHERE id = $1`, [req.params.id]);
  if (!rows[0]) return res.status(404).json({ error: 'not_found' });

  const { rows: workloadCounts } = await pool.query(
    `SELECT kind, COUNT(*)::int as count FROM k8s_workloads WHERE cluster_id = $1 GROUP BY kind`,
    [req.params.id]
  );

  const { rows: namespaceCounts } = await pool.query(
    `SELECT namespace, COUNT(*)::int as count FROM k8s_workloads WHERE cluster_id = $1 GROUP BY namespace ORDER BY namespace`,
    [req.params.id]
  );

  res.json({ cluster: rows[0], workloadSummary: workloadCounts, namespaces: namespaceCounts });
});

const CNIS = ['unknown', 'calico', 'cilium', 'kindnet', 'antrea', 'weave', 'kube-router', 'other'] as const;

const clusterSchema = z.object({
  cni: z.enum(CNIS).default('unknown'),
  name: z.string().min(1),
  description: z.string().optional(),
  // Required, except when a kubeconfig is supplied (it carries the server URL).
  apiServerUrl: z.string().default(''),
  authType: z.enum(['kubeconfig', 'service_account', 'token']).default('kubeconfig'),
  // Write-only: a kubeconfig (authType kubeconfig) or a bearer token (service_account / token).
  // Stored encrypted in secret_store; omitted on update = keep the stored one, null = remove it.
  credentials: z.string().max(200_000).nullable().optional(),
  // Write-only PEM CA certificate of the API server (a kubeconfig may embed its own).
  caCert: z.string().max(100_000).nullable().optional(),
  // Disables API server certificate verification. Insecure; prefer providing the CA certificate.
  tlsSkipVerify: z.boolean().default(false),
  defaultNamespace: z.string().default('default'),
  enabled: z.boolean().default(true),
});

async function actorId(username: string): Promise<string | null> {
  const r = await pool.query(`SELECT id FROM users WHERE username=$1 LIMIT 1`, [username]);
  return r.rows[0]?.id ?? null;
}

async function audit(username: string, action: string, entityType: string, entityId: string, metadata: unknown) {
  await pool.query(
    `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
     VALUES ((SELECT id FROM users WHERE username=$1 LIMIT 1), $2, $3, $4, $5)`,
    [username, action, entityType, entityId, JSON.stringify(metadata)]
  );
}

/** Validate a credential for the auth type; returns an error response body or null. */
function checkCredentials(authType: string, credentials: string, caCert?: string | null): { error: string; message: string } | null {
  try {
    validateCredentials(authType, credentials);
  } catch (e: any) {
    return { error: 'invalid_credentials', message: e.message };
  }
  if (caCert && !/-----BEGIN CERTIFICATE-----/.test(caCert)) {
    return { error: 'invalid_ca_cert', message: 'caCert must be a PEM certificate' };
  }
  return null;
}

function checkServerUrl(url: string): { error: string; message: string } | null {
  try {
    validateClusterUrl(url);
    return null;
  } catch (e: any) {
    return { error: 'invalid_api_server_url', message: e.message };
  }
}

// Create cluster
kubernetesRouter.post('/clusters', requireRole('admin'), async (req, res) => {
  const parsed = clusterSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body', details: parsed.error.issues });
  const b = parsed.data;

  // With credentials the API server URL must be a valid https URL; a kubeconfig carries its own,
  // which is what Segmentra will connect to, so it replaces the typed one.
  let apiServerUrl = b.apiServerUrl;
  if (b.credentials) {
    const problem = checkCredentials(b.authType, b.credentials, b.caCert);
    if (problem) return res.status(400).json(problem);
    if (b.authType === 'kubeconfig') apiServerUrl = validateCredentials('kubeconfig', b.credentials).serverUrl ?? apiServerUrl;
    else {
      const urlProblem = checkServerUrl(apiServerUrl);
      if (urlProblem) return res.status(400).json(urlProblem);
    }
  }

  if (!apiServerUrl.trim()) return res.status(400).json({ error: 'invalid_body', message: 'apiServerUrl is required (a kubeconfig supplies it)' });

  const userId = await actorId(req.auth!.username);
  const credSecret = b.credentials ? await createSecret({ name: `k8s:${b.name}`.slice(0, 200), type: 'K8S_CREDENTIALS', plaintext: Buffer.from(b.credentials.trim(), 'utf8') }) : null;
  const caSecret = b.caCert ? await createSecret({ name: `k8s-ca:${b.name}`.slice(0, 200), type: 'TLS_CA_CERT', plaintext: Buffer.from(b.caCert.trim(), 'utf8') }) : null;

  let rows: any[];
  try {
    ({ rows } = await pool.query(
    `INSERT INTO k8s_clusters (name, description, api_server_url, auth_type, cni, credentials_secret_id, ca_cert_secret_id, tls_skip_verify, default_namespace, enabled, created_by)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING id`,
    [b.name, b.description ?? null, apiServerUrl, b.authType, b.cni, credSecret?.id ?? null, caSecret?.id ?? null,
     b.tlsSkipVerify, b.defaultNamespace, b.enabled, userId]
  ));
  } catch (e) {
    // Do not leave encrypted secrets behind when the cluster row could not be created.
    for (const sec of [credSecret, caSecret]) if (sec) await pool.query(`DELETE FROM secret_store WHERE id = $1`, [sec.id]).catch(() => {});
    throw e;
  }
  await pool.query(
    `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
     VALUES ($1, 'K8S_CLUSTER_CREATE', 'k8s_cluster', $2, $3)`,
    [userId, rows[0].id, JSON.stringify({ name: b.name, apiServerUrl, hasCredentials: !!credSecret })]
  );

  const created = await pool.query(`SELECT ${CLUSTER_COLUMNS} FROM k8s_clusters WHERE id = $1`, [rows[0].id]);
  res.status(201).json({ cluster: created.rows[0] });
});

// Update cluster
kubernetesRouter.put('/clusters/:id', requireRole('admin'), async (req, res) => {
  const parsed = z.object({ ...clusterSchema.shape, cni: z.enum(CNIS), tlsSkipVerify: z.boolean() }).partial().safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body' });
  const b = parsed.data;

  const cur = await pool.query(`SELECT * FROM k8s_clusters WHERE id = $1`, [req.params.id]);
  if (!cur.rows[0]) return res.status(404).json({ error: 'not_found' });
  const c = cur.rows[0];

  const authType = b.authType ?? c.auth_type;
  let apiServerUrl = b.apiServerUrl;
  if (typeof b.credentials === 'string' && b.credentials.trim()) {
    const problem = checkCredentials(authType, b.credentials, typeof b.caCert === 'string' ? b.caCert : null);
    if (problem) return res.status(400).json(problem);
    if (authType === 'kubeconfig') apiServerUrl = validateCredentials('kubeconfig', b.credentials).serverUrl ?? apiServerUrl;
  } else if (typeof b.caCert === 'string' && b.caCert.trim() && !/-----BEGIN CERTIFICATE-----/.test(b.caCert)) {
    return res.status(400).json({ error: 'invalid_ca_cert', message: 'caCert must be a PEM certificate' });
  }
  const hasCreds = typeof b.credentials === 'string' ? !!b.credentials.trim() : !!c.credentials_secret_id;
  if (hasCreds && authType !== 'kubeconfig' && (apiServerUrl ?? c.api_server_url)) {
    const urlProblem = checkServerUrl(apiServerUrl ?? c.api_server_url);
    if (urlProblem) return res.status(400).json(urlProblem);
  }

  // Replace / remove the encrypted secrets (updated in place so references stay valid).
  const upsertSecret = async (existingId: string | null, type: 'K8S_CREDENTIALS' | 'TLS_CA_CERT', value: string | null | undefined) => {
    if (value === undefined) return existingId;                      // untouched
    if (value === null || value.trim() === '') {                     // removed
      if (existingId) await pool.query(`DELETE FROM secret_store WHERE id = $1`, [existingId]).catch(() => {});
      return null;
    }
    const blob = encryptBlob(Buffer.from(value.trim(), 'utf8'));
    if (existingId) {
      const r = await pool.query(`UPDATE secret_store SET encrypted_blob = $2, rotated_at = now(), is_active = true WHERE id = $1`, [existingId, blob]);
      if (r.rowCount) return existingId;
    }
    return (await createSecret({ name: `k8s:${b.name ?? c.name}`.slice(0, 200), type, plaintext: Buffer.from(value.trim(), 'utf8') })).id;
  };
  const credId = await upsertSecret(c.credentials_secret_id, 'K8S_CREDENTIALS', b.credentials);
  const caId = await upsertSecret(c.ca_cert_secret_id, 'TLS_CA_CERT', b.caCert);

  await pool.query(
    `UPDATE k8s_clusters
     SET name = COALESCE($2, name),
         description = COALESCE($3, description),
         api_server_url = COALESCE($4, api_server_url),
         auth_type = COALESCE($5, auth_type),
         credentials_secret_id = $6,
         ca_cert_secret_id = $7,
         default_namespace = COALESCE($8, default_namespace),
         enabled = COALESCE($9, enabled),
         cni = COALESCE($10, cni),
         tls_skip_verify = COALESCE($11, tls_skip_verify),
         updated_at = now()
     WHERE id = $1`,
    [req.params.id, b.name ?? null, b.description ?? null, apiServerUrl ?? null, b.authType ?? null, credId, caId,
     b.defaultNamespace ?? null, b.enabled ?? null, b.cni ?? null, b.tlsSkipVerify ?? null]
  );

  await audit(req.auth!.username, 'K8S_CLUSTER_UPDATE', 'k8s_cluster', req.params.id, {
    name: b.name ?? c.name,
    credentialsChanged: b.credentials !== undefined,
    caCertChanged: b.caCert !== undefined,
    tlsSkipVerify: b.tlsSkipVerify,
  });

  const updated = await pool.query(`SELECT ${CLUSTER_COLUMNS} FROM k8s_clusters WHERE id = $1`, [req.params.id]);
  res.json({ cluster: updated.rows[0] });
});

// Delete cluster (the cluster's own Kubernetes resources are not touched; remove policies first)
kubernetesRouter.delete('/clusters/:id', requireRole('admin'), async (req, res) => {
  const { rows } = await pool.query(`DELETE FROM k8s_clusters WHERE id = $1 RETURNING credentials_secret_id, ca_cert_secret_id`, [req.params.id]);
  if (!rows[0]) return res.status(404).json({ error: 'not_found' });
  for (const sid of [rows[0].credentials_secret_id, rows[0].ca_cert_secret_id].filter(Boolean)) {
    await pool.query(`DELETE FROM secret_store WHERE id = $1`, [sid]).catch(() => {});
  }
  await audit(req.auth!.username, 'K8S_CLUSTER_DELETE', 'k8s_cluster', req.params.id, { clusterId: req.params.id });
  res.json({ ok: true });
});

async function loadCluster(id: string) {
  const { rows } = await pool.query(`SELECT * FROM k8s_clusters WHERE id = $1`, [id]);
  return rows[0] ?? null;
}

// Test the stored credentials: API server version and read access to NetworkPolicies.
kubernetesRouter.post('/clusters/:id/test-connection', requireRole('operator', 'admin'), async (req, res) => {
  const cluster = await loadCluster(req.params.id);
  if (!cluster) return res.status(404).json({ error: 'not_found' });
  let result: { ok: boolean; serverVersion?: string; namespaceAccess?: { ok: boolean; message?: string }; error?: string; message?: string };
  try {
    const conn = await loadConnection(cluster);
    const serverVersion = await getVersion(conn);
    const namespaceAccess = await canListNetworkPolicies(conn, cluster.default_namespace || 'default');
    result = { ok: namespaceAccess.ok, serverVersion, namespaceAccess, ...(namespaceAccess.ok ? {} : { error: 'forbidden', message: namespaceAccess.message }) };
  } catch (e: any) {
    result = { ok: false, error: e.code ?? 'k8s_error', message: e.message };
  }
  await pool.query(
    `UPDATE k8s_clusters SET last_sync_at = now(), last_sync_status = $2 WHERE id = $1`,
    [req.params.id, result.ok ? `connected (${result.serverVersion})` : `error: ${result.message}`.slice(0, 300)]
  );
  await audit(req.auth!.username, 'K8S_CLUSTER_TEST', 'k8s_cluster', req.params.id, { ok: result.ok, error: result.error });
  res.status(result.ok ? 200 : 502).json(result);
});

// Sync cluster workloads (discovery)
kubernetesRouter.post('/clusters/:id/sync', requireRole('operator', 'admin'), async (req, res) => {
  const { rows } = await pool.query(`SELECT id FROM k8s_clusters WHERE id = $1`, [req.params.id]);
  if (!rows[0]) return res.status(404).json({ error: 'not_found' });
  // Workload discovery is not implemented. Report that honestly instead of pretending it succeeded.
  res.status(501).json({
    error: 'not_implemented',
    message: 'Kubernetes workload discovery is not implemented yet. Register workloads on the Workloads tab (or with POST /api/k8s/clusters/:id/workloads) and map them to tags.'
  });
});

// List workloads
kubernetesRouter.get('/clusters/:id/workloads', requireRole('viewer', 'operator', 'approver', 'admin'), async (req, res) => {
  const namespace = req.query.namespace ? String(req.query.namespace) : null;
  const kind = req.query.kind ? String(req.query.kind) : null;

  let query = `SELECT w.*,
    (SELECT array_agg(t.name) FROM k8s_workload_tags wt JOIN tags t ON t.id = wt.tag_id WHERE wt.workload_id = w.id) as tag_names,
    (SELECT json_agg(json_build_object('id', t.id, 'name', t.name)) FROM k8s_workload_tags wt JOIN tags t ON t.id = wt.tag_id WHERE wt.workload_id = w.id) as tags
   FROM k8s_workloads w WHERE w.cluster_id = $1`;
  const params: any[] = [req.params.id];
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

const workloadSchema = z.object({
  namespace: z.string().min(1),
  kind: z.string().min(1).default('Pod'),
  name: z.string().min(1),
  // Labels of the pods (for Deployments etc. the pod-template labels). Used as podSelector.
  labels: z.record(z.string(), z.string()).default({}),
  podIps: z.array(z.string()).optional(),
});

// Register a workload by hand (there is no cluster discovery yet). Re-registering the same
// namespace/kind/name updates its labels.
kubernetesRouter.post('/clusters/:id/workloads', requireRole('operator', 'admin'), async (req, res) => {
  const parsed = workloadSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body', details: parsed.error.issues });
  const b = parsed.data;
  const cluster = await pool.query(`SELECT id FROM k8s_clusters WHERE id = $1`, [req.params.id]);
  if (!cluster.rows[0]) return res.status(404).json({ error: 'not_found' });

  const existing = await pool.query(
    `SELECT id FROM k8s_workloads WHERE cluster_id = $1 AND namespace = $2 AND kind = $3 AND name = $4`,
    [req.params.id, b.namespace, b.kind, b.name]
  );
  const { rows } = existing.rows[0]
    ? await pool.query(
        `UPDATE k8s_workloads SET labels = $2, pod_ips = COALESCE($3, pod_ips), last_seen_at = now() WHERE id = $1 RETURNING *`,
        [existing.rows[0].id, JSON.stringify(b.labels), b.podIps ?? null]
      )
    : await pool.query(
        `INSERT INTO k8s_workloads (cluster_id, namespace, kind, name, labels, pod_ips)
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
        [req.params.id, b.namespace, b.kind, b.name, JSON.stringify(b.labels), b.podIps ?? null]
      );
  res.status(existing.rows[0] ? 200 : 201).json({ workload: rows[0] });
});

// Map workload labels to tags
kubernetesRouter.post('/workloads/:workloadId/map-tag', requireRole('operator', 'admin'), async (req, res) => {
  const bodySchema = z.object({ tagId: z.string().uuid() });
  const parsed = bodySchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body' });

  await pool.query(
    `INSERT INTO k8s_workload_tags (workload_id, tag_id, source) VALUES ($1, $2, 'manual')
     ON CONFLICT (workload_id, tag_id) DO NOTHING`,
    [req.params.workloadId, parsed.data.tagId]
  );
  res.json({ ok: true });
});

// Remove a workload record (does not touch the cluster)
kubernetesRouter.delete('/workloads/:workloadId', requireRole('operator', 'admin'), async (req, res) => {
  const { rowCount } = await pool.query(`DELETE FROM k8s_workloads WHERE id = $1`, [req.params.workloadId]);
  if (!rowCount) return res.status(404).json({ error: 'not_found' });
  res.json({ ok: true });
});

// Unmap a workload from a tag
kubernetesRouter.delete('/workloads/:workloadId/tags/:tagId', requireRole('operator', 'admin'), async (req, res) => {
  const { rowCount } = await pool.query(`DELETE FROM k8s_workload_tags WHERE workload_id = $1 AND tag_id = $2`, [req.params.workloadId, req.params.tagId]);
  if (!rowCount) return res.status(404).json({ error: 'not_found' });
  res.json({ ok: true });
});

// List network policies for cluster
kubernetesRouter.get('/clusters/:id/network-policies', requireRole('viewer', 'operator', 'approver', 'admin'), async (req, res) => {
  const { rows } = await pool.query(
    `SELECT np.*, pv.version_number, ps.name as policy_set_name
     FROM k8s_network_policies np
     LEFT JOIN policy_versions pv ON pv.id = np.policy_version_id
     LEFT JOIN policy_sets ps ON ps.id = pv.policy_set_id
     WHERE np.cluster_id = $1 ORDER BY np.namespace, np.policy_name`,
    [req.params.id]
  );
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
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body' });
  const b = parsed.data;

  const clusterRes = await pool.query(`SELECT id, cni FROM k8s_clusters WHERE id = $1`, [req.params.id]);
  if (!clusterRes.rows[0]) return res.status(404).json({ error: 'not_found' });
  const cni: string = clusterRes.rows[0].cni ?? 'unknown';

  const pvRes = await pool.query(`SELECT status FROM policy_versions WHERE id = $1`, [b.policyVersionId]);
  if (!pvRes.rows[0]) return res.status(404).json({ error: 'policy_version_not_found' });
  if (!['APPROVED', 'DEPLOYED'].includes(pvRes.rows[0].status)) {
    return res.status(409).json({
      error: 'policy_version_not_approved',
      message: `Policy version is ${pvRes.rows[0].status}; only APPROVED or DEPLOYED versions can be exported as NetworkPolicy.`
    });
  }

  // Get policy rules
  const { rows: rules } = await pool.query(
    `SELECT * FROM policy_rules WHERE policy_version_id = $1 ORDER BY order_index ASC`,
    [b.policyVersionId]
  );

  // Build NetworkPolicy manifest. NetworkPolicy is allow-only and unordered, so DENY rules and
  // anything that cannot be expressed exactly are skipped with a warning rather than widened.
  const ingressRules: any[] = [];
  const warnings: string[] = [];
  const resolve = createSourceResolver({ vlanMode: 'subnet' });

  const toIpBlockCidr = (addr: string): string | null => {
    const parsedAddr = parseCidr(addr);
    if (!parsedAddr) return null;
    return addr.includes('/') ? addr : `${addr}/${parsedAddr.family === 4 ? 32 : 128}`;
  };

  const cniIgnoresIpBlockForPods = cni === 'cilium' || cni === 'unknown';
  const workloadPeers = async (tagId: string, label: string) => {
    const { rows: wl } = await pool.query(
      `SELECT DISTINCT w.namespace, w.name, w.labels
         FROM k8s_workloads w JOIN k8s_workload_tags wt ON wt.workload_id = w.id
        WHERE w.cluster_id = $1 AND wt.tag_id = $2 ORDER BY w.namespace, w.name`,
      [req.params.id, tagId]
    ).catch(() => ({ rows: [] as any[] })); // non-uuid tag ids cannot match anything
    const out: any[] = [];
    for (const w of wl) {
      const labels = w.labels && typeof w.labels === 'object' ? w.labels : {};
      if (Object.keys(labels).length === 0) {
        warnings.push(`${label}: workload ${w.namespace}/${w.name} has no labels; skipped because an empty podSelector would match every pod in the namespace`);
        continue;
      }
      out.push({
        namespaceSelector: { matchLabels: { 'kubernetes.io/metadata.name': w.namespace } },
        podSelector: { matchLabels: labels },
      });
    }
    return out;
  };

  for (const rule of rules) {
    const label = `rule #${rule.order_index}${rule.comment ? ` (${rule.comment})` : ''}`;

    if (rule.direction === 'FORWARD') {
      warnings.push(`${label}: FORWARD rules (traffic routed through a gateway) have no NetworkPolicy equivalent; skipped`);
      continue;
    }

    if (rule.action !== 'ALLOW') {
      warnings.push(`${label}: DENY rules cannot be expressed in a Kubernetes NetworkPolicy (allow-only); skipped`);
      continue;
    }
    if (rule.protocol === 'icmp') {
      warnings.push(`${label}: ICMP is not supported by NetworkPolicy; skipped`);
      continue;
    }

    const proto = String(rule.protocol).toUpperCase();
    let ports: Array<{ protocol: string; port?: number; endPort?: number }> | undefined;
    if (rule.ports && String(rule.ports).trim()) {
      if (!['TCP', 'UDP', 'SCTP'].includes(proto)) {
        warnings.push(`${label}: ports require protocol TCP/UDP/SCTP (got ${rule.protocol}); skipped`);
        continue;
      }
      const ranges = parsePortSpec(rule.ports);
      if (!ranges) {
        warnings.push(`${label}: invalid port specification "${rule.ports}"; skipped`);
        continue;
      }
      ports = ranges.map((r) => (r.from === r.to ? { protocol: proto, port: r.from } : { protocol: proto, port: r.from, endPort: r.to }));
    } else if (['TCP', 'UDP', 'SCTP'].includes(proto)) {
      ports = [{ protocol: proto }];
    } else if (rule.protocol !== 'any') {
      warnings.push(`${label}: unsupported protocol "${rule.protocol}"; skipped`);
      continue;
    }
    // protocol 'any' without ports: omit `ports` (= all ports and protocols)

    const addrs = await resolve(rule.source_type, rule.source_value);
    const cidrs = Array.from(new Set(addrs.map(toIpBlockCidr).filter((c): c is string => !!c)));
    // TAG sources also select the workloads registered in this cluster and mapped to the tag,
    // by label. Unlike ipBlock, selector peers match in-cluster pods on every CNI.
    const selectorPeers = rule.source_type === 'TAG' ? await workloadPeers(rule.source_value, label) : [];
    if (cidrs.length === 0 && selectorPeers.length === 0) {
      warnings.push(`${label}: ${rule.source_type} source "${rule.source_value}" resolves to no IP addresses${rule.source_type === 'TAG' ? ' or labelled workloads' : ''}; skipped instead of allowing 0.0.0.0/0`);
      continue;
    }
    if (cidrs.length > 0 && cniIgnoresIpBlockForPods) {
      warnings.push(`${label}: ${cni === 'cilium' ? 'Cilium does not apply ipBlock to cluster-internal pod and node traffic' : 'the cluster CNI is not set, and some CNIs (for example Cilium) do not apply ipBlock to cluster-internal traffic'}, so the ipBlock source(s) ${cidrs.join(', ')} only match clients outside the cluster; map in-cluster workloads to a Segmentra tag and use that TAG as the source (selector peers work on every CNI)`);
    }
    const peers = [...cidrs.map((cidr) => ({ ipBlock: { cidr } })), ...selectorPeers];
    const policyRule: any = ports ? { ports } : {};

    if (rule.direction === 'IN' || rule.direction === 'BOTH') {
      ingressRules.push({ ...policyRule, from: peers });
    }
    if (rule.direction === 'OUT' || rule.direction === 'BOTH') {
      // Segmentra's outbound default is allow, so OUT ALLOW rules don't restrict anything.
      // Emitting them as NetworkPolicy egress would deny every other outbound connection (DNS too).
      warnings.push(`${label}: outbound allow is already the default (egress is not restricted); not emitted`);
    }
  }

  const manifest = {
    apiVersion: 'networking.k8s.io/v1',
    kind: 'NetworkPolicy',
    metadata: {
      name: b.policyName,
      namespace: b.namespace,
      // The label marks the policy as Segmentra's: apply/remove refuse to touch same-named policies
      // that are not labelled, so a hand-written policy is never overwritten by accident.
      labels: { [MANAGED_BY_LABEL]: MANAGED_BY_VALUE },
      annotations: { 'segmentra.io/policy-version-id': b.policyVersionId },
    },
    spec: {
      podSelector: {},
      // Only Ingress is restricted, matching Segmentra (inbound default deny, outbound default
      // allow). Listing Egress would make Kubernetes deny all outbound traffic not listed.
      policyTypes: ['Ingress'],
      ingress: ingressRules,
    },
  };

  const crypto = await import('node:crypto');
  const hash = crypto.createHash('sha256').update(JSON.stringify(manifest)).digest('hex');

  const { rows } = await pool.query(
    `INSERT INTO k8s_network_policies (cluster_id, policy_version_id, namespace, policy_name, manifest, status, deployed_hash, deployed_at, warnings)
     VALUES ($1, $2, $3, $4, $5, 'GENERATED', $6, now(), $7) RETURNING *`,
    [req.params.id, b.policyVersionId, b.namespace, b.policyName, JSON.stringify(manifest), hash, JSON.stringify(warnings)]
  );

  const userRes = await pool.query(`SELECT id FROM users WHERE username=$1 LIMIT 1`, [req.auth!.username]);
  const userId = userRes.rows[0]?.id ?? null;
  await pool.query(
    `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
     VALUES ($1, 'K8S_POLICY_DEPLOY', 'k8s_network_policy', $2, $3)`,
    [userId, rows[0].id, JSON.stringify({ clusterId: req.params.id, namespace: b.namespace, policyName: b.policyName, warnings })]
  );

  res.status(201).json({ networkPolicy: rows[0], warnings });
});


// ---- Apply / check / remove on the cluster -----------------------------------------------------

async function loadPolicyRow(clusterId: string, npId: string) {
  const { rows } = await pool.query(`SELECT * FROM k8s_network_policies WHERE id = $1 AND cluster_id = $2`, [npId, clusterId]);
  if (!rows[0]) return null;
  const row = rows[0];
  // Compared inside SQL: a JS Date would truncate created_at to milliseconds.
  const { rows: newer } = await pool.query(
    `SELECT 1 FROM k8s_network_policies n2
       JOIN k8s_network_policies me ON me.id = $2
      WHERE n2.cluster_id = $1 AND n2.namespace = me.namespace AND n2.policy_name = me.policy_name
        AND (n2.created_at, n2.id) > (me.created_at, me.id)
      LIMIT 1`,
    [clusterId, row.id]
  );
  return { row, isLatest: newer.length === 0 };
}

function httpStatusFor(e: unknown): number {
  const err = e as K8sError;
  if (err?.code === 'no_credentials') return 409;
  if (err?.code === 'namespace_not_found') return 404;
  return 502;
}

// Apply (create or update) a generated NetworkPolicy on the cluster. Body: { dryRun?, overwrite? }.
// dryRun asks the API server to validate without persisting. overwrite allows replacing a
// same-named policy that Segmentra did not create.
kubernetesRouter.post('/clusters/:id/network-policies/:npId/apply', requireRole('operator', 'admin'), async (req, res) => {
  const body = z.object({ dryRun: z.boolean().default(false), overwrite: z.boolean().default(false) }).safeParse(req.body ?? {});
  if (!body.success) return res.status(400).json({ error: 'invalid_body' });
  const { dryRun, overwrite } = body.data;

  const cluster = await loadCluster(req.params.id);
  if (!cluster) return res.status(404).json({ error: 'not_found' });
  if (!cluster.enabled) return res.status(409).json({ error: 'cluster_disabled', message: 'This cluster is disabled' });
  const found = await loadPolicyRow(req.params.id, req.params.npId);
  if (!found) return res.status(404).json({ error: 'policy_not_found' });
  const { row, isLatest } = found;
  if (!isLatest) {
    return res.status(409).json({ error: 'superseded', message: 'A newer manifest with this name exists; apply that one (applying an older one would revert the policy)' });
  }
  const manifest = typeof row.manifest === 'string' ? JSON.parse(row.manifest) : row.manifest;

  try {
    const conn = await loadConnection(cluster);
    const existing = await getNetworkPolicy(conn, row.namespace, row.policy_name);
    if (existing && !isManagedBySegmentra(existing) && !overwrite) {
      return res.status(409).json({
        error: 'not_managed_by_segmentra',
        message: `NetworkPolicy ${row.namespace}/${row.policy_name} already exists and was not created by Segmentra; refusing to overwrite it. Remove it, pick another name, or apply with overwrite.`,
      });
    }
    await applyNetworkPolicy(conn, manifest, { dryRun });
    if (dryRun) return res.json({ ok: true, dryRun: true, replaces: !!existing, message: existing ? 'Valid; would update the existing policy' : 'Valid; would create the policy' });

    const userId = await actorId(req.auth!.username);
    await pool.query(
      `UPDATE k8s_network_policies
          SET status = 'APPLIED', applied_at = now(), applied_by = $2, last_error = NULL, live_state = 'IN_SYNC', live_checked_at = now()
        WHERE id = $1`,
      [row.id, userId]
    );
    await pool.query(
      `UPDATE k8s_network_policies SET status = 'SUPERSEDED'
        WHERE cluster_id = $1 AND namespace = $2 AND policy_name = $3 AND id <> $4 AND status <> 'REMOVED'`,
      [req.params.id, row.namespace, row.policy_name, row.id]
    );
    await audit(req.auth!.username, 'K8S_POLICY_APPLY', 'k8s_network_policy', row.id, {
      clusterId: req.params.id, namespace: row.namespace, policyName: row.policy_name, hash: row.deployed_hash, replaced: !!existing, overwrite,
    });
    const { rows } = await pool.query(`SELECT * FROM k8s_network_policies WHERE id = $1`, [row.id]);
    res.json({ ok: true, networkPolicy: rows[0], replaced: !!existing });
  } catch (e: any) {
    if (!dryRun) {
      await pool.query(`UPDATE k8s_network_policies SET status = 'FAILED', last_error = $2 WHERE id = $1`, [row.id, String(e.message).slice(0, 1000)]);
    }
    await audit(req.auth!.username, 'K8S_POLICY_APPLY_FAILED', 'k8s_network_policy', row.id, { clusterId: req.params.id, dryRun, error: e.message });
    res.status(httpStatusFor(e)).json({ error: e.code ?? 'k8s_error', message: e.message });
  }
});

// Compare the stored manifest with what is live in the cluster (drift detection).
kubernetesRouter.post('/clusters/:id/network-policies/:npId/check', requireRole('operator', 'admin'), async (req, res) => {
  const cluster = await loadCluster(req.params.id);
  if (!cluster) return res.status(404).json({ error: 'not_found' });
  const found = await loadPolicyRow(req.params.id, req.params.npId);
  if (!found) return res.status(404).json({ error: 'policy_not_found' });
  const { row } = found;
  const manifest = typeof row.manifest === 'string' ? JSON.parse(row.manifest) : row.manifest;
  try {
    const conn = await loadConnection(cluster);
    const live = await getNetworkPolicy(conn, row.namespace, row.policy_name);
    const state = !live ? 'MISSING' : canonicalJson(live.spec) === canonicalJson(manifest.spec) ? 'IN_SYNC' : 'DRIFTED';
    await pool.query(`UPDATE k8s_network_policies SET live_state = $2, live_checked_at = now() WHERE id = $1`, [row.id, state]);
    res.json({ ok: true, state, managedBySegmentra: live ? isManagedBySegmentra(live) : null, liveSpec: live?.spec ?? null });
  } catch (e: any) {
    res.status(httpStatusFor(e)).json({ error: e.code ?? 'k8s_error', message: e.message });
  }
});

// Remove the policy from the cluster. Only policies carrying Segmentra's managed-by label are deleted.
kubernetesRouter.post('/clusters/:id/network-policies/:npId/remove', requireRole('operator', 'admin'), async (req, res) => {
  const cluster = await loadCluster(req.params.id);
  if (!cluster) return res.status(404).json({ error: 'not_found' });
  const found = await loadPolicyRow(req.params.id, req.params.npId);
  if (!found) return res.status(404).json({ error: 'policy_not_found' });
  const { row } = found;
  try {
    const conn = await loadConnection(cluster);
    const live = await getNetworkPolicy(conn, row.namespace, row.policy_name);
    if (live && !isManagedBySegmentra(live)) {
      return res.status(409).json({ error: 'not_managed_by_segmentra', message: `NetworkPolicy ${row.namespace}/${row.policy_name} was not created by Segmentra; refusing to delete it` });
    }
    if (live) await deleteNetworkPolicy(conn, row.namespace, row.policy_name);
    await pool.query(
      `UPDATE k8s_network_policies SET status = 'REMOVED', last_error = NULL, live_state = 'MISSING', live_checked_at = now() WHERE id = $1`,
      [row.id]
    );
    await audit(req.auth!.username, 'K8S_POLICY_REMOVE', 'k8s_network_policy', row.id, {
      clusterId: req.params.id, namespace: row.namespace, policyName: row.policy_name, alreadyAbsent: !live,
    });
    res.json({ ok: true, alreadyAbsent: !live });
  } catch (e: any) {
    await audit(req.auth!.username, 'K8S_POLICY_REMOVE_FAILED', 'k8s_network_policy', row.id, { clusterId: req.params.id, error: e.message });
    res.status(httpStatusFor(e)).json({ error: e.code ?? 'k8s_error', message: e.message });
  }
});
