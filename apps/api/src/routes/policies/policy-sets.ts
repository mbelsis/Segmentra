import { Router } from 'express';
import { z } from 'zod';

import { pool } from '../../db/pool.js';
import { requireAuth, requireRole } from '../../middleware/auth.js';

export const policySetsRouter = Router();
policySetsRouter.use(requireAuth);

// GET endpoints are read-only and accessible to viewers
policySetsRouter.get('/', requireRole('viewer', 'operator', 'approver', 'admin'), async (_req, res) => {
  const { rows } = await pool.query(
    `SELECT ps.*,
       (SELECT COUNT(*)::int FROM policy_versions pv WHERE pv.policy_set_id = ps.id) as version_count,
       (SELECT COUNT(*)::int FROM policy_versions pv WHERE pv.policy_set_id = ps.id AND pv.status IN ('APPROVED', 'DEPLOYED')) as approved_count,
       (SELECT COUNT(*)::int FROM policy_versions pv WHERE pv.policy_set_id = ps.id AND pv.status = 'DEPLOYED') as deployed_count,
       (SELECT COUNT(*)::int FROM policy_versions pv WHERE pv.policy_set_id = ps.id AND pv.status = 'PENDING_APPROVAL') as pending_count,
       (SELECT COUNT(*)::int FROM policy_versions pv WHERE pv.policy_set_id = ps.id AND pv.status = 'DRAFT') as draft_count,
       (SELECT COUNT(*)::int FROM policy_versions pv WHERE pv.policy_set_id = ps.id AND pv.status = 'REJECTED') as rejected_count
     FROM policy_sets ps ORDER BY ps.created_at DESC`
  );
  res.json({ policySets: rows });
});

const createPolicySetSchema = z.object({
  name: z.string().min(1),
  description: z.string().optional(),
  scopeType: z.enum(['TAG', 'VLAN', 'HOST_LIST']),
  scopeTagId: z.string().uuid().optional().nullable(),
  scopeVlanId: z.string().uuid().optional().nullable(),
  hostIds: z.array(z.string().uuid()).optional()
});

type ScopeType = 'TAG' | 'VLAN' | 'HOST_LIST';
type Queryable = { query: (text: string, values?: any[]) => Promise<{ rows: any[] }> };

class ScopeError extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
  }
}

/**
 * Validate a policy set scope: TAG needs scopeTagId, VLAN needs scopeVlanId, HOST_LIST needs at least one
 * host; every referenced tag / VLAN / host must exist. Returns the columns to store (the scope columns
 * that do not belong to the scope type are always null).
 */
async function resolveScope(
  db: Queryable,
  scope: { scopeType: ScopeType; scopeTagId: string | null; scopeVlanId: string | null; hostIds: string[] | null }
): Promise<{ scopeTagId: string | null; scopeVlanId: string | null; hostIds: string[] | null }> {
  if (scope.scopeType === 'TAG') {
    if (!scope.scopeTagId) throw new ScopeError('scope_tag_required', 'A TAG-scoped policy set needs scopeTagId.');
    const t = await db.query(`SELECT 1 FROM tags WHERE id=$1`, [scope.scopeTagId]);
    if (!t.rows[0]) throw new ScopeError('scope_tag_not_found', 'The scope tag does not exist.');
    return { scopeTagId: scope.scopeTagId, scopeVlanId: null, hostIds: null };
  }
  if (scope.scopeType === 'VLAN') {
    if (!scope.scopeVlanId) throw new ScopeError('scope_vlan_required', 'A VLAN-scoped policy set needs scopeVlanId.');
    const v = await db.query(`SELECT 1 FROM vlans WHERE id=$1`, [scope.scopeVlanId]);
    if (!v.rows[0]) throw new ScopeError('scope_vlan_not_found', 'The scope VLAN does not exist.');
    return { scopeTagId: null, scopeVlanId: scope.scopeVlanId, hostIds: null };
  }
  if (scope.hostIds === null) return { scopeTagId: null, scopeVlanId: null, hostIds: null }; // keep the current list
  const hostIds = [...new Set(scope.hostIds)];
  if (hostIds.length === 0) throw new ScopeError('host_ids_required', 'A HOST_LIST policy set needs at least one host in hostIds.');
  const h = await db.query(`SELECT id FROM hosts WHERE id = ANY($1::uuid[])`, [hostIds]);
  const found = new Set(h.rows.map((r) => String(r.id)));
  const missing = hostIds.filter((id) => !found.has(id));
  if (missing.length) throw new ScopeError('hosts_not_found', `Unknown host id(s): ${missing.join(', ')}`);
  return { scopeTagId: null, scopeVlanId: null, hostIds };
}

async function replaceHostList(db: Queryable, policySetId: string, hostIds: string[]): Promise<void> {
  await db.query(`DELETE FROM policy_set_hosts WHERE policy_set_id=$1 AND NOT (host_id = ANY($2::uuid[]))`, [policySetId, hostIds]);
  await db.query(
    `INSERT INTO policy_set_hosts (policy_set_id, host_id) SELECT $1, unnest($2::uuid[]) ON CONFLICT DO NOTHING`,
    [policySetId, hostIds]
  );
}

// Write operations require operator/admin
policySetsRouter.post('/', requireRole('operator', 'admin'), async (req, res) => {
  const parsed = createPolicySetSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body', details: parsed.error.issues });
  const b = parsed.data;

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const scope = await resolveScope(client, {
      scopeType: b.scopeType,
      scopeTagId: b.scopeTagId ?? null,
      scopeVlanId: b.scopeVlanId ?? null,
      hostIds: b.scopeType === 'HOST_LIST' ? b.hostIds ?? [] : null
    });
    const ps = await client.query(
      `INSERT INTO policy_sets (name, description, scope_type, scope_tag_id, scope_vlan_id, created_by)
       VALUES ($1,$2,$3,$4,$5,(SELECT id FROM users WHERE username=$6 LIMIT 1))
       RETURNING *`,
      [b.name, b.description ?? null, b.scopeType, scope.scopeTagId, scope.scopeVlanId, req.auth!.username]
    );
    const policySet = ps.rows[0];

    if (scope.hostIds) await replaceHostList(client, policySet.id, scope.hostIds);

    await client.query(
      `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
       VALUES ((SELECT id FROM users WHERE username=$1 LIMIT 1), $2, $3, $4, $5)`,
      [req.auth!.username, 'POLICY_SET_CREATE', 'policy_set', policySet.id, JSON.stringify({ name: b.name, scopeType: b.scopeType })]
    );

    await client.query('COMMIT');
    res.status(201).json({ policySet });
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    if (e instanceof ScopeError) return res.status(400).json({ error: e.code, message: e.message });
    throw e; // pg errors (unique / FK violations, ...) are mapped to 4xx by the global error handler
  } finally {
    client.release();
  }
});

policySetsRouter.get('/:id', requireRole('viewer', 'operator', 'approver', 'admin'), async (req, res) => {
  const { rows } = await pool.query(`SELECT * FROM policy_sets WHERE id=$1`, [req.params.id]);
  if (!rows[0]) return res.status(404).json({ error: 'not_found' });
  res.json({ policySet: rows[0] });
});

policySetsRouter.put('/:id', requireRole('operator', 'admin'), async (req, res) => {
  const parsed = createPolicySetSchema.partial().safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body', details: parsed.error.issues });
  const b = parsed.data;

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const cur = await client.query(`SELECT * FROM policy_sets WHERE id=$1 FOR UPDATE`, [req.params.id]);
    if (!cur.rows[0]) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'not_found' });
    }
    const current = cur.rows[0];
    const scopeType = (b.scopeType ?? current.scope_type) as ScopeType;
    const typeChanged = scopeType !== current.scope_type;
    // A changed scope type starts from a clean scope: values of the old type are never carried over.
    // A rename / description change alone leaves the stored scope as it is.
    const scopeTouched = b.scopeType !== undefined || b.scopeTagId !== undefined || b.scopeVlanId !== undefined || b.hostIds !== undefined;
    const scope = !scopeTouched
      ? { scopeTagId: current.scope_tag_id, scopeVlanId: current.scope_vlan_id, hostIds: null }
      : await resolveScope(client, {
      scopeType,
      scopeTagId: b.scopeTagId !== undefined ? b.scopeTagId : typeChanged ? null : current.scope_tag_id,
      scopeVlanId: b.scopeVlanId !== undefined ? b.scopeVlanId : typeChanged ? null : current.scope_vlan_id,
      hostIds: scopeType === 'HOST_LIST' ? (b.hostIds ?? (typeChanged ? [] : null)) : null
    });

    const { rows } = await client.query(
      `UPDATE policy_sets
       SET name = COALESCE($2, name),
           description = COALESCE($3, description),
           scope_type = $4,
           scope_tag_id = $5,
           scope_vlan_id = $6
       WHERE id=$1
       RETURNING *`,
      [req.params.id, b.name ?? null, b.description ?? null, scopeType, scope.scopeTagId, scope.scopeVlanId]
    );

    if (!scopeTouched) {
      // nothing to do for the scope
    } else if (scopeType !== 'HOST_LIST') {
      await client.query(`DELETE FROM policy_set_hosts WHERE policy_set_id=$1`, [req.params.id]);
    } else if (scope.hostIds) {
      await replaceHostList(client, req.params.id, scope.hostIds);
    }

    await client.query(
      `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
       VALUES ((SELECT id FROM users WHERE username=$1 LIMIT 1), $2, $3, $4, $5)`,
      [
        req.auth!.username,
        'POLICY_SET_UPDATE',
        'policy_set',
        req.params.id,
        JSON.stringify({ policySetId: req.params.id, scopeType, scopeChanged: typeChanged, hostIds: scope.hostIds ?? undefined })
      ]
    );
    await client.query('COMMIT');
    res.json({ policySet: rows[0] });
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    if (e instanceof ScopeError) return res.status(400).json({ error: e.code, message: e.message });
    throw e;
  } finally {
    client.release();
  }
});

policySetsRouter.delete('/:id', requireRole('operator', 'admin'), async (req, res) => {
  // Only allow deletion if no versions exist
  const { rows: versionCheck } = await pool.query(
    `SELECT COUNT(*)::int as count FROM policy_versions WHERE policy_set_id = $1`,
    [req.params.id]
  );
  if (versionCheck[0]?.count > 0) {
    return res.status(400).json({
      error: 'has_versions',
      message: `Cannot delete this policy set — it has ${versionCheck[0].count} version(s). Delete all versions first.`
    });
  }

  const { rowCount } = await pool.query(`DELETE FROM policy_sets WHERE id=$1`, [req.params.id]);
  if (!rowCount) return res.status(404).json({ error: 'not_found' });

  await pool.query(
    `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
     VALUES ((SELECT id FROM users WHERE username=$1 LIMIT 1), $2, $3, $4, $5)`,
    [req.auth!.username, 'POLICY_SET_DELETE', 'policy_set', req.params.id, JSON.stringify({ policySetId: req.params.id })]
  );

  res.json({ ok: true });
});



