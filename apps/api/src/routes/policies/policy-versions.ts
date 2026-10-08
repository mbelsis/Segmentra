import { Router } from 'express';
import { z } from 'zod';

import { pool } from '../../db/pool.js';
import { requireAuth, requireRole } from '../../middleware/auth.js';
import { comparePolicyVersions } from '../../services/policy-diff.js';
import { isPolicyVersionHighRisk } from '../../services/high-risk.js';
import { recordPolicyVersionEditor } from '../../lib/policy-editors.js';
import { interfaceNamesSchema, interfaceRolesSchema, interfaceScopeTypeSchema } from '../../lib/rule-validation.js';

export const policyVersionsRouter = Router();
policyVersionsRouter.use(requireAuth);

// GET endpoints are read-only and accessible to viewers
policyVersionsRouter.get('/policy-sets/:id/versions', requireRole('viewer', 'operator', 'approver', 'admin'), async (req, res) => {
  const { rows } = await pool.query(
    `SELECT pv.*,
       u_created.username as created_by_username,
       u_approved.username as approved_by_username,
       u_rejected.username as rejected_by_username
     FROM policy_versions pv
     LEFT JOIN users u_created ON u_created.id = pv.created_by
     LEFT JOIN users u_approved ON u_approved.id = pv.approved_by
     LEFT JOIN users u_rejected ON u_rejected.id = pv.rejected_by
     WHERE pv.policy_set_id=$1 ORDER BY pv.version_number DESC`,
    [req.params.id]
  );
  res.json({ versions: rows });
});

const createVersionSchema = z.object({
  changeSummary: z.string().max(2000).optional(),
  interfaceScopeType: interfaceScopeTypeSchema.default('INTERFACE_ROLE'),
  interfaceScopeRoles: interfaceRolesSchema.optional(),
  interfaceScopeNames: interfaceNamesSchema.optional()
});

/**
 * Lock the policy set row and compute the next version number inside the caller's transaction,
 * so concurrent creates/clones can't pick the same number (backed by the unique index from migration 025).
 * Returns null if the policy set does not exist.
 */
async function nextVersionNumber(client: { query: (text: string, params?: any[]) => Promise<any> }, policySetId: string): Promise<number | null> {
  const ps = await client.query(`SELECT id FROM policy_sets WHERE id=$1 FOR UPDATE`, [policySetId]);
  if (!ps.rows[0]) return null;
  const latest = await client.query(
    `SELECT COALESCE(MAX(version_number), 0)::int AS v FROM policy_versions WHERE policy_set_id=$1`,
    [policySetId]
  );
  return (latest.rows[0]?.v ?? 0) + 1;
}

// Write operations require operator/admin
policyVersionsRouter.post('/policy-sets/:id/versions', requireRole('operator', 'admin'), async (req, res) => {
  const parsed = createVersionSchema.safeParse(req.body ?? {});
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body', details: parsed.error.issues });
  const b = parsed.data;

  const userId = req.auth!.userId;
  if (!userId) return res.status(401).json({ error: 'user_not_found' });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const nextVersion = await nextVersionNumber(client, req.params.id);
    if (nextVersion === null) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'policy_set_not_found' });
    }

    const { rows } = await client.query(
      `INSERT INTO policy_versions
        (policy_set_id, version_number, status, change_summary, created_by, interface_scope_type, interface_scope_roles, interface_scope_names)
       VALUES ($1,$2,'DRAFT',$3,$4,$5,$6,$7)
       RETURNING *`,
      [
        req.params.id,
        nextVersion,
        b.changeSummary ?? null,
        userId,
        b.interfaceScopeType,
        b.interfaceScopeRoles ?? null,
        b.interfaceScopeNames ?? null
      ]
    );
    await recordPolicyVersionEditor(client, rows[0].id, userId);
    await client.query('COMMIT');
    res.status(201).json({ version: rows[0] });
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    throw e;
  } finally {
    client.release();
  }
});

/**
 * List all policy versions pending approval, with policy set and creator info.
 * Must be defined BEFORE the :versionId param route to avoid shadowing.
 */
policyVersionsRouter.get('/policy-versions/pending-approval', requireRole('approver', 'admin'), async (_req, res) => {
  const { rows } = await pool.query(
    `SELECT pv.id, pv.version_number, pv.status, pv.change_summary, pv.is_high_risk,
            pv.created_at, pv.submitted_at,
            pv.interface_scope_type, pv.interface_scope_roles, pv.interface_scope_names,
            pv.policy_set_id,
            ps.name AS policy_set_name, ps.scope_type AS policy_set_scope_type,
            ps.scope_tag_id, ps.scope_vlan_id,
            u.username AS created_by_username, u.display_name AS created_by_display_name,
            (SELECT COUNT(*)::int FROM policy_rules pr WHERE pr.policy_version_id = pv.id) AS rule_count
     FROM policy_versions pv
     JOIN policy_sets ps ON ps.id = pv.policy_set_id
     LEFT JOIN users u ON u.id = pv.created_by
     WHERE pv.status = 'PENDING_APPROVAL'
     ORDER BY pv.submitted_at ASC`
  );
  res.json({ versions: rows });
});

policyVersionsRouter.get('/policy-versions/:versionId', requireRole('viewer', 'operator', 'approver', 'admin'), async (req, res) => {
  const { rows } = await pool.query(`SELECT * FROM policy_versions WHERE id=$1`, [req.params.versionId]);
  if (!rows[0]) return res.status(404).json({ error: 'not_found' });
  res.json({ version: rows[0] });
});

policyVersionsRouter.put('/policy-versions/:versionId', requireRole('operator', 'admin'), async (req, res) => {
  const parsed = createVersionSchema.partial().safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body', details: parsed.error.issues });
  const b = parsed.data;
  const { rows } = await pool.query(
    `UPDATE policy_versions
     SET change_summary = COALESCE($2, change_summary),
         interface_scope_type = COALESCE($3, interface_scope_type),
         interface_scope_roles = COALESCE($4, interface_scope_roles),
         interface_scope_names = COALESCE($5, interface_scope_names)
     WHERE id=$1 AND (status='DRAFT' OR status='REJECTED')
     RETURNING *`,
    [req.params.versionId, b.changeSummary ?? null, b.interfaceScopeType ?? null, b.interfaceScopeRoles ?? null, b.interfaceScopeNames ?? null]
  );
  if (!rows[0]) return res.status(404).json({ error: 'not_found_or_not_editable' });
  await recordPolicyVersionEditor(pool, rows[0].id, req.auth!.userId);
  res.json({ version: rows[0] });
});

policyVersionsRouter.post('/policy-versions/:versionId/submit-approval', requireRole('operator', 'admin'), async (req, res) => {
  const userId = req.auth!.userId;

  // Evaluate high-risk status before submission
  const isHighRisk = await isPolicyVersionHighRisk({
    policyVersionId: req.params.versionId
  });
  
  const client = await pool.connect();
  let rows: any[] = [];
  let previousStatus: string | null = null;
  try {
    await client.query('BEGIN');
    const prev = await client.query(`SELECT status FROM policy_versions WHERE id=$1 FOR UPDATE`, [req.params.versionId]);
    previousStatus = prev.rows[0]?.status ?? null;
    if (previousStatus === 'DRAFT' || previousStatus === 'REJECTED') {
      const upd = await client.query(
        `UPDATE policy_versions
         SET status='PENDING_APPROVAL', submitted_at=now(), submitted_by=$3, rejection_reason=NULL, is_high_risk=$2
         WHERE id=$1
         RETURNING *`,
        [req.params.versionId, isHighRisk, userId]
      );
      rows = upd.rows;
    }
    await client.query('COMMIT');
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    throw e;
  } finally {
    client.release();
  }
  if (!rows[0]) return res.status(404).json({ error: 'not_found_or_not_submittable' });
  const resubmitted = previousStatus === 'REJECTED';
  await pool.query(
    `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
     VALUES ($1,'POLICY_SUBMIT','policy_version',$2,$3)`,
    [userId, req.params.versionId, { by: req.auth!.username, resubmitted, isHighRisk }]
  );
  res.json({ version: rows[0] });
});

policyVersionsRouter.post(
  '/policy-versions/:versionId/approve',
  requireRole('approver', 'admin'),
  async (req, res) => {
    const approverId = req.auth!.userId;
    if (!approverId) return res.status(401).json({ error: 'user_not_found' });

    const vRes = await pool.query(
      `SELECT created_by, submitted_by, is_high_risk,
              EXISTS (SELECT 1 FROM policy_version_editors e WHERE e.policy_version_id = pv.id AND e.user_id = $2) AS is_editor
       FROM policy_versions pv WHERE id=$1`,
      [req.params.versionId, approverId]
    );
    if (!vRes.rows[0]) return res.status(404).json({ error: 'not_found' });

    const isHighRisk = vRes.rows[0].is_high_risk === true;

    // Separation of duties: the approver must not have created, edited or submitted this version
    const v = vRes.rows[0];
    if (v.created_by === approverId || v.submitted_by === approverId || v.is_editor) {
      return res.status(403).json({
        error: 'cannot_approve_own_changes',
        message: 'You cannot approve a policy version that you created, edited or submitted. A different approver is required for separation of duties.'
      });
    }

    // Re-check the same conditions atomically with the status transition
    const { rows } = await pool.query(
      `UPDATE policy_versions pv
       SET status='APPROVED', approved_by=$2, approved_at=now()
       WHERE pv.id=$1 AND pv.status='PENDING_APPROVAL'
         AND pv.created_by IS DISTINCT FROM $2
         AND pv.submitted_by IS DISTINCT FROM $2
         AND NOT EXISTS (SELECT 1 FROM policy_version_editors e WHERE e.policy_version_id = pv.id AND e.user_id = $2)
       RETURNING *`,
      [req.params.versionId, approverId]
    );
    if (!rows[0]) return res.status(404).json({ error: 'not_found_or_not_approvable' });
    await pool.query(
      `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
       VALUES ($1,'POLICY_APPROVE','policy_version',$2,$3)`,
      [approverId, req.params.versionId, { by: req.auth!.username, isHighRisk }]
    );
    res.json({ version: rows[0] });
  }
);

policyVersionsRouter.post(
  '/policy-versions/:versionId/reject',
  requireRole('approver', 'admin'),
  async (req, res) => {
    const body = z.object({ reason: z.string().min(1) }).safeParse(req.body);
    if (!body.success) return res.status(400).json({ error: 'invalid_body' });
    const approverId = req.auth!.userId;
    if (!approverId) return res.status(401).json({ error: 'user_not_found' });

    const { rows } = await pool.query(
      `UPDATE policy_versions
       SET status='REJECTED', rejected_by=$2, rejected_at=now(), rejection_reason=$3
       WHERE id=$1 AND status='PENDING_APPROVAL'
       RETURNING *`,
      [req.params.versionId, approverId, body.data.reason]
    );
    if (!rows[0]) return res.status(404).json({ error: 'not_found_or_not_rejectable' });
    await pool.query(
      `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
       VALUES ($1,'POLICY_REJECT','policy_version',$2,$3)`,
      [approverId, req.params.versionId, { by: req.auth!.username, reason: body.data.reason }]
    );
    res.json({ version: rows[0] });
  }
);

policyVersionsRouter.post('/policy-versions/:versionId/clone', requireRole('operator', 'admin'), async (req, res) => {
  const userId = req.auth!.userId;
  if (!userId) return res.status(401).json({ error: 'user_not_found' });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Get the source version
    const sourceVersionRes = await client.query(`SELECT * FROM policy_versions WHERE id=$1`, [req.params.versionId]);
    if (!sourceVersionRes.rows[0]) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'not_found' });
    }
    const sourceVersion = sourceVersionRes.rows[0];

    // Get the next version number for this policy set (locks the policy set row)
    const nextVersion = await nextVersionNumber(client, sourceVersion.policy_set_id);
    if (nextVersion === null) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'policy_set_not_found' });
    }

    // Create new version with same settings but new version number
    const newVersionRes = await client.query(
      `INSERT INTO policy_versions
        (policy_set_id, version_number, status, change_summary, created_by, interface_scope_type, interface_scope_roles, interface_scope_names)
       VALUES ($1,$2,'DRAFT',$3,$4,$5,$6,$7)
       RETURNING *`,
      [
        sourceVersion.policy_set_id,
        nextVersion,
        sourceVersion.change_summary,
        userId,
        sourceVersion.interface_scope_type,
        sourceVersion.interface_scope_roles,
        sourceVersion.interface_scope_names
      ]
    );
    const newVersion = newVersionRes.rows[0];
    await recordPolicyVersionEditor(client, newVersion.id, userId);

    // Clone all rules from source version
    const sourceRulesRes = await client.query(
      `SELECT order_index, direction, action, protocol, ports, source_type, source_value, log_mode, comment,
              use_policy_interface_scope, interface_scope_type, interface_scope_roles, interface_scope_names
       FROM policy_rules WHERE policy_version_id=$1 ORDER BY order_index ASC`,
      [req.params.versionId]
    );

    for (const rule of sourceRulesRes.rows) {
      await client.query(
        `INSERT INTO policy_rules
          (policy_version_id, order_index, direction, action, protocol, ports, source_type, source_value, log_mode, comment,
           use_policy_interface_scope, interface_scope_type, interface_scope_roles, interface_scope_names)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
        [
          newVersion.id,
          rule.order_index,
          rule.direction,
          rule.action,
          rule.protocol,
          rule.ports,
          rule.source_type,
          rule.source_value,
          rule.log_mode,
          rule.comment,
          rule.use_policy_interface_scope,
          rule.interface_scope_type,
          rule.interface_scope_roles,
          rule.interface_scope_names
        ]
      );
    }

    // Log audit event
    await client.query(
      `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
       VALUES ($1,'POLICY_CLONE','policy_version',$2,$3)`,
      [userId, newVersion.id, { by: req.auth!.username, cloned_from: req.params.versionId, source_version_number: sourceVersion.version_number }]
    );

    await client.query('COMMIT');
    res.status(201).json({ version: newVersion });
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    throw e;
  } finally {
    client.release();
  }
});

policyVersionsRouter.get('/policy-versions/:versionId/diff', requireRole('viewer', 'operator', 'approver', 'admin'), async (req, res) => {
  const from = String(req.query.fromVersionId ?? '');
  if (!from) return res.status(400).json({ error: 'missing_fromVersionId' });

  const [a, b] = await Promise.all([
    pool.query(`SELECT * FROM policy_versions WHERE id=$1`, [from]),
    pool.query(`SELECT * FROM policy_versions WHERE id=$1`, [req.params.versionId])
  ]);
  if (!a.rows[0] || !b.rows[0]) return res.status(404).json({ error: 'not_found' });

  const [aRules, bRules] = await Promise.all([
    pool.query(
      `SELECT order_index, direction, action, protocol, ports, source_type, source_value, log_mode, comment
       FROM policy_rules WHERE policy_version_id=$1 ORDER BY order_index ASC`,
      [from]
    ),
    pool.query(
      `SELECT order_index, direction, action, protocol, ports, source_type, source_value, log_mode, comment
       FROM policy_rules WHERE policy_version_id=$1 ORDER BY order_index ASC`,
      [req.params.versionId]
    )
  ]);

  res.json({
    from: a.rows[0],
    to: b.rows[0],
    rulesFrom: aRules.rows,
    rulesTo: bRules.rows
  });
});

// Delete a DRAFT or REJECTED policy version
policyVersionsRouter.delete('/policy-versions/:versionId', requireRole('operator', 'admin'), async (req, res) => {
  const { rows } = await pool.query(`SELECT status, policy_set_id FROM policy_versions WHERE id=$1`, [req.params.versionId]);
  if (!rows[0]) return res.status(404).json({ error: 'not_found' });

  if (rows[0].status !== 'DRAFT' && rows[0].status !== 'REJECTED') {
    return res.status(400).json({
      error: 'cannot_delete',
      message: `Only DRAFT or REJECTED versions can be deleted. This version is ${rows[0].status}. Use archive instead.`
    });
  }

  // Delete atomically only if still DRAFT/REJECTED (rules cascade)
  const del = await pool.query(
    `DELETE FROM policy_versions WHERE id = $1 AND status IN ('DRAFT', 'REJECTED') RETURNING id`,
    [req.params.versionId]
  );
  if (!del.rows[0]) {
    return res.status(409).json({ error: 'cannot_delete', message: 'The version changed state and can no longer be deleted.' });
  }

  await pool.query(
    `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
     VALUES ((SELECT id FROM users WHERE username=$1 LIMIT 1), 'POLICY_VERSION_DELETE', 'policy_version', $2, $3)`,
    [req.auth!.username, req.params.versionId, JSON.stringify({ status: rows[0].status })]
  );

  res.json({ ok: true });
});

// Archive a policy version (APPROVED, DEPLOYED, or PENDING_APPROVAL)
policyVersionsRouter.post('/policy-versions/:versionId/archive', requireRole('operator', 'admin'), async (req, res) => {
  const { rows } = await pool.query(
    `UPDATE policy_versions SET status = 'ARCHIVED'
     WHERE id = $1 AND status IN ('APPROVED', 'DEPLOYED', 'PENDING_APPROVAL')
     RETURNING *`,
    [req.params.versionId]
  );
  if (!rows[0]) return res.status(404).json({ error: 'not_found_or_not_archivable', message: 'Only APPROVED, DEPLOYED, or PENDING_APPROVAL versions can be archived.' });

  await pool.query(
    `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
     VALUES ((SELECT id FROM users WHERE username=$1 LIMIT 1), 'POLICY_VERSION_ARCHIVE', 'policy_version', $2, $3)`,
    [req.auth!.username, req.params.versionId, JSON.stringify({ previousStatus: rows[0].status })]
  );

  res.json({ version: rows[0] });
});

/**
 * Get semantic diff between two policy versions for sample hosts
 * POST /policy-versions/:candidateVersionId/impact-diff
 * Body: { currentVersionId: string, hostIds: string[] }
 */
policyVersionsRouter.post('/policy-versions/:candidateVersionId/impact-diff', requireRole('viewer', 'operator', 'approver', 'admin'), async (req, res) => {
  const { currentVersionId, hostIds } = req.body;
  const candidateVersionId = req.params.candidateVersionId;

  if (!currentVersionId || !Array.isArray(hostIds) || hostIds.length === 0) {
    return res.status(400).json({ error: 'invalid_body' });
  }

  try {
    const diffResults = await comparePolicyVersions({
      currentVersionId,
      candidateVersionId,
      hostIds
    });

    res.json({ diff: diffResults });
  } catch (error: any) {
    res.status(500).json({ error: 'diff_failed', message: error.message });
  }
});


