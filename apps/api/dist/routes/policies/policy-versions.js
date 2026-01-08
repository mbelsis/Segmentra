import { Router } from 'express';
import { z } from 'zod';
import { pool } from '../../db/pool.js';
import { requireAuth, requireRole } from '../../middleware/auth.js';
export const policyVersionsRouter = Router();
policyVersionsRouter.use(requireAuth, requireRole('operator', 'approver', 'admin'));
policyVersionsRouter.get('/policy-sets/:id/versions', async (req, res) => {
    const { rows } = await pool.query(`SELECT * FROM policy_versions WHERE policy_set_id=$1 ORDER BY version_number DESC`, [req.params.id]);
    res.json({ versions: rows });
});
const createVersionSchema = z.object({
    changeSummary: z.string().optional(),
    interfaceScopeType: z.enum(['ALL_INTERFACES', 'INTERFACE_ROLE', 'INTERFACE_NAME']).default('INTERFACE_ROLE'),
    interfaceScopeRoles: z.array(z.string()).optional(),
    interfaceScopeNames: z.array(z.string()).optional()
});
policyVersionsRouter.post('/policy-sets/:id/versions', async (req, res) => {
    const parsed = createVersionSchema.safeParse(req.body ?? {});
    if (!parsed.success)
        return res.status(400).json({ error: 'invalid_body' });
    const b = parsed.data;
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const latest = await client.query(`SELECT COALESCE(MAX(version_number), 0)::int AS v FROM policy_versions WHERE policy_set_id=$1`, [req.params.id]);
        const nextVersion = (latest.rows[0]?.v ?? 0) + 1;
        const userRes = await client.query(`SELECT id FROM users WHERE username=$1 LIMIT 1`, [req.auth.username]);
        const userId = userRes.rows[0]?.id ?? null;
        const { rows } = await client.query(`INSERT INTO policy_versions
        (policy_set_id, version_number, status, change_summary, created_by, interface_scope_type, interface_scope_roles, interface_scope_names)
       VALUES ($1,$2,'DRAFT',$3,$4,$5,$6,$7)
       RETURNING *`, [
            req.params.id,
            nextVersion,
            b.changeSummary ?? null,
            userId,
            b.interfaceScopeType,
            b.interfaceScopeRoles ?? null,
            b.interfaceScopeNames ?? null
        ]);
        await client.query('COMMIT');
        res.status(201).json({ version: rows[0] });
    }
    catch (e) {
        await client.query('ROLLBACK');
        // eslint-disable-next-line no-console
        console.error(e);
        res.status(500).json({ error: 'create_failed' });
    }
    finally {
        client.release();
    }
});
policyVersionsRouter.get('/policy-versions/:versionId', async (req, res) => {
    const { rows } = await pool.query(`SELECT * FROM policy_versions WHERE id=$1`, [req.params.versionId]);
    if (!rows[0])
        return res.status(404).json({ error: 'not_found' });
    res.json({ version: rows[0] });
});
policyVersionsRouter.put('/policy-versions/:versionId', async (req, res) => {
    const parsed = createVersionSchema.partial().safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ error: 'invalid_body' });
    const b = parsed.data;
    const { rows } = await pool.query(`UPDATE policy_versions
     SET change_summary = COALESCE($2, change_summary),
         interface_scope_type = COALESCE($3, interface_scope_type),
         interface_scope_roles = COALESCE($4, interface_scope_roles),
         interface_scope_names = COALESCE($5, interface_scope_names)
     WHERE id=$1 AND (status='DRAFT' OR status='REJECTED')
     RETURNING *`, [req.params.versionId, b.changeSummary ?? null, b.interfaceScopeType ?? null, b.interfaceScopeRoles ?? null, b.interfaceScopeNames ?? null]);
    if (!rows[0])
        return res.status(404).json({ error: 'not_found_or_not_editable' });
    res.json({ version: rows[0] });
});
policyVersionsRouter.post('/policy-versions/:versionId/submit-approval', async (req, res) => {
    const userRes = await pool.query(`SELECT id FROM users WHERE username=$1 LIMIT 1`, [req.auth.username]);
    const userId = userRes.rows[0]?.id ?? null;
    const { rows } = await pool.query(`UPDATE policy_versions
     SET status='PENDING_APPROVAL', submitted_at=now(), rejection_reason=NULL
     WHERE id=$1 AND (status='DRAFT' OR status='REJECTED')
     RETURNING *`, [req.params.versionId]);
    if (!rows[0])
        return res.status(404).json({ error: 'not_found_or_not_submittable' });
    await pool.query(`INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
     VALUES ($1,'POLICY_SUBMIT','policy_version',$2,$3)`, [userId, req.params.versionId, { by: req.auth.username, resubmitted: rows[0].status === 'REJECTED' }]);
    res.json({ version: rows[0] });
});
policyVersionsRouter.post('/policy-versions/:versionId/approve', requireRole('approver', 'admin'), async (req, res) => {
    const userRes = await pool.query(`SELECT id FROM users WHERE username=$1 LIMIT 1`, [req.auth.username]);
    const approverId = userRes.rows[0]?.id ?? null;
    const vRes = await pool.query(`SELECT created_by FROM policy_versions WHERE id=$1`, [req.params.versionId]);
    if (!vRes.rows[0])
        return res.status(404).json({ error: 'not_found' });
    // Check if approver is the creator - allow admin override for local development
    if (vRes.rows[0].created_by && vRes.rows[0].created_by === approverId) {
        // Check if user has admin role (from auth middleware) - allow self-approval for admins
        const isAdmin = req.auth?.roles?.includes('admin') ?? false;
        if (!isAdmin) {
            // eslint-disable-next-line no-console
            console.log(`[DEBUG] User ${req.auth?.username} attempting self-approval. Roles:`, req.auth?.roles);
            return res.status(400).json({
                error: 'approver_must_differ',
                message: 'You cannot approve a policy version that you created. If you are an admin, try logging out and logging back in to refresh your session. Otherwise, please have another approver review it.'
            });
        }
        // Admin can self-approve (for local development)
        // eslint-disable-next-line no-console
        console.log(`[DEBUG] Admin ${req.auth?.username} self-approving policy version ${req.params.versionId}`);
    }
    const { rows } = await pool.query(`UPDATE policy_versions
       SET status='APPROVED', approved_by=$2, approved_at=now()
       WHERE id=$1 AND status='PENDING_APPROVAL'
       RETURNING *`, [req.params.versionId, approverId]);
    if (!rows[0])
        return res.status(404).json({ error: 'not_found_or_not_approvable' });
    await pool.query(`INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
       VALUES ($1,'POLICY_APPROVE','policy_version',$2,$3)`, [approverId, req.params.versionId, { by: req.auth.username }]);
    res.json({ version: rows[0] });
});
policyVersionsRouter.post('/policy-versions/:versionId/reject', requireRole('approver', 'admin'), async (req, res) => {
    const body = z.object({ reason: z.string().min(1) }).safeParse(req.body);
    if (!body.success)
        return res.status(400).json({ error: 'invalid_body' });
    const userRes = await pool.query(`SELECT id FROM users WHERE username=$1 LIMIT 1`, [req.auth.username]);
    const approverId = userRes.rows[0]?.id ?? null;
    const { rows } = await pool.query(`UPDATE policy_versions
       SET status='REJECTED', rejected_by=$2, rejected_at=now(), rejection_reason=$3
       WHERE id=$1 AND status='PENDING_APPROVAL'
       RETURNING *`, [req.params.versionId, approverId, body.data.reason]);
    if (!rows[0])
        return res.status(404).json({ error: 'not_found_or_not_rejectable' });
    await pool.query(`INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
       VALUES ($1,'POLICY_REJECT','policy_version',$2,$3)`, [approverId, req.params.versionId, { by: req.auth.username, reason: body.data.reason }]);
    res.json({ version: rows[0] });
});
policyVersionsRouter.post('/policy-versions/:versionId/clone', async (req, res) => {
    const userRes = await pool.query(`SELECT id FROM users WHERE username=$1 LIMIT 1`, [req.auth.username]);
    const userId = userRes.rows[0]?.id ?? null;
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
        // Get the latest version number for this policy set
        const latestRes = await client.query(`SELECT COALESCE(MAX(version_number), 0)::int AS v FROM policy_versions WHERE policy_set_id=$1`, [sourceVersion.policy_set_id]);
        const nextVersion = (latestRes.rows[0]?.v ?? 0) + 1;
        // Create new version with same settings but new version number
        const newVersionRes = await client.query(`INSERT INTO policy_versions
        (policy_set_id, version_number, status, change_summary, created_by, interface_scope_type, interface_scope_roles, interface_scope_names)
       VALUES ($1,$2,'DRAFT',$3,$4,$5,$6,$7)
       RETURNING *`, [
            sourceVersion.policy_set_id,
            nextVersion,
            sourceVersion.change_summary,
            userId,
            sourceVersion.interface_scope_type,
            sourceVersion.interface_scope_roles,
            sourceVersion.interface_scope_names
        ]);
        const newVersion = newVersionRes.rows[0];
        // Clone all rules from source version
        const sourceRulesRes = await client.query(`SELECT order_index, direction, action, protocol, ports, source_type, source_value, log_mode, comment,
              use_policy_interface_scope, interface_scope_type, interface_scope_roles, interface_scope_names
       FROM policy_rules WHERE policy_version_id=$1 ORDER BY order_index ASC`, [req.params.versionId]);
        for (const rule of sourceRulesRes.rows) {
            await client.query(`INSERT INTO policy_rules
          (policy_version_id, order_index, direction, action, protocol, ports, source_type, source_value, log_mode, comment,
           use_policy_interface_scope, interface_scope_type, interface_scope_roles, interface_scope_names)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, [
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
            ]);
        }
        // Log audit event
        await client.query(`INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
       VALUES ($1,'POLICY_CLONE','policy_version',$2,$3)`, [userId, newVersion.id, { by: req.auth.username, cloned_from: req.params.versionId, source_version_number: sourceVersion.version_number }]);
        await client.query('COMMIT');
        res.status(201).json({ version: newVersion });
    }
    catch (e) {
        await client.query('ROLLBACK');
        // eslint-disable-next-line no-console
        console.error(e);
        res.status(500).json({ error: 'clone_failed' });
    }
    finally {
        client.release();
    }
});
policyVersionsRouter.get('/policy-versions/:versionId/diff', async (req, res) => {
    const from = String(req.query.fromVersionId ?? '');
    if (!from)
        return res.status(400).json({ error: 'missing_fromVersionId' });
    const [a, b] = await Promise.all([
        pool.query(`SELECT * FROM policy_versions WHERE id=$1`, [from]),
        pool.query(`SELECT * FROM policy_versions WHERE id=$1`, [req.params.versionId])
    ]);
    if (!a.rows[0] || !b.rows[0])
        return res.status(404).json({ error: 'not_found' });
    const [aRules, bRules] = await Promise.all([
        pool.query(`SELECT order_index, direction, action, protocol, ports, source_type, source_value, log_mode, comment
       FROM policy_rules WHERE policy_version_id=$1 ORDER BY order_index ASC`, [from]),
        pool.query(`SELECT order_index, direction, action, protocol, ports, source_type, source_value, log_mode, comment
       FROM policy_rules WHERE policy_version_id=$1 ORDER BY order_index ASC`, [req.params.versionId])
    ]);
    res.json({
        from: a.rows[0],
        to: b.rows[0],
        rulesFrom: aRules.rows,
        rulesTo: bRules.rows
    });
});
