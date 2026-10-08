import { Router } from 'express';
import type { PoolClient } from 'pg';
import { z } from 'zod';

import { pool } from '../../db/pool.js';
import { requireAuth, requireRole } from '../../middleware/auth.js';
import { EDITABLE_VERSION_STATUSES, recordPolicyVersionEditor } from '../../lib/policy-editors.js';
import {
  interfaceNamesSchema,
  interfaceRolesSchema,
  interfaceScopeTypeSchema,
  portsSchema,
  protocolSchema,
  ruleCommentSchema,
  sourceTypeSchema,
  validateRuleSemantics
} from '../../lib/rule-validation.js';

export const policyRulesRouter = Router();
policyRulesRouter.use(requireAuth);

// GET endpoints are read-only and accessible to viewers
policyRulesRouter.get('/policy-versions/:versionId/rules', requireRole('viewer', 'operator', 'approver', 'admin'), async (req, res) => {
  const { rows } = await pool.query(
    `SELECT * FROM policy_rules WHERE policy_version_id=$1 ORDER BY order_index ASC`,
    [req.params.versionId]
  );
  res.json({ rules: rows });
});

const ruleSchema = z.object({
  orderIndex: z.number().int().min(0),
  direction: z.enum(['IN', 'OUT', 'BOTH']).default('IN'),
  action: z.enum(['ALLOW', 'DENY']),
  protocol: protocolSchema,
  // '' and null both mean "no ports"
  ports: portsSchema.or(z.literal('')).nullable().optional(),
  sourceType: sourceTypeSchema,
  sourceValue: z.string().trim().min(1),
  logMode: z.enum(['NONE', 'LOG', 'LOG_RATE_LIMITED']).default('NONE'),
  comment: ruleCommentSchema.nullable().optional(),
  usePolicyInterfaceScope: z.boolean().default(true),
  interfaceScopeType: interfaceScopeTypeSchema.optional().nullable(),
  interfaceScopeRoles: interfaceRolesSchema.optional().nullable(),
  interfaceScopeNames: interfaceNamesSchema.optional().nullable()
});

// Partial schema for PUT: no defaults, so omitted fields are really omitted (kept as-is).
const ruleUpdateSchema = z.object({
  orderIndex: z.number().int().min(0),
  direction: z.enum(['IN', 'OUT', 'BOTH']),
  action: z.enum(['ALLOW', 'DENY']),
  protocol: protocolSchema,
  ports: portsSchema.or(z.literal('')).nullable(),
  sourceType: sourceTypeSchema,
  sourceValue: z.string().trim().min(1),
  logMode: z.enum(['NONE', 'LOG', 'LOG_RATE_LIMITED']),
  comment: ruleCommentSchema.nullable(),
  usePolicyInterfaceScope: z.boolean(),
  interfaceScopeType: interfaceScopeTypeSchema.nullable(),
  interfaceScopeRoles: interfaceRolesSchema.nullable(),
  interfaceScopeNames: interfaceNamesSchema.nullable()
}).partial();

// Body key -> column. Nullable columns can be cleared by sending null explicitly.
const UPDATE_COLUMNS: Record<string, { column: string; nullable: boolean }> = {
  orderIndex: { column: 'order_index', nullable: false },
  direction: { column: 'direction', nullable: false },
  action: { column: 'action', nullable: false },
  protocol: { column: 'protocol', nullable: false },
  ports: { column: 'ports', nullable: true },
  sourceType: { column: 'source_type', nullable: false },
  sourceValue: { column: 'source_value', nullable: false },
  logMode: { column: 'log_mode', nullable: false },
  comment: { column: 'comment', nullable: true },
  usePolicyInterfaceScope: { column: 'use_policy_interface_scope', nullable: false },
  interfaceScopeType: { column: 'interface_scope_type', nullable: true },
  interfaceScopeRoles: { column: 'interface_scope_roles', nullable: true },
  interfaceScopeNames: { column: 'interface_scope_names', nullable: true }
};

/**
 * Lock the version row (FOR UPDATE) and verify it is editable, inside the caller's transaction.
 * This closes the race between "is it DRAFT?" and the write (e.g. a concurrent submit/approve).
 */
async function lockEditableVersion(client: PoolClient, versionId: string): Promise<{ ok: true } | { ok: false; status: number; body: any }> {
  const v = await client.query(`SELECT status FROM policy_versions WHERE id=$1 FOR UPDATE`, [versionId]);
  if (!v.rows[0]) return { ok: false, status: 404, body: { error: 'version_not_found' } };
  if (!EDITABLE_VERSION_STATUSES.includes(v.rows[0].status)) {
    return { ok: false, status: 400, body: { error: 'version_not_editable', message: 'Only DRAFT or REJECTED versions can be edited' } };
  }
  return { ok: true };
}

async function withTransaction<T>(fn: (client: PoolClient) => Promise<T>): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    throw e;
  } finally {
    client.release();
  }
}

class HttpError extends Error {
  constructor(public status: number, public body: any) {
    super(body?.error ?? 'http_error');
  }
}

// Write operations require operator/admin
policyRulesRouter.post('/policy-versions/:versionId/rules', requireRole('operator', 'admin'), async (req, res) => {
  const parsed = ruleSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body', details: parsed.error.issues });
  const b = parsed.data;
  const problems = validateRuleSemantics({ protocol: b.protocol, ports: b.ports ?? null, sourceType: b.sourceType, sourceValue: b.sourceValue });
  if (problems.length) return res.status(400).json({ error: 'invalid_rule', message: problems.join('; '), details: problems });

  const versionId = req.params.versionId;
  try {
    const rule = await withTransaction(async (client) => {
      const lock = await lockEditableVersion(client, versionId);
      if (!lock.ok) throw new HttpError(lock.status, lock.body);

      const { rows } = await client.query(
        `INSERT INTO policy_rules
          (policy_version_id, order_index, direction, action, protocol, ports, source_type, source_value, log_mode, comment,
           use_policy_interface_scope, interface_scope_type, interface_scope_roles, interface_scope_names)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
         RETURNING *`,
        [
          versionId,
          b.orderIndex,
          b.direction,
          b.action,
          b.protocol,
          b.ports || null,
          b.sourceType,
          b.sourceValue,
          b.logMode,
          b.comment ?? null,
          b.usePolicyInterfaceScope,
          b.interfaceScopeType ?? null,
          b.interfaceScopeRoles ?? null,
          b.interfaceScopeNames ?? null
        ]
      );
      await recordPolicyVersionEditor(client, versionId, req.auth!.userId);
      await client.query(
        `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
         VALUES ($1, $2, $3, $4, $5)`,
        [req.auth!.userId, 'POLICY_RULE_CREATE', 'policy_rule', rows[0].id, JSON.stringify({ versionId, direction: b.direction, action: b.action, protocol: b.protocol, ports: b.ports || null, sourceType: b.sourceType })]
      );
      return rows[0];
    });
    res.status(201).json({ rule });
  } catch (e) {
    if (e instanceof HttpError) return res.status(e.status).json(e.body);
    throw e;
  }
});

policyRulesRouter.put('/policy-rules/:ruleId', requireRole('operator', 'admin'), async (req, res) => {
  const parsed = ruleUpdateSchema.safeParse(req.body ?? {});
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body', details: parsed.error.issues });
  const b = parsed.data as Record<string, unknown>;

  // Only keys actually present in the body are updated; explicit null clears nullable fields.
  const presentKeys = Object.keys(UPDATE_COLUMNS).filter((k) => Object.prototype.hasOwnProperty.call(b, k) && b[k] !== undefined);
  for (const k of presentKeys) {
    if (b[k] === null && !UPDATE_COLUMNS[k].nullable) {
      return res.status(400).json({ error: 'invalid_body', message: `${k} cannot be null` });
    }
  }

  const ruleId = req.params.ruleId;
  try {
    const rule = await withTransaction(async (client) => {
      const existing = await client.query(`SELECT * FROM policy_rules WHERE id=$1`, [ruleId]);
      if (!existing.rows[0]) throw new HttpError(404, { error: 'rule_not_found' });
      const versionId = existing.rows[0].policy_version_id;

      const lock = await lockEditableVersion(client, versionId);
      if (!lock.ok) throw new HttpError(lock.status, lock.body);

      // Validate the effective rule after the update
      const cur = existing.rows[0];
      const effective = {
        protocol: (presentKeys.includes('protocol') ? b.protocol : cur.protocol) as string,
        ports: (presentKeys.includes('ports') ? b.ports : cur.ports) as string | null,
        sourceType: (presentKeys.includes('sourceType') ? b.sourceType : cur.source_type) as string,
        sourceValue: (presentKeys.includes('sourceValue') ? b.sourceValue : cur.source_value) as string
      };
      const problems = validateRuleSemantics(effective);
      if (problems.length) throw new HttpError(400, { error: 'invalid_rule', message: problems.join('; '), details: problems });

      if (presentKeys.length === 0) return cur;

      const sets: string[] = [];
      const params: unknown[] = [ruleId];
      for (const k of presentKeys) {
        let value = b[k];
        if (k === 'ports' && value === '') value = null;
        params.push(value);
        sets.push(`${UPDATE_COLUMNS[k].column} = $${params.length}`);
      }
      const { rows } = await client.query(
        `UPDATE policy_rules SET ${sets.join(', ')} WHERE id=$1 RETURNING *`,
        params
      );
      if (!rows[0]) throw new HttpError(404, { error: 'not_found' });

      await recordPolicyVersionEditor(client, versionId, req.auth!.userId);
      await client.query(
        `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
         VALUES ($1, $2, $3, $4, $5)`,
        [req.auth!.userId, 'POLICY_RULE_UPDATE', 'policy_rule', ruleId, JSON.stringify({ ruleId, versionId, fields: presentKeys })]
      );
      return rows[0];
    });
    res.json({ rule });
  } catch (e) {
    if (e instanceof HttpError) return res.status(e.status).json(e.body);
    throw e;
  }
});

policyRulesRouter.delete('/policy-rules/:ruleId', requireRole('operator', 'admin'), async (req, res) => {
  const ruleId = req.params.ruleId;
  try {
    await withTransaction(async (client) => {
      const existing = await client.query(`SELECT policy_version_id FROM policy_rules WHERE id=$1`, [ruleId]);
      if (!existing.rows[0]) throw new HttpError(404, { error: 'rule_not_found' });
      const versionId = existing.rows[0].policy_version_id;

      const lock = await lockEditableVersion(client, versionId);
      if (!lock.ok) throw new HttpError(lock.status, lock.body);

      const { rowCount } = await client.query(`DELETE FROM policy_rules WHERE id=$1`, [ruleId]);
      if (!rowCount) throw new HttpError(404, { error: 'not_found' });

      await recordPolicyVersionEditor(client, versionId, req.auth!.userId);
      await client.query(
        `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
         VALUES ($1, $2, $3, $4, $5)`,
        [req.auth!.userId, 'POLICY_RULE_DELETE', 'policy_rule', ruleId, JSON.stringify({ ruleId, versionId })]
      );
    });
    res.json({ ok: true });
  } catch (e) {
    if (e instanceof HttpError) return res.status(e.status).json(e.body);
    throw e;
  }
});
