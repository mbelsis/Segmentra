import type { PoolClient } from 'pg';

/**
 * Helpers for creating a new policy version that builds on an existing one instead of
 * replacing the whole rule set with a partial snapshot.
 */

export type BaseVersion = {
  id: string;
  version_number: number;
  status: string;
  interface_scope_type: string;
  interface_scope_roles: string[] | null;
  interface_scope_names: string[] | null;
};

/**
 * Pick the version to build on: the latest DEPLOYED/APPROVED version (what is or will be
 * enforced), otherwise the latest version of any status. Returns null for an empty set.
 * Must be called inside a transaction; locks the policy set row so concurrent writers
 * cannot allocate the same version number.
 */
export async function lockPolicySetAndGetBase(
  client: PoolClient,
  policySetId: string
): Promise<{ base: BaseVersion | null; nextVersionNumber: number } | null> {
  const lock = await client.query(`SELECT id FROM policy_sets WHERE id = $1 FOR UPDATE`, [policySetId]);
  if (!lock.rows[0]) return null;

  const { rows: baseRows } = await client.query(
    `SELECT id, version_number, status, interface_scope_type, interface_scope_roles, interface_scope_names
       FROM policy_versions
      WHERE policy_set_id = $1
      ORDER BY (status IN ('DEPLOYED', 'APPROVED')) DESC, version_number DESC
      LIMIT 1`,
    [policySetId]
  );

  const { rows: maxRows } = await client.query(
    `SELECT COALESCE(MAX(version_number), 0)::int AS v FROM policy_versions WHERE policy_set_id = $1`,
    [policySetId]
  );

  return { base: (baseRows[0] as BaseVersion) ?? null, nextVersionNumber: (maxRows[0]?.v ?? 0) + 1 };
}

/** Load every rule (all columns) of a version ordered by order_index. */
export async function loadVersionRules(client: PoolClient, versionId: string): Promise<any[]> {
  const { rows } = await client.query(
    `SELECT * FROM policy_rules WHERE policy_version_id = $1 ORDER BY order_index ASC, id ASC`,
    [versionId]
  );
  return rows;
}

/** Insert a rule row (any subset of policy_rules columns, minus id/version) into a version. */
export async function insertRule(
  client: PoolClient,
  versionId: string,
  orderIndex: number,
  rule: {
    direction?: string | null;
    action: string;
    protocol: string;
    ports?: string | null;
    source_type: string;
    source_value: string;
    log_mode?: string | null;
    comment?: string | null;
    use_policy_interface_scope?: boolean | null;
    interface_scope_type?: string | null;
    interface_scope_roles?: string[] | null;
    interface_scope_names?: string[] | null;
  }
): Promise<void> {
  await client.query(
    `INSERT INTO policy_rules
       (policy_version_id, order_index, direction, action, protocol, ports, source_type, source_value,
        log_mode, comment, use_policy_interface_scope, interface_scope_type, interface_scope_roles, interface_scope_names)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
    [
      versionId,
      orderIndex,
      rule.direction ?? 'IN',
      rule.action,
      rule.protocol,
      rule.ports ?? null,
      rule.source_type,
      rule.source_value,
      rule.log_mode ?? 'NONE',
      rule.comment ?? null,
      rule.use_policy_interface_scope ?? true,
      rule.interface_scope_type ?? null,
      rule.interface_scope_roles ?? null,
      rule.interface_scope_names ?? null,
    ]
  );
}

/** Create a DRAFT version that inherits the interface scope of `base` (or ALL_INTERFACES). */
export async function createDraftVersion(
  client: PoolClient,
  params: {
    policySetId: string;
    versionNumber: number;
    base: BaseVersion | null;
    changeSummary: string;
    createdBy: string | null;
  }
): Promise<string> {
  const { rows } = await client.query(
    `INSERT INTO policy_versions
       (policy_set_id, version_number, status, change_summary, created_by,
        interface_scope_type, interface_scope_roles, interface_scope_names)
     VALUES ($1, $2, 'DRAFT', $3, $4, $5, $6, $7) RETURNING id`,
    [
      params.policySetId,
      params.versionNumber,
      params.changeSummary,
      params.createdBy,
      params.base?.interface_scope_type ?? 'ALL_INTERFACES',
      params.base?.interface_scope_roles ?? null,
      params.base?.interface_scope_names ?? null,
    ]
  );
  return rows[0].id;
}
