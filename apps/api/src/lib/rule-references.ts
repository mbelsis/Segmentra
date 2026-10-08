import { pool } from '../db/pool.js';

/**
 * Count policy / template rules that use a tag, VLAN or host as their source or (FORWARD)
 * destination. Rule sources/destinations are stored as plain ids without a foreign key, so
 * deleting a referenced object would silently turn such rules into rules matching nothing
 * (an ALLOW stops allowing, a DENY stops denying). Archived and rejected versions are ignored.
 */
export async function countRuleReferences(type: 'TAG' | 'VLAN' | 'HOST', id: string): Promise<{ policyRules: number; templateRules: number; total: number }> {
  const { rows } = await pool.query(
    `SELECT
       (SELECT COUNT(*)::int FROM policy_rules pr JOIN policy_versions pv ON pv.id = pr.policy_version_id
         WHERE pv.status NOT IN ('ARCHIVED', 'REJECTED')
           AND ((pr.source_type = $1 AND pr.source_value = $2) OR (pr.destination_type = $1 AND pr.destination_value = $2))) AS policy_rules,
       (SELECT COUNT(*)::int FROM policy_template_rules tr
         WHERE (tr.source_type = $1 AND tr.source_value = $2) OR (tr.destination_type = $1 AND tr.destination_value = $2)) AS template_rules`,
    [type, id]
  );
  const policyRules = rows[0]?.policy_rules ?? 0;
  const templateRules = rows[0]?.template_rules ?? 0;
  return { policyRules, templateRules, total: policyRules + templateRules };
}
