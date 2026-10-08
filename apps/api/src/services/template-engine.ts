import { pool } from '../db/pool.js';

export async function instantiateTemplate(
  templateId: string,
  userId: string | null,
  options?: { name?: string; scopeType?: string; scopeTagId?: string; scopeVlanId?: string; hostIds?: string[] }
): Promise<{ policySet: any; version: any; rulesCreated: number }> {
  const { rows: templates } = await pool.query(`SELECT * FROM policy_templates WHERE id = $1`, [templateId]);
  if (!templates[0]) throw new Error('Template not found');
  const template = templates[0];

  const { rows: templateRules } = await pool.query(
    `SELECT * FROM policy_template_rules WHERE policy_template_id = $1 ORDER BY order_index ASC`,
    [templateId]
  );

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Create policy set
    const scopeType = options?.scopeType ?? (template.target_tag_id ? 'TAG' : 'HOST_LIST');
    const scopeTagId = options?.scopeTagId ?? template.target_tag_id;
    const psRes = await client.query(
      `INSERT INTO policy_sets (name, description, scope_type, scope_tag_id, scope_vlan_id, source_template_id, created_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
      [
        options?.name ?? `${template.name} (from template)`,
        template.description ?? `Auto-created from template: ${template.name}`,
        scopeType,
        scopeTagId ?? null,
        options?.scopeVlanId ?? null,
        templateId,
        userId
      ]
    );
    const policySet = psRes.rows[0];

    // If HOST_LIST scope, add hosts
    if (scopeType === 'HOST_LIST' && options?.hostIds?.length) {
      for (const hostId of options.hostIds) {
        await client.query(
          `INSERT INTO policy_set_hosts (policy_set_id, host_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
          [policySet.id, hostId]
        );
      }
    }

    // Create version
    const vRes = await client.query(
      `INSERT INTO policy_versions
        (policy_set_id, version_number, status, change_summary, created_by, source_template_id,
         interface_scope_type, interface_scope_roles, interface_scope_names)
       VALUES ($1, 1, 'DRAFT', $2, $3, $4, $5, $6, $7) RETURNING *`,
      [
        policySet.id,
        `Created from template: ${template.name}`,
        userId,
        templateId,
        template.interface_scope_type,
        template.interface_scope_roles,
        template.interface_scope_names
      ]
    );
    const version = vRes.rows[0];

    // Clone template rules into policy rules
    let rulesCreated = 0;
    for (const rule of templateRules) {
      await client.query(
        `INSERT INTO policy_rules
          (policy_version_id, order_index, direction, action, protocol, ports, source_type, source_value,
           log_mode, comment, use_policy_interface_scope, interface_scope_type, interface_scope_roles, interface_scope_names)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
        [
          version.id,
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
      rulesCreated++;
    }

    // Audit event
    await client.query(
      `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
       VALUES ($1, 'TEMPLATE_INSTANTIATE', 'policy_template', $2, $3)`,
      [userId, templateId, JSON.stringify({ policySetId: policySet.id, versionId: version.id, rulesCreated })]
    );

    await client.query('COMMIT');
    return { policySet, version, rulesCreated };
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
}

export async function autoApplyTemplates(tagId: string): Promise<{ templatesApplied: number }> {
  const { rows: templates } = await pool.query(
    `SELECT * FROM policy_templates WHERE auto_apply = true AND target_tag_id = $1`,
    [tagId]
  );

  let templatesApplied = 0;
  for (const template of templates) {
    // Check if there's already a policy set from this template for this tag
    const { rows: existing } = await pool.query(
      `SELECT id FROM policy_sets WHERE source_template_id = $1 AND scope_tag_id = $2`,
      [template.id, tagId]
    );
    if (existing.length > 0) continue;

    // Get system user ID for auto-apply
    const { rows: sysUser } = await pool.query(`SELECT id FROM users WHERE username = 'admin' LIMIT 1`);
    const systemUserId = sysUser[0]?.id ?? null;

    await instantiateTemplate(template.id, systemUserId, {
      scopeType: 'TAG',
      scopeTagId: tagId
    });
    templatesApplied++;
  }

  return { templatesApplied };
}

export async function previewInstantiation(templateId: string): Promise<{
  template: any;
  rules: any[];
  targetHosts: any[];
}> {
  const { rows: templates } = await pool.query(`SELECT * FROM policy_templates WHERE id = $1`, [templateId]);
  if (!templates[0]) throw new Error('Template not found');
  const template = templates[0];

  const { rows: rules } = await pool.query(
    `SELECT * FROM policy_template_rules WHERE policy_template_id = $1 ORDER BY order_index ASC`,
    [templateId]
  );

  let targetHosts: any[] = [];
  if (template.target_tag_id) {
    const { rows } = await pool.query(
      `SELECT h.id, h.hostname, h.mgmt_ip FROM hosts h
       JOIN host_tags ht ON ht.host_id = h.id
       WHERE ht.tag_id = $1 AND h.enabled = true`,
      [template.target_tag_id]
    );
    targetHosts = rows;
  }

  return { template, rules, targetHosts };
}
