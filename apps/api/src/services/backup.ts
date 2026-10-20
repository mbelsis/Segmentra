/**
 * Application-level backup and restore.
 *
 * Exports the configuration a team builds up in Segmentra (VLANs, tags, hosts with interfaces,
 * auto-tagging rules, OT/IoT assets, policy templates, policy sets with every version and rule,
 * and two system settings) as one JSON document that refers to things by name, and imports such a
 * document into a fresh installation. Ids are never exported, so the document can be restored
 * into a database whose uuids differ.
 *
 * Not included on purpose: SSH, Kubernetes, LDAP and integration secrets (they are encrypted with
 * the installation's KEK and have to be entered again), deployment and audit history, discovery
 * profiles, notification channels, Kubernetes clusters and users. A full database dump
 * (scripts/segmentra-backup.sh) is the right tool when all of that must survive as well.
 *
 * Import semantics: everything is matched by name (VLANs by their tag number, policy versions by
 * policy set name + version number). Missing things are created, existing ones are left untouched
 * and reported, so an import is idempotent and safe to repeat. Policy versions keep the status and
 * the approval trail they had; users in that trail are matched by username and dropped when they
 * do not exist. Nothing is deployed.
 */
import type { PoolClient } from 'pg';
import { z } from 'zod';

import { pool } from '../db/pool.js';

export const BACKUP_API_VERSION = 'segmentra.io/v1';
export const BACKUP_KIND = 'Backup';

// ---------------------------------------------------------------------------------------------
// Document schema
// ---------------------------------------------------------------------------------------------

const interfaceScopeSchema = z.object({
  type: z.enum(['ALL_INTERFACES', 'INTERFACE_ROLE', 'INTERFACE_NAME']),
  roles: z.array(z.string()).nullable().optional(),
  names: z.array(z.string()).nullable().optional()
});

const selectorSchema = z.object({
  type: z.enum(['CIDR', 'TAG', 'VLAN', 'HOST', 'IOT_ASSET']),
  value: z.string().min(1)
});

const ruleSchema = z.object({
  orderIndex: z.number().int().min(0),
  direction: z.enum(['IN', 'OUT', 'BOTH', 'FORWARD']).default('IN'),
  action: z.enum(['ALLOW', 'DENY']),
  protocol: z.string().min(1),
  ports: z.string().nullable().optional(),
  source: selectorSchema,
  destination: selectorSchema.nullable().optional(),
  logMode: z.enum(['NONE', 'LOG', 'LOG_RATE_LIMITED']).default('NONE'),
  comment: z.string().nullable().optional(),
  usePolicyInterfaceScope: z.boolean().default(true),
  interfaceScope: interfaceScopeSchema.nullable().optional()
});

const versionSchema = z.object({
  versionNumber: z.number().int().min(1),
  status: z.enum(['DRAFT', 'PENDING_APPROVAL', 'APPROVED', 'REJECTED', 'DEPLOYED', 'ARCHIVED']),
  changeSummary: z.string().nullable().optional(),
  createdBy: z.string().nullable().optional(),
  createdAt: z.string().nullable().optional(),
  submittedBy: z.string().nullable().optional(),
  submittedAt: z.string().nullable().optional(),
  submissionNote: z.string().nullable().optional(),
  approvedBy: z.string().nullable().optional(),
  approvedAt: z.string().nullable().optional(),
  rejectedBy: z.string().nullable().optional(),
  rejectedAt: z.string().nullable().optional(),
  rejectionReason: z.string().nullable().optional(),
  interfaceScope: interfaceScopeSchema,
  isHighRisk: z.boolean().default(false),
  expiresAt: z.string().nullable().optional(),
  expiryAction: z.enum(['NOTIFY_ONLY', 'REMOVE', 'REVERT']).default('NOTIFY_ONLY'),
  sourceTemplate: z.string().nullable().optional(),
  rules: z.array(ruleSchema).default([])
});

const policySetSchema = z.object({
  name: z.string().min(1),
  description: z.string().nullable().optional(),
  scope: z.object({
    type: z.enum(['TAG', 'VLAN', 'HOST_LIST']),
    tag: z.string().nullable().optional(),
    vlanTag: z.number().int().nullable().optional(),
    hosts: z.array(z.string()).default([])
  }),
  sourceTemplate: z.string().nullable().optional(),
  createdBy: z.string().nullable().optional(),
  createdAt: z.string().nullable().optional(),
  versions: z.array(versionSchema).default([])
});

const templateSchema = z.object({
  name: z.string().min(1),
  description: z.string().nullable().optional(),
  category: z.string().nullable().optional(),
  targetTag: z.string().nullable().optional(),
  autoApply: z.boolean().default(false),
  interfaceScope: interfaceScopeSchema,
  rules: z.array(ruleSchema).default([])
});

const hostSchema = z.object({
  hostname: z.string().min(1),
  mgmtIp: z.string().nullable().optional(),
  sshPort: z.number().int().min(1).max(65535).default(22),
  environment: z.string().nullable().optional(),
  osFamily: z.string().nullable().optional(),
  firewallBackend: z.string().nullable().optional(),
  vlanTag: z.number().int().nullable().optional(),
  enabled: z.boolean().default(true),
  swarm: z
    .object({
      cluster: z.string().min(1),
      role: z.enum(['manager', 'worker']).nullable().optional(),
      addr: z.string().nullable().optional(),
      encryptedOverlay: z.boolean().default(false)
    })
    .nullable()
    .optional(),
  dockerPublishedPorts: z.boolean().default(false),
  tags: z.array(z.string()).default([]),
  interfaces: z
    .array(
      z.object({
        name: z.string().min(1),
        role: z.string().min(1),
        ipAddress: z.string().nullable().optional(),
        cidr: z.number().int().nullable().optional(),
        vlanTag: z.number().int().nullable().optional(),
        isPrimary: z.boolean().default(false),
        enabled: z.boolean().default(true)
      })
    )
    .default([])
});

const iotAssetSchema = z.object({
  name: z.string().min(1),
  description: z.string().nullable().optional(),
  assetType: z.string().default('sensor'),
  vendor: z.string().nullable().optional(),
  model: z.string().nullable().optional(),
  firmwareVersion: z.string().nullable().optional(),
  macAddress: z.string().nullable().optional(),
  ipAddress: z.string().nullable().optional(),
  vlanTag: z.number().int().nullable().optional(),
  zone: z.string().nullable().optional(),
  criticality: z.enum(['critical', 'high', 'medium', 'low']).default('medium'),
  fingerprint: z.record(z.unknown()).default({}),
  discoveredBy: z.string().nullable().optional(),
  enabled: z.boolean().default(true),
  gateways: z.array(z.string()).default([]),
  tags: z.array(z.string()).default([])
});

const tagRuleSchema = z.object({
  name: z.string().min(1),
  description: z.string().nullable().optional(),
  tag: z.string().min(1),
  enabled: z.boolean().default(true),
  priority: z.number().int().default(0),
  criteria: z.object({
    logic: z.enum(['AND', 'OR']).default('AND'),
    conditions: z.array(z.object({ field: z.string(), operator: z.string(), value: z.string() })).default([])
  })
});

export const backupDocumentSchema = z.object({
  apiVersion: z.literal(BACKUP_API_VERSION),
  kind: z.literal(BACKUP_KIND),
  exportedAt: z.string().optional(),
  exportedBy: z.string().nullable().optional(),
  counts: z.record(z.number()).optional(),
  data: z.object({
    settings: z
      .object({
        managementVlanTag: z.number().int().nullable().optional(),
        deploymentExecutor: z.string().nullable().optional()
      })
      .default({}),
    vlans: z.array(z.object({ vlanTag: z.number().int(), name: z.string().min(1), description: z.string().nullable().optional(), subnet: z.string().nullable().optional() })).default([]),
    tags: z.array(z.object({ name: z.string().min(1), description: z.string().nullable().optional(), isSystem: z.boolean().default(false) })).default([]),
    hosts: z.array(hostSchema).default([]),
    tagRules: z.array(tagRuleSchema).default([]),
    iotAssets: z.array(iotAssetSchema).default([]),
    policyTemplates: z.array(templateSchema).default([]),
    policySets: z.array(policySetSchema).default([])
  })
});

export type BackupDocument = z.infer<typeof backupDocumentSchema>;

// ---------------------------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------------------------

type Db = Pick<PoolClient, 'query'>;

function scopeOut(type: string, roles: string[] | null, names: string[] | null) {
  return { type, roles: roles ?? null, names: names ?? null };
}

async function nameMaps(db: Db) {
  const [tags, vlans, hosts, assets, users, templates] = await Promise.all([
    db.query(`SELECT id, name FROM tags`),
    db.query(`SELECT id, vlan_tag FROM vlans`),
    db.query(`SELECT id, hostname FROM hosts`),
    db.query(`SELECT id, name FROM iot_assets`),
    db.query(`SELECT id, username FROM users`),
    db.query(`SELECT id, name FROM policy_templates`)
  ]);
  return {
    tag: new Map<string, string>(tags.rows.map((r: any) => [r.id, r.name])),
    vlan: new Map<string, number>(vlans.rows.map((r: any) => [r.id, Number(r.vlan_tag)])),
    host: new Map<string, string>(hosts.rows.map((r: any) => [r.id, r.hostname])),
    asset: new Map<string, string>(assets.rows.map((r: any) => [r.id, r.name])),
    user: new Map<string, string>(users.rows.map((r: any) => [r.id, r.username])),
    template: new Map<string, string>(templates.rows.map((r: any) => [r.id, r.name]))
  };
}

type Maps = Awaited<ReturnType<typeof nameMaps>>;

/** Turn a stored selector (ids for TAG/VLAN/HOST/IOT_ASSET) into a name-based one. */
function selectorOut(type: string, value: string, maps: Maps, warnings: string[], where: string) {
  switch (type) {
    case 'TAG': {
      const n = maps.tag.get(value);
      if (!n) warnings.push(`${where}: tag ${value} no longer exists; the raw id was exported`);
      return { type, value: n ?? value };
    }
    case 'VLAN': {
      const n = maps.vlan.get(value);
      if (n === undefined) warnings.push(`${where}: VLAN ${value} no longer exists; the raw id was exported`);
      return { type, value: n === undefined ? value : String(n) };
    }
    case 'HOST': {
      const n = maps.host.get(value);
      if (!n) warnings.push(`${where}: host ${value} no longer exists; the raw id was exported`);
      return { type, value: n ?? value };
    }
    case 'IOT_ASSET': {
      const n = maps.asset.get(value);
      if (!n) warnings.push(`${where}: IoT asset ${value} no longer exists; the raw id was exported`);
      return { type, value: n ?? value };
    }
    default:
      return { type, value };
  }
}

function ruleOut(r: any, maps: Maps, warnings: string[], where: string) {
  return {
    orderIndex: Number(r.order_index),
    direction: r.direction ?? 'IN',
    action: r.action,
    protocol: r.protocol,
    ports: r.ports ?? null,
    source: selectorOut(r.source_type, r.source_value, maps, warnings, where),
    destination: r.destination_type ? selectorOut(r.destination_type, r.destination_value, maps, warnings, where) : null,
    logMode: r.log_mode ?? 'NONE',
    comment: r.comment ?? null,
    usePolicyInterfaceScope: r.use_policy_interface_scope !== false,
    interfaceScope: r.interface_scope_type ? scopeOut(r.interface_scope_type, r.interface_scope_roles, r.interface_scope_names) : null
  };
}

const iso = (v: any) => (v ? new Date(v).toISOString() : null);

export async function buildBackup(exportedBy: string | null, db: Db = pool): Promise<{ document: BackupDocument; warnings: string[] }> {
  const warnings: string[] = [];
  const maps = await nameMaps(db);

  const settingsRes = await db.query(`SELECT key, value FROM system_settings WHERE key IN ('management_vlan_id', 'deployment_executor')`);
  const settings: Record<string, string> = Object.fromEntries(settingsRes.rows.map((r: any) => [r.key, r.value]));
  const mgmtVlanTag = settings.management_vlan_id ? (maps.vlan.get(settings.management_vlan_id) ?? null) : null;

  const vlans = (await db.query(`SELECT vlan_tag, name, description, subnet FROM vlans ORDER BY vlan_tag`)).rows.map((v: any) => ({
    vlanTag: Number(v.vlan_tag),
    name: v.name,
    description: v.description ?? null,
    subnet: v.subnet ?? null
  }));

  const tags = (await db.query(`SELECT name, description, is_system FROM tags ORDER BY name`)).rows.map((t: any) => ({
    name: t.name,
    description: t.description ?? null,
    isSystem: Boolean(t.is_system)
  }));

  const hostRows = (await db.query(`SELECT * FROM hosts ORDER BY hostname`)).rows;
  const hostTags = (await db.query(`SELECT ht.host_id, t.name FROM host_tags ht JOIN tags t ON t.id = ht.tag_id WHERE ht.source <> 'rule' ORDER BY t.name`)).rows;
  const ifaces = (await db.query(`SELECT * FROM host_interfaces ORDER BY host_id, name`)).rows;
  const hosts = hostRows.map((h: any) => ({
    hostname: h.hostname,
    mgmtIp: h.mgmt_ip ? String(h.mgmt_ip).split('/')[0] : null,
    sshPort: Number(h.ssh_port) || 22,
    environment: h.environment ?? null,
    osFamily: h.os_family ?? null,
    firewallBackend: h.firewall_backend ?? null,
    vlanTag: h.vlan_id ? (maps.vlan.get(h.vlan_id) ?? null) : null,
    enabled: Boolean(h.enabled),
    swarm: h.swarm_cluster
      ? { cluster: h.swarm_cluster, role: h.swarm_role ?? null, addr: h.swarm_addr ?? null, encryptedOverlay: Boolean(h.swarm_encrypted_overlay) }
      : null,
    dockerPublishedPorts: Boolean(h.docker_published_ports),
    tags: hostTags.filter((x: any) => x.host_id === h.id).map((x: any) => x.name),
    interfaces: ifaces
      .filter((i: any) => i.host_id === h.id)
      .map((i: any) => ({
        name: i.name,
        role: i.role,
        ipAddress: i.ip_address ? String(i.ip_address).split('/')[0] : null,
        cidr: i.cidr === null || i.cidr === undefined ? null : Number(i.cidr),
        vlanTag: i.vlan_id ? (maps.vlan.get(i.vlan_id) ?? null) : null,
        isPrimary: Boolean(i.is_primary),
        enabled: i.enabled !== false
      }))
  }));

  const tagRules = (await db.query(`SELECT r.*, t.name AS tag_name FROM tag_rules r JOIN tags t ON t.id = r.tag_id ORDER BY r.priority DESC, r.name`)).rows.map((r: any) => {
    const criteria = r.criteria ?? { logic: 'AND', conditions: [] };
    // vlan_id conditions carry an id; rewrite them to the equivalent vlan_tag condition so they survive a restore
    const conditions = (criteria.conditions ?? []).map((c: any) => {
      if (c.field === 'vlan_id') {
        const tag = maps.vlan.get(String(c.value));
        if (tag !== undefined) return { ...c, field: 'vlan_tag', value: String(tag) };
        warnings.push(`auto-tagging rule "${r.name}": VLAN ${c.value} no longer exists; the condition was exported unchanged`);
      }
      return c;
    });
    return {
      name: r.name,
      description: r.description ?? null,
      tag: r.tag_name,
      enabled: Boolean(r.enabled),
      priority: Number(r.priority) || 0,
      criteria: { logic: criteria.logic ?? 'AND', conditions }
    };
  });

  const assetRows = (await db.query(`SELECT * FROM iot_assets ORDER BY name`)).rows;
  const assetGateways = (await db.query(`SELECT g.asset_id, h.hostname FROM iot_asset_gateways g JOIN hosts h ON h.id = g.host_id ORDER BY h.hostname`)).rows;
  const assetTags = (await db.query(`SELECT it.asset_id, t.name FROM iot_asset_tags it JOIN tags t ON t.id = it.tag_id ORDER BY t.name`)).rows;
  const iotAssets = assetRows.map((a: any) => ({
    name: a.name,
    description: a.description ?? null,
    assetType: a.asset_type ?? 'sensor',
    vendor: a.vendor ?? null,
    model: a.model ?? null,
    firmwareVersion: a.firmware_version ?? null,
    macAddress: a.mac_address ?? null,
    ipAddress: a.ip_address ?? null,
    vlanTag: a.vlan_id ? (maps.vlan.get(a.vlan_id) ?? null) : null,
    zone: a.zone ?? null,
    criticality: a.criticality ?? 'medium',
    fingerprint: a.fingerprint ?? {},
    discoveredBy: a.discovered_by ?? null,
    enabled: a.enabled !== false,
    gateways: assetGateways.filter((g: any) => g.asset_id === a.id).map((g: any) => g.hostname),
    tags: assetTags.filter((t: any) => t.asset_id === a.id).map((t: any) => t.name)
  }));

  const templateRows = (await db.query(`SELECT * FROM policy_templates ORDER BY name`)).rows;
  const templateRules = (await db.query(`SELECT * FROM policy_template_rules ORDER BY policy_template_id, order_index`)).rows;
  const policyTemplates = templateRows.map((t: any) => ({
    name: t.name,
    description: t.description ?? null,
    category: t.category ?? null,
    targetTag: t.target_tag_id ? (maps.tag.get(t.target_tag_id) ?? null) : null,
    autoApply: Boolean(t.auto_apply),
    interfaceScope: scopeOut(t.interface_scope_type ?? 'ALL_INTERFACES', t.interface_scope_roles, t.interface_scope_names),
    rules: templateRules.filter((r: any) => r.policy_template_id === t.id).map((r: any) => ruleOut(r, maps, warnings, `template "${t.name}"`))
  }));

  const setRows = (await db.query(`SELECT * FROM policy_sets ORDER BY name`)).rows;
  const setHosts = (await db.query(`SELECT ph.policy_set_id, h.hostname FROM policy_set_hosts ph JOIN hosts h ON h.id = ph.host_id ORDER BY h.hostname`)).rows;
  const versionRows = (await db.query(`SELECT * FROM policy_versions ORDER BY policy_set_id, version_number`)).rows;
  const ruleRows = (await db.query(`SELECT * FROM policy_rules ORDER BY policy_version_id, order_index`)).rows;
  const policySets = setRows
    .filter((s: any) => {
      if (['TAG', 'VLAN', 'HOST_LIST'].includes(s.scope_type)) return true;
      warnings.push(`policy set "${s.name}" has scope ${s.scope_type}, which is not exported`);
      return false;
    })
    .map((s: any) => ({
      name: s.name,
      description: s.description ?? null,
      scope: {
        type: s.scope_type,
        tag: s.scope_tag_id ? (maps.tag.get(s.scope_tag_id) ?? null) : null,
        vlanTag: s.scope_vlan_id ? (maps.vlan.get(s.scope_vlan_id) ?? null) : null,
        hosts: setHosts.filter((x: any) => x.policy_set_id === s.id).map((x: any) => x.hostname)
      },
      sourceTemplate: s.source_template_id ? (maps.template.get(s.source_template_id) ?? null) : null,
      createdBy: s.created_by ? (maps.user.get(s.created_by) ?? null) : null,
      createdAt: iso(s.created_at),
      versions: versionRows
        .filter((v: any) => v.policy_set_id === s.id)
        .map((v: any) => ({
          versionNumber: Number(v.version_number),
          status: v.status,
          changeSummary: v.change_summary ?? null,
          createdBy: v.created_by ? (maps.user.get(v.created_by) ?? null) : null,
          createdAt: iso(v.created_at),
          submittedBy: v.submitted_by ? (maps.user.get(v.submitted_by) ?? null) : null,
          submittedAt: iso(v.submitted_at),
          submissionNote: v.submission_note ?? null,
          approvedBy: v.approved_by ? (maps.user.get(v.approved_by) ?? null) : null,
          approvedAt: iso(v.approved_at),
          rejectedBy: v.rejected_by ? (maps.user.get(v.rejected_by) ?? null) : null,
          rejectedAt: iso(v.rejected_at),
          rejectionReason: v.rejection_reason ?? null,
          interfaceScope: scopeOut(v.interface_scope_type, v.interface_scope_roles, v.interface_scope_names),
          isHighRisk: Boolean(v.is_high_risk),
          expiresAt: iso(v.expires_at),
          expiryAction: v.expiry_action ?? 'NOTIFY_ONLY',
          sourceTemplate: v.source_template_id ? (maps.template.get(v.source_template_id) ?? null) : null,
          rules: ruleRows
            .filter((r: any) => r.policy_version_id === v.id)
            .map((r: any) => ruleOut(r, maps, warnings, `policy set "${s.name}" v${v.version_number}`))
        }))
    }));

  // Validated through the import schema so every export is guaranteed to be importable.
  const document: BackupDocument = backupDocumentSchema.parse({
    apiVersion: BACKUP_API_VERSION,
    kind: BACKUP_KIND,
    exportedAt: new Date().toISOString(),
    exportedBy,
    counts: {
      vlans: vlans.length,
      tags: tags.length,
      hosts: hosts.length,
      tagRules: tagRules.length,
      iotAssets: iotAssets.length,
      policyTemplates: policyTemplates.length,
      policySets: policySets.length,
      policyVersions: policySets.reduce((n, s) => n + s.versions.length, 0),
      policyRules: policySets.reduce((n, s) => n + s.versions.reduce((m, v) => m + v.rules.length, 0), 0)
    },
    data: {
      settings: { managementVlanTag: mgmtVlanTag, deploymentExecutor: settings.deployment_executor ?? null },
      vlans,
      tags,
      hosts,
      tagRules,
      iotAssets,
      policyTemplates,
      policySets
    }
  });
  return { document, warnings };
}

// ---------------------------------------------------------------------------------------------
// Import
// ---------------------------------------------------------------------------------------------

export type ImportCounts = { created: number; skipped: number };
export type ImportResult = {
  dryRun: boolean;
  counts: Record<string, ImportCounts>;
  warnings: string[];
  problems: Array<{ path: string; message: string }>;
};

/** Parse and validate a backup document; returns every problem with its path. */
export function parseBackupDocument(raw: unknown): { document?: BackupDocument; problems: Array<{ path: string; message: string }> } {
  const parsed = backupDocumentSchema.safeParse(raw);
  if (!parsed.success) {
    return { problems: parsed.error.issues.map((i) => ({ path: i.path.join('.') || '(root)', message: i.message })) };
  }
  return { document: parsed.data, problems: [] };
}

class Resolver {
  tags = new Map<string, string>();
  vlans = new Map<number, string>();
  hosts = new Map<string, string>();
  assets = new Map<string, string>();
  users = new Map<string, string>();
  templates = new Map<string, string>();

  constructor(private db: Db) {}

  async load() {
    const [t, v, h, a, u, p] = await Promise.all([
      this.db.query(`SELECT id, name FROM tags`),
      this.db.query(`SELECT id, vlan_tag FROM vlans`),
      this.db.query(`SELECT id, hostname FROM hosts`),
      this.db.query(`SELECT id, name FROM iot_assets`),
      this.db.query(`SELECT id, username FROM users`),
      this.db.query(`SELECT id, name FROM policy_templates`)
    ]);
    for (const r of t.rows) this.tags.set(r.name, r.id);
    for (const r of v.rows) this.vlans.set(Number(r.vlan_tag), r.id);
    for (const r of h.rows) this.hosts.set(r.hostname, r.id);
    for (const r of a.rows) this.assets.set(r.name, r.id);
    for (const r of u.rows) this.users.set(r.username, r.id);
    for (const r of p.rows) this.templates.set(r.name, r.id);
  }

  user(username: string | null | undefined): string | null {
    return username ? (this.users.get(username) ?? null) : null;
  }

  /** Name-based selector -> stored selector (ids). Returns null when the referenced thing is missing. */
  selector(sel: { type: string; value: string }): { type: string; value: string } | null {
    switch (sel.type) {
      case 'CIDR':
        return sel;
      case 'TAG': {
        const id = this.tags.get(sel.value);
        return id ? { type: 'TAG', value: id } : null;
      }
      case 'VLAN': {
        const id = this.vlans.get(Number(sel.value));
        return id ? { type: 'VLAN', value: id } : null;
      }
      case 'HOST': {
        const id = this.hosts.get(sel.value);
        return id ? { type: 'HOST', value: id } : null;
      }
      case 'IOT_ASSET': {
        const id = this.assets.get(sel.value);
        return id ? { type: 'IOT_ASSET', value: id } : null;
      }
      default:
        return null;
    }
  }
}

function count(counts: Record<string, ImportCounts>, key: string, what: 'created' | 'skipped') {
  counts[key] ??= { created: 0, skipped: 0 };
  counts[key][what] += 1;
}

type RuleIn = z.infer<typeof ruleSchema>;

async function insertRules(
  db: Db,
  table: 'policy_rules' | 'policy_template_rules',
  fkColumn: 'policy_version_id' | 'policy_template_id',
  ownerId: string,
  rules: RuleIn[],
  res: Resolver,
  warnings: string[],
  where: string
): Promise<number> {
  let inserted = 0;
  for (const r of rules) {
    const src = res.selector(r.source);
    if (!src) {
      warnings.push(`${where}: rule #${r.orderIndex} skipped, its source ${r.source.type} "${r.source.value}" does not exist`);
      continue;
    }
    let dst: { type: string; value: string } | null = null;
    if (r.direction === 'FORWARD') {
      if (!r.destination) {
        warnings.push(`${where}: FORWARD rule #${r.orderIndex} skipped, it has no destination`);
        continue;
      }
      dst = res.selector(r.destination);
      if (!dst) {
        warnings.push(`${where}: rule #${r.orderIndex} skipped, its destination ${r.destination.type} "${r.destination.value}" does not exist`);
        continue;
      }
    }
    const scope = r.interfaceScope ?? null;
    await db.query(
      `INSERT INTO ${table}
         (${fkColumn}, order_index, direction, action, protocol, ports, source_type, source_value, destination_type, destination_value,
          log_mode, comment, use_policy_interface_scope, interface_scope_type, interface_scope_roles, interface_scope_names)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
      [
        ownerId,
        r.orderIndex,
        r.direction,
        r.action,
        r.protocol,
        r.ports || null,
        src.type,
        src.value,
        dst?.type ?? null,
        dst?.value ?? null,
        r.logMode,
        r.comment ?? null,
        r.usePolicyInterfaceScope,
        scope?.type ?? null,
        scope?.roles ?? null,
        scope?.names ?? null
      ]
    );
    inserted += 1;
  }
  return inserted;
}

/**
 * Import a backup document. Runs in one transaction; with dryRun the transaction is rolled back
 * and the result shows what would happen.
 */
export async function importBackup(document: BackupDocument, opts: { dryRun: boolean; actorUserId: string | null; actorUsername: string }): Promise<ImportResult> {
  const warnings: string[] = [];
  const counts: Record<string, ImportCounts> = {};
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const res = new Resolver(client);
    await res.load();
    const d = document.data;

    // VLANs
    for (const v of d.vlans) {
      if (res.vlans.has(v.vlanTag)) {
        count(counts, 'vlans', 'skipped');
        continue;
      }
      const { rows } = await client.query(
        `INSERT INTO vlans (vlan_tag, name, description, subnet) VALUES ($1,$2,$3,$4) RETURNING id`,
        [v.vlanTag, v.name, v.description ?? null, v.subnet ?? null]
      );
      res.vlans.set(v.vlanTag, rows[0].id);
      count(counts, 'vlans', 'created');
    }

    // Tags
    for (const t of d.tags) {
      if (res.tags.has(t.name)) {
        count(counts, 'tags', 'skipped');
        continue;
      }
      const { rows } = await client.query(`INSERT INTO tags (name, description, is_system) VALUES ($1,$2,$3) RETURNING id`, [t.name, t.description ?? null, t.isSystem]);
      res.tags.set(t.name, rows[0].id);
      count(counts, 'tags', 'created');
    }

    const vlanId = (tag: number | null | undefined, where: string): string | null => {
      if (tag === null || tag === undefined) return null;
      const id = res.vlans.get(tag);
      if (!id) warnings.push(`${where}: VLAN ${tag} does not exist; left without VLAN`);
      return id ?? null;
    };
    const tagIds = (names: string[], where: string): string[] => {
      const ids: string[] = [];
      for (const n of names) {
        const id = res.tags.get(n);
        if (id) ids.push(id);
        else warnings.push(`${where}: tag "${n}" does not exist; not assigned`);
      }
      return ids;
    };

    // Hosts
    for (const h of d.hosts) {
      const where = `host "${h.hostname}"`;
      if (res.hosts.has(h.hostname)) {
        count(counts, 'hosts', 'skipped');
        continue;
      }
      const { rows } = await client.query(
        `INSERT INTO hosts (hostname, mgmt_ip, ssh_port, environment, os_family, firewall_backend, vlan_id, enabled,
                            swarm_cluster, swarm_role, swarm_addr, swarm_encrypted_overlay, docker_published_ports)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING id`,
        [
          h.hostname,
          h.mgmtIp ?? null,
          h.sshPort,
          h.environment ?? null,
          h.osFamily ?? null,
          h.firewallBackend ?? null,
          vlanId(h.vlanTag, where),
          h.enabled,
          h.swarm?.cluster ?? null,
          h.swarm?.role ?? null,
          h.swarm?.addr ?? null,
          h.swarm?.encryptedOverlay ?? false,
          h.dockerPublishedPorts
        ]
      );
      const hostId = rows[0].id;
      res.hosts.set(h.hostname, hostId);
      for (const tid of tagIds(h.tags, where)) {
        await client.query(`INSERT INTO host_tags (host_id, tag_id, source) VALUES ($1,$2,'manual') ON CONFLICT DO NOTHING`, [hostId, tid]);
      }
      for (const i of h.interfaces) {
        await client.query(
          `INSERT INTO host_interfaces (host_id, name, role, ip_address, cidr, vlan_id, is_primary, enabled) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
          [hostId, i.name, i.role, i.ipAddress ?? null, i.cidr ?? null, vlanId(i.vlanTag, `${where} interface ${i.name}`), i.isPrimary, i.enabled]
        );
      }
      count(counts, 'hosts', 'created');
    }

    // Auto-tagging rules (matched by name)
    const existingRules = new Set((await client.query(`SELECT name FROM tag_rules`)).rows.map((r: any) => r.name));
    for (const r of d.tagRules) {
      if (existingRules.has(r.name)) {
        count(counts, 'tagRules', 'skipped');
        continue;
      }
      const tagId = res.tags.get(r.tag);
      if (!tagId) {
        warnings.push(`auto-tagging rule "${r.name}" skipped: tag "${r.tag}" does not exist`);
        continue;
      }
      await client.query(
        `INSERT INTO tag_rules (tag_id, name, description, enabled, priority, criteria, created_by) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
        [tagId, r.name, r.description ?? null, r.enabled, r.priority, JSON.stringify(r.criteria), opts.actorUserId]
      );
      count(counts, 'tagRules', 'created');
    }

    // IoT assets
    for (const a of d.iotAssets) {
      const where = `IoT asset "${a.name}"`;
      if (res.assets.has(a.name)) {
        count(counts, 'iotAssets', 'skipped');
        continue;
      }
      const { rows } = await client.query(
        `INSERT INTO iot_assets (name, description, asset_type, vendor, model, firmware_version, mac_address, ip_address, vlan_id, zone,
                                 criticality, fingerprint, discovered_by, enabled)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) RETURNING id`,
        [
          a.name,
          a.description ?? null,
          a.assetType,
          a.vendor ?? null,
          a.model ?? null,
          a.firmwareVersion ?? null,
          a.macAddress ?? null,
          a.ipAddress ?? null,
          vlanId(a.vlanTag, where),
          a.zone ?? null,
          a.criticality,
          JSON.stringify(a.fingerprint ?? {}),
          a.discoveredBy ?? null,
          a.enabled
        ]
      );
      const assetId = rows[0].id;
      res.assets.set(a.name, assetId);
      for (const g of a.gateways) {
        const hostId = res.hosts.get(g);
        if (!hostId) {
          warnings.push(`${where}: gateway host "${g}" does not exist; not assigned`);
          continue;
        }
        await client.query(`INSERT INTO iot_asset_gateways (asset_id, host_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`, [assetId, hostId]);
      }
      for (const tid of tagIds(a.tags, where)) {
        await client.query(`INSERT INTO iot_asset_tags (asset_id, tag_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`, [assetId, tid]);
      }
      count(counts, 'iotAssets', 'created');
    }

    // Policy templates
    for (const t of d.policyTemplates) {
      const where = `template "${t.name}"`;
      if (res.templates.has(t.name)) {
        count(counts, 'policyTemplates', 'skipped');
        continue;
      }
      let targetTagId: string | null = null;
      if (t.targetTag) {
        targetTagId = res.tags.get(t.targetTag) ?? null;
        if (!targetTagId) warnings.push(`${where}: target tag "${t.targetTag}" does not exist; auto-apply target left empty`);
      }
      const { rows } = await client.query(
        `INSERT INTO policy_templates (name, description, category, target_tag_id, auto_apply, interface_scope_type, interface_scope_roles, interface_scope_names, created_by)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id`,
        [t.name, t.description ?? null, t.category ?? null, targetTagId, t.autoApply && !!targetTagId, t.interfaceScope.type, t.interfaceScope.roles ?? null, t.interfaceScope.names ?? null, opts.actorUserId]
      );
      res.templates.set(t.name, rows[0].id);
      await insertRules(client, 'policy_template_rules', 'policy_template_id', rows[0].id, t.rules, res, warnings, where);
      count(counts, 'policyTemplates', 'created');
    }

    // Policy sets, versions and rules
    const existingSets = new Map<string, string>((await client.query(`SELECT id, name FROM policy_sets`)).rows.map((r: any) => [r.name, r.id]));
    for (const s of d.policySets) {
      const where = `policy set "${s.name}"`;
      let setId = existingSets.get(s.name) ?? null;
      let existingVersions = new Set<number>();
      if (setId) {
        count(counts, 'policySets', 'skipped');
        existingVersions = new Set((await client.query(`SELECT version_number FROM policy_versions WHERE policy_set_id=$1`, [setId])).rows.map((r: any) => Number(r.version_number)));
      } else {
        let scopeTagId: string | null = null;
        let scopeVlanId: string | null = null;
        if (s.scope.type === 'TAG') {
          scopeTagId = s.scope.tag ? (res.tags.get(s.scope.tag) ?? null) : null;
          if (!scopeTagId) {
            warnings.push(`${where} skipped: its scope tag "${s.scope.tag ?? ''}" does not exist`);
            continue;
          }
        } else if (s.scope.type === 'VLAN') {
          scopeVlanId = s.scope.vlanTag !== null && s.scope.vlanTag !== undefined ? (res.vlans.get(s.scope.vlanTag) ?? null) : null;
          if (!scopeVlanId) {
            warnings.push(`${where} skipped: its scope VLAN ${s.scope.vlanTag ?? ''} does not exist`);
            continue;
          }
        }
        const { rows } = await client.query(
          `INSERT INTO policy_sets (name, description, scope_type, scope_tag_id, scope_vlan_id, created_by, created_at, source_template_id)
           VALUES ($1,$2,$3,$4,$5,$6,COALESCE($7::timestamptz, now()),$8) RETURNING id`,
          [s.name, s.description ?? null, s.scope.type, scopeTagId, scopeVlanId, res.user(s.createdBy) ?? opts.actorUserId, s.createdAt ?? null, s.sourceTemplate ? (res.templates.get(s.sourceTemplate) ?? null) : null]
        );
        setId = rows[0].id;
        existingSets.set(s.name, setId!);
        if (s.scope.type === 'HOST_LIST') {
          for (const hn of s.scope.hosts) {
            const hostId = res.hosts.get(hn);
            if (!hostId) {
              warnings.push(`${where}: scope host "${hn}" does not exist; not added to the host list`);
              continue;
            }
            await client.query(`INSERT INTO policy_set_hosts (policy_set_id, host_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`, [setId, hostId]);
          }
        }
        count(counts, 'policySets', 'created');
      }

      for (const v of s.versions) {
        if (existingVersions.has(v.versionNumber)) {
          count(counts, 'policyVersions', 'skipped');
          continue;
        }
        const vWhere = `${where} v${v.versionNumber}`;
        const { rows } = await client.query(
          `INSERT INTO policy_versions
             (policy_set_id, version_number, status, change_summary, created_by, created_at, submitted_by, submitted_at, submission_note,
              approved_by, approved_at, rejected_by, rejected_at, rejection_reason, interface_scope_type, interface_scope_roles,
              interface_scope_names, is_high_risk, expires_at, expiry_action, source_template_id)
           VALUES ($1,$2,$3,$4,$5,COALESCE($6::timestamptz, now()),$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21) RETURNING id`,
          [
            setId,
            v.versionNumber,
            v.status,
            v.changeSummary ?? null,
            res.user(v.createdBy) ?? opts.actorUserId,
            v.createdAt ?? null,
            res.user(v.submittedBy),
            v.submittedAt ?? null,
            v.submissionNote ?? null,
            res.user(v.approvedBy),
            v.approvedAt ?? null,
            res.user(v.rejectedBy),
            v.rejectedAt ?? null,
            v.rejectionReason ?? null,
            v.interfaceScope.type,
            v.interfaceScope.roles ?? null,
            v.interfaceScope.names ?? null,
            v.isHighRisk,
            v.expiresAt ?? null,
            v.expiryAction,
            v.sourceTemplate ? (res.templates.get(v.sourceTemplate) ?? null) : null
          ]
        );
        const inserted = await insertRules(client, 'policy_rules', 'policy_version_id', rows[0].id, v.rules, res, warnings, vWhere);
        counts.policyRules ??= { created: 0, skipped: 0 };
        counts.policyRules.created += inserted;
        counts.policyRules.skipped += v.rules.length - inserted;
        count(counts, 'policyVersions', 'created');
      }
    }

    // Settings: only filled in when empty here
    const settings = d.settings ?? {};
    if (settings.managementVlanTag !== null && settings.managementVlanTag !== undefined) {
      const current = await client.query(`SELECT value FROM system_settings WHERE key='management_vlan_id'`);
      const id = res.vlans.get(settings.managementVlanTag);
      if (current.rows[0]?.value) {
        warnings.push(`management VLAN already set here; the backup's VLAN ${settings.managementVlanTag} was not applied`);
      } else if (!id) {
        warnings.push(`management VLAN ${settings.managementVlanTag} does not exist; setting not applied`);
      } else {
        await client.query(
          `INSERT INTO system_settings (key, value, description) VALUES ('management_vlan_id', $1, 'Management VLAN for baseline SSH access')
           ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
          [id]
        );
        count(counts, 'settings', 'created');
      }
    }
    if (settings.deploymentExecutor) {
      const current = await client.query(`SELECT value FROM system_settings WHERE key='deployment_executor'`);
      if (current.rows[0]?.value) {
        count(counts, 'settings', 'skipped');
      } else {
        await client.query(
          `INSERT INTO system_settings (key, value, description) VALUES ('deployment_executor', $1, 'Deployment executor')
           ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
          [settings.deploymentExecutor]
        );
        count(counts, 'settings', 'created');
      }
    }

    if (!opts.dryRun) {
      await client.query(
        `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
         VALUES ($1, 'BACKUP_IMPORT', 'backup', uuid_generate_v4(), $2)`,
        [opts.actorUserId, JSON.stringify({ by: opts.actorUsername, exportedAt: document.exportedAt ?? null, counts, warnings: warnings.length })]
      );
      await client.query('COMMIT');
    } else {
      await client.query('ROLLBACK');
    }
    return { dryRun: opts.dryRun, counts, warnings, problems: [] };
  } catch (error) {
    await client.query('ROLLBACK').catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}
