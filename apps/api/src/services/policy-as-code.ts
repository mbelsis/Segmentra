import type { PoolClient } from 'pg';
import { parse as parseYaml, stringify as stringifyYaml } from 'yaml';
import { z } from 'zod';

import { pool } from '../db/pool.js';
import { recordPolicyVersionEditor } from '../lib/policy-editors.js';
import {
  INTERFACE_NAME_REGEX,
  INTERFACE_ROLE_REGEX,
  ruleCommentSchema,
  validateRuleSemantics,
} from '../lib/rule-validation.js';
import { PROTOCOLS, expandService } from './iot-protocols.js';
import { createDraftVersion, insertRule, loadVersionRules, lockPolicySetAndGetBase } from './policy-version-clone.js';

/**
 * Policy as code: a policy set as a YAML/JSON document that references tags, VLANs, hosts and IoT assets
 * by NAME (not database id), so it can live in Git and be applied to another Segmentra instance.
 *
 *   apiVersion: segmentra.io/v1
 *   kind: PolicySet
 *   metadata: { name, description }
 *   spec: { scope, interfaceScope, changeSummary, rules[] }
 *
 * Importing never approves anything: it creates (or reuses) a DRAFT version that goes through the normal
 * submit / approve workflow. The document is the source of truth for the rules; the scope of an existing
 * policy set is only changed when explicitly asked for.
 */

export const POLICY_API_VERSION = 'segmentra.io/v1';
export const MAX_DOCUMENT_BYTES = 1024 * 1024;
export const MAX_RULES = 5000;

export type Problem = { path: string; message: string };

// ---- document schema (strict: unknown keys are errors, so typos never go unnoticed) ---------------

const refObject = z
  .object({
    type: z.enum(['CIDR', 'TAG', 'VLAN', 'HOST', 'IOT_ASSET']),
    value: z.string().trim().min(1).optional(), // CIDR
    name: z.string().trim().min(1).optional(), // TAG / VLAN / HOST / IOT_ASSET by name
    id: z.string().uuid().optional(), // same-instance reference by id
  })
  .strict();
const refSchema = z.union([z.string().trim().min(1), refObject]);

const interfaceScopeSchema = z
  .object({
    type: z.enum(['ALL_INTERFACES', 'INTERFACE_ROLE', 'INTERFACE_NAME']),
    names: z.array(z.string().regex(INTERFACE_NAME_REGEX, 'Invalid interface name')).optional(),
    roles: z.array(z.string().regex(INTERFACE_ROLE_REGEX, 'Invalid interface role')).optional(),
  })
  .strict();

const ruleDocSchema = z
  .object({
    order: z.number().int().min(0).optional(),
    direction: z.enum(['IN', 'OUT', 'BOTH', 'FORWARD']).default('IN'),
    action: z.enum(['ALLOW', 'DENY']),
    // Either protocol (+ ports) or a service from the IoT/OT protocol catalog (docs/iot.md), which expands to one rule per transport.
    protocol: z.enum(['tcp', 'udp', 'icmp', 'any']).optional(),
    service: z.string().trim().min(1).optional(),
    ports: z.union([z.string(), z.number().int()]).nullable().optional(),
    source: refSchema,
    destination: refSchema.nullable().optional(), // FORWARD rules only
    log: z.enum(['NONE', 'LOG', 'LOG_RATE_LIMITED']).default('NONE'),
    comment: ruleCommentSchema.nullable().optional(),
    interfaceScope: interfaceScopeSchema.nullable().optional(),
  })
  .strict();

const scopeSchema = z
  .object({
    type: z.enum(['TAG', 'VLAN', 'HOST_LIST']),
    tag: z.string().trim().min(1).optional(),
    vlan: z.string().trim().min(1).optional(), // VLAN name
    vlanTag: z.number().int().optional(), // or its 802.1Q tag number
    hosts: z.array(z.string().trim().min(1)).optional(),
  })
  .strict();

export const policyDocumentSchema = z
  .object({
    apiVersion: z.literal(POLICY_API_VERSION),
    kind: z.literal('PolicySet'),
    metadata: z.object({ name: z.string().trim().min(1).max(200), description: z.string().nullable().optional() }).strict(),
    spec: z
      .object({
        scope: scopeSchema,
        interfaceScope: interfaceScopeSchema.optional(),
        changeSummary: z.string().max(500).nullable().optional(),
        // Each rule is validated on its own (see normalizeDocument) so one malformed rule does not hide the others.
        rules: z.array(z.unknown()).max(MAX_RULES),
      })
      .strict(),
  })
  .strict();

export type PolicyDocument = z.infer<typeof policyDocumentSchema>;

/** Parse YAML or JSON text (JSON is valid YAML). Alias bombs are limited. */
export function parseDocumentText(text: string): { value?: unknown; problem?: string } {
  if (Buffer.byteLength(text, 'utf8') > MAX_DOCUMENT_BYTES) return { problem: `document is larger than ${MAX_DOCUMENT_BYTES} bytes` };
  try {
    const value = parseYaml(text, { maxAliasCount: 20 });
    if (value === null || typeof value !== 'object' || Array.isArray(value)) return { problem: 'the document must be a YAML/JSON object' };
    return { value };
  } catch (e: any) {
    return { problem: `not valid YAML/JSON: ${String(e?.message ?? e).split('\n')[0]}` };
  }
}

// ---- reference lookup -------------------------------------------------------------------------------

type Refs = {
  tagByName: Map<string, string[]>;
  tagName: Map<string, string>;
  vlanByName: Map<string, string[]>;
  vlanByTag: Map<number, string[]>;
  vlanName: Map<string, string>;
  hostByName: Map<string, string[]>;
  hostName: Map<string, string>;
  assetByName: Map<string, string[]>;
  assetName: Map<string, string>;
};

function addTo(map: Map<any, string[]>, key: any, id: string) {
  const list = map.get(key) ?? [];
  list.push(id);
  map.set(key, list);
}

async function loadRefs(db: Pick<PoolClient, 'query'> = pool): Promise<Refs> {
  const refs: Refs = {
    tagByName: new Map(), tagName: new Map(), vlanByName: new Map(), vlanByTag: new Map(), vlanName: new Map(),
    hostByName: new Map(), hostName: new Map(), assetByName: new Map(), assetName: new Map(),
  };
  for (const r of (await db.query(`SELECT id, name FROM tags`)).rows) { addTo(refs.tagByName, r.name, r.id); refs.tagName.set(r.id, r.name); }
  for (const r of (await db.query(`SELECT id, name, vlan_tag FROM vlans`)).rows) {
    addTo(refs.vlanByName, r.name, r.id); addTo(refs.vlanByTag, Number(r.vlan_tag), r.id); refs.vlanName.set(r.id, r.name);
  }
  for (const r of (await db.query(`SELECT id, hostname FROM hosts`)).rows) { addTo(refs.hostByName, r.hostname, r.id); refs.hostName.set(r.id, r.hostname); }
  for (const r of (await db.query(`SELECT id, name FROM iot_assets`)).rows) { addTo(refs.assetByName, r.name, r.id); refs.assetName.set(r.id, r.name); }
  return refs;
}

// ---- normalised form (what is stored and compared) --------------------------------------------------

export type NormalizedRule = {
  orderIndex: number;
  direction: string;
  action: string;
  protocol: string;
  ports: string | null;
  source_type: string;
  source_value: string;
  destination_type: string | null;
  destination_value: string | null;
  log_mode: string;
  comment: string | null;
  use_policy_interface_scope: boolean;
  interface_scope_type: string | null;
  interface_scope_roles: string[] | null;
  interface_scope_names: string[] | null;
};

export type NormalizedScope = { type: 'TAG' | 'VLAN' | 'HOST_LIST'; tagId: string | null; vlanId: string | null; hostIds: string[] };

export type NormalizedPolicy = {
  name: string;
  description: string | null;
  scope: NormalizedScope;
  interfaceScope: { type: string; roles: string[] | null; names: string[] | null };
  changeSummary: string | null;
  rules: NormalizedRule[];
};

function resolveOne(
  path: string, kind: string, name: string, map: Map<string, string[]>, problems: Problem[]
): string | null {
  const ids = map.get(name);
  if (!ids || ids.length === 0) { problems.push({ path, message: `${kind} "${name}" does not exist` }); return null; }
  if (ids.length > 1) { problems.push({ path, message: `${kind} name "${name}" is ambiguous (${ids.length} matches); use id` }); return null; }
  return ids[0];
}

function resolveRef(
  path: string, spec: z.infer<typeof refSchema>, refs: Refs, problems: Problem[], allowed: string[]
): { type: string; value: string } | null {
  if (typeof spec === 'string') return { type: 'CIDR', value: spec.trim() };
  if (!allowed.includes(spec.type)) { problems.push({ path: `${path}.type`, message: `type ${spec.type} is not allowed here` }); return null; }
  if (spec.type === 'CIDR') {
    if (!spec.value) { problems.push({ path, message: 'a CIDR reference needs "value"' }); return null; }
    return { type: 'CIDR', value: spec.value.trim() };
  }
  const idMap: Record<string, Map<string, string>> = { TAG: refs.tagName, VLAN: refs.vlanName, HOST: refs.hostName, IOT_ASSET: refs.assetName };
  const nameMap: Record<string, Map<string, string[]>> = { TAG: refs.tagByName, VLAN: refs.vlanByName, HOST: refs.hostByName, IOT_ASSET: refs.assetByName };
  const label: Record<string, string> = { TAG: 'tag', VLAN: 'VLAN', HOST: 'host', IOT_ASSET: 'IoT asset' };
  if (spec.id) {
    if (!idMap[spec.type].has(spec.id)) { problems.push({ path, message: `${label[spec.type]} with id ${spec.id} does not exist` }); return null; }
    return { type: spec.type, value: spec.id };
  }
  if (!spec.name) { problems.push({ path, message: `a ${spec.type} reference needs "name" (or "id")` }); return null; }
  const id = resolveOne(path, label[spec.type], spec.name, nameMap[spec.type], problems);
  return id ? { type: spec.type, value: id } : null;
}

function normalizeInterfaceScope(s: z.infer<typeof interfaceScopeSchema> | null | undefined, path: string, problems: Problem[]) {
  if (!s || s.type === 'ALL_INTERFACES') {
    if (s && (s.names?.length || s.roles?.length)) problems.push({ path, message: 'ALL_INTERFACES takes no names or roles' });
    return { type: 'ALL_INTERFACES', roles: null as string[] | null, names: null as string[] | null };
  }
  if (s.type === 'INTERFACE_NAME') {
    if (!s.names?.length) problems.push({ path, message: 'INTERFACE_NAME needs "names"' });
    return { type: s.type, roles: null, names: s.names ?? [] };
  }
  if (!s.roles?.length) problems.push({ path, message: 'INTERFACE_ROLE needs "roles"' });
  return { type: s.type, roles: s.roles ?? [], names: null };
}

/** zod issue path -> "spec.rules[2].source.name" */
function pathOf(base: string, issuePath: Array<string | number>): string {
  return issuePath.reduce<string>((acc, part) => (typeof part === 'number' ? `${acc}[${part}]` : acc ? `${acc}.${part}` : String(part)), base);
}

/** Validate a parsed document and resolve every name to an id. Collects all problems. */
export async function normalizeDocument(raw: unknown, db: Pick<PoolClient, 'query'> = pool): Promise<{ policy?: NormalizedPolicy; problems: Problem[] }> {
  const parsed = policyDocumentSchema.safeParse(raw);
  if (!parsed.success) {
    return { problems: parsed.error.issues.map((i) => ({ path: pathOf('', i.path) || '(document)', message: i.message })) };
  }
  const doc = parsed.data;
  const problems: Problem[] = [];
  const refs = await loadRefs(db);

  // scope
  const sc = doc.spec.scope;
  const scope: NormalizedScope = { type: sc.type, tagId: null, vlanId: null, hostIds: [] };
  if (sc.type === 'TAG') {
    if (!sc.tag) problems.push({ path: 'spec.scope.tag', message: 'TAG scope needs "tag"' });
    else scope.tagId = resolveOne('spec.scope.tag', 'tag', sc.tag, refs.tagByName, problems);
  } else if (sc.type === 'VLAN') {
    if (sc.vlan !== undefined) scope.vlanId = resolveOne('spec.scope.vlan', 'VLAN', sc.vlan, refs.vlanByName, problems);
    else if (sc.vlanTag !== undefined) {
      const ids = refs.vlanByTag.get(sc.vlanTag) ?? [];
      if (ids.length === 1) scope.vlanId = ids[0];
      else problems.push({ path: 'spec.scope.vlanTag', message: ids.length ? `VLAN tag ${sc.vlanTag} is ambiguous` : `no VLAN with tag ${sc.vlanTag}` });
    } else problems.push({ path: 'spec.scope', message: 'VLAN scope needs "vlan" (name) or "vlanTag"' });
  } else {
    if (!sc.hosts?.length) problems.push({ path: 'spec.scope.hosts', message: 'HOST_LIST scope needs "hosts" (hostnames)' });
    for (const [i, h] of (sc.hosts ?? []).entries()) {
      const id = resolveOne(`spec.scope.hosts[${i}]`, 'host', h, refs.hostByName, problems);
      if (id && !scope.hostIds.includes(id)) scope.hostIds.push(id);
    }
  }

  const interfaceScope = normalizeInterfaceScope(doc.spec.interfaceScope, 'spec.interfaceScope', problems);

  // rules
  const rules: NormalizedRule[] = [];
  const seenOrders = new Set<number>();
  for (const [i, rawRule] of doc.spec.rules.entries()) {
    const p = `spec.rules[${i}]`;
    const ruleParsed = ruleDocSchema.safeParse(rawRule);
    if (!ruleParsed.success) {
      for (const issue of ruleParsed.error.issues) problems.push({ path: pathOf(p, issue.path), message: issue.message });
      continue;
    }
    const r = ruleParsed.data;
    const baseOrder = r.order ?? (i + 1) * 10;

    // protocol/ports, or a catalog service (one rule per transport: DNP3 is tcp and udp, so it becomes two rules)
    const explicitPorts = r.ports === undefined || r.ports === null || String(r.ports).trim() === '' ? null : String(r.ports).replace(/\s+/g, '');
    let variants: Array<{ protocol: string; ports: string | null }> = [];
    if (r.service !== undefined) {
      if (r.protocol !== undefined || explicitPorts !== null) {
        problems.push({ path: `${p}.service`, message: 'use either "service" or "protocol"/"ports", not both' });
      } else {
        const ex = expandService(r.service);
        if (!ex) problems.push({ path: `${p}.service`, message: `unknown service "${r.service}"; known services: ${PROTOCOLS.map((x) => x.id).join(', ')}` });
        else variants = ex.map((t) => ({ protocol: t.protocol, ports: t.ports }));
      }
    } else if (r.protocol === undefined) {
      problems.push({ path: `${p}.protocol`, message: 'a rule needs "protocol" (or "service")' });
    } else {
      variants = [{ protocol: r.protocol, ports: explicitPorts }];
    }

    const source = resolveRef(`${p}.source`, r.source, refs, problems, ['CIDR', 'TAG', 'VLAN', 'HOST']);
    let destination: { type: string; value: string } | null = null;
    if (r.direction === 'FORWARD') {
      if (!r.destination) problems.push({ path: `${p}.destination`, message: 'FORWARD rules need a destination' });
      else destination = resolveRef(`${p}.destination`, r.destination, refs, problems, ['CIDR', 'TAG', 'VLAN', 'HOST', 'IOT_ASSET']);
    } else if (r.destination) {
      problems.push({ path: `${p}.destination`, message: `only FORWARD rules have a destination (direction is ${r.direction})` });
    }
    const scoped = r.interfaceScope ? normalizeInterfaceScope(r.interfaceScope, `${p}.interfaceScope`, problems) : null;

    for (const [vi, variant] of variants.entries()) {
      const orderIndex = baseOrder + vi;
      if (seenOrders.has(orderIndex)) {
        problems.push({ path: `${p}.order`, message: `order ${orderIndex} is used more than once${r.service && vi > 0 ? ' (a service with several transports uses consecutive order numbers)' : ''}` });
      }
      seenOrders.add(orderIndex);
      if (source) {
        const issues = validateRuleSemantics({
          protocol: variant.protocol, ports: variant.ports, sourceType: source.type, sourceValue: source.value, direction: r.direction,
          destinationType: destination?.type ?? null, destinationValue: destination?.value ?? null,
        });
        for (const m of issues) problems.push({ path: p, message: m });
      }
      rules.push({
        orderIndex, direction: r.direction, action: r.action, protocol: variant.protocol, ports: variant.ports,
        source_type: source?.type ?? 'CIDR', source_value: source?.value ?? '',
        destination_type: destination?.type ?? null, destination_value: destination?.value ?? null,
        log_mode: r.log, comment: r.comment ? r.comment.trim() : null,
        use_policy_interface_scope: !scoped,
        interface_scope_type: scoped?.type ?? null, interface_scope_roles: scoped?.roles ?? null, interface_scope_names: scoped?.names ?? null,
      });
    }
  }
  if (problems.length) return { problems };
  rules.sort((a, b) => a.orderIndex - b.orderIndex);
  return {
    problems,
    policy: {
      name: doc.metadata.name, description: doc.metadata.description ?? null, scope, interfaceScope,
      changeSummary: doc.spec.changeSummary ?? null, rules,
    },
  };
}

// ---- comparison -------------------------------------------------------------------------------------

type RuleLike = Partial<Record<string, any>>;

/** Content of a rule without its order_index (the sequence is compared separately). */
export function ruleKey(r: RuleLike): string {
  const arr = (v: unknown) => (Array.isArray(v) && v.length ? [...v].sort() : null);
  const ports = r.ports == null || String(r.ports).trim() === '' ? null : String(r.ports).replace(/\s+/g, '');
  const forward = (r.direction ?? 'IN') === 'FORWARD';
  return JSON.stringify([
    r.direction ?? 'IN', r.action, r.protocol, ports, r.source_type, String(r.source_value ?? '').trim().toLowerCase(),
    forward ? r.destination_type ?? null : null, forward ? String(r.destination_value ?? '').trim().toLowerCase() : null,
    r.log_mode ?? 'NONE', (r.comment ?? '') || null, r.use_policy_interface_scope !== false,
    r.use_policy_interface_scope === false ? r.interface_scope_type ?? null : null,
    r.use_policy_interface_scope === false ? arr(r.interface_scope_roles) : null,
    r.use_policy_interface_scope === false ? arr(r.interface_scope_names) : null,
  ]);
}

function versionScopeKey(v: { interface_scope_type: string; interface_scope_roles: string[] | null; interface_scope_names: string[] | null }) {
  const arr = (x: string[] | null) => (x && x.length ? [...x].sort() : null);
  return JSON.stringify([v.interface_scope_type, arr(v.interface_scope_roles), arr(v.interface_scope_names)]);
}

export type RuleDiff = { added: string[]; removed: string[]; reordered: boolean; unchanged: number };

function describeKey(key: string, refs: Refs): string {
  const [direction, action, protocol, ports, st, sv, dt, dv, , comment] = JSON.parse(key) as any[];
  const nameOf = (t: string | null, v: string | null) => {
    if (!t || v == null) return '';
    const m: Record<string, Map<string, string>> = { TAG: refs.tagName, VLAN: refs.vlanName, HOST: refs.hostName, IOT_ASSET: refs.assetName };
    return t === 'CIDR' ? v : `${t.toLowerCase()}:${m[t]?.get(v) ?? v}`;
  };
  const dest = direction === 'FORWARD' ? ` -> ${nameOf(dt, dv)}` : '';
  return `${action} ${direction} ${protocol}${ports ? `/${ports}` : ''} from ${nameOf(st, sv)}${dest}${comment ? ` (${comment})` : ''}`;
}

export function diffRules(current: RuleLike[], desired: RuleLike[], refs: Refs): RuleDiff {
  const cur = current.map(ruleKey);
  const des = desired.map(ruleKey);
  const count = (list: string[]) => list.reduce((m, k) => m.set(k, (m.get(k) ?? 0) + 1), new Map<string, number>());
  const cc = count(cur), dc = count(des);
  const added: string[] = [], removed: string[] = [];
  let unchanged = 0;
  for (const [k, n] of dc) { const have = cc.get(k) ?? 0; unchanged += Math.min(n, have); for (let i = have; i < n; i++) added.push(describeKey(k, refs)); }
  for (const [k, n] of cc) { const want = dc.get(k) ?? 0; for (let i = want; i < n; i++) removed.push(describeKey(k, refs)); }
  const sameSet = added.length === 0 && removed.length === 0;
  return { added, removed, unchanged, reordered: sameSet && cur.join('|') !== des.join('|') };
}

// ---- apply ------------------------------------------------------------------------------------------

export type ApplyResult = {
  action: 'created' | 'new_version' | 'unchanged';
  policySetId: string | null;
  name: string;
  versionId: string | null;
  versionNumber: number | null;
  versionStatus: string | null;
  /** Existing version whose content equals the document (action unchanged). */
  matchesVersion: number | null;
  diff: RuleDiff;
  scopeChanged: boolean;
  scopeUpdated: boolean;
  warnings: string[];
};

async function readScope(client: PoolClient, set: any): Promise<NormalizedScope> {
  const hosts = set.scope_type === 'HOST_LIST'
    ? (await client.query(`SELECT host_id FROM policy_set_hosts WHERE policy_set_id = $1 ORDER BY host_id`, [set.id])).rows.map((r: any) => r.host_id as string)
    : [];
  return { type: set.scope_type, tagId: set.scope_tag_id ?? null, vlanId: set.scope_vlan_id ?? null, hostIds: hosts };
}

const sameScope = (a: NormalizedScope, b: NormalizedScope) =>
  a.type === b.type && a.tagId === b.tagId && a.vlanId === b.vlanId && [...a.hostIds].sort().join() === [...b.hostIds].sort().join();

async function writeScope(client: PoolClient, setId: string, scope: NormalizedScope) {
  await client.query(`UPDATE policy_sets SET scope_type = $2, scope_tag_id = $3, scope_vlan_id = $4 WHERE id = $1`, [setId, scope.type, scope.tagId, scope.vlanId]);
  await client.query(`DELETE FROM policy_set_hosts WHERE policy_set_id = $1`, [setId]);
  for (const h of scope.hostIds) await client.query(`INSERT INTO policy_set_hosts (policy_set_id, host_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`, [setId, h]);
}

/**
 * Apply a normalised policy inside the caller's transaction. Creates the policy set when it does not exist,
 * otherwise adds a DRAFT version unless the base version or an existing DRAFT already has the same content.
 */
export async function applyPolicy(
  client: PoolClient,
  policy: NormalizedPolicy,
  opts: { userId: string | null; updateScope: boolean; source: string }
): Promise<ApplyResult> {
  const refs = await loadRefs(client);
  const summary = policy.changeSummary ?? `Imported from ${opts.source}`;
  const warnings: string[] = [];

  const existing = (await client.query(`SELECT * FROM policy_sets WHERE name = $1 ORDER BY created_at`, [policy.name])).rows;
  if (existing.length > 1) throw new ImportError(409, 'ambiguous_policy_set', `${existing.length} policy sets are named "${policy.name}"; rename them so the name is unique`);

  const addRules = async (versionId: string) => {
    for (const r of policy.rules) await insertRule(client, versionId, r.orderIndex, r);
    await recordPolicyVersionEditor(client, versionId, opts.userId);
  };
  const audit = async (action: string, entityId: string, metadata: unknown) => {
    await client.query(
      `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata) VALUES ($1, $2, $3, $4, $5)`,
      [opts.userId, action, 'policy_set', entityId, JSON.stringify(metadata)]
    );
  };

  if (existing.length === 0) {
    const ps = (await client.query(
      `INSERT INTO policy_sets (name, description, scope_type, scope_tag_id, scope_vlan_id, created_by) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`,
      [policy.name, policy.description, policy.scope.type, policy.scope.tagId, policy.scope.vlanId, opts.userId]
    )).rows[0];
    for (const h of policy.scope.hostIds) await client.query(`INSERT INTO policy_set_hosts (policy_set_id, host_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`, [ps.id, h]);
    const versionId = await createDraftVersion(client, {
      policySetId: ps.id, versionNumber: 1, changeSummary: summary, createdBy: opts.userId,
      base: { id: '', version_number: 0, status: 'DRAFT', interface_scope_type: policy.interfaceScope.type, interface_scope_roles: policy.interfaceScope.roles, interface_scope_names: policy.interfaceScope.names },
    });
    await addRules(versionId);
    await audit('POLICY_IMPORT', ps.id, { name: policy.name, action: 'created', versionId, rules: policy.rules.length, source: opts.source });
    return {
      action: 'created', policySetId: ps.id, name: policy.name, versionId, versionNumber: 1, versionStatus: 'DRAFT', matchesVersion: null,
      diff: diffRules([], policy.rules, refs), scopeChanged: false, scopeUpdated: false, warnings,
    };
  }

  const set = existing[0];
  const locked = await lockPolicySetAndGetBase(client, set.id);
  if (!locked) throw new ImportError(404, 'not_found', 'policy set disappeared');

  // Scope: the document is only allowed to change it when asked to.
  const currentScope = await readScope(client, set);
  const scopeChanged = !sameScope(currentScope, policy.scope);
  let scopeUpdated = false;
  if (scopeChanged) {
    if (opts.updateScope) { await writeScope(client, set.id, policy.scope); scopeUpdated = true; }
    else warnings.push('The scope in the document differs from the policy set\'s current scope and was NOT changed (it decides which hosts a deployment targets). Apply with updateScope to change it.');
  }
  if ((policy.description ?? null) !== (set.description ?? null) && policy.description !== null) {
    await client.query(`UPDATE policy_sets SET description = $2 WHERE id = $1`, [set.id, policy.description]);
  }

  const base = locked.base;
  const baseRules = base ? await loadVersionRules(client, base.id) : [];
  const desiredScopeKey = versionScopeKey({ interface_scope_type: policy.interfaceScope.type, interface_scope_roles: policy.interfaceScope.roles, interface_scope_names: policy.interfaceScope.names });
  const sameContent = (rules: RuleLike[], v: any) =>
    rules.length === policy.rules.length && rules.map(ruleKey).join('|') === policy.rules.map(ruleKey).join('|') && versionScopeKey(v) === desiredScopeKey;

  const diff = diffRules(baseRules, policy.rules, refs);
  if (base && sameContent(baseRules, base)) {
    return { action: 'unchanged', policySetId: set.id, name: policy.name, versionId: base.id, versionNumber: base.version_number, versionStatus: base.status, matchesVersion: base.version_number, diff, scopeChanged, scopeUpdated, warnings };
  }
  // Re-running the same document before the draft is approved must not create another draft.
  const drafts = (await client.query(
    `SELECT id, version_number, status, interface_scope_type, interface_scope_roles, interface_scope_names FROM policy_versions
      WHERE policy_set_id = $1 AND status = 'DRAFT' ORDER BY version_number DESC`, [set.id]
  )).rows;
  for (const d of drafts) {
    if (sameContent(await loadVersionRules(client, d.id), d)) {
      return { action: 'unchanged', policySetId: set.id, name: policy.name, versionId: d.id, versionNumber: d.version_number, versionStatus: d.status, matchesVersion: d.version_number, diff, scopeChanged, scopeUpdated, warnings };
    }
  }

  const versionId = await createDraftVersion(client, {
    policySetId: set.id, versionNumber: locked.nextVersionNumber, changeSummary: summary, createdBy: opts.userId,
    base: { id: '', version_number: 0, status: 'DRAFT', interface_scope_type: policy.interfaceScope.type, interface_scope_roles: policy.interfaceScope.roles, interface_scope_names: policy.interfaceScope.names },
  });
  await addRules(versionId);
  await audit('POLICY_IMPORT', set.id, {
    name: policy.name, action: 'new_version', versionId, versionNumber: locked.nextVersionNumber,
    added: diff.added.length, removed: diff.removed.length, source: opts.source, scopeUpdated,
  });
  return { action: 'new_version', policySetId: set.id, name: policy.name, versionId, versionNumber: locked.nextVersionNumber, versionStatus: 'DRAFT', matchesVersion: null, diff, scopeChanged, scopeUpdated, warnings };
}

export class ImportError extends Error {
  constructor(public status: number, public code: string, message: string) {
    super(message);
  }
}

// ---- export -----------------------------------------------------------------------------------------

/** Pick the version to export: an id, a version number, or the one a new draft would build on. */
export async function pickVersion(policySetId: string, selector: string | undefined) {
  const cols = `id, version_number, status, change_summary, interface_scope_type, interface_scope_roles, interface_scope_names`;
  if (selector && selector !== 'latest') {
    const isUuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(selector);
    const q = isUuid
      ? await pool.query(`SELECT ${cols} FROM policy_versions WHERE policy_set_id = $1 AND id = $2`, [policySetId, selector])
      : /^\d+$/.test(selector)
        ? await pool.query(`SELECT ${cols} FROM policy_versions WHERE policy_set_id = $1 AND version_number = $2`, [policySetId, Number(selector)])
        : { rows: [] as any[] };
    return q.rows[0] ?? null;
  }
  const { rows } = await pool.query(
    `SELECT ${cols} FROM policy_versions WHERE policy_set_id = $1
      ORDER BY (status IN ('DEPLOYED', 'APPROVED')) DESC, version_number DESC LIMIT 1`, [policySetId]
  );
  return rows[0] ?? null;
}

function nameOrId(type: string, value: string, refs: Refs): any {
  if (type === 'CIDR') return type === 'CIDR' && /^[^,]+$/.test(value) ? value : { type: 'CIDR', value };
  const maps: Record<string, Map<string, string>> = { TAG: refs.tagName, VLAN: refs.vlanName, HOST: refs.hostName, IOT_ASSET: refs.assetName };
  const name = maps[type]?.get(value);
  return name ? { type, name } : { type, id: value };
}

export async function buildExportDocument(policySetId: string, version: { id: string; version_number: number; interface_scope_type: string; interface_scope_roles: string[] | null; interface_scope_names: string[] | null; change_summary: string | null }) {
  const refs = await loadRefs();
  const set = (await pool.query(`SELECT * FROM policy_sets WHERE id = $1`, [policySetId])).rows[0];
  const rules = (await pool.query(`SELECT * FROM policy_rules WHERE policy_version_id = $1 ORDER BY order_index ASC, id ASC`, [version.id])).rows;

  const scope: any = { type: set.scope_type };
  if (set.scope_type === 'TAG') scope.tag = refs.tagName.get(set.scope_tag_id) ?? set.scope_tag_id;
  if (set.scope_type === 'VLAN') scope.vlan = refs.vlanName.get(set.scope_vlan_id) ?? set.scope_vlan_id;
  if (set.scope_type === 'HOST_LIST') {
    const hosts = (await pool.query(`SELECT host_id FROM policy_set_hosts WHERE policy_set_id = $1`, [policySetId])).rows;
    scope.hosts = hosts.map((h: any) => refs.hostName.get(h.host_id) ?? h.host_id).sort();
  }
  const iface = (type: string, roles: string[] | null, names: string[] | null) =>
    type === 'ALL_INTERFACES' ? { type } : type === 'INTERFACE_NAME' ? { type, names: names ?? [] } : { type, roles: roles ?? [] };

  return {
    apiVersion: POLICY_API_VERSION,
    kind: 'PolicySet',
    metadata: { name: set.name, ...(set.description ? { description: set.description } : {}) },
    spec: {
      scope,
      interfaceScope: iface(version.interface_scope_type, version.interface_scope_roles, version.interface_scope_names),
      ...(version.change_summary ? { changeSummary: version.change_summary } : {}),
      rules: rules.map((r: any) => ({
        order: Number(r.order_index),
        direction: r.direction ?? 'IN',
        action: r.action,
        protocol: r.protocol,
        ...(r.ports ? { ports: r.ports } : {}),
        source: nameOrId(r.source_type, r.source_value, refs),
        ...((r.direction ?? 'IN') === 'FORWARD' && r.destination_type ? { destination: nameOrId(r.destination_type, r.destination_value, refs) } : {}),
        ...(r.log_mode && r.log_mode !== 'NONE' ? { log: r.log_mode } : {}),
        ...(r.comment ? { comment: r.comment } : {}),
        ...(r.use_policy_interface_scope === false && r.interface_scope_type ? { interfaceScope: iface(r.interface_scope_type, r.interface_scope_roles, r.interface_scope_names) } : {}),
      })),
    },
  };
}

export function serializeDocument(doc: unknown, format: 'yaml' | 'json'): string {
  if (format === 'json') return JSON.stringify(doc, null, 2) + '\n';
  return `# Segmentra policy as code (${POLICY_API_VERSION}). Apply with: segmentra-policy apply <file>\n` + stringifyYaml(doc, { lineWidth: 0, indent: 2 });
}
