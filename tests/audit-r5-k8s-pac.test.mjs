// Regression tests for deep audit round 5 (Kubernetes NetworkPolicy generation, policy as code, compliance report
// Kubernetes metric, discovery hostname race). Runs against the built API (apps/api/dist, or SEGMENTRA_API_DIST)
// with the database pool mocked; no PostgreSQL or cluster needed.
import assert from 'node:assert/strict';
import { test } from 'node:test';

process.env.NODE_ENV = 'test';
process.env.DATABASE_URL = 'postgres://localhost/segmentra_test';
process.env.JWT_SECRET = 'test-only-secret-with-at-least-32-characters';
process.env.SEGMENTRA_KEK_B64 = Buffer.alloc(32, 1).toString('base64');
process.env.CORS_ORIGIN = '';

const distBase = process.env.SEGMENTRA_API_DIST
  ? new URL(`file://${process.env.SEGMENTRA_API_DIST.replace(/\/?$/, '/')}`)
  : new URL('../apps/api/dist/', import.meta.url);
const dist = (p) => new URL(p, distBase).href;
const { pool } = await import(dist('db/pool.js'));
const k8s = await import(dist('routes/kubernetes.js'));
const pac = await import(dist('services/policy-as-code.js'));
const discovery = await import(dist('services/discovery.js'));
const compliance = await import(dist('services/compliance-report.js'));

const CLUSTER = '11111111-2222-4333-8444-555555555555';
const PV = '22222222-2222-4333-8444-555555555555';

function mockRes() {
  return {
    statusCode: 200,
    status(code) { this.statusCode = code; return this; },
    json(payload) { this.body = payload; return this; },
  };
}
function routeHandler(router, method, path) {
  const layer = router.stack.find((l) => l.route?.path === path && l.route.methods[method]);
  assert.ok(layer, `route ${method.toUpperCase()} ${path} exists`);
  const stack = layer.route.stack;
  return stack[stack.length - 1].handle;
}
/** Replace pool.query with a SQL-pattern based fake for the duration of fn. */
async function withPool(handler, fn) {
  const orig = pool.query;
  const seen = [];
  pool.query = async (sql, params) => { seen.push({ sql, params }); return handler(String(sql), params ?? []) ?? { rows: [] }; };
  try { return await fn(seen); } finally { pool.query = orig; }
}

const rule = (o) => ({ order_index: 10, direction: 'IN', action: 'ALLOW', protocol: 'tcp', ports: null, source_type: 'CIDR', source_value: '10.0.0.0/8', comment: null, ...o });

async function generate(rules, body = {}) {
  const handler = routeHandler(k8s.kubernetesRouter, 'post', '/clusters/:id/deploy-policy');
  return withPool((sql) => {
    if (/FROM k8s_clusters WHERE id/.test(sql)) return { rows: [{ id: CLUSTER, cni: 'calico' }] };
    if (/SELECT status FROM policy_versions/.test(sql)) return { rows: [{ status: 'APPROVED' }] };
    if (/FROM policy_rules/.test(sql)) return { rows: rules };
    if (/INSERT INTO k8s_network_policies/.test(sql)) return { rows: [{ id: 'np-1' }] };
    return { rows: [] };
  }, async (seen) => {
    const res = mockRes();
    await handler({ params: { id: CLUSTER }, body: { policyVersionId: PV, namespace: 'apps', policyName: 'segmentra-main', ...body }, auth: { username: 'op' } }, res);
    const insert = seen.find((q) => /INSERT INTO k8s_network_policies/.test(q.sql));
    return { res, manifest: insert ? JSON.parse(insert.params[4]) : null };
  });
}

// ---- 1. all rules skipped / drift normalisation ---------------------------------------------------

test('k8s: generation is refused (422) when no ingress rule survives, unless allowDenyAll', async () => {
  const rules = [rule({ action: 'ALLOW', protocol: 'icmp', comment: 'ping' }), rule({ order_index: 20, direction: 'FORWARD' })];
  const refused = await generate(rules);
  assert.equal(refused.res.statusCode, 422);
  assert.equal(refused.res.body.error, 'no_ingress_rules');
  assert.match(refused.res.body.message, /ICMP is not supported/);
  assert.match(refused.res.body.message, /FORWARD/);
  assert.equal(refused.manifest, null, 'nothing stored');

  const allowed = await generate(rules, { allowDenyAll: true });
  assert.equal(allowed.res.statusCode, 201);
  assert.deepEqual(allowed.manifest.spec.ingress, []);
});

test('k8s: drift comparison treats omitted and empty lists as equal and defaults port protocol to TCP', () => {
  const n = k8s.normalizeNetworkPolicySpec;
  assert.deepEqual(n({ podSelector: {}, policyTypes: ['Ingress'], ingress: [] }), n({ podSelector: {}, policyTypes: ['Ingress'] }));
  assert.deepEqual(
    n({ podSelector: {}, policyTypes: ['Ingress'], ingress: [{ ports: [{ port: 80 }], from: [{ ipBlock: { cidr: '10.0.0.0/8', except: [] } }] }] }),
    n({ podSelector: {}, policyTypes: ['Ingress'], ingress: [{ ports: [{ port: 80, protocol: 'TCP' }], from: [{ ipBlock: { cidr: '10.0.0.0/8' } }] }] }),
  );
  // A real difference still shows.
  assert.notDeepEqual(n({ podSelector: {}, ingress: [{ ports: [{ port: 80 }] }] }), n({ podSelector: {}, ingress: [{ ports: [{ port: 81 }] }] }));
  assert.notDeepEqual(n({ podSelector: {}, ingress: [{ ports: [{ port: 80, protocol: 'UDP' }] }] }), n({ podSelector: {}, ingress: [{ ports: [{ port: 80 }] }] }));
});

// ---- 2. DENY before a broader ALLOW ---------------------------------------------------------------

test('k8s: a covering DENY before a broader ALLOW becomes ipBlock.except (same family only)', async () => {
  const { res, manifest } = await generate([
    rule({ order_index: 10, action: 'DENY', ports: '22', source_value: '10.1.0.0/16', comment: 'deny' }),
    rule({ order_index: 20, ports: '22', source_value: 'any', comment: 'allow' }),
  ]);
  assert.equal(res.statusCode, 201, JSON.stringify(res.body));
  const from = manifest.spec.ingress[0].from;
  assert.deepEqual(from.find((f) => f.ipBlock.cidr === '0.0.0.0/0').ipBlock.except, ['10.1.0.0/16']);
  assert.equal(from.find((f) => f.ipBlock.cidr === '::/0').ipBlock.except, undefined, 'no IPv4 except on the IPv6 block');
});

test('k8s: a DENY that covers the whole ALLOW block drops that peer; a later DENY changes nothing', () => {
  const t = (proto, ranges) => ({ proto, ranges });
  const r = k8s.buildIngressRules([
    { action: 'DENY', label: 'd', traffic: t('any', null), cidrs: ['10.0.0.0/8'], selectorPeers: [] },
    { action: 'ALLOW', label: 'a', traffic: t('tcp', [{ from: 443, to: 443 }]), cidrs: ['10.2.0.0/16', '192.168.0.0/16'], selectorPeers: [], ports: [{ protocol: 'TCP', port: 443 }] },
    { action: 'DENY', label: 'late', traffic: t('tcp', null), cidrs: ['192.168.1.0/24'], selectorPeers: [] },
  ]);
  assert.deepEqual(r.conflicts, []);
  assert.deepEqual(r.ingress, [{ ports: [{ protocol: 'TCP', port: 443 }], from: [{ ipBlock: { cidr: '192.168.0.0/16' } }] }]);
});

test('k8s: partial port overlap (DENY tcp/22 inside ALLOW tcp/1-1024) is refused with 422 naming both rules', async () => {
  const { res, manifest } = await generate([
    rule({ order_index: 10, action: 'DENY', ports: '22', source_value: '10.1.2.3', comment: 'no-ssh' }),
    rule({ order_index: 20, ports: '1-1024', source_value: '10.0.0.0/8', comment: 'low-ports' }),
  ]);
  assert.equal(res.statusCode, 422);
  assert.equal(res.body.error, 'deny_not_expressible');
  assert.match(res.body.message, /no-ssh/);
  assert.match(res.body.message, /low-ports/);
  assert.equal(manifest, null);
});

test('k8s: DENY ICMP before ALLOW any protocol is refused; disjoint DENY is ignored', () => {
  const t = (proto, ranges) => ({ proto, ranges });
  const allowAny = { action: 'ALLOW', label: 'a', traffic: t('any', null), cidrs: ['10.0.0.0/8'], selectorPeers: [] };
  assert.equal(k8s.buildIngressRules([{ action: 'DENY', label: 'd', traffic: t('icmp', null), cidrs: ['10.1.0.0/16'], selectorPeers: [] }, allowAny]).conflicts.length, 1);
  const disjoint = k8s.buildIngressRules([{ action: 'DENY', label: 'd', traffic: t('tcp', null), cidrs: ['172.16.0.0/12'], selectorPeers: [] }, allowAny]);
  assert.deepEqual(disjoint.conflicts, []);
  assert.deepEqual(disjoint.ingress[0].from, [{ ipBlock: { cidr: '10.0.0.0/8' } }]);
  // superset ports: DENY tcp/1-1024 covers ALLOW tcp/22
  const sup = k8s.buildIngressRules([
    { action: 'DENY', label: 'd', traffic: t('tcp', [{ from: 1, to: 1024 }]), cidrs: ['10.1.0.0/16'], selectorPeers: [] },
    { action: 'ALLOW', label: 'a', traffic: t('tcp', [{ from: 22, to: 22 }]), cidrs: ['10.0.0.0/8'], selectorPeers: [], ports: [{ protocol: 'TCP', port: 22 }] },
  ]);
  assert.deepEqual(sup.ingress[0].from[0].ipBlock.except, ['10.1.0.0/16']);
});

test('k8s: overlapping DENY with label-selected workloads on either side is refused', () => {
  const t = (proto, ranges) => ({ proto, ranges });
  const sel = { namespaceSelector: { matchLabels: { 'kubernetes.io/metadata.name': 'x' } }, podSelector: { matchLabels: { app: 'x' } } };
  const r1 = k8s.buildIngressRules([
    { action: 'DENY', label: 'd', traffic: t('tcp', null), cidrs: ['10.1.0.0/16'], selectorPeers: [] },
    { action: 'ALLOW', label: 'a', traffic: t('tcp', null), cidrs: [], selectorPeers: [sel], ports: [{ protocol: 'TCP' }] },
  ]);
  assert.equal(r1.conflicts.length, 1);
  const r2 = k8s.buildIngressRules([
    { action: 'DENY', label: 'd', traffic: t('tcp', null), cidrs: [], selectorPeers: [{ workloads: 1 }] },
    { action: 'ALLOW', label: 'a', traffic: t('tcp', null), cidrs: ['0.0.0.0/0'], selectorPeers: [], ports: [{ protocol: 'TCP' }] },
  ]);
  assert.equal(r2.conflicts.length, 1);
});

test('k8s: traffic coverage helpers', () => {
  const t = (proto, ranges) => ({ proto, ranges });
  assert.equal(k8s.trafficCovers(t('tcp', [{ from: 1, to: 100 }, { from: 101, to: 200 }]), t('tcp', [{ from: 50, to: 150 }])), true);
  assert.equal(k8s.trafficCovers(t('tcp', [{ from: 22, to: 22 }]), t('tcp', null)), false);
  assert.equal(k8s.trafficCovers(t('tcp', null), t('udp', null)), false);
  assert.equal(k8s.trafficCovers(t('any', null), t('any', null)), true);
  assert.equal(k8s.trafficOverlaps(t('tcp', [{ from: 22, to: 22 }]), t('udp', [{ from: 22, to: 22 }])), false);
});

// ---- 3. namespace / name validation --------------------------------------------------------------

test('k8s: namespace and policyName must be DNS-1123 names', async () => {
  for (const body of [{ namespace: 'Apps' }, { namespace: 'a'.repeat(64) }, { namespace: 'a.b' }, { policyName: 'Bad_Name' }, { policyName: 'x'.repeat(254) }]) {
    const { res } = await generate([rule({ ports: '80' })], body);
    assert.equal(res.statusCode, 400, JSON.stringify(body).slice(0, 60));
  }
  const ok = await generate([rule({ ports: '80' })], { namespace: 'a'.repeat(63), policyName: 'segmentra.web-1' });
  assert.equal(ok.res.statusCode, 201);
});

// ---- 4. compliance report: APPLIED record wins ----------------------------------------------------

test('compliance: the Kubernetes metric prefers the APPLIED record per (cluster, namespace, name)', async () => {
  let sql = null;
  await withPool((q) => {
    if (/FROM k8s_network_policies/.test(q)) { sql = q; return { rows: [{ status: 'APPLIED', live_state: 'DRIFTED' }] }; }
    if (/count\(/i.test(q)) return { rows: [{ n: 0, count: 0 }] };
    return { rows: [] };
  }, async () => {
    try { await compliance.collectEvidence({ liveDrift: false }); } catch { /* other sections may need more data; only the query matters */ }
  });
  assert.ok(sql, 'k8s_network_policies queried');
  assert.match(sql, /\(status = 'APPLIED'\) DESC,\s*created_at DESC/);
});

// ---- 5. policy as code: scope / description changes reported --------------------------------------

const TAG_A = 'aaaaaaaa-0000-4000-8000-000000000001';
const TAG_B = 'aaaaaaaa-0000-4000-8000-000000000002';
const VLAN_1 = 'bbbbbbbb-0000-4000-8000-000000000001';
const VLAN_2 = 'bbbbbbbb-0000-4000-8000-000000000002';
const SET = 'cccccccc-0000-4000-8000-000000000001';
const BASE = 'dddddddd-0000-4000-8000-000000000001';

function refsHandler(sql) {
  if (/SELECT id, name FROM tags/.test(sql)) return { rows: [{ id: TAG_A, name: 'web' }, { id: TAG_B, name: 'db' }] };
  // Two VLANs share a name; tag numbers are unique.
  if (/FROM vlans/.test(sql)) return { rows: [{ id: VLAN_1, name: 'servers', vlan_tag: 10 }, { id: VLAN_2, name: 'servers', vlan_tag: 20 }] };
  if (/FROM hosts/.test(sql)) return { rows: [] };
  if (/FROM iot_assets/.test(sql)) return { rows: [] };
  return null;
}
const baseRuleRow = { order_index: 10, direction: 'IN', action: 'ALLOW', protocol: 'tcp', ports: '443', source_type: 'CIDR', source_value: '10.0.0.0/8', destination_type: null, destination_value: null, log_mode: 'NONE', comment: null, use_policy_interface_scope: true, interface_scope_type: null, interface_scope_roles: null, interface_scope_names: null };
const docOf = (over = {}) => ({
  apiVersion: 'segmentra.io/v1', kind: 'PolicySet',
  metadata: { name: 'p', description: 'old', ...(over.metadata ?? {}) },
  spec: { scope: { type: 'TAG', tag: 'web' }, interfaceScope: { type: 'ALL_INTERFACES' }, rules: [{ order: 10, action: 'ALLOW', protocol: 'tcp', ports: '443', source: '10.0.0.0/8' }], ...(over.spec ?? {}) },
});

async function applyDoc(doc, updateScope) {
  const writes = [];
  const client = {
    async query(sql, params) {
      sql = String(sql);
      const r = refsHandler(sql);
      if (r) return r;
      if (/SELECT \* FROM policy_sets WHERE name/.test(sql)) return { rows: [{ id: SET, name: 'p', description: 'old', scope_type: 'TAG', scope_tag_id: TAG_A, scope_vlan_id: null }] };
      if (/FOR UPDATE/.test(sql)) return { rows: [{ id: SET }] };
      if (/FROM policy_versions[\s\S]*LIMIT 1/.test(sql)) return { rows: [{ id: BASE, version_number: 1, status: 'APPROVED', interface_scope_type: 'ALL_INTERFACES', interface_scope_roles: null, interface_scope_names: null }] };
      if (/MAX\(version_number\)/.test(sql)) return { rows: [{ v: 1 }] };
      if (/FROM policy_rules WHERE policy_version_id/.test(sql)) return { rows: [baseRuleRow] };
      if (/^\s*(UPDATE|INSERT|DELETE)/.test(sql)) writes.push(sql);
      return { rows: [] };
    },
  };
  const { policy, problems } = await pac.normalizeDocument(doc, client);
  assert.deepEqual(problems, []);
  return { result: await pac.applyPolicy(client, policy, { userId: null, updateScope, source: 'test' }), writes };
}

test('policy as code: a scope difference without updateScope is reported (changes, scopeChangeSkipped)', async () => {
  const { result } = await applyDoc(docOf({ spec: { scope: { type: 'TAG', tag: 'db' } } }), false);
  assert.equal(result.action, 'unchanged');
  assert.equal(result.scopeChangeSkipped, true);
  assert.equal(result.changes.length, 1);
  assert.match(result.changes[0], /scope: TAG web -> TAG db .*updateScope/);
});

test('policy as code: scope (with updateScope) and description changes make the action "updated"', async () => {
  const scoped = await applyDoc(docOf({ spec: { scope: { type: 'TAG', tag: 'db' } } }), true);
  assert.equal(scoped.result.action, 'updated');
  assert.equal(scoped.result.scopeUpdated, true);
  assert.ok(scoped.writes.some((w) => /UPDATE policy_sets SET scope_type/.test(w)));
  const described = await applyDoc(docOf({ metadata: { description: 'new' } }), false);
  assert.equal(described.result.action, 'updated');
  assert.equal(described.result.descriptionChanged, true);
  assert.match(described.result.changes[0], /description: "old" -> "new"/);
  const same = await applyDoc(docOf(), false);
  assert.equal(same.result.action, 'unchanged');
  assert.deepEqual(same.result.changes, []);
});

// ---- 6. policy as code: round trip -----------------------------------------------------------------

test('policy as code: empty INTERFACE_ROLE, rule scope override without a type and VLAN by tag round-trip', async () => {
  const rules = [
    { ...baseRuleRow, id: 'r1', order_index: 10, use_policy_interface_scope: false, interface_scope_type: null },
    { ...baseRuleRow, id: 'r2', order_index: 20, source_type: 'VLAN', source_value: VLAN_2, use_policy_interface_scope: false, interface_scope_type: 'INTERFACE_ROLE', interface_scope_roles: null },
  ];
  const exported = await withPool((sql) => {
    const r = refsHandler(sql);
    if (r) return r;
    if (/FROM policy_sets WHERE id/.test(sql)) return { rows: [{ id: SET, name: 'p', description: null, scope_type: 'VLAN', scope_vlan_id: VLAN_2 }] };
    if (/FROM policy_rules/.test(sql)) return { rows: rules };
    return { rows: [] };
  }, () => pac.buildExportDocument(SET, { id: BASE, version_number: 1, interface_scope_type: 'INTERFACE_ROLE', interface_scope_roles: null, interface_scope_names: null, change_summary: null }));

  assert.deepEqual(exported.spec.scope, { type: 'VLAN', vlan: 'servers', vlanTag: 20 });
  assert.deepEqual(exported.spec.interfaceScope, { type: 'INTERFACE_ROLE', roles: [] });
  assert.equal(exported.spec.rules[0].usePolicyInterfaceScope, false);
  assert.equal(exported.spec.rules[0].interfaceScope, undefined);
  assert.deepEqual(exported.spec.rules[1].source, { type: 'VLAN', name: 'servers', vlanTag: 20 });

  const db = { query: async (sql) => refsHandler(String(sql)) ?? { rows: [] } };
  const { policy, problems } = await pac.normalizeDocument(JSON.parse(JSON.stringify(exported)), db);
  assert.deepEqual(problems, []);
  assert.equal(policy.scope.vlanId, VLAN_2, 'resolved by tag although the name is ambiguous');
  assert.equal(policy.interfaceScope.type, 'INTERFACE_ROLE');
  assert.equal(policy.rules[0].use_policy_interface_scope, false);
  assert.equal(policy.rules[0].interface_scope_type, null);
  assert.equal(policy.rules[1].source_value, VLAN_2);
  for (const [i, r] of policy.rules.entries()) assert.equal(pac.ruleKey(r), pac.ruleKey(rules[i]), `rule ${i} unchanged after round trip`);

  // Name only (ambiguous) is still an error; tag that does not exist falls back to the name.
  const byName = await pac.normalizeDocument({ ...exported, spec: { ...exported.spec, scope: { type: 'VLAN', vlan: 'servers' } } }, db);
  assert.ok(byName.problems.some((p) => /ambiguous/.test(p.message)));
  const conflicting = await pac.normalizeDocument({ ...exported, spec: { ...exported.spec, rules: [{ order: 1, action: 'ALLOW', protocol: 'tcp', source: '10.0.0.0/8', interfaceScope: { type: 'ALL_INTERFACES' }, usePolicyInterfaceScope: true }] } }, db);
  assert.ok(conflicting.problems.some((p) => /usePolicyInterfaceScope/.test(p.path)));
});

// ---- 7. discovery: hostname race --------------------------------------------------------------------

test('discovery: a hostname taken between check and insert moves to the next candidate', async () => {
  const taken = new Set(['web']);
  const calls = [];
  const client = {
    async query(sql, params) {
      calls.push(String(sql));
      if (/SELECT 1 FROM hosts WHERE hostname/.test(sql)) return { rows: taken.has(params[0]) ? [{}] : [] };
      return { rows: [] };
    },
  };
  let attempts = 0;
  const r = await discovery.insertWithFreeHostname(client, 'web', '10.0.0.7', async (name) => {
    attempts += 1;
    if (name === 'web-7') { taken.add(name); throw Object.assign(new Error('dup'), { code: '23505', constraint: 'hosts_hostname_key' }); }
    return { rows: [{ id: 'h1' }] };
  });
  assert.deepEqual(r, { id: 'h1', hostname: 'web-10-0-0-7' });
  assert.equal(attempts, 2);
  assert.ok(calls.includes('ROLLBACK TO SAVEPOINT segmentra_host_insert'));

  // Other errors are not swallowed; retries are bounded.
  await assert.rejects(discovery.insertWithFreeHostname(client, 'x', '10.0.0.8', async () => { throw Object.assign(new Error('boom'), { code: '23502' }); }), /boom/);
  await assert.rejects(
    discovery.insertWithFreeHostname(client, 'y', '10.0.0.9', async () => { throw Object.assign(new Error('dup'), { code: '23505', constraint: 'hosts_hostname_key' }); }),
    /no free hostname/,
  );
});
