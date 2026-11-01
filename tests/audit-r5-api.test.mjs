// Audit round 5: auth/LDAP helpers, notifications, policy sets, flow collectors, troubleshoot by-ip, audit paging,
// backup import body limit. Pure helpers plus route handlers run against a stubbed pg pool.
// Run after `npm run build`: node --test tests/audit-r5-api.test.mjs
// (R5_API_DIST=<dir> points the test at another compiled apps/api dist.)
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { pathToFileURL } from 'node:url';

process.env.DATABASE_URL ||= 'postgres://segmentra:unused@127.0.0.1:1/unused';
process.env.JWT_SECRET ||= 'audit-r5-api-test-secret-0123456789abcdef';

const DIST = process.env.R5_API_DIST
  ? pathToFileURL(process.env.R5_API_DIST.replace(/\/?$/, '/')).href
  : new URL('../apps/api/dist/', import.meta.url).href;
const load = (p) => import(new URL(p, DIST).href);

const { pool } = await load('db/pool.js');
const { signJwt } = await load('services/jwt.js');
const { formatObjectGuid, canonicalLdapUsername } = await load('services/ldap.js');
const { notificationFilterMatches, sendNotification } = await load('services/notifications.js');
const { auditRouter, clampAuditLimit, encodeAuditCursor, decodeAuditCursor } = await load('routes/audit.js');
const { flowCollectorsRouter } = await load('routes/flow-collectors.js');
const { policySetsRouter } = await load('routes/policies/policy-sets.js');
const { troubleshootRouter } = await load('routes/troubleshoot.js');
const { backupRouter, BACKUP_IMPORT_BODY_LIMIT } = await load('routes/backup.js');
const express = (await import('express')).default;

const USER_ID = '11111111-1111-4111-8111-111111111111';
const PS_ID = '33333333-3333-4333-8333-333333333333';
const TAG_ID = '44444444-4444-4444-8444-444444444444';
const HOST_A = '55555555-5555-4555-8555-555555555555';
const HOST_B = '66666666-6666-4666-8666-666666666666';

let currentRoles = ['operator'];
const token = () => signJwt({ sub: 'u', roles: currentRoles, uid: USER_ID, tv: 0 });

/** Stub pool.query: `handler(sql, params)` returns { rows, rowCount } or undefined (= empty). Records calls. */
function stubPool(handler = () => undefined) {
  const calls = [];
  const q = async (sql, params = []) => {
    const text = typeof sql === 'string' ? sql : sql.text;
    if (/FROM users u\s+LEFT JOIN user_roles/.test(text)) {
      return { rows: [{ id: USER_ID, username: 'u', is_active: true, token_version: 0, roles: currentRoles }], rowCount: 1 };
    }
    calls.push({ sql: text, params });
    const r = (await handler(text, params)) ?? {};
    return { rows: r.rows ?? [], rowCount: r.rowCount ?? (r.rows ?? []).length };
  };
  pool.query = q;
  pool.connect = async () => ({ query: q, release() {} });
  return calls;
}

async function call(mount, router, method, path, body, { rawBody, globalJson = true } = {}) {
  const app = express();
  if (globalJson) app.use(express.json());
  app.use(mount, router);
  // eslint-disable-next-line no-unused-vars
  app.use((err, _req, res, _next) => res.status(typeof err?.status === 'number' ? err.status : 500).json({ error: String(err?.message ?? err), code: err?.code }));
  const server = await new Promise((resolve) => { const s = app.listen(0, '127.0.0.1', () => resolve(s)); });
  try {
    const res = await fetch(`http://127.0.0.1:${server.address().port}${mount}${path}`, {
      method,
      headers: { authorization: `Bearer ${token()}`, 'content-type': 'application/json' },
      body: rawBody ?? (body === undefined ? undefined : JSON.stringify(body))
    });
    return { status: res.status, body: await res.json().catch(() => null) };
  } finally {
    await new Promise((r) => server.close(r));
  }
}

// --- LDAP helpers ---------------------------------------------------------------------------------------

test('formatObjectGuid: AD byte order, hex for other lengths, null for non-buffers', () => {
  const buf = Buffer.from('e004253f894fd3119a0c0305e82c3301', 'hex');
  assert.equal(formatObjectGuid(buf), '3f2504e0-4f89-11d3-9a0c-0305e82c3301');
  assert.equal(formatObjectGuid([buf]), '3f2504e0-4f89-11d3-9a0c-0305e82c3301');
  assert.equal(formatObjectGuid(Buffer.from('abcd', 'hex')), 'abcd');
  assert.equal(formatObjectGuid('mangled�'), null);
  assert.equal(formatObjectGuid(undefined), null);
});

test('canonicalLdapUsername lower-cases and trims', () => {
  assert.equal(canonicalLdapUsername('  JDoe '), 'jdoe');
  assert.equal(canonicalLdapUsername('jdoe'), 'jdoe');
});

// --- notifications --------------------------------------------------------------------------------------

test('notificationFilterMatches: AND over keys, arrays are any-of, dotted paths, missing never matches', () => {
  const body = { hostname: 'web-1', policySet: 'prod', count: 42, host: { env: 'prod' } };
  assert.equal(notificationFilterMatches(null, body), true);
  assert.equal(notificationFilterMatches({}, body), true);
  assert.equal(notificationFilterMatches({ hostname: 'web-1' }, body), true);
  assert.equal(notificationFilterMatches({ hostname: 'web-2' }, body), false);
  assert.equal(notificationFilterMatches({ hostname: ['web-2', 'web-1'] }, body), true);
  assert.equal(notificationFilterMatches({ hostname: 'web-1', policySet: 'dev' }, body), false);
  assert.equal(notificationFilterMatches({ count: '42' }, body), true);
  assert.equal(notificationFilterMatches({ 'host.env': 'prod' }, body), true);
  assert.equal(notificationFilterMatches({ missing: 'x' }, body), false);
  assert.equal(notificationFilterMatches('not-an-object', body), false);
});

test('sendNotification: applies filters and sends once per channel even with duplicate rules', async () => {
  const logged = [];
  stubPool((sql, params) => {
    if (/FROM notification_rules nr/.test(sql)) {
      return {
        rows: [
          { id: 'r1', channel_id: 'c1', filter: null, channel_type: 'none', channel_config: {} },
          { id: 'r2', channel_id: 'c1', filter: null, channel_type: 'none', channel_config: {} }, // duplicate
          { id: 'r3', channel_id: 'c2', filter: { hostname: 'other' }, channel_type: 'none', channel_config: {} },
          { id: 'r4', channel_id: 'c3', filter: { hostname: 'web-1' }, channel_type: 'none', channel_config: {} }
        ]
      };
    }
    if (/INSERT INTO notification_log/.test(sql)) {
      logged.push(params[0]);
      return { rows: [{ id: `log-${logged.length}` }] };
    }
  });
  await sendNotification({ eventType: 'DEPLOYMENT_FAILED', subject: 's', body: { hostname: 'web-1' } });
  assert.deepEqual(logged, ['c1', 'c3']);
});

// --- audit paging ---------------------------------------------------------------------------------------

test('audit limit clamp and cursor round trip', () => {
  assert.equal(clampAuditLimit(undefined), 500);
  assert.equal(clampAuditLimit('abc'), 500);
  assert.equal(clampAuditLimit('-3'), 1);
  assert.equal(clampAuditLimit('999999'), 5000);
  assert.equal(clampAuditLimit('25'), 25);
  const c = encodeAuditCursor('2026-11-01T10:00:00.123456Z', USER_ID);
  assert.deepEqual(decodeAuditCursor(c), { ts: '2026-11-01T10:00:00.123456Z', id: USER_ID });
  assert.equal(decodeAuditCursor('garbage'), null);
  assert.equal(decodeAuditCursor(Buffer.from("2026-11-01'; DROP|x").toString('base64url')), null);
});

test('GET /audit pages with limit + before and returns nextCursor', async () => {
  currentRoles = ['viewer'];
  const mk = (i) => ({ id: `0000000${i}-0000-4000-8000-000000000000`, action: 'X', _cursor_ts: `2026-11-01T10:00:0${i}.000001Z` });
  const calls = stubPool((sql) => {
    if (/FROM audit_events a/.test(sql)) return { rows: [mk(3), mk(2), mk(1)] };
  });
  const r = await call('/api', auditRouter, 'GET', '/audit?limit=2');
  assert.equal(r.status, 200);
  assert.equal(r.body.events.length, 2);
  assert.equal(r.body.events[0]._cursor_ts, undefined);
  assert.deepEqual(decodeAuditCursor(r.body.nextCursor), { ts: '2026-11-01T10:00:02.000001Z', id: mk(2).id });
  assert.equal(calls.at(-1).params.at(-1), 3); // limit + 1

  const r2 = await call('/api', auditRouter, 'GET', `/audit?limit=2&before=${r.body.nextCursor}`);
  assert.equal(r2.status, 200);
  const q = calls.at(-1);
  assert.match(q.sql, /\(a\.timestamp, a\.id\) < \(\$1::timestamptz, \$2::uuid\)/);
  assert.deepEqual(q.params.slice(0, 2), ['2026-11-01T10:00:02.000001Z', mk(2).id]);

  const bad = await call('/api', auditRouter, 'GET', '/audit?before=nope');
  assert.equal(bad.status, 400);
});

// --- flow collectors ------------------------------------------------------------------------------------

test('GET /flow-collectors/:id/flows clamps limit and allows approvers', async () => {
  currentRoles = ['approver'];
  const calls = stubPool();
  for (const [q, expected] of [['-5', 1], ['99999', 1000], ['abc', 100], ['50', 50]]) {
    const r = await call('/api/flow-collectors', flowCollectorsRouter, 'GET', `/c1/flows?limit=${q}`);
    assert.equal(r.status, 200);
    assert.equal(calls.at(-1).params[1], expected, q);
  }
  const list = await call('/api/flow-collectors', flowCollectorsRouter, 'GET', '/');
  assert.equal(list.status, 200);
});

// --- policy sets ----------------------------------------------------------------------------------------

test('POST /policy-sets validates the scope', async () => {
  currentRoles = ['operator'];
  stubPool((sql) => {
    if (/FROM tags WHERE id/.test(sql)) return { rows: [] };
    if (/FROM hosts WHERE id = ANY/.test(sql)) return { rows: [{ id: HOST_A }] };
  });
  let r = await call('/api/policy-sets', policySetsRouter, 'POST', '/', { name: 'a', scopeType: 'TAG' });
  assert.equal(r.status, 400);
  assert.equal(r.body.error, 'scope_tag_required');
  r = await call('/api/policy-sets', policySetsRouter, 'POST', '/', { name: 'a', scopeType: 'TAG', scopeTagId: TAG_ID });
  assert.equal(r.body.error, 'scope_tag_not_found');
  r = await call('/api/policy-sets', policySetsRouter, 'POST', '/', { name: 'a', scopeType: 'VLAN' });
  assert.equal(r.body.error, 'scope_vlan_required');
  r = await call('/api/policy-sets', policySetsRouter, 'POST', '/', { name: 'a', scopeType: 'HOST_LIST', hostIds: [] });
  assert.equal(r.body.error, 'host_ids_required');
  r = await call('/api/policy-sets', policySetsRouter, 'POST', '/', { name: 'a', scopeType: 'HOST_LIST', hostIds: [HOST_A, HOST_B] });
  assert.equal(r.status, 400);
  assert.equal(r.body.error, 'hosts_not_found');
});

test('PUT /policy-sets/:id TAG -> HOST_LIST clears the tag and replaces the host list in one transaction', async () => {
  currentRoles = ['operator'];
  const calls = stubPool((sql, params) => {
    if (/SELECT \* FROM policy_sets WHERE id=\$1 FOR UPDATE/.test(sql)) {
      return { rows: [{ id: PS_ID, scope_type: 'TAG', scope_tag_id: TAG_ID, scope_vlan_id: null }] };
    }
    if (/FROM hosts WHERE id = ANY/.test(sql)) return { rows: params[0].map((id) => ({ id })) };
    if (/UPDATE policy_sets/.test(sql)) return { rows: [{ id: PS_ID, scope_type: params[3], scope_tag_id: params[4] }] };
  });
  const r = await call('/api/policy-sets', policySetsRouter, 'PUT', `/${PS_ID}`, { scopeType: 'HOST_LIST', hostIds: [HOST_A] });
  assert.equal(r.status, 200);
  const upd = calls.find((c) => /UPDATE policy_sets/.test(c.sql));
  assert.deepEqual(upd.params.slice(3), ['HOST_LIST', null, null]);
  assert.ok(calls.some((c) => /DELETE FROM policy_set_hosts WHERE policy_set_id=\$1 AND NOT/.test(c.sql)));
  const ins = calls.find((c) => /INSERT INTO policy_set_hosts/.test(c.sql));
  assert.deepEqual(ins.params, [PS_ID, [HOST_A]]);
  assert.equal(calls[0].sql, 'BEGIN');
  assert.equal(calls.at(-1).sql, 'COMMIT');

  // Switching to HOST_LIST without hosts is refused
  const r2 = await call('/api/policy-sets', policySetsRouter, 'PUT', `/${PS_ID}`, { scopeType: 'HOST_LIST' });
  assert.equal(r2.status, 400);
  assert.equal(r2.body.error, 'host_ids_required');

  // HOST_LIST -> TAG drops the host list
  const calls3 = stubPool((sql) => {
    if (/FOR UPDATE/.test(sql)) return { rows: [{ id: PS_ID, scope_type: 'HOST_LIST', scope_tag_id: null, scope_vlan_id: null }] };
    if (/FROM tags WHERE id/.test(sql)) return { rows: [{ '?column?': 1 }] };
    if (/UPDATE policy_sets/.test(sql)) return { rows: [{ id: PS_ID }] };
  });
  const r3 = await call('/api/policy-sets', policySetsRouter, 'PUT', `/${PS_ID}`, { scopeType: 'TAG', scopeTagId: TAG_ID });
  assert.equal(r3.status, 200);
  assert.ok(calls3.some((c) => /DELETE FROM policy_set_hosts WHERE policy_set_id=\$1$/.test(c.sql.trim())));
});

// --- troubleshoot by-ip ---------------------------------------------------------------------------------

test('GET /troubleshoot/policies/by-ip: set-based, disabled hosts do not match TAG/VLAN sources', async () => {
  currentRoles = ['viewer'];
  const V1 = 'aaaaaaaa-0000-4000-8000-000000000001';
  const calls = stubPool((sql) => {
    if (/DISTINCT ON \(dh\.host_id\)/.test(sql)) {
      return { rows: [{ id: 'd1', policy_version_id: V1, host_id: HOST_B, hostname: 'gw', mgmt_ip: '10.0.0.9', status: 'COMPLETED', host_status: 'SUCCEEDED' }] };
    }
    if (/FROM hosts h\s+LEFT JOIN host_tags/.test(sql)) {
      return { rows: [{ id: HOST_A, enabled: false, vlan_id: 'vlan-1', tag_ids: [TAG_ID] }] };
    }
    if (/FROM policy_rules pr/.test(sql)) {
      return {
        rows: [
          { id: 'r-cidr', source_type: 'CIDR', source_value: '10.0.0.0/24', version_id: V1, version_status: 'DEPLOYED' },
          { id: 'r-host', source_type: 'HOST', source_value: HOST_A, version_id: V1 },
          { id: 'r-tag', source_type: 'TAG', source_value: TAG_ID, version_id: V1 },
          { id: 'r-vlan', source_type: 'VLAN', source_value: 'vlan-1', version_id: V1 }
        ]
      };
    }
  });
  const r = await call('/api/troubleshoot', troubleshootRouter, 'GET', '/policies/by-ip?ip=10.0.0.5');
  assert.equal(r.status, 200);
  assert.deepEqual(r.body.results.map((x) => x.rule.id), ['r-cidr', 'r-host']);
  assert.equal(r.body.results[0].deployedHosts[0].hostname, 'gw');
  assert.equal(calls.length, 3);
  assert.match(calls.find((c) => /FROM policy_rules pr/.test(c.sql)).sql, /pv\.status <> 'ARCHIVED' OR pv\.id = ANY/);
});

// --- backup import body limit ---------------------------------------------------------------------------

test(`POST /backup/import parses bodies above 1 MB (limit ${BACKUP_IMPORT_BODY_LIMIT}) after the admin check`, async () => {
  currentRoles = ['admin'];
  stubPool();
  const big = JSON.stringify({ content: 'x'.repeat(3 * 1024 * 1024) });
  const r = await call('/api/backup', backupRouter, 'POST', '/import?dryRun=1', undefined, { rawBody: big, globalJson: false });
  assert.equal(r.status, 400); // parsed (invalid JSON content), not 413
  assert.equal(r.body.error, 'invalid_json');

  currentRoles = ['operator'];
  const denied = await call('/api/backup', backupRouter, 'POST', '/import', undefined, { rawBody: big, globalJson: false });
  assert.equal(denied.status, 403);
});
