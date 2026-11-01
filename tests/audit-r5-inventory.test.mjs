// Audit round 5: inventory / IoT asset fixes. Pure helpers plus route handlers run against a stubbed pg pool.
// Run after `npm run build`: node --test tests/audit-r5-inventory.test.mjs
// (R5_API_DIST=<dir> points the test at another compiled apps/api dist.)
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { pathToFileURL } from 'node:url';

process.env.DATABASE_URL ||= 'postgres://segmentra:unused@127.0.0.1:1/unused';
process.env.JWT_SECRET ||= 'audit-r5-inventory-test-secret-0123456789';

const DIST = process.env.R5_API_DIST
  ? pathToFileURL(process.env.R5_API_DIST.replace(/\/?$/, '/')).href
  : new URL('../apps/api/dist/', import.meta.url).href;
const load = (p) => import(new URL(p, DIST).href);

const { normalizeIotAddress, normalizeDestinationAddress } = await load('services/ip-utils.js');
const { pool } = await load('db/pool.js');
const { signJwt } = await load('services/jwt.js');
const { iotAssetsRouter, iotIpAddress, iotMacAddress } = await load('routes/iot-assets.js');
const { iotExtrasRouter } = await load('routes/iot-extras.js');
const { interfacesRouter, INTERFACE_NAME_REGEX } = await load('routes/inventory/interfaces.js');
const { vlansRouter } = await load('routes/inventory/vlans.js');
const { resolveDestinationAddresses, getProtectedDestinations } = await load('services/forward-rules.js');
const express = (await import('express')).default;

const USER_ID = '11111111-1111-4111-8111-111111111111';
const ASSET_ID = '22222222-2222-4222-8222-222222222222';
const token = signJwt({ sub: 'op', roles: ['operator'], uid: USER_ID, tv: 0 });

/** Stub pool.query: `handler(sql, params)` returns { rows, rowCount } or undefined (= empty). Records calls. */
function stubPool(handler) {
  const calls = [];
  const q = async (sql, params = []) => {
    const text = typeof sql === 'string' ? sql : sql.text;
    calls.push({ sql: text, params });
    if (/FROM users u\s+LEFT JOIN user_roles/.test(text)) {
      return { rows: [{ id: USER_ID, username: 'op', is_active: true, token_version: 0, roles: ['operator'] }], rowCount: 1 };
    }
    const r = (await handler(text, params)) ?? {};
    return { rows: r.rows ?? [], rowCount: r.rowCount ?? (r.rows ?? []).length };
  };
  pool.query = q;
  pool.connect = async () => ({ query: q, release() {} });
  return calls;
}

async function call(mount, router, method, path, body) {
  const app = express();
  app.use(express.json());
  app.use(mount, router);
  // eslint-disable-next-line no-unused-vars
  app.use((err, _req, res, _next) => res.status(500).json({ error: String(err?.message ?? err) }));
  const server = await new Promise((resolve) => { const s = app.listen(0, '127.0.0.1', () => resolve(s)); });
  try {
    const res = await fetch(`http://127.0.0.1:${server.address().port}${mount}${path}`, {
      method,
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body)
    });
    return { status: res.status, body: await res.json().catch(() => null) };
  } finally {
    await new Promise((r) => server.close(r));
  }
}

// --- 1. host-bits CIDR = the device -------------------------------------------------------------------

test('normalizeIotAddress: host bits set means the host, a network CIDR stays a CIDR', () => {
  assert.equal(normalizeIotAddress('192.168.10.5/24'), '192.168.10.5');
  assert.equal(normalizeIotAddress(' 192.168.10.5/24 '), '192.168.10.5');
  assert.equal(normalizeIotAddress('192.168.10.0/24'), '192.168.10.0/24');
  assert.equal(normalizeIotAddress('10.0.0.1/32'), '10.0.0.1');
  assert.equal(normalizeIotAddress('10.0.0.1'), '10.0.0.1');
  assert.equal(normalizeIotAddress('fe80::1/64'), 'fe80::1');
  assert.equal(normalizeIotAddress('2001:db8::/64'), '2001:db8::/64');
  assert.equal(normalizeIotAddress('2001:db8::5/128'), '2001:db8::5');
  assert.equal(normalizeIotAddress('0.0.0.0/0'), '0.0.0.0/0');
  for (const bad of ['', 'garbage', '999.1.1.1', '10.0.0.0/33', 'host.example', null, undefined]) {
    assert.equal(normalizeIotAddress(bad), null, String(bad));
  }
  assert.equal(normalizeDestinationAddress('192.168.10.5/24'), '192.168.10.5');
});

test('IOT_ASSET destination and protected destinations: a legacy 192.168.10.5/24 row is one device', async () => {
  stubPool((sql) => {
    if (/FROM iot_assets WHERE id = \$1/.test(sql)) return { rows: [{ ip_address: '192.168.10.5/24' }] };
    if (/FROM iot_asset_gateways g/.test(sql)) {
      return { rows: [{ ip: '192.168.10.5/24' }, { ip: '192.168.10.5' }, { ip: '192.168.20.0/24' }, { ip: 'bogus' }] };
    }
  });
  assert.deepEqual(await resolveDestinationAddresses('IOT_ASSET', ASSET_ID), ['192.168.10.5']);
  // duplicates collapse; invalid text is passed on so the compiler still refuses it loudly
  assert.deepEqual(await getProtectedDestinations('h1'), ['192.168.10.5', '192.168.20.0/24', 'bogus']);
});

test('IoT asset schemas: host-bits address accepted and stored normalized; MAC stored lowercase colon form', () => {
  assert.equal(iotIpAddress.parse('192.168.10.5/24'), '192.168.10.5');
  assert.equal(iotIpAddress.parse('192.168.10.0/24'), '192.168.10.0/24');
  assert.equal(iotIpAddress.parse(''), '');
  assert.equal(iotIpAddress.safeParse('not-an-ip').success, false);
  assert.equal(iotMacAddress.parse('AA-BB-CC-DD-EE-FF'), 'aa:bb:cc:dd:ee:ff');
  assert.equal(iotMacAddress.parse('aabb.ccdd.eeff'), 'aa:bb:cc:dd:ee:ff');
  assert.equal(iotMacAddress.parse(''), '');
  assert.equal(iotMacAddress.safeParse('AA-BB-CC').success, false);
});

test('PUT /iot-assets/:id resending a legacy host-bits address succeeds and stores the bare IP and MAC', async () => {
  const calls = stubPool((sql, params) => {
    if (/UPDATE iot_assets/.test(sql)) return { rows: [{ id: params[0], name: 'plc', ip_address: params[8], mac_address: params[7] }] };
  });
  const r = await call('/api/iot', iotAssetsRouter, 'PUT', `/${ASSET_ID}`, { ipAddress: '192.168.10.5/24', macAddress: 'AA-BB-CC-DD-EE-FF' });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  const upd = calls.find((c) => /UPDATE iot_assets/.test(c.sql));
  assert.equal(upd.params[8], '192.168.10.5');
  assert.equal(upd.params[7], 'aa:bb:cc:dd:ee:ff');
});

test('POST /iot-assets stores normalized address and MAC', async () => {
  const calls = stubPool((sql) => {
    if (/INSERT INTO iot_assets/.test(sql)) return { rows: [{ id: ASSET_ID }] };
  });
  const r = await call('/api/iot', iotAssetsRouter, 'POST', '/', { name: 'cam', ipAddress: '10.1.2.3/16', macAddress: 'AABB.CCDD.EEFF' });
  assert.equal(r.status, 201, JSON.stringify(r.body));
  const ins = calls.find((c) => /INSERT INTO iot_assets/.test(c.sql));
  assert.equal(ins.params[6], 'aa:bb:cc:dd:ee:ff');
  assert.equal(ins.params[7], '10.1.2.3');
});

// --- 2. IoT asset delete refuses rule references -----------------------------------------------------

test('DELETE /iot-assets/:id is refused with 409 while rules reference the asset', async () => {
  const calls = stubPool((sql, params) => {
    if (/FROM policy_rules pr/.test(sql)) {
      assert.deepEqual(params, ['IOT_ASSET', ASSET_ID]);
      return { rows: [{ policy_rules: 2, template_rules: 1 }] };
    }
    if (/DELETE FROM iot_assets/.test(sql)) throw new Error('must not delete');
  });
  const r = await call('/api/iot', iotAssetsRouter, 'DELETE', `/${ASSET_ID}`);
  assert.equal(r.status, 409);
  assert.equal(r.body.error, 'iot_asset_in_use');
  assert.match(r.body.message, /2 policy rule\(s\) and 1 template rule\(s\)/);
  assert.ok(!calls.some((c) => /DELETE FROM iot_assets/.test(c.sql)));
});

test('DELETE /iot-assets/:id without references deletes', async () => {
  stubPool((sql) => {
    if (/FROM policy_rules pr/.test(sql)) return { rows: [{ policy_rules: 0, template_rules: 0 }] };
    if (/DELETE FROM iot_assets/.test(sql)) return { rowCount: 1 };
  });
  const r = await call('/api/iot', iotAssetsRouter, 'DELETE', `/${ASSET_ID}`);
  assert.equal(r.status, 200);
});

// --- 3. discovery import duplicate check compares normalized MACs -----------------------------------

test('discover/import duplicate check strips separators on both sides', async () => {
  const GW = '33333333-3333-4333-8333-333333333333';
  const calls = stubPool((sql) => {
    if (/FROM hosts/.test(sql) && /WHERE/.test(sql) && !/iot_assets/.test(sql)) {
      return { rows: [{ id: GW, hostname: 'gw1', mgmt_ip: '10.0.0.1', enabled: true }] };
    }
    if (/regexp_replace\(lower\(coalesce\(mac_address/.test(sql)) return { rows: [{ name: 'manual-plc' }] };
  });
  const r = await call('/api/iot', iotExtrasRouter, 'POST', '/discover/import', {
    gatewayId: GW, devices: [{ ip: '192.168.50.7', mac: 'AA-BB-CC-DD-EE-01' }]
  });
  const dup = calls.find((c) => /regexp_replace\(lower\(coalesce\(mac_address/.test(c.sql));
  assert.ok(dup, `duplicate query not run (status ${r.status}: ${JSON.stringify(r.body)})`);
  assert.equal(dup.params[0], 'aabbccddee01');
  assert.equal(r.body.created.length, 0);
  assert.match(r.body.skipped[0].reason, /manual-plc/);
});

// --- 4. interface names / clearing -------------------------------------------------------------------

test('interface names are validated like the compiler does', async () => {
  for (const ok of ['eth0', 'ens192', 'br-lan', 'eth0.100', 'wg0', 'veth@if5']) assert.ok(INTERFACE_NAME_REGEX.test(ok), ok);
  for (const bad of ['', 'eth0; reboot', 'a'.repeat(16), 'eth 0', 'eth0"', 'éth0']) assert.ok(!INTERFACE_NAME_REGEX.test(bad), bad);
  const { compileHostPolicy } = await import('@segmentra/compiler');
  const compileWith = (name) => compileHostPolicy({
    host: { id: '1', hostname: 'n1', mgmtIp: '10.0.0.5', sshPort: 22, firewallBackend: 'nftables', interfaces: [] },
    policyInterfaceScope: { type: 'INTERFACE_NAME', names: [name] },
    rules: [{ orderIndex: 10, direction: 'IN', action: 'ALLOW', protocol: 'tcp', ports: '80', sourceType: 'CIDR', sourceValue: '10.0.0.0/24', logMode: 'NONE', usePolicyInterfaceScope: true, remote: { kind: 'CIDR' } }],
    sets: {}, baseline: { mgmtSshCidrs: ['10.0.0.0/24'] }
  });
  for (const n of ['eth0', 'a'.repeat(15), 'eth0;x', 'a'.repeat(16)]) {
    let compiles = true;
    try { compileWith(n); } catch { compiles = false; }
    assert.equal(compiles, INTERFACE_NAME_REGEX.test(n), `API and compiler disagree on "${n}"`);
  }

  const calls = stubPool(() => { throw new Error('must not reach the database'); });
  const r = await call('/api', interfacesRouter, 'POST', `/hosts/${ASSET_ID}/interfaces`, { name: 'eth0; rm -rf /', role: 'lan' });
  assert.equal(r.status, 400);
  assert.ok(!calls.some((c) => /host_interfaces/.test(c.sql)));
});

test('PUT /interfaces/:id: explicit null clears ip_address/vlan_id, omitted keeps', async () => {
  const calls = stubPool((sql, params) => {
    if (/UPDATE host_interfaces/.test(sql)) return { rows: [{ id: params[0] }] };
  });
  let r = await call('/api', interfacesRouter, 'PUT', `/interfaces/${ASSET_ID}`, { ipAddress: null, vlanId: null });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  let p = calls.find((c) => /UPDATE host_interfaces/.test(c.sql)).params;
  assert.equal(p[3], null);
  assert.equal(p[5], null);
  assert.deepEqual([p[8], p[9], p[10]], [true, false, true]); // ip set, cidr kept, vlan set
  calls.length = 0;
  r = await call('/api', interfacesRouter, 'PUT', `/interfaces/${ASSET_ID}`, { role: 'wan' });
  assert.equal(r.status, 200);
  p = calls.find((c) => /UPDATE host_interfaces/.test(c.sql)).params;
  assert.deepEqual([p[8], p[9], p[10]], [false, false, false]);
  r = await call('/api', interfacesRouter, 'PUT', `/interfaces/${ASSET_ID}`, { name: 'bad name!' });
  assert.equal(r.status, 400);
});

// --- 5. VLAN subnet can be cleared -------------------------------------------------------------------

test('PUT /vlans/:id: null or empty subnet clears it, omitted keeps, invalid refused', async () => {
  const calls = stubPool((sql, params) => {
    if (/UPDATE vlans/.test(sql)) return { rows: [{ id: params[0] }] };
  });
  for (const [body, expectSet] of [[{ subnet: null }, true], [{ subnet: '' }, true], [{ name: 'x' }, false], [{ subnet: '10.0.10.0/24' }, true]]) {
    calls.length = 0;
    const r = await call('/api/vlans', vlansRouter, 'PUT', `/${ASSET_ID}`, body);
    assert.equal(r.status, 200, JSON.stringify(body));
    const p = calls.find((c) => /UPDATE vlans/.test(c.sql)).params;
    assert.equal(p[5], expectSet, JSON.stringify(body));
    assert.equal(p[4], body.subnet ? body.subnet : null);
  }
  const bad = await call('/api/vlans', vlansRouter, 'PUT', `/${ASSET_ID}`, { subnet: '10.0.10.1' });
  assert.equal(bad.status, 400);
});
