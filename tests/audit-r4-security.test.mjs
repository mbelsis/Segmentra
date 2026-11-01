// Regression tests for deep audit round 4 (security): SSH target changes are admin-only, backup import
// does not trust approval trails, JWT sessions are revocable, and login timing does not reveal usernames.
// Runs against the built API (apps/api/dist) with the database pool mocked; no PostgreSQL needed.
import assert from 'node:assert/strict';
import { test } from 'node:test';

process.env.NODE_ENV = 'test';
process.env.DATABASE_URL = 'postgres://localhost/segmentra_test';
process.env.JWT_SECRET = 'test-only-secret-with-at-least-32-characters';
process.env.SEGMENTRA_KEK_B64 = Buffer.alloc(32, 1).toString('base64');
process.env.CORS_ORIGIN = '';

const dist = (p) => new URL(`../apps/api/dist/${p}`, import.meta.url).href;
const { pool } = await import(dist('db/pool.js'));
const { hostsRouter, createSshTargetForbidden, SSH_TARGET_FORBIDDEN } = await import(dist('routes/inventory/hosts.js'));
const { importedVersionStatus } = await import(dist('services/backup.js'));
const { requireAuth } = await import(dist('middleware/auth.js'));
const { signJwt, verifyJwt } = await import(dist('services/jwt.js'));
const { authRouter } = await import(dist('routes/auth.js'));
const { hashPassword, burnPasswordCheck } = await import(dist('services/password.js'));
const bcrypt = (await import('bcrypt')).default;

const UID = '11111111-2222-4333-8444-555555555555';
const HOST_ID = '99999999-2222-4333-8444-555555555555';

function mockRes() {
  return {
    statusCode: 200,
    status(code) { this.statusCode = code; return this; },
    json(payload) { this.body = payload; return this; }
  };
}

function routeHandler(router, method, path) {
  const layer = router.stack.find((l) => l.route?.path === path && l.route.methods[method]);
  assert.ok(layer, `route ${method.toUpperCase()} ${path} exists`);
  const stack = layer.route.stack;
  return stack[stack.length - 1].handle;
}

const operator = { username: 'op', roles: ['operator'], userId: UID };
const admin = { username: 'adm', roles: ['admin'], userId: UID };

// ---------- 1. SSH target (mgmt_ip / ssh_port) is admin-only ----------

test('creating a host: operators may not set an SSH address or a non-default port', () => {
  const req = { auth: operator };
  assert.equal(createSshTargetForbidden(req, { mgmtIp: '10.0.0.5' }), true);
  assert.equal(createSshTargetForbidden(req, { sshPort: 2222 }), true);
  assert.equal(createSshTargetForbidden(req, {}), false);
  assert.equal(createSshTargetForbidden(req, { mgmtIp: '', sshPort: 22 }), false);
  assert.equal(createSshTargetForbidden({ auth: admin }, { mgmtIp: '10.0.0.5', sshPort: 2222 }), false);
  assert.equal(SSH_TARGET_FORBIDDEN.error, 'forbidden');
  assert.match(SSH_TARGET_FORBIDDEN.message, /Only admins can set or change a host's SSH address\/port/);
});

test('POST /hosts with a management IP from an operator is refused before touching the database', async (t) => {
  const handler = routeHandler(hostsRouter, 'post', '/');
  const connect = t.mock.method(pool, 'connect', async () => { throw new Error('must not connect'); });
  const res = mockRes();
  await handler({ auth: operator, body: { hostname: 'evil', mgmtIp: '203.0.113.7' } }, res);
  assert.equal(res.statusCode, 403);
  assert.deepEqual(res.body, { ...SSH_TARGET_FORBIDDEN });
  assert.equal(connect.mock.callCount(), 0);
});

function hostUpdateClient(current) {
  const queries = [];
  return {
    queries,
    async query(sql, args) {
      queries.push({ sql, args });
      if (sql.includes('IS NOT DISTINCT FROM $2::inet')) {
        // emulate inet comparison on already normalised strings
        return { rows: current ? [{ same_ip: (current.mgmt_ip ?? null) === (args[1] ?? null), ssh_port: current.ssh_port }] : [] };
      }
      if (sql.includes('UPDATE hosts')) return { rows: [{ id: HOST_ID, hostname: 'web1' }] };
      if (sql.includes('FROM hosts h')) return { rows: [{ id: HOST_ID, hostname: 'web1' }] };
      return { rows: [] };
    },
    release() {}
  };
}

test('PUT /hosts/:id: operators can resend the unchanged SSH target but not change it', async (t) => {
  const handler = routeHandler(hostsRouter, 'put', '/:id');
  t.mock.method(pool, 'query', async () => ({ rows: [] }));

  // Changed address -> 403 and rolled back, no UPDATE
  let client = hostUpdateClient({ mgmt_ip: '10.0.0.5', ssh_port: 22 });
  t.mock.method(pool, 'connect', async () => client);
  let res = mockRes();
  await handler({ auth: operator, params: { id: HOST_ID }, body: { mgmtIp: '203.0.113.7' } }, res);
  assert.equal(res.statusCode, 403);
  assert.equal(res.body.message, SSH_TARGET_FORBIDDEN.message);
  assert.ok(!client.queries.some((q) => q.sql.includes('UPDATE hosts')));
  assert.equal(client.queries.at(-1).sql, 'ROLLBACK');

  // Clearing the address is a change as well
  client = hostUpdateClient({ mgmt_ip: '10.0.0.5', ssh_port: 22 });
  res = mockRes();
  await handler({ auth: operator, params: { id: HOST_ID }, body: { mgmtIp: null } }, res);
  assert.equal(res.statusCode, 403);

  // Changed port -> 403
  client = hostUpdateClient({ mgmt_ip: '10.0.0.5', ssh_port: 22 });
  res = mockRes();
  await handler({ auth: operator, params: { id: HOST_ID }, body: { sshPort: 2222 } }, res);
  assert.equal(res.statusCode, 403);

  // Same address and port (whole form) plus other changes -> accepted
  client = hostUpdateClient({ mgmt_ip: '10.0.0.5', ssh_port: 22 });
  res = mockRes();
  await handler({ auth: operator, params: { id: HOST_ID }, body: { mgmtIp: '10.0.0.5', sshPort: 22, environment: 'prod', tagIds: [] } }, res);
  assert.equal(res.statusCode, 200);
  assert.ok(client.queries.some((q) => q.sql.includes('UPDATE hosts')));

  // No SSH fields at all -> no target check
  client = hostUpdateClient({ mgmt_ip: '10.0.0.5', ssh_port: 22 });
  res = mockRes();
  await handler({ auth: operator, params: { id: HOST_ID }, body: { enabled: false } }, res);
  assert.equal(res.statusCode, 200);
  assert.ok(!client.queries.some((q) => q.sql.includes('IS NOT DISTINCT FROM $2::inet')));

  // Admins may change it
  client = hostUpdateClient({ mgmt_ip: '10.0.0.5', ssh_port: 22 });
  res = mockRes();
  await handler({ auth: admin, params: { id: HOST_ID }, body: { mgmtIp: '10.0.0.6', sshPort: 2222 } }, res);
  assert.equal(res.statusCode, 200);
  const upd = client.queries.find((q) => q.sql.includes('UPDATE hosts'));
  assert.equal(upd.args[2], '10.0.0.6');
  assert.equal(upd.args[3], 2222);
});

test('CSV import: operator rows that set or change the SSH target fail, others are imported', async (t) => {
  const handler = routeHandler(hostsRouter, 'post', '/bulk/import');
  const existing = new Map([['old1', { mgmt_ip: '10.0.0.5', ssh_port: 22 }]]);
  const inserts = [];
  const client = {
    async query(sql, args) {
      if (sql.includes('FROM vlans') || sql.includes('FROM tags')) return { rows: [] };
      if (sql.includes('IS NOT DISTINCT FROM $2::inet')) {
        const cur = existing.get(args[0]);
        return { rows: cur ? [{ same_ip: cur.mgmt_ip === args[1], ssh_port: cur.ssh_port }] : [] };
      }
      if (sql.includes('INSERT INTO hosts')) { inserts.push(args); return { rows: [{ id: HOST_ID }] }; }
      return { rows: [] };
    },
    release() {}
  };
  t.mock.method(pool, 'connect', async () => client);
  t.mock.method(pool, 'query', async () => ({ rows: [] }));
  const csvData = [
    'hostname,mgmt_ip,ssh_port',
    'new1,,',            // new host without target: ok
    'new2,203.0.113.7,', // new host with address: refused
    'old1,10.0.0.5,22',  // unchanged: ok
    'old1,203.0.113.7,22', // changed address: refused
    'old1,10.0.0.5,2222' // changed port: refused
  ].join('\n');
  const res = mockRes();
  await handler({ auth: operator, body: { csvData } }, res);
  assert.equal(res.statusCode, 200);
  assert.deepEqual(res.body.results.map((r) => r.success), [true, false, true, false, false]);
  for (const r of res.body.results.filter((x) => !x.success)) assert.equal(r.error, SSH_TARGET_FORBIDDEN.message);
  assert.equal(inserts.length, 2);
  // the update flags tell the upsert that the IP/port columns are present
  assert.deepEqual(inserts[0].slice(6), [true, true]);
  await new Promise((r) => setTimeout(r, 50)); // let the background tag-rule evaluation hit the mocked pool
});

// ---------- 2. Backup import does not trust the approval trail ----------

test('backup import creates approved/deployed/pending versions as PENDING_APPROVAL with a warning', () => {
  for (const status of ['APPROVED', 'DEPLOYED', 'PENDING_APPROVAL']) {
    const r = importedVersionStatus({ versionNumber: 3, status });
    assert.equal(r.status, 'PENDING_APPROVAL');
    assert.equal(r.resubmit, true);
    assert.match(r.warning, /version 3 .*imported as PENDING_APPROVAL, needs re-approval/);
  }
  for (const status of ['DRAFT', 'REJECTED', 'ARCHIVED']) {
    const r = importedVersionStatus({ versionNumber: 1, status });
    assert.equal(r.status, status);
    assert.equal(r.resubmit, false);
    assert.equal(r.warning, null);
  }
});

// ---------- 3. JWT revocation ----------

function authUserRow(over = {}) {
  return { id: UID, username: 'alice', is_active: true, token_version: 4, roles: ['operator'], ...over };
}

async function runRequireAuth(token, row) {
  const res = mockRes();
  let nextCalled = false;
  const req = { header: (h) => (h.toLowerCase() === 'authorization' && token ? `Bearer ${token}` : undefined) };
  await new Promise((resolve) => {
    const origJson = res.json.bind(res);
    res.json = (p) => { origJson(p); resolve(); return res; };
    requireAuth(req, res, () => { nextCalled = true; resolve(); });
  });
  return { res, req, nextCalled };
}

test('requireAuth loads the user by id and checks username and token_version', async (t) => {
  let lookups = [];
  let row = authUserRow();
  t.mock.method(pool, 'query', async (sql, args) => { lookups.push(args); return { rows: row ? [row] : [] }; });

  const good = signJwt({ sub: 'alice', roles: ['admin'], uid: UID, tv: 4 });
  let r = await runRequireAuth(good, row);
  assert.equal(r.nextCalled, true);
  assert.deepEqual(r.req.auth.roles, ['operator'], 'roles come from the database, not the token');
  assert.equal(r.req.auth.userId, UID);
  assert.deepEqual(lookups.at(-1), [UID]);

  // token_version bumped (logout / password change / reset) -> rejected
  row = authUserRow({ token_version: 5 });
  r = await runRequireAuth(good, row);
  assert.equal(r.res.statusCode, 401);
  assert.equal(r.res.body.error, 'invalid_token');

  // user deleted and re-created with the same name has a new id -> no row for the old uid
  row = null;
  r = await runRequireAuth(good, row);
  assert.equal(r.res.statusCode, 401);

  // same id but a different username -> rejected
  row = authUserRow({ username: 'mallory' });
  r = await runRequireAuth(good, row);
  assert.equal(r.res.statusCode, 401);

  // inactive -> user_disabled
  row = authUserRow({ is_active: false });
  r = await runRequireAuth(good, row);
  assert.equal(r.res.statusCode, 401);
  assert.equal(r.res.body.error, 'user_disabled');

  // legacy token without uid/tv -> rejected without a database lookup
  lookups = [];
  const legacy = signJwt({ sub: 'alice', roles: ['admin'] });
  r = await runRequireAuth(legacy, authUserRow());
  assert.equal(r.res.statusCode, 401);
  assert.equal(lookups.length, 0);
});

test('logout bumps token_version of the token owner; change-password bumps it and returns a fresh token', async (t) => {
  const queries = [];
  const hash = await hashPassword('old-password-1');
  t.mock.method(pool, 'query', async (sql, args) => {
    queries.push({ sql, args });
    if (sql.includes('password_hash FROM users WHERE id=$1')) return { rows: [{ id: UID, username: 'alice', password_hash: hash }] };
    if (sql.includes('RETURNING token_version')) return { rows: [{ token_version: 8 }] };
    return { rows: [], rowCount: 1 };
  });

  const logout = routeHandler(authRouter, 'post', '/logout');
  const token = signJwt({ sub: 'alice', roles: ['operator'], uid: UID, tv: 7 });
  let res = mockRes();
  await logout({ header: () => `Bearer ${token}` }, res);
  assert.equal(res.body.ok, true);
  const bump = queries.find((q) => q.sql.includes('token_version = token_version + 1'));
  assert.ok(bump, 'logout bumps token_version');
  assert.deepEqual(bump.args, [UID, 'alice', 7]);

  // no / invalid token: no-op
  queries.length = 0;
  res = mockRes();
  await logout({ header: () => 'Bearer not-a-token' }, res);
  assert.equal(res.body.ok, true);
  assert.equal(queries.length, 0);

  const changePassword = routeHandler(authRouter, 'post', '/change-password');
  res = mockRes();
  await changePassword({ auth: { username: 'alice', roles: ['operator'], userId: UID }, body: { currentPassword: 'old-password-1', newPassword: 'new-password-2' } }, res);
  assert.equal(res.statusCode, 200);
  assert.ok(queries.some((q) => q.sql.includes('token_version = token_version + 1') && q.sql.includes('password_hash')));
  const claims = verifyJwt(res.body.token);
  assert.equal(claims.uid, UID);
  assert.equal(claims.tv, 8);
});

// ---------- 4. Login timing ----------

test('login for an unknown local user still runs a bcrypt comparison', async (t) => {
  assert.equal(await burnPasswordCheck('whatever'), false);
  const compare = t.mock.method(bcrypt, 'compare');
  t.mock.method(pool, 'query', async () => ({ rows: [] })); // no local user, LDAP not configured
  const login = routeHandler(authRouter, 'post', '/login');
  const res = mockRes();
  await login({ body: { username: 'nobody', password: 'pw' }, ip: 'timing-test-ip', socket: {} }, res);
  assert.equal(res.statusCode, 401);
  assert.equal(res.body.error, 'invalid_credentials');
  assert.ok(compare.mock.callCount() >= 1, 'a dummy bcrypt compare ran');
});

test('login checks the password before revealing that a local account is disabled', async (t) => {
  const hash = await hashPassword('right-password');
  const compare = t.mock.method(bcrypt, 'compare');
  t.mock.method(pool, 'query', async (sql) => {
    if (sql.includes('password_hash IS NOT NULL')) return { rows: [{ id: UID, username: 'bob', password_hash: hash, is_active: false, token_version: 0 }] };
    return { rows: [] };
  });
  const login = routeHandler(authRouter, 'post', '/login');
  const res = mockRes();
  await login({ body: { username: 'bob', password: 'right-password' }, ip: 'timing-test-ip-2', socket: {} }, res);
  assert.equal(res.statusCode, 401);
  assert.equal(compare.mock.callCount(), 1);
});
