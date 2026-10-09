import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';

import { corsOptions } from '../apps/api/dist/lib/cors.js';

const envModule = new URL('../apps/api/dist/lib/env.js', import.meta.url).href;
const validKek = Buffer.alloc(32, 1).toString('base64');

function validateEnvironment(overrides = {}) {
  return spawnSync(process.execPath, ['--input-type=module', '-e', `await import(${JSON.stringify(envModule)})`], {
    env: {
      ...process.env,
      NODE_ENV: 'production',
      DATABASE_URL: 'postgres://localhost/segmentra_test',
      JWT_SECRET: 'test-only-secret-with-at-least-32-characters',
      SEGMENTRA_KEK_B64: validKek,
      CORS_ORIGIN: '',
      ...overrides
    },
    encoding: 'utf8'
  });
}

test('production startup requires a separate encryption key', () => {
  const result = validateEnvironment({ SEGMENTRA_KEK_B64: '' });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /SEGMENTRA_KEK_B64 is required in production/);
});

test('startup rejects malformed or incorrectly sized encryption keys', () => {
  for (const key of ['invalid', Buffer.alloc(31).toString('base64'), `${validKek}!`]) {
    const result = validateEnvironment({ SEGMENTRA_KEK_B64: key });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /must encode exactly 32 bytes/);
  }
  assert.equal(validateEnvironment().status, 0);
  assert.equal(validateEnvironment({ NODE_ENV: 'development', SEGMENTRA_KEK_B64: '' }).status, 0);
});

test('CORS defaults to same-origin production and supports explicit origins', () => {
  assert.equal(corsOptions('production', '').origin, false);
  assert.equal(corsOptions('development', '').origin, '*');
  assert.deepEqual(corsOptions('production', 'https://one.example, https://two.example').origin,
    ['https://one.example', 'https://two.example']);
  for (const origin of ['*', 'null', 'https://one.example/path', 'https://one.example,']) {
    assert.notEqual(validateEnvironment({ CORS_ORIGIN: origin }).status, 0);
  }
  assert.equal(validateEnvironment({ CORS_ORIGIN: 'https://one.example, https://two.example' }).status, 0);
});

test('bootstrap requires a usable password, stores its hash, and locks before checking users', async (t) => {
  process.env.NODE_ENV = 'test';
  process.env.DATABASE_URL = 'postgres://localhost/segmentra_test';
  process.env.JWT_SECRET = 'test-only-secret-with-at-least-32-characters';
  process.env.SEGMENTRA_KEK_B64 = validKek;
  process.env.SEGMENTRA_BOOTSTRAP_TOKEN = 'test-bootstrap-token';
  process.env.CORS_ORIGIN = '';
  const { adminRouter } = await import('../apps/api/dist/routes/admin.js');
  const { pool } = await import('../apps/api/dist/db/pool.js');
  const { verifyPassword } = await import('../apps/api/dist/services/password.js');
  const handler = adminRouter.stack.find(layer => layer.route?.path === '/bootstrap').route.stack[0].handle;
  const queries = [];
  let initialized = false;
  let savedHash;
  let released = 0;
  const client = {
    async query(sql, args) {
      queries.push(sql);
      if (sql.includes('COUNT(*)')) return { rows: [{ c: initialized ? 1 : 0 }] };
      if (sql.includes('INSERT INTO users')) {
        savedHash = args[2];
        return { rows: [{ id: 'user-id', username: args[0] }] };
      }
      if (sql.includes('SELECT id FROM roles')) return { rows: [{ id: 'role-id' }] };
      if (sql === 'COMMIT') initialized = true;
      return { rows: [] };
    },
    release() { released++; }
  };
  t.mock.method(pool, 'connect', async () => client);
  let requestNumber = 0;
  async function bootstrap(body) {
    const res = {
      statusCode: 200,
      status(code) { this.statusCode = code; return this; },
      json(payload) { this.body = payload; return this; }
    };
    await handler({ body, ip: `test-ip-${requestNumber++}` }, res);
    return res;
  }
  const credentials = { token: 'test-bootstrap-token', username: 'bootstrap_admin', password: 'secure-test-password' };
  assert.equal((await bootstrap({ token: credentials.token })).statusCode, 400);
  assert.equal((await bootstrap({ ...credentials, password: 'short' })).statusCode, 400);
  assert.equal((await bootstrap({ ...credentials, password: 'a'.repeat(73) })).statusCode, 400);
  assert.equal((await bootstrap({ ...credentials, token: 'wrong-token' })).statusCode, 403);
  assert.equal(queries.length, 0);
  const result = await bootstrap(credentials);
  assert.equal(result.statusCode, 200);
  assert.ok(result.body.token);
  assert.notEqual(savedHash, credentials.password);
  assert.equal(await verifyPassword(credentials.password, savedHash), true);
  assert.deepEqual(queries.slice(0, 3), ['BEGIN', 'LOCK TABLE users IN EXCLUSIVE MODE', 'SELECT COUNT(*)::int AS c FROM users']);
  assert.equal((await bootstrap(credentials)).statusCode, 409);
  assert.equal(queries.at(-1), 'ROLLBACK');
  assert.equal(released, 2);
});
