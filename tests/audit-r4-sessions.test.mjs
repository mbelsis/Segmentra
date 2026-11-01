// Audit round 4: policy-test and firewall-learning restore claims (no double restore, no overlapping passes).
// Run after a build: node --test tests/audit-r4-sessions.test.mjs
// No database is needed: the modules are loaded with an unreachable DATABASE_URL, so DB calls fail fast.
import assert from 'node:assert/strict';
import { test } from 'node:test';

process.env.DATABASE_URL ??= 'postgres://segmentra:unused@127.0.0.1:1/unused';
process.env.JWT_SECRET ??= 'audit-r4-test-secret-0123456789abcdef';
process.env.SEGMENTRA_HOST_LOCK_TIMEOUT_MS ??= String(30 * 60 * 1000);

const audit = await import('../apps/api/dist/services/audit-scheduler.js');
const pts = await import('../apps/api/dist/lib/policy-test-session.js');
const { endHostLockPool } = await import('../apps/api/dist/services/host-lock.js');
const { pool } = await import('../apps/api/dist/db/pool.js');

test.after(async () => {
  await endHostLockPool().catch(() => {});
  await pool.end().catch(() => {});
});

test('audit restore lease outlasts the host-lock wait plus the restore', () => {
  const lock = 30 * 60 * 1000;
  const ssh = 5 * 60 * 1000;
  const lease = audit.auditRestoreLeaseMs(lock, ssh);
  assert.ok(lease > lock + 2 * ssh, `lease ${lease} must exceed lock timeout + restore/log SSH time`);
  // Default (env-derived) lease is longer than the old fixed 10 minutes and than the default lock timeout.
  assert.ok(audit.auditRestoreLeaseMs() > 30 * 60 * 1000);
  // Follows the lock timeout when it is configured shorter or longer.
  assert.ok(audit.auditRestoreLeaseMs(2 * 60 * 60 * 1000, ssh) > 2 * 60 * 60 * 1000);
});

test('audit log_data: a run that collected fewer entries keeps the stored ones', () => {
  const stored = { entries: [1, 2, 3], flows: ['a', 'b'] };
  const kept = audit.finalAuditLogData(stored, { entries: [1], flows: ['a'] }, { restore: { attempts: 2 } });
  assert.deepEqual(kept.entries, [1, 2, 3]);
  assert.deepEqual(kept.flows, ['a', 'b']);
  assert.deepEqual(kept.restore, { attempts: 2 });
  // Also when the column comes back as a JSON string.
  assert.deepEqual(audit.finalAuditLogData(JSON.stringify(stored), { entries: [], flows: [] }).entries, [1, 2, 3]);
});

test('audit log_data: more (or equal) entries replace the stored ones; empty/absent log_data is fine', () => {
  const stored = { entries: [1], flows: ['a'], restore: { attempts: 1 } };
  const replaced = audit.finalAuditLogData(stored, { entries: [1, 2], flows: ['a', 'b'] });
  assert.deepEqual(replaced, { entries: [1, 2], flows: ['a', 'b'] });
  assert.deepEqual(audit.finalAuditLogData(null, { entries: [], flows: [] }), { entries: [], flows: [] });
  assert.deepEqual(audit.finalAuditLogData({ restore: { attempts: 3 } }, { entries: [9], flows: ['z'] }), { entries: [9], flows: ['z'] });
});

test('policy-test expiry passes never overlap', async () => {
  const first = pts.processExpiredTestSessions();
  // Started synchronously up to its first await: a second pass now must be skipped, not run concurrently.
  assert.equal(await pts.processExpiredTestSessions(), false);
  await first.catch(() => {}); // the unreachable database makes the first pass fail
  // Once it has finished (even with an error) the guard is released: the next pass runs (and fails on the DB again).
  assert.equal(await pts.processExpiredTestSessions().then((v) => v, () => 'ran'), 'ran');
});

test('learning-session expiry passes never overlap', async () => {
  let firstSettled = false;
  const first = audit.processExpiredAuditSessions().then(() => 'ok', () => 'err').finally(() => { firstSettled = true; });
  const second = await audit.processExpiredAuditSessions().then(() => 'skipped', () => 'err');
  // The second call returns at once without touching the database (so it neither errors nor waits for the first).
  assert.equal(second, 'skipped');
  assert.equal(firstSettled, false);
  assert.equal(await first, 'err');
});
