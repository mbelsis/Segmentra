// Regression tests for the round-4 deployment audit findings (pure helpers only, no database).
// Run after a build: npm run build -w @segmentra/api && node --test tests/audit-r4-deployments.test.mjs
import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  ANSIBLE_USER_RE,
  clampPagination,
  countHostStatuses,
  finalDeploymentStatus,
  hostDeploymentTimeoutMs,
  isSafeAnsibleUsername
} from '../apps/api/dist/lib/deployment-status.js';

const counts = (o) => countHostStatuses(Object.entries(o).map(([status, count]) => ({ status, count: String(count) })));

// --- #4: one finalization rule for executor, stale-host timeout and restart recovery ---
test('all hosts SKIPPED is FAILED, not SUCCEEDED', () => {
  assert.equal(finalDeploymentStatus(counts({ SKIPPED: 3 })), 'FAILED');
});
test('failed hosts plus skipped hosts (no success) is FAILED', () => {
  assert.equal(finalDeploymentStatus(counts({ FAILED: 1, SKIPPED: 2 })), 'FAILED');
});
test('failed and succeeded is PARTIAL (skipped ones do not matter)', () => {
  assert.equal(finalDeploymentStatus(counts({ FAILED: 1, SUCCEEDED: 2, SKIPPED: 1 })), 'PARTIAL');
});
test('succeeded with skipped (no failure) is SUCCEEDED', () => {
  assert.equal(finalDeploymentStatus(counts({ SUCCEEDED: 2, SKIPPED: 1 })), 'SUCCEEDED');
});
test('no hosts at all is FAILED', () => {
  assert.equal(finalDeploymentStatus(counts({})), 'FAILED');
});
test('unfinished hosts (PENDING/RUNNING/PAUSED) are never finalized', () => {
  for (const s of ['PENDING', 'RUNNING', 'PAUSED']) {
    assert.equal(finalDeploymentStatus(counts({ SUCCEEDED: 2, [s]: 1 })), null, s);
  }
});
test('countHostStatuses parses pg COUNT strings and totals', () => {
  const c = counts({ SUCCEEDED: 2, FAILED: 1, SKIPPED: 4, PENDING: 1 });
  assert.deepEqual([c.succeeded, c.failed, c.skipped, c.total, c.unfinished], [2, 1, 4, 7, 1]);
});

// --- #2: stale-host timeout exceeds the realistic per-host maximum ---
test('stale-host timeout default is well above 10 minutes, the SSH command timeout and the Ansible timeout', () => {
  const t = hostDeploymentTimeoutMs({});
  assert.ok(t >= 60 * 60 * 1000, `got ${t}`);
  assert.ok(t > 30 * 60 * 1000 + 5 * 60 * 1000);
});
test('stale-host timeout grows with SEGMENTRA_SSH_COMMAND_TIMEOUT_MS', () => {
  const t = hostDeploymentTimeoutMs({ SEGMENTRA_SSH_COMMAND_TIMEOUT_MS: String(20 * 60 * 1000) });
  assert.ok(t >= 8 * 20 * 60 * 1000, `got ${t}`);
});
test('stale-host timeout grows with the Ansible timeout', () => {
  const t = hostDeploymentTimeoutMs({}, 90 * 60 * 1000);
  assert.ok(t > 90 * 60 * 1000);
});
test('SEGMENTRA_HOST_DEPLOYMENT_TIMEOUT_MS overrides; nonsense values are ignored', () => {
  assert.equal(hostDeploymentTimeoutMs({ SEGMENTRA_HOST_DEPLOYMENT_TIMEOUT_MS: '7200000' }), 7200000);
  assert.equal(hostDeploymentTimeoutMs({ SEGMENTRA_HOST_DEPLOYMENT_TIMEOUT_MS: '5' }), hostDeploymentTimeoutMs({}));
  assert.equal(hostDeploymentTimeoutMs({ SEGMENTRA_HOST_DEPLOYMENT_TIMEOUT_MS: 'abc' }), hostDeploymentTimeoutMs({}));
});

// --- #10: pagination never produces a negative/zero LIMIT or a negative OFFSET ---
test('pagination clamps negative and zero page/limit', () => {
  for (const [p, l] of [['-3', '-10'], ['0', '0'], ['-1', '5'], ['2', '-1'], [undefined, undefined], ['x', 'y']]) {
    const r = clampPagination(p, l, { defaultLimit: 50, maxLimit: 100 });
    assert.ok(r.page >= 1 && r.limit >= 1 && r.limit <= 100 && r.offset >= 0, JSON.stringify({ p, l, r }));
  }
});
test('pagination caps the limit and computes the offset', () => {
  assert.deepEqual(clampPagination('3', '1000', { maxLimit: 100 }), { page: 3, limit: 100, offset: 200 });
  assert.deepEqual(clampPagination('2', '25'), { page: 2, limit: 25, offset: 25 });
  assert.deepEqual(clampPagination(undefined, undefined), { page: 1, limit: 50, offset: 0 });
});

// --- #7: Ansible inventory username injection ---
test('plain login names are accepted', () => {
  for (const u of ['root', 'deploy', 'svc.segmentra', 'user_1', 'a-b', '_x']) assert.ok(isSafeAnsibleUsername(u), u);
});
test('Jinja / INI injection in the username is refused', () => {
  for (const u of [
    "{{ lookup('pipe','id') }}", '{% raw %}', 'root ansible_python_interpreter=/tmp/x', 'a=b', "o'neil", 'a"b',
    'a\tb', 'a\nb', '', '-oProxyCommand=x', 'a'.repeat(65), 'root;id', 'a$b', '`id`', 'user@host'
  ]) assert.equal(isSafeAnsibleUsername(u), false, JSON.stringify(u));
  assert.equal(isSafeAnsibleUsername(undefined), false);
  assert.equal(isSafeAnsibleUsername(42), false);
});
test('ANSIBLE_USER_RE matches the SSH executor rule (packages/executor/src/ssh-options.ts USER_RE)', () => {
  assert.equal(ANSIBLE_USER_RE.source, '^[A-Za-z0-9._][A-Za-z0-9._-]{0,63}$');
});
