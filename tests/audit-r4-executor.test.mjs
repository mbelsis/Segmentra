// Regression tests for the round-4 audit findings in the executor (revert settling, cancel of a
// started systemd revert, process-group timeouts, backup nonces, busybox grep, Ansible dead-man).
// Build the executor first (npx tsc -p packages/executor/tsconfig.json), then:
//   node --test tests/audit-r4-executor.test.mjs
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  SEGMENTRA_IPTABLES_SH,
  SEGMENTRA_NFT_SH,
  awaitRevertSettled,
  describeRevertState,
  parseRevertState,
  remoteTimeoutWrap,
  revertCancelScript,
  revertStatusScript,
  spawnWithTimeout
} from '../packages/executor/dist/index.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const read = (p) => fs.readFileSync(path.join(root, p), 'utf8');

/** Run `script` with a fake `systemctl` first in PATH. `units` maps unit -> is-active output. */
function withFakeSystemctl(script, { units = {}, stopFails = false } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'seg-r4-'));
  const state = path.join(dir, 'state');
  fs.writeFileSync(state, Object.entries(units).map(([u, s]) => `${u} ${s}`).join('\n') + '\n');
  fs.writeFileSync(path.join(dir, 'systemctl'), [
    '#!/bin/sh',
    `state=${JSON.stringify(state)}`,
    'cmd=$1; shift; [ "$1" = --quiet ] && { q=1; shift; }',
    'u=$1',
    'cur=$(awk -v u="$u" \'$1==u{print $2}\' "$state")',
    'case "$cmd" in',
    `  stop) ${stopFails ? 'exit 5' : 'grep -v "^$u " "$state" > "$state.n"; mv "$state.n" "$state"; exit 0'} ;;`,
    '  is-active) s=${cur:-inactive}; [ -z "$q" ] && echo "$s"; [ "$s" = active ] || [ "$s" = activating ]; exit $? ;;',
    '  *) exit 0 ;;',
    'esac',
    ''
  ].join('\n'), { mode: 0o755 });
  const marker = path.join(dir, 'marker');
  const r = spawnSync('/bin/sh', ['-c', script(marker)], { env: { ...process.env, PATH: `${dir}:${process.env.PATH}` }, encoding: 'utf8' });
  return { ...r, dir, marker };
}

// --- 3. cancel of a systemd revert must notice a .service the timer already started ---
test('systemd cancel: pending timer is cancelled (exit 0)', () => {
  const r = withFakeSystemctl((m) => revertCancelScript('systemd:seg-u', m), { units: { 'seg-u.timer': 'active' } });
  assert.equal(r.status, 0, r.stderr);
});
test('systemd cancel: a running revert .service is reported as fired (exit 9), not cancelled', () => {
  const r = withFakeSystemctl((m) => revertCancelScript('systemd:seg-u', m), { units: { 'seg-u.timer': 'active', 'seg-u.service': 'active' } });
  assert.equal(r.status, 9);
});
test('systemd cancel: marker present -> exit 9', () => {
  const r = withFakeSystemctl((m) => `touch ${m}; ${revertCancelScript('systemd:seg-u', m)}`, { units: { 'seg-u.timer': 'active' } });
  assert.equal(r.status, 9);
});
test('systemd cancel: failing stop without marker -> exit 1; with marker -> 9', () => {
  assert.equal(withFakeSystemctl((m) => revertCancelScript('systemd:seg-u', m), { stopFails: true }).status, 1);
  assert.equal(withFakeSystemctl((m) => `(sleep 0; touch ${m}) ; ${revertCancelScript('systemd:seg-u', m).replace(/^if \[ -e .*exit 9; fi\n/, '')}`, { stopFails: true }).status, 9);
});

test('systemd status: pending / running / done / gone', () => {
  const st = (o, pre = '') => withFakeSystemctl((m) => `${pre ? `touch ${m}; ` : ''}${revertStatusScript('systemd:seg-u', m)}`, o).stdout.trim();
  assert.equal(st({ units: { 'seg-u.timer': 'active' } }), 'pending');
  assert.equal(st({ units: { 'seg-u.service': 'activating' } }, 'm'), 'running');
  assert.equal(st({}, 'm'), 'done');
  assert.equal(st({}), 'gone');
});

test('pid watchdog: cancel kills a pending watchdog (0); status follows the process and marker', async () => {
  // Same shape as the real watchdog: a nohup'ed background shell reparented to init (so it is reaped).
  const sh = (s) => spawnSync('/bin/sh', ['-c', s], { encoding: 'utf8' });
  const pid = sh('nohup sh -c "sleep 30" >/dev/null 2>&1 </dev/null & echo $!').stdout.trim();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'seg-r4-'));
  const marker = path.join(dir, 'marker');
  assert.equal(sh(revertStatusScript(`pid:${pid}`, marker)).stdout.trim(), 'pending');
  assert.equal(sh(revertCancelScript(`pid:${pid}`, marker)).status, 0);
  assert.equal(sh(revertStatusScript(`pid:${pid}`, marker)).stdout.trim(), 'gone');
  fs.writeFileSync(marker, '');
  assert.equal(sh(revertStatusScript(`pid:${pid}`, marker)).stdout.trim(), 'done');
  assert.equal(sh(revertCancelScript(`pid:${pid}`, marker)).status, 9);
});

test('parseRevertState only accepts known states from a successful command', () => {
  assert.equal(parseRevertState('noise\ndone\n', 0), 'done');
  assert.equal(parseRevertState('done', 255), 'unknown');
  assert.equal(parseRevertState('weird', 0), 'unknown');
});

// --- 1. deployToHost must not return while the revert is still armed ---
function fakeClock(start = 0) {
  let t = start;
  return { now: () => t, sleep: async (ms) => { t += ms; } };
}
test('awaitRevertSettled waits past the deadline until the revert reports done', async () => {
  const c = fakeClock();
  const seen = [];
  const state = await awaitRevertSettled(async () => {
    const s = c.now() < 120_000 ? 'pending' : c.now() < 130_000 ? 'running' : 'done';
    seen.push([c.now(), s]);
    return s;
  }, 120_000, { ...c, pollMs: 5_000 });
  assert.equal(state, 'done');
  assert.ok(c.now() >= 130_000, 'returned only after the revert finished');
  assert.ok(seen.some(([, s]) => s === 'running'));
});
test('awaitRevertSettled gives up (unknown) only after deadline + grace when the host never answers', async () => {
  const c = fakeClock();
  const state = await awaitRevertSettled(async () => 'unknown', 60_000, { ...c, graceMs: 30_000 });
  assert.equal(state, 'unknown');
  assert.ok(c.now() >= 90_000);
});
test('awaitRevertSettled returns early when the revert is gone (cancelled)', async () => {
  const c = fakeClock();
  assert.equal(await awaitRevertSettled(async () => 'gone', 60_000, c), 'gone');
  assert.equal(c.now(), 0);
});
test('describeRevertState names the settled state', () => {
  assert.match(describeRevertState('done', '/b'), /fired and finished/);
  assert.match(describeRevertState('running', '/b'), /STILL RUNNING/);
  assert.match(describeRevertState('unknown', '/b'), /could not be determined/);
});

test('run-ssh.ts settles the revert on every failure path that leaves it armed', () => {
  const src = read('packages/executor/src/run-ssh.ts');
  assert.ok((src.match(/await settleRevert\(\)/g) ?? []).length >= 5, 'apply-failure (2), unreachable, fired, cancel-failure');
  assert.doesNotMatch(src, /automatic revert will retry within/);
});

// --- 4. managed-backend rollback exit code is reported ---
test('run-ssh.ts reports a failed managed-backend rollback after the persistence check', () => {
  const src = read('packages/executor/src/run-ssh.ts');
  assert.match(src, /rollback FAILED \(exit \$\{rb\.exitCode\}\), host left with the unpersisted new policy/);
});

// --- 2. backup names carry a random nonce ---
test('backup file names include a random nonce (run-ssh, audit-ssh, playbook)', () => {
  const ssh = read('packages/executor/src/run-ssh.ts');
  assert.match(ssh, /nft\.ruleset\.\$\{timestamp\}-\$\{nonce\}/);
  assert.match(ssh, /iptables\.\$\{timestamp\}-\$\{nonce\}/);
  assert.match(ssh, /ip6tables\.\$\{timestamp\}-\$\{nonce\}/);
  assert.match(read('packages/executor/src/audit-ssh.ts'), /audit-backup\.\$\{timestamp\}-\$\{crypto\.randomBytes/);
  assert.match(read('infra/ansible-runner/playbooks/apply-firewall.yml'), /segmentra_ts: .*date \+%Y-%m-%dT%H-%M-%S.*\| random/);
  // restore-previous-policy.sh --latest must still recognise the new names
  const re = /^((nft\.ruleset|iptables)\.[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9][0-9A-Za-z-]*)$/;
  assert.ok(re.test('nft.ruleset.2026-11-01T10-00-00-1a2b3c4d'));
});

// --- 6. no GNU-only BRE alternation in the kernel-log fallback ---
test('audit-ssh.ts finds kernel lines with grep -E and an exact pattern (busybox has no \\| in BRE; sudo logs our script text)', () => {
  const src = read('packages/executor/src/audit-ssh.ts');
  assert.doesNotMatch(src, /SRC=\\\\\\\\\|saddr/);
  assert.doesNotMatch(src, /SRC=\|saddr/);
  assert.match(src, /KERNEL_LINE = "'SRC=\[0-9a-fA-F\.:\]\+ DST='"/);
  const re = /SRC=[0-9a-fA-F.:]+ DST=/;
  assert.match('kernel: FW-AUDIT: ALLOW: catch-all: IN=eth0 OUT= SRC=10.0.0.1 DST=10.0.0.2 LEN=84', re);
  assert.match('FW-AUDIT: ALLOW: catch-all: IN=eth0 OUT= SRC=fe80::1 DST=ff02::1 LEN=84', re);
  assert.doesNotMatch(`sudo: segmentra : (command continued) grep -Eq 'SRC=[0-9a-fA-F.:]+ DST=' /var/log/x FW-AUDIT`, re);
});

// --- 5. timeouts kill the process group and do not hang on inherited pipes ---
test('spawnWithTimeout (detached) kills the whole process group on timeout', async () => {
  const t0 = Date.now();
  const r = await spawnWithTimeout('/bin/sh', ['-c', 'sleep 30 & sleep 30; wait'], { timeoutMs: 300, detached: true });
  assert.equal(r.exitCode, 124);
  assert.ok(Date.now() - t0 < 4_000, `resolved after ${Date.now() - t0}ms`);
});
test('spawnWithTimeout resolves shortly after exit when a grandchild keeps the pipes open', async () => {
  const t0 = Date.now();
  const r = await spawnWithTimeout('/bin/sh', ['-c', 'sleep 20 & echo hi'], { timeoutMs: 60_000, detached: true });
  assert.equal(r.exitCode, 0);
  assert.match(r.stdout, /hi/);
  assert.ok(Date.now() - t0 < 6_000, `resolved after ${Date.now() - t0}ms`);
});
test('remoteTimeoutWrap bounds the apply with the host timeout and keeps the exit status', () => {
  const w = remoteTimeoutWrap('exit 3', 100);
  assert.match(w, /timeout 100 \/bin\/sh -c 'exit 3'/);
  assert.match(w, /timeout 1 true/);
  assert.equal(spawnSync('/bin/sh', ['-c', w]).status, 3);
  assert.match(remoteTimeoutWrap('true', 1), /timeout 5 /);
});

// --- 7. Ansible raw nft/iptables deploys use the dead-man pattern ---
test('apply-firewall.yml arms a revert, verifies a fresh connection, cancels, then persists', () => {
  const pb = read('infra/ansible-runner/playbooks/apply-firewall.yml');
  const at = (s) => { const i = pb.indexOf(s); assert.ok(i >= 0, `missing: ${s}`); return i; };
  const sched = at('- name: Schedule the unattended revert before changing the firewall');
  const apply = at('- name: Apply nftables ruleset');
  const reset = at('meta: reset_connection');
  const verify = at('- name: Verify a fresh SSH connection through the new policy');
  const cancel = at('- name: Cancel the unattended revert only if it has not fired');
  const persist = at('- name: Persist table inet segmentra for reboots');
  assert.ok(sched < apply && apply < reset && reset < verify && verify < cancel && cancel < persist);
  assert.match(pb, /systemd-run --quiet --unit=/);
  assert.match(pb, /nohup sh -c/);
  assert.match(pb, /- name: Wait for the unattended revert to finish/);
});
test('playbook host scripts stay byte-identical with the TS copies', () => {
  assert.equal(read('infra/ansible-runner/playbooks/files/segmentra-nft.sh'), SEGMENTRA_NFT_SH);
  assert.equal(read('infra/ansible-runner/playbooks/files/segmentra-iptables.sh'), SEGMENTRA_IPTABLES_SH);
});
