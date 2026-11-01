// Regression tests for the round-5 audit findings in the executor and the Ansible playbooks:
//   1. apply-firewall.yml: the arm -> apply -> verify -> cancel window must not grow with the fleet
//      (lockout-protected apply runs in `serial` batches and never fails a host on purpose)
//   2. remoteTimeoutWrap: process-group kill, busybox exit 143/137 treated as a timeout
//   3. revert status: a revert that fired but failed is reported as `failed`, not `done`
//   4. iptables persistence: never enable iptables.service over the stock reject-all sysconfig file
// Build the executor first (npx tsc -p packages/executor/tsconfig.json), then:
//   node --test tests/audit-r5-executor.test.mjs
// Tests that need Docker (alpine, debian:12, rockylinux:9 containers) are skipped without it.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  PERSISTENCE_BLOCKING_CODES,
  SEGMENTRA_IPTABLES_SH,
  SEGMENTRA_NFT_SH,
  awaitRevertSettled,
  describeRevertState,
  parseRevertState,
  remoteTimeoutWrap,
  revertFiringScript,
  revertStatusScript
} from '../packages/executor/dist/index.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const read = (p) => fs.readFileSync(path.join(root, p), 'utf8');
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'seg-r5-'));

const dockerOk = spawnSync('docker', ['info'], { encoding: 'utf8' }).status === 0;
const noDocker = dockerOk ? false : 'Docker not available';

/** Run a script file in a throwaway container (`dir` mounted at /s). */
function inContainer(image, dir, script, extra = []) {
  return spawnSync('docker', ['run', '--rm', ...extra, '-v', `${dir}:/s`, image, 'sh', `/s/${script}`], { encoding: 'utf8', timeout: 300_000 });
}

// --- 1. Ansible: fleet-size independent lockout protection ---
const pb = read('infra/ansible-runner/playbooks/apply-firewall.yml');
const plays = pb.split(/^- name: /m).slice(1);

test('apply-firewall.yml: prepare / serial apply / report plays', () => {
  assert.equal(plays.length, 3);
  assert.match(plays[0], /^Segmentra apply firewall rules \(prepare\)/);
  assert.match(plays[1], /^Segmentra apply firewall rules \(lockout-protected apply, in batches\)/);
  assert.match(plays[2], /^Segmentra apply firewall rules \(report\)/);
  // batches of `forks` hosts (the same vars in every play)
  assert.match(plays[1], /\n  serial: "\{\{ lookup\('env', 'SEGMENTRA_ANSIBLE_SERIAL'\) \| default\(ansible_forks \| default\(5\), true\) \| int \}\}"/);
  assert.doesNotMatch(plays[0], /\n  serial:/);
  assert.match(plays[0], /vars: &segmentra_vars/);
  assert.match(plays[1], /vars: \*segmentra_vars/);
  assert.match(plays[2], /vars: \*segmentra_vars/);
});

test('apply-firewall.yml: arm, apply, verify and cancel all live in the serial play', () => {
  const p2 = plays[1];
  const at = (s) => { const i = p2.indexOf(s); assert.ok(i >= 0, `missing in the serial play: ${s}`); return i; };
  const order = [
    '- name: Schedule the unattended revert before changing the firewall',
    '- name: Apply nftables ruleset',
    'meta: reset_connection',
    '- name: Verify a fresh SSH connection through the new policy',
    '- name: Cancel the unattended revert only if it has not fired',
    '- name: Persist table inet segmentra for reboots'
  ].map(at);
  for (let i = 1; i < order.length; i++) assert.ok(order[i - 1] < order[i]);
  // backups / uploads happen once for the whole fleet before any revert is armed
  assert.ok(plays[0].includes('- name: Backup iptables SEGMENTRA chains'));
  assert.ok(plays[0].includes('- name: Copy policy file to host'));
  assert.ok(plays[0].includes('- name: Define the unattended revert command'));
  assert.ok(!plays[0].includes('systemd-run'));
});

test('apply-firewall.yml: the serial play never fails a host on purpose (a failed batch would end the playbook)', () => {
  const p2 = plays[1];
  assert.doesNotMatch(p2, /^\s+fail:/m);
  assert.match(p2, /register: seg_revert_sched\n\s+failed_when: false/);
  assert.match(p2, /seg_apply_failed_msg: "Could not schedule the unattended revert/);
  assert.match(p2, /- name: Record the failure \(reported by the last play\)\n[\s\S]*seg_apply_failed_msg: >-/);
  // every become task of the rescue tolerates an unreachable host
  const rescue = p2.slice(p2.indexOf('      rescue:'));
  const become = rescue.match(/become: true\n/g) ?? [];
  const tolerant = rescue.match(/become: true\n\s+ignore_unreachable: true\n/g) ?? [];
  assert.ok(become.length >= 7);
  assert.equal(tolerant.length, become.length);
  assert.match(plays[2], /- name: Fail after rollback\n\s+when: seg_apply_failed_msg is defined\n\s+fail:\n\s+msg: "\{\{ seg_apply_failed_msg \}\}"/);
});

test('apply-manager: prepare split out, apply part runs in the serial play and records failures', () => {
  const prep = read('infra/ansible-runner/playbooks/apply-manager-prepare.yml');
  const mgr = read('infra/ansible-runner/playbooks/apply-manager.yml');
  assert.match(plays[0], /include_tasks: apply-manager-prepare\.yml/);
  assert.match(plays[0], /meta: end_host\n\s+when: \(segmentra_backend/);
  assert.match(plays[1], /include_tasks: apply-manager\.yml/);
  assert.match(prep, /Back up native permanent configuration/);
  assert.doesNotMatch(prep, /systemd-run/);
  assert.match(mgr, /^- name: Schedule unattended rollback before changing the native firewall/m);
  assert.doesNotMatch(mgr, /^\s+fail:/m);
  assert.match(mgr, /seg_apply_failed_msg: "Native firewall apply or persistence verification failed/);
});

test('apply-firewall.yml: unattended revert records its exit code; status reports failed', () => {
  assert.match(pb, /echo "\$rc" > \{\{ \(seg_revert_marker ~ '\.rc'\) \| quote \}\}; exit \$rc/);
  assert.match(pb, /systemctl show -p Result \{\{ svc \}\}/);
  assert.match(pb, /if \[ "\$\{seg_rrc:-0\}" = 0 \] && \[ "\$\(systemctl is-active \{\{ svc \}\} 2>\/dev\/null\)" != failed \]/);
  assert.match(pb, /then echo done; else echo failed; fi/);
  assert.match(pb, /until: seg_revert_state\.stdout \| default\(''\) in \['done', 'failed', 'gone'\]/);
  assert.match(pb, /'FAILED \(it fired, but restoring the backup of this run did not succeed\); host state unknown/);
});

test('ansible-playbook --syntax-check accepts the playbook', { skip: noDocker }, (t) => {
  const img = spawnSync('docker', ['image', 'inspect', 'segmentra-it-ansible-runner'], { encoding: 'utf8' });
  if (img.status !== 0) return t.skip('runner image segmentra-it-ansible-runner not built');
  const r = spawnSync('docker', ['run', '--rm', '-v', `${path.join(root, 'infra/ansible-runner/playbooks')}:/runner/playbooks:ro`,
    'segmentra-it-ansible-runner', 'sh', '-c',
    'printf "h1 ansible_connection=local\\n" > /tmp/inv && ansible-playbook --syntax-check -i /tmp/inv /runner/playbooks/apply-firewall.yml'], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stdout + r.stderr);
});

// --- 2. remote timeout: whole process group, 124 for every timeout flavour ---
test('remoteTimeoutWrap keeps the exit status and offers a setsid watchdog plus timeout fallback', () => {
  const w = remoteTimeoutWrap('exit 3', 100);
  assert.equal(spawnSync('/bin/sh', ['-c', w]).status, 3);
  assert.equal(spawnSync('/bin/sh', ['-c', remoteTimeoutWrap('true', 100)]).status, 0);
  assert.match(w, /setsid \/bin\/sh -c 'exit 3' &/);
  assert.match(w, /kill -s "\$1" -- "-\$2" 2>\/dev\/null \|\| kill -s "\$1" "-\$2"/);
  assert.match(w, /case "\$seg_rc" in 124\|137\|143\) seg_rc=124 ;; esac/);
  assert.match(w, /timeout -k 5 100 \/bin\/sh -c 'exit 3'/);
});

function timeoutCases(dir) {
  const W = remoteTimeoutWrap;
  const procs = (pat) => `for p in /proc/[0-9]*; do tr '\\0' ' ' < $p/cmdline 2>/dev/null; echo; done | grep -c '^${pat}'`;
  fs.writeFileSync(path.join(dir, 't.sh'), [
    `${W('exit 3', 100)}\necho "exit3 rc=$?"`,
    `t0=$(date +%s)\n${W('sh -c "sleep 30; echo leak > /tmp/leak"; echo after > /tmp/leak', 5)}\necho "nested rc=$? dt=$(( $(date +%s) - t0 ))"; sleep 1; echo "nested left=$(${procs('sleep 30')})"; [ -e /tmp/leak ] && echo "nested LEAKED"`,
    `t0=$(date +%s)\n${W('trap "" TERM; sh -c "trap \\"\\" TERM; sleep 40"', 5)}\necho "noterm rc=$? dt=$(( $(date +%s) - t0 ))"; sleep 1; echo "noterm left=$(${procs('sleep 40')})"`,
    ''
  ].join('\n'));
}

for (const image of ['alpine', 'debian:12']) {
  test(`remoteTimeoutWrap on ${image}: kills the nested script group, reports 124, KILLs after TERM is ignored`, { skip: noDocker, timeout: 300_000 }, () => {
    const dir = tmp();
    timeoutCases(dir);
    const r = inContainer(image, dir, 't.sh');
    const out = r.stdout;
    assert.match(out, /exit3 rc=3/, out + r.stderr);
    const nested = out.match(/nested rc=(\d+) dt=(\d+)/);
    assert.ok(nested, out + r.stderr);
    assert.equal(nested[1], '124');
    assert.ok(Number(nested[2]) <= 8, out);
    assert.match(out, /nested left=0/);
    assert.doesNotMatch(out, /LEAKED/);
    const noterm = out.match(/noterm rc=(\d+) dt=(\d+)/);
    assert.equal(noterm[1], '124');
    assert.ok(Number(noterm[2]) <= 14, out);
    assert.match(out, /noterm left=0/);
  });
}

// --- 3. a failed revert is not "done" ---
/** Fake systemctl: `units` maps unit -> { active, result }. */
function withFakeSystemctl(script, units) {
  const dir = tmp();
  const lines = ['#!/bin/sh', 'cmd=$1; shift; q=; [ "$1" = --quiet ] && { q=1; shift; }', 'case "$cmd" in'];
  lines.push('  show) [ "$1" = -p ] && shift 2; u=$1 ;;', '  *) u=$1 ;;', 'esac', 'case "$u" in');
  for (const [u, s] of Object.entries(units)) lines.push(`  ${u}) a=${s.active ?? 'inactive'}; res=${s.result ?? 'success'} ;;`);
  lines.push('  *) a=inactive; res=success ;;', 'esac', 'case "$cmd" in');
  lines.push('  is-active) [ -z "$q" ] && echo "$a"; [ "$a" = active ] || [ "$a" = activating ]; exit $? ;;');
  lines.push('  show) echo "Result=$res" ;;', 'esac', 'exit 0', '');
  fs.writeFileSync(path.join(dir, 'systemctl'), lines.join('\n'), { mode: 0o755 });
  const marker = path.join(dir, 'marker');
  const r = spawnSync('/bin/sh', ['-c', script(marker)], { env: { ...process.env, PATH: `${dir}:${process.env.PATH}` }, encoding: 'utf8' });
  return { ...r, marker, dir };
}

test('revertFiringScript records the restore exit status in <marker>.rc', () => {
  for (const [restore, rc] of [['true', 0], ['echo restoring; (exit 4)', 4]]) {
    const dir = tmp();
    const marker = path.join(dir, 'revert-fired.x');
    const r = spawnSync('/bin/sh', ['-c', revertFiringScript(marker, restore)], { encoding: 'utf8' });
    assert.equal(r.status, rc);
    assert.ok(fs.existsSync(marker));
    assert.equal(fs.readFileSync(`${marker}.rc`, 'utf8').trim(), String(rc));
  }
});

const sysd = (marker, rc, units, pre = '') =>
  withFakeSystemctl((m) => `${pre}touch ${m}; ${rc === null ? '' : `echo ${rc} > ${m}.rc;`}\n${revertStatusScript('systemd:seg-u', m)}`, units).stdout.trim();

test('systemd revert status: done only when the restore succeeded and the unit did not fail', () => {
  assert.equal(sysd(null, 0, {}), 'done');
  assert.equal(sysd(null, 1, { 'seg-u.service': { active: 'failed', result: 'exit-code' } }), 'failed');
  assert.equal(sysd(null, 0, { 'seg-u.service': { active: 'failed', result: 'exit-code' } }), 'failed');
  assert.equal(sysd(null, null, {}), 'done'); // no .rc (armed by an older version): systemd decides
  assert.equal(sysd(null, null, { 'seg-u.service': { active: 'failed', result: 'signal' } }), 'failed'); // killed
  assert.equal(sysd(null, 0, { 'seg-u.service': { active: 'inactive', result: 'timeout' } }), 'failed');
  assert.equal(sysd(null, 0, { 'seg-u.service': { active: 'active' } }), 'running');
  const pending = withFakeSystemctl((m) => revertStatusScript('systemd:seg-u', m), { 'seg-u.timer': { active: 'active' } });
  assert.equal(pending.stdout.trim(), 'pending');
  const gone = withFakeSystemctl((m) => revertStatusScript('systemd:seg-u', m), {});
  assert.equal(gone.stdout.trim(), 'gone');
});

test('nohup revert status: failed when the recorded exit code is not 0', () => {
  const dir = tmp();
  const marker = path.join(dir, 'm');
  const st = () => spawnSync('/bin/sh', ['-c', revertStatusScript('pid:999999', marker)], { encoding: 'utf8' }).stdout.trim();
  assert.equal(st(), 'gone');
  fs.writeFileSync(marker, '');
  assert.equal(st(), 'done'); // no .rc: armed by an older version
  fs.writeFileSync(`${marker}.rc`, '0\n');
  assert.equal(st(), 'done');
  fs.writeFileSync(`${marker}.rc`, '2\n');
  assert.equal(st(), 'failed');
});

test('failed is a settled revert state with an explicit message', async () => {
  assert.equal(parseRevertState('failed\n', 0), 'failed');
  assert.equal(parseRevertState('failed\n', 1), 'unknown');
  const msg = describeRevertState('failed', '/var/backups/segmentra/iptables.x');
  assert.match(msg, /automatic revert FAILED/);
  assert.match(msg, /host state unknown/);
  let calls = 0;
  const state = await awaitRevertSettled(async () => { calls++; return 'failed'; }, Date.now() + 60_000, { sleep: async () => {} });
  assert.equal(state, 'failed');
  assert.equal(calls, 1);
  const src = read('packages/executor/src/run-ssh.ts');
  assert.match(src, /const firingScript = revertFiringScript\(marker, restoreScript\);/);
  assert.match(src, /rolledBack: state !== 'failed'/);
});

// --- 4. RHEL stock /etc/sysconfig/iptables ---
test('iptables persist refuses to enable a disabled service over a reject-all saved file (script text)', () => {
  assert.match(SEGMENTRA_IPTABLES_SH, /ipt_blocks_all\(\) \{/);
  assert.match(SEGMENTRA_IPTABLES_SH, /inf && \/\^-A \(INPUT\|FORWARD\) -j \(REJECT\|DROP\)\/ \{ f = 1 \}/);
  assert.match(SEGMENTRA_IPTABLES_SH, /inf && \/\^:\(INPUT\|FORWARD\) \(DROP\|REJECT\)\/ \{ f = 1 \}/);
  assert.match(SEGMENTRA_IPTABLES_SH, /! unit_enabled "\$IUNIT" && ipt_blocks_all "\$IFILE"; then blockall=1; fi/);
  assert.match(SEGMENTRA_IPTABLES_SH, /pwarn saved_rules_block_all /);
  assert.ok(PERSISTENCE_BLOCKING_CODES.includes('saved_rules_block_all'));
  // byte-identical copies for Ansible
  assert.equal(read('infra/ansible-runner/playbooks/files/segmentra-iptables.sh'), SEGMENTRA_IPTABLES_SH);
  assert.equal(read('infra/ansible-runner/playbooks/files/segmentra-nft.sh'), SEGMENTRA_NFT_SH);
});

test('iptables persist on Rocky Linux 9 with iptables-services: stock file is left alone unless the admin enabled the service', { skip: noDocker, timeout: 600_000 }, () => {
  const dir = tmp();
  fs.writeFileSync(path.join(dir, 'segmentra-iptables.sh'), SEGMENTRA_IPTABLES_SH);
  fs.writeFileSync(path.join(dir, 'rhel.sh'), [
    'set -u',
    'dnf -y -q install iptables-services systemd >/dev/null 2>&1 || { echo INSTALL_FAILED; exit 0; }',
    'cp /etc/sysconfig/iptables /tmp/stock',
    'iptables -N SEGMENTRA-IN; iptables -A SEGMENTRA-IN -p tcp --dport 80 -j RETURN; iptables -A SEGMENTRA-IN -j DROP; iptables -I INPUT -j SEGMENTRA-IN',
    'echo "== check"; sh /s/segmentra-iptables.sh check iptables',
    'echo "== persist-stock"; sh /s/segmentra-iptables.sh persist iptables',
    'echo "enabled=$(systemctl is-enabled iptables.service 2>/dev/null)"',
    '[ "$(cksum < /etc/sysconfig/iptables)" = "$(cksum < /tmp/stock)" ] && echo stock-untouched',
    'echo "== persist-admin-enabled"; systemctl enable iptables.service >/dev/null 2>&1; sh /s/segmentra-iptables.sh persist iptables',
    'echo "merged=$(grep -c SEGMENTRA /etc/sysconfig/iptables)"',
    'echo "== persist-open-file"; systemctl disable iptables.service >/dev/null 2>&1',
    "printf '*filter\\n:INPUT ACCEPT [0:0]\\n:FORWARD ACCEPT [0:0]\\n:OUTPUT ACCEPT [0:0]\\nCOMMIT\\n' > /etc/sysconfig/iptables",
    'sh /s/segmentra-iptables.sh persist iptables; echo "enabled2=$(systemctl is-enabled iptables.service 2>/dev/null)"',
    ''
  ].join('\n'));
  const r = inContainer('rockylinux:9', dir, 'rhel.sh', ['--cap-add', 'NET_ADMIN']);
  const out = r.stdout;
  if (/INSTALL_FAILED/.test(out)) return; // no package mirror reachable
  const section = (name) => out.split(`== ${name}\n`)[1].split('\n== ')[0];
  for (const s of ['check', 'persist-stock']) {
    assert.match(section(s), /SEGMENTRA_PERSIST_WARN saved_rules_block_all \/etc\/sysconfig\/iptables rejects or drops/, out);
    assert.match(section(s), /SEGMENTRA_PERSIST status=not_persisted method=iptables-services distro=rhel/);
  }
  assert.match(out, /enabled=disabled/);
  assert.match(out, /stock-untouched/);
  assert.match(section('persist-admin-enabled'), /SEGMENTRA_PERSIST status=persisted method=iptables-services/);
  assert.doesNotMatch(section('persist-admin-enabled'), /saved_rules_block_all/);
  assert.match(out, /merged=[1-9]/);
  assert.match(section('persist-open-file'), /SEGMENTRA_PERSIST status=persisted/);
  assert.match(out, /enabled2=enabled/);
});
