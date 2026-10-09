#!/usr/bin/env node
// Real end-to-end check of the audit-versus-deployment race: a gateway-like container (sshd + iptables) is managed by a running
// Segmentra API (default http://localhost:8080/api, admin/admin123). It checks that a firewall-learning session restoring its
// backup never overwrites a deployment that succeeded after the session started, and that the normal restore still works.
// Needs Docker. Creates users, a host and policy sets in the development database; removes its container and network.
import { spawnSync } from 'node:child_process';
import { copyFileSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const apiBase = process.env.SEGMENTRA_API ?? 'http://localhost:8080/api';
const adminUser = process.env.SEGMENTRA_ADMIN_USER ?? 'admin';
const adminPass = process.env.SEGMENTRA_ADMIN_PASSWORD ?? 'admin123';
const suffix = Date.now().toString(36);
const NET = `segrace-${suffix}`, GW = `segrace-gw-${suffix}`;
const SSH_PORT = 2390 + Math.floor(Math.random() * 90);
const results = [];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const docker = (...a) => spawnSync('docker', a, { encoding: 'utf8' });
function check(label, pass, detail = '') { results.push({ label, pass: !!pass }); console.log(`  ${pass ? 'PASS' : 'FAIL'}  ${label}${detail ? `  (${detail})` : ''}`); }
async function raw(method, path, { token, body } = {}) {
  const res = await fetch(`${apiBase}${path}`, { method, headers: { ...(token ? { authorization: `Bearer ${token}` } : {}), ...(body !== undefined ? { 'content-type': 'application/json' } : {}) }, body: body !== undefined ? JSON.stringify(body) : undefined });
  const text = await res.text(); let json = null; try { json = JSON.parse(text); } catch { /* not json */ }
  return { status: res.status, text, json };
}
const api = async (m, p, o) => { const r = await raw(m, p, o); if (r.status >= 400) throw new Error(`${m} ${p} -> ${r.status}: ${r.text}`); return r.json; };
const login = async (u, p) => (await api('POST', '/auth/login', { body: { username: u, password: p } })).token;
async function ensureUser(admin, username, role) {
  const r = await raw('POST', '/admin/users', { token: admin, body: { username, displayName: username, password: 'RaceTest-pass-123!', roles: [role], isActive: true } });
  if (![201, 409].includes(r.status)) throw new Error(`user ${username}: ${r.status} ${r.text}`);
  return login(username, 'RaceTest-pass-123!');
}
function forgetHostKey(port) {
  const kh = process.env.SEGMENTRA_KNOWN_HOSTS || join(process.env.HOME ?? '', '.ssh', 'known_hosts');
  if (!existsSync(kh)) return;
  const tmp = join(mkdtempSync(join(tmpdir(), 'segrace-kh-')), 'known_hosts');
  copyFileSync(kh, tmp);
  spawnSync('ssh-keygen', ['-q', '-R', `[127.0.0.1]:${port}`, '-f', tmp], { encoding: 'utf8' });
  if (readFileSync(kh, 'utf8') !== readFileSync(tmp, 'utf8')) writeFileSync(kh, readFileSync(tmp));
  rmSync(dirname(tmp), { recursive: true, force: true });
}
const rules = () => docker('exec', GW, 'iptables', '-S', 'SEGMENTRA-IN').stdout;
const has = (port) => new RegExp(`--dport ${port}\\b`).test(rules());

async function main() {
  if (docker('info').status !== 0) throw new Error('Docker is not available');
  const admin = await login(adminUser, adminPass);
  const op = await ensureUser(admin, 'race-operator', 'operator');
  const appr = await ensureUser(admin, 'race-approver', 'approver');
  const executorBefore = (await api('GET', '/admin/executor-setting', { token: admin })).executor;
  const versions = []; let credId = null; let hostId = null; let keyDir = null;

  try {
    docker('build', '-q', '-t', 'segmentra-iot-gw:test', join(here, '..', 'docker-ssh-integration', 'target'));
    docker('network', 'create', NET);
    // Key login: the lab image's password login through sshpass fails now and then even with the right password, which made
    // this test flaky for reasons unrelated to Segmentra.
    keyDir = mkdtempSync(join(tmpdir(), 'segrace-key-'));
    spawnSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-f', join(keyDir, 'id_ed25519'), '-C', 'segmentra-race-test']);
    spawnSync('chmod', ['644', join(keyDir, 'id_ed25519.pub')]);
    const run = docker('run', '-d', '--name', GW, '--network', NET, '--cap-add', 'NET_ADMIN', '-p', `127.0.0.1:${SSH_PORT}:${SSH_PORT}`, '-v', `${keyDir}:/runtime-keys:ro`, '-e', 'TARGET_USER=segmentra', 'segmentra-iot-gw:test');
    if (run.status !== 0) throw new Error(`container: ${run.stderr}`);
    for (let i = 0; i < 30 && docker('exec', GW, 'sh', '-c', 'pgrep sshd >/dev/null').status !== 0; i += 1) await sleep(1000);
    docker('exec', GW, 'sh', '-c', `printf 'Port 22\\nPort ${SSH_PORT}\\n' >> /etc/ssh/sshd_config && kill -HUP $(pgrep -o sshd)`);
    await sleep(1500);
    // Wait until the container is really usable: iptables answers and a password login works on the published port.
    let ready = false;
    for (let i = 0; i < 40 && !ready; i += 1) {
      const ipt = docker('exec', GW, 'iptables', '-S').status === 0;
      const ssh = spawnSync('ssh', ['-i', join(keyDir, 'id_ed25519'), '-o', 'IdentitiesOnly=yes', '-p', String(SSH_PORT), '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null', '-o', 'LogLevel=ERROR', '-o', 'ConnectTimeout=3', 'segmentra@127.0.0.1', 'sudo -n iptables -S >/dev/null'], { encoding: 'utf8' }).status === 0;
      ready = ipt && ssh;
      if (!ready) await sleep(1000);
    }
    if (!ready) throw new Error('the gateway container did not become usable (iptables and SSH login)');

    const host = (await api('POST', '/hosts', { token: op, body: { hostname: `race-${suffix}`, mgmtIp: '127.0.0.1', sshPort: SSH_PORT, firewallBackend: 'iptables', enabled: true } })).host;
    hostId = host.id;
    const cred = await api('POST', '/ssh-credentials', { token: admin, body: { name: `race-${suffix}`, username: 'segmentra', authMethod: 'KEY', privateKeyPem: readFileSync(join(keyDir, 'id_ed25519'), 'utf8'), scopeType: 'HOST', scopeId: host.id } });
    credId = (cred.sshCredential ?? cred.credential ?? cred).id;
    await api('PUT', '/admin/executor-setting', { token: admin, body: { executor: 'ssh' } });

    const ps = (await api('POST', '/policy-sets', { token: op, body: { name: `race-pol-${suffix}`, scopeType: 'HOST_LIST', hostIds: [host.id] } })).policySet;
    const version = async (port) => {
      const v = (await api('POST', `/policy-sets/${ps.id}/versions`, { token: op, body: { changeSummary: `race ${port}`, interfaceScopeType: 'ALL_INTERFACES' } })).version;
      versions.push(v.id);
      await api('POST', `/policy-versions/${v.id}/rules`, { token: op, body: { orderIndex: 10, direction: 'IN', action: 'ALLOW', protocol: 'tcp', ports: String(port), sourceType: 'CIDR', sourceValue: '10.77.0.0/16', logMode: 'NONE', usePolicyInterfaceScope: true, comment: `race ${port}` } });
      await api('POST', `/policy-versions/${v.id}/submit-approval`, { token: op, body: {} });
      await api('POST', `/policy-versions/${v.id}/approve`, { token: appr, body: {} });
      return v;
    };
    const startDeploy = async (v, extra = {}) => {
      const dep = await api('POST', '/deployments', { token: op, body: { policyVersionId: v.id, mode: 'FULL', targetQuery: { hosts: [host.id], tags: [], vlans: [] }, ...extra } });
      await api('POST', `/deployments/${dep.deployment.id}/start`, { token: op, body: {} });
      return dep.deployment.id;
    };
    const wait = async (id) => { for (let i = 0; i < 60; i += 1) { const d = await api('GET', `/deployments/${id}`, { token: op }); if (['SUCCEEDED', 'FAILED', 'PARTIAL'].includes(d.deployment.status)) return d.deployment.status; await sleep(1500); } return 'TIMEOUT'; };
    const deploy = async (v) => {
      const id = await startDeploy(v); const st = await wait(id);
      if (st !== 'SUCCEEDED') { const d = await raw('GET', `/deployments/${id}`, { token: op }); console.log(`  (deployment ${st}: ${JSON.stringify(d.json?.hosts ?? d.json?.deployment?.hosts ?? '').slice(0, 300)})`); }
      return st;
    };
    const startAudit = async () => {
      const r = await api('POST', '/troubleshoot/audit/start', { token: op, body: { hosts: [host.id], durationMinutes: 30 } });
      return r.results?.[0] ?? r.sessions?.[0] ?? r;
    };
    const session = async (id) => (await api('GET', `/troubleshoot/audit/sessions/${id}`, { token: op })).session ?? (await api('GET', `/troubleshoot/audit/sessions/${id}`, { token: op }));

    const vA = await version(8081), vB = await version(9091), vC = await version(7071), vD = await version(6061);

    console.log('Normal restore (no deployment in between)');
    check('policy A deploys over SSH', (await deploy(vA)) === 'SUCCEEDED');
    check('the gateway enforces port 8081', has(8081));
    const s1 = await startAudit();
    check('a learning session starts (log-only rules replace the policy)', s1.status === 'RUNNING' && !!s1.sessionId, JSON.stringify(s1).slice(0, 140));
    check('... the host is now in log-only mode (port 8081 rule gone)', !has(8081), rules().split('\n').filter((l) => /dport|LOG/.test(l)).join(' | ').slice(0, 120));
    const r1 = await raw('POST', `/troubleshoot/audit/sessions/${s1.sessionId}/restore`, { token: op, body: {} });
    check('restoring the session works', r1.status === 200, r1.text.slice(0, 120));
    check('... and puts policy A back (8081)', has(8081));
    const ses1 = await raw('GET', `/troubleshoot/audit/sessions/${s1.sessionId}`, { token: op });
    check('... without a "restoreSkipped" note', !/restoreSkipped/.test(ses1.text));

    console.log('\nA deployment succeeds while a session is running, then the session restores');
    const s2 = await startAudit();
    check('a second learning session starts', s2.status === 'RUNNING', JSON.stringify(s2).slice(0, 120));
    check('policy B deploys while the session is running', (await deploy(vB)) === 'SUCCEEDED');
    check('the gateway enforces B (9091)', has(9091));
    const r2 = await raw('POST', `/troubleshoot/audit/sessions/${s2.sessionId}/restore`, { token: op, body: {} });
    check('the session restore is accepted', r2.status === 200, r2.text.slice(0, 120));
    check('B is STILL enforced afterwards (9091 present)', has(9091), rules().split('\n').filter((l) => /dport/.test(l)).join(' | ').slice(0, 120));
    check('the old policy A was NOT put back over it (8081 absent)', !has(8081));
    const ses2 = await raw('GET', `/troubleshoot/audit/sessions/${s2.sessionId}`, { token: op });
    check('the session records that the restore was skipped and is completed', /restoreSkipped/.test(ses2.text) && /COMPLETED/.test(ses2.text));

    console.log('\nA deployment and a restore at the same moment');
    const s3 = await startAudit();
    check('a third learning session starts', s3.status === 'RUNNING', JSON.stringify(s3).slice(0, 300));
    const [depId, r3] = await Promise.all([startDeploy(vC), raw('POST', `/troubleshoot/audit/sessions/${s3.sessionId}/restore`, { token: op, body: {} })]);
    const depStatus = await wait(depId);
    check('both operations finish (no deadlock): deployment SUCCEEDED, restore accepted', depStatus === 'SUCCEEDED' && r3.status === 200, `${depStatus} ${r3.status}`);
    check('whichever came first, the host ends on policy C (7071), not on an older one', has(7071) && !has(9091) && !has(8081), rules().split('\n').filter((l) => /dport/.test(l)).join(' | ').slice(0, 120));
    const ses3 = await raw('GET', `/troubleshoot/audit/sessions/${s3.sessionId}`, { token: op });
    check('the session is completed', /COMPLETED/.test(ses3.text));

    console.log('\nExpiry REMOVE (through the host lock), then a session restore');
    const expiresAt = new Date(Date.now() + 20 * 1000).toISOString();
    check('policy D deploys with an expiry (action REMOVE)', (await wait(await startDeploy(vD, { expiresAt, expiryAction: 'REMOVE' }))) === 'SUCCEEDED');
    check('the gateway enforces D (6061)', has(6061));
    const s4 = await startAudit();
    check('a learning session starts on top of D', s4.status === 'RUNNING');
    let removed = false;
    for (let i = 0; i < 100 && !removed; i += 1) { removed = docker('exec', GW, 'iptables', '-S', 'SEGMENTRA-IN').status !== 0; if (!removed) await sleep(2000); }
    check('the expiry job removed Segmentra\'s chains from the host', removed);
    const r4 = await raw('POST', `/troubleshoot/audit/sessions/${s4.sessionId}/restore`, { token: op, body: {} });
    check('the session restore is accepted', r4.status === 200, r4.text.slice(0, 100));
    check('the expired policy was NOT brought back by the restore', docker('exec', GW, 'iptables', '-S', 'SEGMENTRA-IN').status !== 0 && !has(6061));
    const ses4 = await raw('GET', `/troubleshoot/audit/sessions/${s4.sessionId}`, { token: op });
    check('the session records that the restore was skipped', /restoreSkipped/.test(ses4.text));

    console.log('\nInterface scope: the default must deploy, an unresolvable role must fail loudly');
    // This is the flow of a host found by Discovery (no interfaces recorded) and a version created with the defaults.
    const mkDefault = async (extra = {}) => {
      const v = (await api('POST', `/policy-sets/${ps.id}/versions`, { token: op, body: { changeSummary: 'scope default', ...extra } })).version;
      versions.push(v.id);
      await api('POST', `/policy-versions/${v.id}/rules`, { token: op, body: { orderIndex: 0, direction: 'IN', action: 'ALLOW', protocol: 'tcp', ports: '5151', sourceType: 'CIDR', sourceValue: '10.77.0.0/16', logMode: 'NONE', usePolicyInterfaceScope: true, comment: 'scope' } });
      await api('POST', `/policy-versions/${v.id}/submit-approval`, { token: op, body: {} });
      await api('POST', `/policy-versions/${v.id}/approve`, { token: appr, body: {} });
      return v;
    };
    const vDef = await mkDefault();
    check('a version created without a scope defaults to ALL_INTERFACES', vDef.interface_scope_type === 'ALL_INTERFACES', String(vDef.interface_scope_type));
    check('it deploys to a host without recorded interfaces', (await deploy(vDef)) === 'SUCCEEDED');
    check('... and the rule is on the host (5151)', has(5151));
    const vRole = await mkDefault({ interfaceScopeType: 'INTERFACE_ROLE', interfaceScopeRoles: ['dmz'] });
    const depRole = await raw('POST', '/deployments', { token: op, body: { policyVersionId: vRole.id, mode: 'FULL', targetQuery: { hosts: [host.id], tags: [], vlans: [] } } });
    check('a role scope that matches no interface is refused when the deployment is created (400, safety check)', depRole.status === 400 && depRole.json?.error === 'safety_check_failed', `${depRole.status}`);
    check('... with a message that says why', /matches no interface/.test(depRole.text));
    check('... and the previous rules are still on the host', has(5151));
  } finally {
    for (const id of versions) await raw('POST', `/policy-versions/${id}/archive`, { token: op, body: {} });
    if (credId) await raw('DELETE', `/ssh-credentials/${credId}`, { token: admin });
    if (hostId) await raw('POST', '/hosts/bulk/set-enabled', { token: op, body: { hostIds: [hostId], enabled: false } });
    await raw('PUT', '/admin/executor-setting', { token: admin, body: { executor: executorBefore } });
    docker('rm', '-f', '-v', GW);
    docker('network', 'rm', NET);
    forgetHostKey(SSH_PORT);
    if (keyDir) rmSync(keyDir, { recursive: true, force: true });
  }
  const failed = results.filter((r) => !r.pass);
  console.log(`\n[race] ${results.length - failed.length}/${results.length} checks passed`);
  for (const f of failed) console.log(`  FAILED: ${f.label}`);
  process.exit(failed.length ? 1 : 0);
}
main().catch((e) => { console.error(e); process.exit(1); });
