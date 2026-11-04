#!/usr/bin/env node
// Policy expiry end to end on a disposable Segmentra: real expiry dates, the real background job, real firewalls on the
// hosts (iptables and nftables), real TCP traffic from a client, and real webhook deliveries. Nothing is forced in the
// database. The job runs once a minute, so this takes about 15 minutes.
//
//   npm run test:integration:expiry [-- --keep]      (API on http://127.0.0.1:18084, login admin/admin123)
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as sleep } from 'node:timers/promises';

const here = dirname(fileURLToPath(import.meta.url));
const composeFile = join(here, 'docker-compose.yml');
const project = 'segmentra-expirytest';
const apiBase = 'http://127.0.0.1:18084/api';
const keep = process.argv.includes('--keep');
const CLIENT = 'seg-expiry-client';
const CLIENT_IP = '172.31.91.50';
const HOSTS = {
  a: { container: 'seg-expiry-a', ip: '172.31.91.11', backend: 'iptables' },
  b: { container: 'seg-expiry-b', ip: '172.31.91.12', backend: 'iptables' },
  c: { container: 'seg-expiry-c', ip: '172.31.91.13', backend: 'iptables' },
  n: { container: 'seg-expiry-n', ip: '172.31.91.14', backend: 'nftables' },
};
const PORT_V1 = 8081, PORT_V2 = 8082, PORT_NEVER = 8083;

const results = [];
function check(label, pass, detail = '') {
  results.push({ label, pass: !!pass });
  console.log(`  ${pass ? 'PASS' : 'FAIL'}  ${label}${detail && !pass ? `  (${detail})` : ''}`);
}
const section = (t) => console.log(`\n${t}`);
const docker = (...a) => spawnSync('docker', a, { encoding: 'utf8' });
const compose = (...a) => docker('compose', '-f', composeFile, '-p', project, ...a);
const inHost = (h, ...cmd) => docker('exec', HOSTS[h].container, ...cmd);

async function raw(method, path, { token, body } = {}) {
  const request = () => fetch(`${apiBase}${path}`, {
    method,
    headers: { ...(token ? { authorization: `Bearer ${token}` } : {}), ...(body !== undefined ? { 'content-type': 'application/json' } : {}) },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  let res;
  try {
    res = await request();
  } catch (e) {
    // fetch reuses idle connections, and the server may close one just as a request goes out. Retry once.
    console.log(`  NOTE  ${method} ${path}: ${e.cause?.code ?? e.cause?.message ?? e.message}; retrying`);
    await sleep(500);
    res = await request();
  }
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* not json */ }
  return { status: res.status, text, json };
}
async function api(method, path, opts) {
  const r = await raw(method, path, opts);
  if (r.status >= 400) throw new Error(`${method} ${path} -> ${r.status}: ${r.text}`);
  return r.json;
}
const login = async (username, password) => (await api('POST', '/auth/login', { body: { username, password } })).token;

// ---- real traffic and the state of the firewall ----
const PROBE = `const s=require('net').connect({host:process.argv[1],port:+process.argv[2]});s.setTimeout(2500);` +
  `s.on('connect',()=>{console.log('open');process.exit(0)});s.on('timeout',()=>{console.log('blocked');process.exit(0)});s.on('error',()=>{console.log('blocked');process.exit(0)});`;
const reach = (h, port) => docker('exec', CLIENT, 'node', '-e', PROBE, HOSTS[h].ip, String(port)).stdout.trim() === 'open';
function traffic(h) {
  return `v1=${reach(h, PORT_V1) ? 'open' : 'blocked'} v2=${reach(h, PORT_V2) ? 'open' : 'blocked'} other=${reach(h, PORT_NEVER) ? 'open' : 'blocked'}`;
}
const OPEN_V1 = 'v1=open v2=blocked other=blocked', OPEN_V2 = 'v1=blocked v2=open other=blocked', ALL_OPEN = 'v1=open v2=open other=open';
function segmentraRules(h) {
  if (HOSTS[h].backend === 'nftables') {
    const r = inHost(h, 'nft', 'list', 'table', 'inet', 'segmentra');
    return r.status === 0 ? r.stdout : '';
  }
  const r = inHost(h, 'iptables', '-S', 'SEGMENTRA-IN');
  return r.status === 0 ? r.stdout : '';
}
const blockSsh = (h) => inHost(h, 'iptables', '-I', 'INPUT', '1', '-p', 'tcp', '--dport', '22', '-j', 'REJECT', '--reject-with', 'tcp-reset');
const unblockSsh = (h) => inHost(h, 'iptables', '-D', 'INPUT', '-p', 'tcp', '--dport', '22', '-j', 'REJECT', '--reject-with', 'tcp-reset');

// ---- webhook receiver and audit log ----
const webhooks = async () => (await fetch('http://127.0.0.1:18086/')).json();
const webhooksFor = async (event, deploymentId) => (await webhooks()).filter((e) => e.event === event && e.data?.deploymentId === deploymentId);
async function auditFor(token, action, entityId) {
  const { events } = await api('GET', `/audit?action=${action}&limit=1000`, { token });
  return events.filter((e) => e.entity_id === entityId);
}

async function main() {
  console.log('[expiry] Starting a disposable Segmentra and four hosts (this builds the API image)');
  compose('down', '-v', '--remove-orphans');
  const up = compose('up', '-d', '--build');
  if (up.status !== 0) throw new Error(`docker compose up failed:\n${up.stderr}`);
  let healthy = false;
  for (let i = 0; i < 90 && !healthy; i += 1) {
    try { healthy = (await fetch(`${apiBase}/health`)).ok; } catch { /* starting */ }
    if (!healthy) await sleep(2000);
  }
  if (!healthy) throw new Error(`the API did not become healthy:\n${compose('logs', '--tail', '30', 'api').stdout}`);

  const admin = await login('admin', 'admin123');
  const newUser = async (username, role) => {
    await api('POST', '/admin/users', { token: admin, body: { username, displayName: username, password: 'ExpiryLab-pass-123!', roles: [role], isActive: true } });
    return login(username, 'ExpiryLab-pass-123!');
  };
  const op = await newUser('exp-operator', 'operator');
  const appr = await newUser('exp-approver', 'approver');
  await api('PUT', '/admin/executor-setting', { token: admin, body: { executor: 'ssh' } });

  const keyDir = mkdtempSync(join(tmpdir(), 'segexpiry-'));
  spawnSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-f', join(keyDir, 'id'), '-C', 'segmentra-expiry-test']);
  const pub = readFileSync(join(keyDir, 'id.pub'), 'utf8').trim();
  const key = readFileSync(join(keyDir, 'id'), 'utf8');
  rmSync(keyDir, { recursive: true, force: true });
  for (const h of Object.keys(HOSTS)) {
    for (let i = 0; i < 30 && inHost(h, 'sh', '-c', 'pgrep sshd >/dev/null && id segmentra >/dev/null').status !== 0; i += 1) await sleep(1000);
    const w = inHost(h, 'sh', '-c', `echo '${pub}' > /home/segmentra/.ssh/authorized_keys && chown segmentra /home/segmentra/.ssh/authorized_keys && chmod 600 /home/segmentra/.ssh/authorized_keys`);
    if (w.status !== 0) throw new Error(`host ${h}: ${w.stderr}`);
    for (const port of [PORT_V1, PORT_V2, PORT_NEVER]) docker('exec', '-d', HOSTS[h].container, 'sh', '-c', `while true; do echo ok | nc -l -p ${port} >/dev/null 2>&1; done`);
  }
  await api('POST', '/ssh-credentials', { token: admin, body: { name: 'expiry-lab', username: 'segmentra', authMethod: 'KEY', privateKeyPem: key, scopeType: 'GLOBAL' } });
  for (const [h, info] of Object.entries(HOSTS)) {
    info.id = (await api('POST', '/hosts', { token: admin, body: { hostname: `expiry-${h}`, mgmtIp: info.ip, sshPort: 22, firewallBackend: info.backend, enabled: true } })).host.id;
  }

  const channel = (await api('POST', '/notifications/channels', { token: admin, body: { name: 'expiry-lab', type: 'webhook', config: { url: `http://${CLIENT_IP}:9000/hook` } } })).channel;
  for (const eventType of ['POLICY_EXPIRED', 'POLICY_EXPIRING_SOON', 'DEPLOYMENT_COMPLETED', 'DEPLOYMENT_FAILED']) {
    await api('POST', `/notifications/channels/${channel.id}/rules`, { token: admin, body: { eventType } });
  }

  // ---- building blocks: the same calls the UI makes ----
  let n = 0;
  const policySet = async (hosts) => (await api('POST', '/policy-sets', { token: op, body: { name: `expiry-${++n}`, scopeType: 'HOST_LIST', hostIds: hosts.map((h) => HOSTS[h].id) } })).policySet;
  const version = async (ps, port) => {
    const v = (await api('POST', `/policy-sets/${ps.id}/versions`, { token: op, body: { changeSummary: `allow ${port}`, interfaceScopeType: 'ALL_INTERFACES' } })).version;
    await api('POST', `/policy-versions/${v.id}/rules`, { token: op, body: { orderIndex: 10, direction: 'IN', action: 'ALLOW', protocol: 'tcp', ports: String(port), sourceType: 'CIDR', sourceValue: `${CLIENT_IP}/32`, logMode: 'NONE', usePolicyInterfaceScope: true, comment: `allow ${port}` } });
    await api('POST', `/policy-versions/${v.id}/submit-approval`, { token: op, body: {} });
    await api('POST', `/policy-versions/${v.id}/approve`, { token: appr, body: {} });
    return v;
  };
  const getDep = async (id) => (await api('GET', `/deployments/${id}`, { token: op })).deployment;
  const hostRows = async (id) => (await api('GET', `/deployments/${id}/hosts`, { token: op })).hosts;
  const finished = async (id, seconds = 180) => {
    for (let i = 0; i < seconds / 2; i += 1) {
      const d = await getDep(id);
      if (['SUCCEEDED', 'FAILED', 'PARTIAL', 'EXPIRED', 'CANCELLED'].includes(d.status)) return d;
      await sleep(2000);
    }
    return getDep(id);
  };
  const deploy = async (v, hosts, extra = {}) => {
    const { deployment } = await api('POST', '/deployments', { token: op, body: { policyVersionId: v.id, mode: 'FULL', targetQuery: { hosts: hosts.map((h) => HOSTS[h].id), tags: [], vlans: [] }, ...extra } });
    await api('POST', `/deployments/${deployment.id}/start`, { token: op, body: { acceptReadinessNotes: true } });
    return { id: deployment.id, final: await finished(deployment.id) };
  };
  const inSeconds = (s) => new Date(Date.now() + s * 1000).toISOString();
  /** Deploy with an expiry a little in the future and let the real job (once a minute) process it. */
  const deployAndExpire = async (v, hosts, expiryAction) => {
    const dep = await deploy(v, hosts, { expiresAt: inSeconds(20), ...(expiryAction ? { expiryAction } : {}) });
    check(`the deployment succeeds on ${hosts.join(', ')} before it expires`, dep.final.status === 'SUCCEEDED', dep.final.status);
    return dep;
  };
  const waitExpired = async (id, seconds = 200) => {
    for (let i = 0; i < seconds / 2; i += 1) {
      const d = await getDep(id);
      if (d.expired && d.expiry_outcome) return d;
      await sleep(2000);
    }
    return getDep(id);
  };
  const outcomeOf = (d) => (typeof d.expiry_outcome === 'string' ? JSON.parse(d.expiry_outcome) : d.expiry_outcome) ?? {};
  const hostExpiry = async (id, h) => (await hostRows(id)).find((r) => r.host_id === HOSTS[h].id)?.expiry_status ?? null;
  const activeOn = async (h) => (await api('GET', `/troubleshoot/hosts/${HOSTS[h].id}/policies`, { token: op })).policies.find((d) => d.current) ?? null;
  const drift = async (h) => (await api('GET', `/compliance/hosts/${HOSTS[h].id}`, { token: op })).status;
  const nextTick = () => sleep(70_000);

  section('0. Before any policy');
  check('the client reaches every port on every host', Object.keys(HOSTS).every((h) => traffic(h) === ALL_OPEN), Object.keys(HOSTS).map((h) => `${h}: ${traffic(h)}`).join('; '));

  // The warnings are checked at the very end, after many runs of the job. Host c is only used for this.
  const warnPs = await policySet(['c']);
  const warnV1 = await version(warnPs, PORT_V1);
  const warn23h = await deploy(warnV1, ['c'], { expiresAt: inSeconds(23 * 3600), expiryAction: 'REMOVE' });
  const warn48h = await deploy(warnV1, ['c'], { expiresAt: inSeconds(48 * 3600), expiryAction: 'REMOVE' });
  const noExpiry = await deploy(warnV1, ['c']);

  section('1. NOTIFY_ONLY (the default when no action is chosen)');
  {
    const ps = await policySet(['a']);
    const v1 = await version(ps, PORT_V1);
    const dep = await deployAndExpire(v1, ['a']);
    check('the policy is enforced', traffic('a') === OPEN_V1, traffic('a'));
    const d = await waitExpired(dep.id);
    const o = outcomeOf(d);
    check('the job marks it EXPIRED with action NOTIFY_ONLY', d.status === 'EXPIRED' && d.expiry_action === 'NOTIFY_ONLY' && o.result === 'NOTIFIED', `${d.status} ${d.expiry_action} ${o.result}`);
    check('the rules stay on the host', traffic('a') === OPEN_V1 && new RegExp(`dport ${PORT_V1}`).test(segmentraRules('a')), traffic('a'));
    check('Active Rules still shows it as the current policy', (await activeOn('a'))?.deployment?.id === dep.id);
    check('no drift is reported', (await drift('a')) === 'compliant', await drift('a'));
    const hooks = await webhooksFor('POLICY_EXPIRED', dep.id);
    check('one POLICY_EXPIRED webhook arrives, naming the policy and the action', hooks.length === 1 && hooks[0].data.policySetName === ps.name && hooks[0].data.expiryAction === 'NOTIFY_ONLY' && hooks[0].data.result === 'NOTIFIED', JSON.stringify(hooks).slice(0, 200));
    const audit = await auditFor(op, 'POLICY_EXPIRED', dep.id);
    check('the audit log records it with no user as the actor', audit.length === 1 && audit[0].actor_user_id === null, JSON.stringify(audit).slice(0, 200));
  }

  section('2. REMOVE on two iptables hosts and one nftables host');
  {
    const other = inHost('a', 'sh', '-c', 'iptables -N OTHER-TOOL 2>/dev/null; iptables -A INPUT -p tcp --dport 9999 -j OTHER-TOOL');
    check('another tool has its own chain on the host', other.status === 0, other.stderr);
    const ps = await policySet(['a', 'b', 'n']);
    const v1 = await version(ps, PORT_V1);
    const dep = await deployAndExpire(v1, ['a', 'b', 'n'], 'REMOVE');
    check('the policy is enforced on all three', ['a', 'b', 'n'].every((h) => traffic(h) === OPEN_V1), ['a', 'b', 'n'].map((h) => traffic(h)).join('; '));
    const d = await waitExpired(dep.id);
    const o = outcomeOf(d);
    check('the outcome is REMOVED, 3 of 3', o.result === 'REMOVED' && o.hostCounts?.removed === 3, JSON.stringify(o).slice(0, 200));
    check('every host is marked REMOVED', (await hostRows(dep.id)).every((r) => r.expiry_status === 'REMOVED'));
    check('Segmentra\'s rules are gone from every host', ['a', 'b', 'n'].every((h) => segmentraRules(h) === ''));
    check('the INPUT jump is gone (iptables)', !/SEGMENTRA/.test(inHost('a', 'iptables', '-S', 'INPUT').stdout));
    check('traffic is open again on every host', ['a', 'b', 'n'].every((h) => traffic(h) === ALL_OPEN), ['a', 'b', 'n'].map((h) => traffic(h)).join('; '));
    check('the other tool\'s chain and rule are untouched', /OTHER-TOOL/.test(inHost('a', 'iptables', '-S', 'INPUT').stdout));
    inHost('a', 'sh', '-c', 'iptables -D INPUT -p tcp --dport 9999 -j OTHER-TOOL; iptables -X OTHER-TOOL');
    check('Active Rules no longer shows a current policy', (await activeOn('a')) === null, JSON.stringify(await activeOn('a')).slice(0, 120));
    check('the audit log has one removal per host', (await auditFor(op, 'POLICY_EXPIRY_RULES_REMOVED', dep.id)).length === 3);
    const hooks = await webhooksFor('POLICY_EXPIRED', dep.id);
    check('one POLICY_EXPIRED webhook with result REMOVED', hooks.length === 1 && hooks[0].data.result === 'REMOVED', JSON.stringify(hooks).slice(0, 200));
  }

  section('3. REVERT: the previous version comes back; a host that never ran it keeps the expired one');
  {
    const ps = await policySet(['a', 'b', 'n']);
    const v1 = await version(ps, PORT_V1);
    const v2 = await version(ps, PORT_V2);
    const first = await deploy(v1, ['a', 'n']);
    check('v1 is deployed to a (iptables) and n (nftables)', first.final.status === 'SUCCEEDED' && traffic('a') === OPEN_V1 && traffic('n') === OPEN_V1, `${first.final.status} ${traffic('a')}; ${traffic('n')}`);
    await sleep(1100);
    const dep = await deployAndExpire(v2, ['a', 'b', 'n'], 'REVERT');
    check('v2 replaces it on a and n, and is new on b', ['a', 'b', 'n'].every((h) => traffic(h) === OPEN_V2), ['a', 'b', 'n'].map((h) => traffic(h)).join('; '));
    const d = await waitExpired(dep.id);
    const o = outcomeOf(d);
    check('the outcome is REVERT_STARTED, back to version 1, for two hosts', o.result === 'REVERT_STARTED' && o.revertToVersionNumber === v1.version_number && o.hostCounts?.reverting === 2, JSON.stringify(o).slice(0, 240));
    const rev = await finished(o.revertDeploymentId);
    check('the revert deployment succeeds without a new approval', rev.status === 'SUCCEEDED' && rev.requires_approval === false, `${rev.status} ${rev.requires_approval}`);
    check('it records what it reverts, deploys v1 and has no expiry of its own', rev.revert_of_deployment_id === dep.id && rev.policy_version_id === v1.id && !rev.expires_at, JSON.stringify({ of: rev.revert_of_deployment_id, v: rev.policy_version_id, e: rev.expires_at }));
    check('v1 is back on a, and v2 is gone: real traffic', traffic('a') === OPEN_V1, traffic('a'));
    check('v1 is back on n (nftables): real traffic', traffic('n') === OPEN_V1, traffic('n'));
    check('b never ran v1, so it keeps v2', traffic('b') === OPEN_V2, traffic('b'));
    let expA = null;
    for (let i = 0; i < 15 && expA !== 'REVERTED'; i += 1) { expA = await hostExpiry(dep.id, 'a'); if (expA !== 'REVERTED') await sleep(1000); }
    check('per-host result: a and n REVERTED, b SKIPPED', expA === 'REVERTED' && (await hostExpiry(dep.id, 'n')) === 'REVERTED' && (await hostExpiry(dep.id, 'b')) === 'SKIPPED', `${expA} ${await hostExpiry(dep.id, 'n')} ${await hostExpiry(dep.id, 'b')}`);
    check('Active Rules shows the revert as current on a', (await activeOn('a'))?.deployment?.id === o.revertDeploymentId);
    check('no drift is reported on a', (await drift('a')) === 'compliant', await drift('a'));
    const hooks = await webhooksFor('POLICY_EXPIRED', dep.id);
    check('the webhook names the revert and the host that kept the expired policy', hooks.length === 1 && hooks[0].data.result === 'REVERT_STARTED' && hooks[0].data.revertDeploymentId === o.revertDeploymentId && hooks[0].data.hostsWithoutPreviousVersion?.includes('expiry-b'), JSON.stringify(hooks).slice(0, 300));
    check('a DEPLOYMENT_COMPLETED webhook arrives for the revert', (await webhooksFor('DEPLOYMENT_COMPLETED', o.revertDeploymentId)).length === 1);
    const created = await auditFor(op, 'DEPLOYMENT_CREATED', o.revertDeploymentId);
    check('the audit log records the revert as automatic, with no user', created.length === 1 && created[0].actor_user_id === null && created[0].metadata?.automatic === true, JSON.stringify(created).slice(0, 200));
  }

  section('4. REVERT when there is nothing to go back to');
  {
    const ps = await policySet(['a']);
    const v1 = await version(ps, PORT_V2);
    const dep = await deployAndExpire(v1, ['a'], 'REVERT');
    const d = await waitExpired(dep.id);
    check('the outcome is NO_PREVIOUS_VERSION', outcomeOf(d).result === 'NO_PREVIOUS_VERSION', JSON.stringify(outcomeOf(d)).slice(0, 200));
    check('the expired policy stays enforced', traffic('a') === OPEN_V2, traffic('a'));
    const hooks = await webhooksFor('POLICY_EXPIRED', dep.id);
    check('the webhook says so', hooks.length === 1 && hooks[0].data.result === 'NO_PREVIOUS_VERSION');
  }

  section('5. REVERT when the previous version was archived');
  {
    const ps = await policySet(['a']);
    const v1 = await version(ps, PORT_V1);
    const v2 = await version(ps, PORT_V2);
    await deploy(v1, ['a']);
    await sleep(1100);
    const dep = await deployAndExpire(v2, ['a'], 'REVERT');
    await api('POST', `/policy-versions/${v1.id}/archive`, { token: op, body: {} });
    const d = await waitExpired(dep.id);
    check('the outcome is REVERT_NOT_DEPLOYABLE: an archived version is never redeployed', outcomeOf(d).result === 'REVERT_NOT_DEPLOYABLE', JSON.stringify(outcomeOf(d)).slice(0, 200));
    check('the expired policy stays enforced', traffic('a') === OPEN_V2, traffic('a'));
    check('no revert deployment was created', !outcomeOf(d).revertDeploymentId);
  }

  section('6. REMOVE when one host cannot be reached');
  {
    const ps = await policySet(['a', 'b']);
    const v1 = await version(ps, PORT_V1);
    const dep = await deployAndExpire(v1, ['a', 'b'], 'REMOVE');
    check('SSH to b is blocked', blockSsh('b').status === 0);
    const d = await waitExpired(dep.id);
    check('the outcome is REMOVE_PARTIAL', outcomeOf(d).result === 'REMOVE_PARTIAL', JSON.stringify(outcomeOf(d)).slice(0, 240));
    check('a is REMOVED and b is FAILED', (await hostExpiry(dep.id, 'a')) === 'REMOVED' && (await hostExpiry(dep.id, 'b')) === 'FAILED');
    check('a is open, b still enforces the expired policy', traffic('a') === ALL_OPEN && traffic('b') === OPEN_V1, `${traffic('a')}; ${traffic('b')}`);
    const hooks = await webhooksFor('POLICY_EXPIRED', dep.id);
    check('the webhook reports the failure and names the host', hooks.length === 1 && hooks[0].data.result === 'REMOVE_PARTIAL' && /expiry-b/.test(JSON.stringify(hooks[0].data.failures ?? '')), JSON.stringify(hooks).slice(0, 300));
    check('the audit log records the failed removal', (await auditFor(op, 'POLICY_EXPIRY_REMOVE_FAILED', dep.id)).length === 1);
    unblockSsh('b');
    await nextTick();
    check('as documented, it is not retried once the host is back', (await hostExpiry(dep.id, 'b')) === 'FAILED' && traffic('b') === OPEN_V1 && (await auditFor(op, 'POLICY_EXPIRY_REMOVE_FAILED', dep.id)).length === 1);
  }

  section('7. REVERT when the host cannot be reached');
  {
    const ps = await policySet(['a']);
    const v1 = await version(ps, PORT_V1);
    const v2 = await version(ps, PORT_V2);
    await deploy(v1, ['a']);
    await sleep(1100);
    const dep = await deployAndExpire(v2, ['a'], 'REVERT');
    check('SSH to a is blocked', blockSsh('a').status === 0);
    const d = await waitExpired(dep.id);
    const o = outcomeOf(d);
    check('the revert starts', o.result === 'REVERT_STARTED', JSON.stringify(o).slice(0, 200));
    const rev = await finished(o.revertDeploymentId);
    check('the revert deployment fails', rev.status === 'FAILED', rev.status);
    let exp = null;
    for (let i = 0; i < 15 && exp !== 'FAILED'; i += 1) { exp = await hostExpiry(dep.id, 'a'); if (exp !== 'FAILED') await sleep(1000); }
    check('the host is marked FAILED on the expired deployment', exp === 'FAILED', exp);
    check('a DEPLOYMENT_FAILED webhook arrives', (await webhooksFor('DEPLOYMENT_FAILED', o.revertDeploymentId)).length === 1);
    unblockSsh('a');
    check('the host still enforces the expired policy', traffic('a') === OPEN_V2, traffic('a'));
  }

  section('8. The API is down when the policy expires');
  {
    const ps = await policySet(['a']);
    const v1 = await version(ps, PORT_V1);
    const dep = await deployAndExpire(v1, ['a'], 'REMOVE');
    compose('stop', 'api');
    await sleep(30_000);
    check('while the API is down the rules are still there', traffic('a') === OPEN_V1, traffic('a'));
    compose('start', 'api');
    for (let i = 0; i < 60; i += 1) { try { if ((await fetch(`${apiBase}/health`)).ok) break; } catch { /* starting */ } await sleep(2000); }
    const d = await waitExpired(dep.id);
    check('after the restart the job catches up and removes them', outcomeOf(d).result === 'REMOVED' && segmentraRules('a') === '' && traffic('a') === ALL_OPEN, `${outcomeOf(d).result} ${traffic('a')}`);
    check('one webhook, not two', (await webhooksFor('POLICY_EXPIRED', dep.id)).length === 1);
  }

  section('9. The 24-hour warning, after all those runs of the job and a restart');
  {
    const soon = await webhooksFor('POLICY_EXPIRING_SOON', warn23h.id);
    check('a policy expiring in 23 hours gets exactly one warning', soon.length === 1, `${soon.length} warnings`);
    check('it names the policy, the hours left and what will happen', soon[0]?.data?.policySetName === warnPs.name && soon[0]?.data?.hoursRemaining === 23 && soon[0]?.data?.expiryAction === 'REMOVE', JSON.stringify(soon[0]).slice(0, 240));
    check('a policy expiring in 48 hours gets none', (await webhooksFor('POLICY_EXPIRING_SOON', warn48h.id)).length === 0);
    check('a deployment without an expiry gets none', (await webhooksFor('POLICY_EXPIRING_SOON', noExpiry.id)).length === 0);
    check('neither has expired', !(await getDep(warn23h.id)).expired && !(await getDep(warn48h.id)).expired);
  }

  section('10. Every expiry fired once');
  {
    const all = (await webhooks()).filter((e) => e.event === 'POLICY_EXPIRED').map((e) => e.data.deploymentId);
    check(`no deployment produced two POLICY_EXPIRED webhooks (${all.length} in total)`, new Set(all).size === all.length);
  }
}

main().catch((e) => {
  check(`the run finished without an error: ${e.message}`, false);
}).finally(() => {
  const failed = results.filter((r) => !r.pass);
  console.log(`\n${results.length - failed.length}/${results.length} checks passed`);
  for (const f of failed) console.log(`  FAILED: ${f.label}`);
  if (keep || failed.length) {
    console.log(`[expiry] Left running to look at. API on ${apiBase}. Clean up: docker compose -f tests/expiry-lab/docker-compose.yml -p ${project} down -v`);
  } else {
    compose('down', '-v', '--remove-orphans');
  }
  process.exitCode = failed.length ? 1 : 0;
});
