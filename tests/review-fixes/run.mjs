#!/usr/bin/env node
// Regression checks for the code-review findings that need the running API and its database
// (default http://localhost:8080/api, admin/admin123; see SEGMENTRA_API, SEGMENTRA_ADMIN_USER, SEGMENTRA_ADMIN_PASSWORD):
//   - troubleshoot: the effective policy of a host after its version is archived, and after expiry REMOVE
//   - host lock + restore guard: mutual exclusion per host, and "did a deployment succeed since the session started?"
// The Docker database container (name matches /segmentra.*db/) is used to seed deployment rows. It leaves its users, host,
// policy set and deployment rows in the development database.
import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const apiBase = process.env.SEGMENTRA_API ?? 'http://localhost:8080/api';
const adminUser = process.env.SEGMENTRA_ADMIN_USER ?? 'admin';
const adminPass = process.env.SEGMENTRA_ADMIN_PASSWORD ?? 'admin123';
const root = resolve(fileURLToPath(import.meta.url), '../../..');
const suffix = Date.now().toString(36);
const results = [];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
function check(label, pass, detail = '') { results.push(pass); console.log(`  ${pass ? 'PASS' : 'FAIL'}  ${label}${detail ? `  (${detail})` : ''}`); }
async function raw(method, path, { token, body } = {}) {
  const res = await fetch(`${apiBase}${path}`, { method, headers: { ...(token ? { authorization: `Bearer ${token}` } : {}), ...(body !== undefined ? { 'content-type': 'application/json' } : {}) }, body: body !== undefined ? JSON.stringify(body) : undefined });
  const text = await res.text(); let json = null; try { json = JSON.parse(text); } catch { /* not json */ }
  return { status: res.status, text, json };
}
const api = async (m, p, o) => { const r = await raw(m, p, o); if (r.status >= 400) throw new Error(`${m} ${p} -> ${r.status}: ${r.text}`); return r.json; };
const login = async (u, p) => (await api('POST', '/auth/login', { body: { username: u, password: p } })).token;
async function ensureUser(admin, username, role) {
  await raw('POST', '/admin/users', { token: admin, body: { username, displayName: username, password: 'ReviewFix-pass-123!', roles: [role], isActive: true } });
  return login(username, 'ReviewFix-pass-123!');
}
const dbContainer = () => (spawnSync('docker', ['ps', '--format', '{{.Names}}'], { encoding: 'utf8' }).stdout.split('\n').find((n) => /segmentra.*db/i.test(n) && !/swarm/.test(n)) ?? '').trim();
const psql = (sql) => { const r = spawnSync('docker', ['exec', dbContainer(), 'psql', '-U', 'segmentra', '-d', 'segmentra', '-tAc', sql], { encoding: 'utf8' }); if (r.status !== 0) throw new Error(r.stderr); return r.stdout.trim(); };

async function main() {
  if (!dbContainer()) throw new Error('the Segmentra database container was not found');
  const admin = await login(adminUser, adminPass);
  const op = await ensureUser(admin, 'rf-operator', 'operator');
  const appr = await ensureUser(admin, 'rf-approver', 'approver');

  // ---- fixture: a host with an approved version carrying one rule, and a "successful" deployment of it ----
  const ip = `198.51.100.${1 + (parseInt(suffix.slice(-3), 36) % 250)}`;
  const host = (await api('POST', '/hosts', { token: op, body: { hostname: `rf-host-${suffix}`, mgmtIp: ip, sshPort: 22, firewallBackend: 'iptables', enabled: true } })).host;
  const ps = (await api('POST', '/policy-sets', { token: op, body: { name: `rf-pol-${suffix}`, scopeType: 'HOST_LIST', hostIds: [host.id] } })).policySet;
  const v = (await api('POST', `/policy-sets/${ps.id}/versions`, { token: op, body: { changeSummary: 'review fixes', interfaceScopeType: 'ALL_INTERFACES' } })).version;
  await api('POST', `/policy-versions/${v.id}/rules`, { token: op, body: { orderIndex: 10, direction: 'IN', action: 'ALLOW', protocol: 'tcp', ports: '8443', sourceType: 'CIDR', sourceValue: '10.9.0.0/16', logMode: 'NONE', usePolicyInterfaceScope: true, comment: 'rf' } });
  await api('POST', `/policy-versions/${v.id}/submit-approval`, { token: op, body: {} });
  await api('POST', `/policy-versions/${v.id}/approve`, { token: appr, body: {} });
  const depId = psql(`INSERT INTO deployments (policy_version_id, mode, target_query, status, finished_at) VALUES ('${v.id}', 'FULL', '{}'::jsonb, 'SUCCEEDED', now() - interval '1 minute') RETURNING id`).split('\n')[0];
  psql(`INSERT INTO deployment_hosts (deployment_id, host_id, status, finished_at) VALUES ('${depId}', '${host.id}', 'SUCCEEDED', now() - interval '1 minute')`);

  const sim = async (src = '10.9.1.1') => (await api('POST', '/troubleshoot/simulate-communication', { token: op, body: { sourceIp: src, destIp: ip, destPort: 8443, protocol: 'tcp' } }));
  const verdict = (r) => JSON.stringify(r).includes('"allowed":true') || /\bALLOWED\b/i.test(JSON.stringify(r.result ?? r.verdict ?? r.decision ?? ''));

  console.log('\nTroubleshoot: the policy that is really enforced');
  const r1 = await sim();
  const r1Text = JSON.stringify(r1);
  check('the deployed (approved) policy is evaluated', r1Text.includes(`rf-pol-${suffix}`), r1Text.slice(0, 120));
  await api('POST', `/policy-versions/${v.id}/archive`, { token: op, body: {} });
  const r2 = await sim();
  check('an archived version is still the policy on the host (archiving does not remove its rules)', JSON.stringify(r2).includes(`rf-pol-${suffix}`), JSON.stringify(r2).slice(0, 120));
  psql(`UPDATE deployment_hosts SET expiry_status = 'REMOVED' WHERE deployment_id = '${depId}' AND host_id = '${host.id}'`);
  const r3 = await sim();
  check('after expiry REMOVE the host is treated as having no deployed policy', !JSON.stringify(r3).includes(`rf-pol-${suffix}`), JSON.stringify(r3).slice(0, 120));
  psql(`UPDATE deployment_hosts SET expiry_status = NULL WHERE deployment_id = '${depId}' AND host_id = '${host.id}'`);

  console.log('\nHost lock and restore guard');
  process.env.DATABASE_URL ??= 'postgres://segmentra:segmentra@127.0.0.1:15432/segmentra';
  process.env.JWT_SECRET ??= 'x'.repeat(40);
  const lock = await import(pathToFileURL(resolve(root, 'apps/api/dist/services/host-lock.js')).href);
  const { pool } = await import(pathToFileURL(resolve(root, 'apps/api/dist/db/pool.js')).href);
  const rel1 = await lock.acquireHostLock(host.id);
  check('a second try-lock on the same host is refused while the lock is held', (await lock.tryAcquireHostLock(host.id)) === null);
  const other = await lock.tryAcquireHostLock('00000000-0000-0000-0000-00000000dead');
  check('a different host is not blocked', typeof other === 'function');
  await other?.();
  let waited = false;
  const t0 = Date.now();
  const waiter = lock.acquireHostLock(host.id).then(async (rel) => { waited = Date.now() - t0 >= 400; await rel(); });
  await sleep(500);
  await rel1();
  await waiter;
  check('a blocking acquire waits until the holder releases', waited);
  const rel2 = await lock.tryAcquireHostLock(host.id);
  check('the lock is free again after release', typeof rel2 === 'function');
  await rel2?.();
  const hostIdsOrdered = [host.id, '00000000-0000-0000-0000-00000000beef'];
  const both = await Promise.all([lock.acquireHostLocks(hostIdsOrdered), sleep(1)]).then(([r]) => r);
  check('locking several hosts at once works and releases them all', typeof both === 'function' && (await lock.tryAcquireHostLock(host.id)) === null);
  await both();
  const free = await lock.tryAcquireHostLock(host.id); check('... all released', typeof free === 'function'); await free?.();

  const longAgo = new Date(Date.now() - 3600 * 1000).toISOString();
  const future = new Date(Date.now() + 60 * 1000).toISOString();
  check('a deployment that succeeded after the session started is detected', (await lock.deploymentSucceededSince(host.id, longAgo)) === true);
  check('... but not one that finished before the session started', (await lock.deploymentSucceededSince(host.id, future)) === false);
  check('... and no start time means no skip', (await lock.deploymentSucceededSince(host.id, null)) === false);
  psql(`UPDATE deployment_hosts SET expiry_status = 'REMOVED' WHERE deployment_id = '${depId}' AND host_id = '${host.id}'`);
  check('a deployment whose rules were removed by expiry does not count', (await lock.deploymentSucceededSince(host.id, longAgo)) === false);
  psql(`UPDATE deployment_hosts SET expiry_processed_at = now() WHERE deployment_id = '${depId}' AND host_id = '${host.id}'`);
  check('... but an expiry REMOVE that ran after the session started does count (do not bring the policy back)', (await lock.deploymentSucceededSince(host.id, longAgo)) === true);
  check('... and one that ran before the session started does not', (await lock.deploymentSucceededSince(host.id, future)) === false);
  psql(`UPDATE deployment_hosts SET status = 'FAILED' WHERE deployment_id = '${depId}' AND host_id = '${host.id}'`);
  psql(`UPDATE deployment_hosts SET expiry_status = NULL WHERE deployment_id = '${depId}' AND host_id = '${host.id}'`);
  check('a failed deployment does not count', (await lock.deploymentSucceededSince(host.id, longAgo)) === false);
  await pool.end();
}

main()
  .then(() => { const failed = results.filter((x) => !x).length; console.log(`\n[review-fixes] ${results.length - failed}/${results.length} checks passed`); process.exit(failed ? 1 : 0); })
  .catch((e) => { console.error(e); process.exit(1); });
