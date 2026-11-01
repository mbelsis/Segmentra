#!/usr/bin/env node
// Docker lab for the second round of review findings. It starts ITS OWN API process (apps/api/dist, built first) against the
// development database container, and a gateway-like container (sshd + iptables) managed over SSH, then checks:
//   1. host locks: one lock connection per operation, never the shared query pool (an Ansible run over 10+ hosts used
//      to take every pool connection and freeze the API), and a bounded wait;
//   2. one learning OR policy-test session per host (a policy test started during a learning session restored the
//      learning session's allow-all rules when it ended);
//   3. a policy test interrupted while DEPLOYING (API killed) is restored: by Stop, at startup and by the expiry job;
//   4. expiry REMOVE/REVERT decides "superseded" by when the rules reached the host, not by creation time.
// Needs Docker and the database container (name matches /segmentra.*db/). Stop any other API on the same database first:
// its background jobs would race this test's. Leaves users, a disabled host and archived policy versions in the database.
import { spawn, spawnSync } from 'node:child_process';
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..', '..');
const API_PORT = Number(process.env.SEGMENTRA_TEST_API_PORT ?? 18095);
const apiBase = `http://127.0.0.1:${API_PORT}/api`;
const DATABASE_URL = process.env.DATABASE_URL ?? 'postgres://segmentra:segmentra@127.0.0.1:15432/segmentra';
const JWT_SECRET = process.env.JWT_SECRET ?? (existsSync(join(root, '.dev-jwt-secret')) ? readFileSync(join(root, '.dev-jwt-secret'), 'utf8').trim() : 'segmentra-sessions-lab-secret-0123456789abcdef');
const adminUser = process.env.SEGMENTRA_ADMIN_USER ?? 'admin';
const adminPass = process.env.SEGMENTRA_ADMIN_PASSWORD ?? 'admin123';
const suffix = Date.now().toString(36);
const NET = `segsess-${suffix}`, GW = `segsess-gw-${suffix}`;
const SSH_PORT = 2480 + Math.floor(Math.random() * 90);
const results = [];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const docker = (...a) => spawnSync('docker', a, { encoding: 'utf8' });
function check(label, pass, detail = '') { results.push({ label, pass: !!pass }); console.log(`  ${pass ? 'PASS' : 'FAIL'}  ${label}${detail ? `  (${detail})` : ''}`); }
function note(label) { console.log(`  NOTE  ${label}`); }
async function raw(method, path, { token, body } = {}) {
  const res = await fetch(`${apiBase}${path}`, { method, headers: { ...(token ? { authorization: `Bearer ${token}` } : {}), ...(body !== undefined ? { 'content-type': 'application/json' } : {}) }, body: body !== undefined ? JSON.stringify(body) : undefined });
  const text = await res.text(); let json = null; try { json = JSON.parse(text); } catch { /* not json */ }
  return { status: res.status, text, json };
}
const api = async (m, p, o) => { const r = await raw(m, p, o); if (r.status >= 400) throw new Error(`${m} ${p} -> ${r.status}: ${r.text}`); return r.json; };
const login = async (u, p) => (await api('POST', '/auth/login', { body: { username: u, password: p } })).token;
async function ensureUser(admin, username, role) {
  const r = await raw('POST', '/admin/users', { token: admin, body: { username, displayName: username, password: 'SessLab-pass-123!', roles: [role], isActive: true } });
  if (![201, 409].includes(r.status)) throw new Error(`user ${username}: ${r.status} ${r.text}`);
  return login(username, 'SessLab-pass-123!');
}
const dbContainer = () => (docker('ps', '--format', '{{.Names}}').stdout.split('\n').find((n) => /segmentra.*db/i.test(n) && !/swarm/.test(n)) ?? '').trim();
const psql = (sql) => { const r = docker('exec', dbContainer(), 'psql', '-U', 'segmentra', '-d', 'segmentra', '-tAc', sql); if (r.status !== 0) throw new Error(r.stderr); return r.stdout.trim(); };
function forgetHostKey(port) {
  const kh = join(process.env.HOME ?? '', '.ssh', 'known_hosts');
  if (!existsSync(kh)) return;
  const tmp = join(mkdtempSync(join(tmpdir(), 'segsess-kh-')), 'known_hosts');
  copyFileSync(kh, tmp);
  spawnSync('ssh-keygen', ['-q', '-R', `[127.0.0.1]:${port}`, '-f', tmp], { encoding: 'utf8' });
  if (readFileSync(kh, 'utf8') !== readFileSync(tmp, 'utf8')) writeFileSync(kh, readFileSync(tmp));
  rmSync(dirname(tmp), { recursive: true, force: true });
}

// ---- the API process under test ----
let apiProc = null;
const apiLog = join(mkdtempSync(join(tmpdir(), 'segsess-log-')), 'api.log');
async function startApi() {
  const bundles = join(root, 'data', 'bundles'); mkdirSync(bundles, { recursive: true });
  apiProc = spawn(process.execPath, [join(root, 'apps/api/dist/index.js')], {
    cwd: join(root, 'apps/api'),
    env: { ...process.env, PORT: String(API_PORT), DATABASE_URL, JWT_SECRET, BUNDLES_DIR: bundles, NODE_ENV: 'development' },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  const out = (d) => { try { writeFileSync(apiLog, d, { flag: 'a' }); } catch { /* ignore */ } };
  apiProc.stdout.on('data', out); apiProc.stderr.on('data', out);
  // Startup takes 15-30 s on a laptop (module loading, migrations check), longer under load.
  for (let i = 0; i < 240; i += 1) {
    if (apiProc.exitCode !== null || apiProc.signalCode !== null) throw new Error(`the API exited with code ${apiProc.exitCode} (log: ${apiLog})`);
    try { const r = await fetch(`${apiBase}/health`); if (r.status < 500) return; } catch { /* not up yet */ }
    await sleep(500);
  }
  throw new Error(`the API did not start (log: ${apiLog})`);
}
async function killApi(signal = 'SIGKILL') {
  if (!apiProc || apiProc.exitCode !== null || apiProc.signalCode !== null) return;
  const exited = new Promise((r) => apiProc.once('exit', r));
  apiProc.kill(signal);
  await exited;
}
const apiLogText = () => (existsSync(apiLog) ? readFileSync(apiLog, 'utf8') : '');

async function lockSection() {
  console.log('\n1. Host locks do not use the shared query pool');
  process.env.DATABASE_URL = DATABASE_URL;
  process.env.JWT_SECRET = JWT_SECRET;
  const lock = await import(pathToFileURL(join(root, 'apps/api/dist/services/host-lock.js')).href);
  const { pool } = await import(pathToFileURL(join(root, 'apps/api/dist/db/pool.js')).href);
  const ids = Array.from({ length: 25 }, (_, i) => `00000000-0000-4000-8000-${String(i).padStart(12, '0')}`);
  const t0 = Date.now();
  const release = await Promise.race([lock.acquireHostLocks(ids), sleep(10_000).then(() => null)]);
  check('25 host locks (an Ansible run over 25 hosts) are acquired', typeof release === 'function', `${Date.now() - t0} ms`);
  if (!release) return;
  const held = psql(`SELECT count(*) || ':' || count(DISTINCT pid) FROM pg_locks WHERE locktype = 'advisory' AND granted AND pid <> pg_backend_pid()`);
  const [nLocks, nPids] = held.split(':').map(Number);
  check('... all on ONE database connection', nLocks >= 25 && nPids === 1, `${nLocks} advisory locks on ${nPids} connection(s)`);
  // The old code took one connection of the shared pool (max 10) per host: with 10+ hosts every later query hung.
  const queries = await Promise.race([
    Promise.all(Array.from({ length: 30 }, (_, i) => pool.query('SELECT $1::int AS n', [i]))).then(() => true),
    sleep(5000).then(() => false)
  ]);
  check('... and 30 concurrent ordinary queries still run while they are held', queries);
  check('... while another operation on one of those hosts gets "busy", not a hang', (await lock.tryAcquireHostLock(ids[7])) === null);
  const t1 = Date.now();
  let err = null;
  try { await lock.acquireHostLock(ids[3], { timeoutMs: 800 }); } catch (e) { err = e; }
  check('a blocking acquire gives up after its timeout with HostLockTimeoutError', err?.name === 'HostLockTimeoutError' && Date.now() - t1 < 5000, `${err?.name ?? 'no error'} after ${Date.now() - t1} ms`);
  await release();
  const again = await lock.tryAcquireHostLock(ids[7]);
  check('releasing frees every host', typeof again === 'function');
  await again?.();
  const left = Number(psql(`SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND granted AND pid <> pg_backend_pid()`));
  check('... and no advisory lock is left behind', left === 0, `${left} left`);
  // 12 operations at the same time on different hosts, each holding its lock while it queries (like a deployment).
  const many = await Promise.race([
    Promise.all(ids.slice(0, 12).map(async (id) => { const r = await lock.acquireHostLock(id); try { await pool.query('SELECT pg_sleep(0.2)'); } finally { await r(); } })).then(() => true),
    sleep(15_000).then(() => false)
  ]);
  check('12 concurrent single-host operations that query while holding the lock all finish', many);
  return { lock, pool };
}

async function main() {
  if (docker('info').status !== 0) throw new Error('Docker is not available');
  if (!dbContainer()) throw new Error('the Segmentra database container was not found (start it with ./start.sh dev or docker compose)');
  if (!existsSync(join(root, 'apps/api/dist/index.js'))) throw new Error('build first: npm run build');

  const { lock, pool } = await lockSection();

  let keyDir = null, credId = null, hostId = null, admin = null, op = null, executorBefore = null;
  const versions = [];
  try {
    await startApi();
    admin = await login(adminUser, adminPass);
    op = await ensureUser(admin, 'sess-operator', 'operator');
    const appr = await ensureUser(admin, 'sess-approver', 'approver');
    executorBefore = (await api('GET', '/admin/executor-setting', { token: admin })).executor;

    docker('build', '-q', '-t', 'segmentra-iot-gw:test', join(here, '..', 'docker-ssh-integration', 'target'));
    docker('network', 'create', NET);
    keyDir = mkdtempSync(join(tmpdir(), 'segsess-key-'));
    spawnSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-f', join(keyDir, 'id_ed25519'), '-C', 'segmentra-sessions-test']);
    spawnSync('chmod', ['644', join(keyDir, 'id_ed25519.pub')]);
    const run = docker('run', '-d', '--name', GW, '--network', NET, '--cap-add', 'NET_ADMIN', '-p', `127.0.0.1:${SSH_PORT}:${SSH_PORT}`, '-v', `${keyDir}:/runtime-keys:ro`, '-e', 'TARGET_USER=segmentra', 'segmentra-iot-gw:test');
    if (run.status !== 0) throw new Error(`container: ${run.stderr}`);
    for (let i = 0; i < 30 && docker('exec', GW, 'sh', '-c', 'pgrep sshd >/dev/null').status !== 0; i += 1) await sleep(1000);
    docker('exec', GW, 'sh', '-c', `printf 'Port 22\\nPort ${SSH_PORT}\\n' >> /etc/ssh/sshd_config && kill -HUP $(pgrep -o sshd)`);
    await sleep(1500);
    let ready = false;
    for (let i = 0; i < 40 && !ready; i += 1) {
      const ipt = docker('exec', GW, 'iptables', '-S').status === 0;
      const ssh = spawnSync('ssh', ['-i', join(keyDir, 'id_ed25519'), '-o', 'IdentitiesOnly=yes', '-p', String(SSH_PORT), '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null', '-o', 'LogLevel=ERROR', '-o', 'ConnectTimeout=3', 'segmentra@127.0.0.1', 'sudo -n iptables -S >/dev/null'], { encoding: 'utf8' }).status === 0;
      ready = ipt && ssh;
      if (!ready) await sleep(1000);
    }
    if (!ready) throw new Error('the gateway container did not become usable (iptables and SSH login)');
    const rules = () => docker('exec', GW, 'iptables', '-S', 'SEGMENTRA-IN').stdout;
    const has = (port) => new RegExp(`--dport ${port}\\b`).test(rules());
    const logOnly = () => /LOG/.test(rules()) && !/-j DROP/.test(rules());
    const brief = () => rules().split('\n').filter((l) => /dport|LOG|DROP/.test(l)).join(' | ').slice(0, 160);

    const host = (await api('POST', '/hosts', { token: op, body: { hostname: `sess-${suffix}`, mgmtIp: '127.0.0.1', sshPort: SSH_PORT, firewallBackend: 'iptables', enabled: true } })).host;
    hostId = host.id;
    const cred = await api('POST', '/ssh-credentials', { token: admin, body: { name: `sess-${suffix}`, username: 'segmentra', authMethod: 'KEY', privateKeyPem: readFileSync(join(keyDir, 'id_ed25519'), 'utf8'), scopeType: 'HOST', scopeId: host.id } });
    credId = (cred.sshCredential ?? cred.credential ?? cred).id;
    await api('PUT', '/admin/executor-setting', { token: admin, body: { executor: 'ssh' } });

    const ps = (await api('POST', '/policy-sets', { token: op, body: { name: `sess-pol-${suffix}`, scopeType: 'HOST_LIST', hostIds: [host.id] } })).policySet;
    const version = async (port) => {
      const v = (await api('POST', `/policy-sets/${ps.id}/versions`, { token: op, body: { changeSummary: `sess ${port}`, interfaceScopeType: 'ALL_INTERFACES' } })).version;
      versions.push(v.id);
      await api('POST', `/policy-versions/${v.id}/rules`, { token: op, body: { orderIndex: 10, direction: 'IN', action: 'ALLOW', protocol: 'tcp', ports: String(port), sourceType: 'CIDR', sourceValue: '10.77.0.0/16', logMode: 'NONE', usePolicyInterfaceScope: true, comment: `sess ${port}` } });
      await api('POST', `/policy-versions/${v.id}/submit-approval`, { token: op, body: {} });
      await api('POST', `/policy-versions/${v.id}/approve`, { token: appr, body: {} });
      return v;
    };
    const createDeploy = async (v, extra = {}) => (await api('POST', '/deployments', { token: op, body: { policyVersionId: v.id, mode: 'FULL', targetQuery: { hosts: [host.id], tags: [], vlans: [] }, ...extra } })).deployment.id;
    const wait = async (id) => { for (let i = 0; i < 60; i += 1) { const d = await api('GET', `/deployments/${id}`, { token: op }); if (['SUCCEEDED', 'FAILED', 'PARTIAL'].includes(d.deployment.status)) return d.deployment.status; await sleep(1500); } return 'TIMEOUT'; };
    const runDeploy = async (id) => { await api('POST', `/deployments/${id}/start`, { token: op, body: {} }); return wait(id); };
    const startAudit = async () => (await api('POST', '/troubleshoot/audit/start', { token: op, body: { hosts: [host.id], durationMinutes: 30 } })).results?.[0];
    const restoreAudit = (id) => raw('POST', `/troubleshoot/audit/sessions/${id}/restore`, { token: op, body: {} });
    const startTest = (v) => raw('POST', '/policy-test/start', { token: op, body: { policyVersionId: v.id, hostId: host.id, durationMinutes: 30 } });
    const stopTest = (id) => raw('POST', `/policy-test/sessions/${id}/stop`, { token: op, body: {} });
    const testStatus = (id) => psql(`SELECT status FROM policy_test_sessions WHERE id = '${id}'`);

    const vA = await version(8181), vB = await version(9191), vT = await version(7171);
    check('policy A deploys over SSH', (await runDeploy(await createDeploy(vA))) === 'SUCCEEDED');
    check('the gateway enforces A (8181) with a final DROP', has(8181) && /-j DROP/.test(rules()), brief());

    // ------------------------------------------------------------------------------------------------------------
    console.log('\n2. One learning or policy-test session per host');
    const l1 = await startAudit();
    check('a learning session starts', l1?.status === 'RUNNING', JSON.stringify(l1).slice(0, 140));
    check('... the host is in log-only mode', logOnly(), brief());
    const t1 = await startTest(vT);
    check('a policy test on the same host is refused (409 learning_session_active)', t1.status === 409 && t1.json?.error === 'learning_session_active', `${t1.status} ${t1.text.slice(0, 120)}`);
    const r1 = await restoreAudit(l1.sessionId);
    check('restoring the learning session puts A back', r1.status === 200 && has(8181) && /-j DROP/.test(rules()), brief());

    const t2 = await startTest(vT);
    check('now a policy test starts', t2.status === 201 && t2.json?.session?.status === 'RUNNING', `${t2.status} ${t2.text.slice(0, 120)}`);
    const l2 = await startAudit();
    check('a learning session on the same host is refused while the test runs', l2?.status === 'FAILED' && /policy test/.test(l2?.error ?? ''), JSON.stringify(l2).slice(0, 160));
    const s2 = await stopTest(t2.json.session.id);
    check('stopping the test restores A (8181 + DROP), not an allow-all ruleset', s2.status === 200 && has(8181) && /-j DROP/.test(rules()) && !has(7171), brief());

    // The original bug sequence: learning A, test B, stop A, stop B. B can no longer start, so the host ends with A.
    const l3 = await startAudit();
    const t3 = await startTest(vT);
    await restoreAudit(l3.sessionId);
    if (t3.status === 201) await stopTest(t3.json.session.id);
    check('report sequence (learn, test, stop learn, stop test) ends with the real policy enforced', t3.status === 409 && has(8181) && /-j DROP/.test(rules()), `test start ${t3.status}; ${brief()}`);

    const [c1, c2] = await Promise.all([
      api('POST', '/troubleshoot/audit/start', { token: op, body: { hosts: [host.id], durationMinutes: 30 } }),
      api('POST', '/troubleshoot/audit/start', { token: op, body: { hosts: [host.id], durationMinutes: 30 } })
    ]);
    const started = [c1.results?.[0], c2.results?.[0]].filter((r) => r?.status === 'RUNNING');
    const active = Number(psql(`SELECT count(*) FROM firewall_audit_sessions WHERE host_id = '${host.id}' AND status IN ('PENDING','RUNNING')`));
    check('two learning starts at the same moment: exactly one session becomes active', started.length === 1 && active === 1, `${started.length} started, ${active} active`);
    if (started[0]) await restoreAudit(started[0].sessionId);
    check('... and restoring it puts A back', has(8181) && /-j DROP/.test(rules()), brief());

    // ------------------------------------------------------------------------------------------------------------
    console.log('\n3. A policy test interrupted while DEPLOYING is recovered');
    // (a) a real crash: kill the API as soon as the log-only rules reach the host, before the session is RUNNING.
    const startP = startTest(vT).catch(() => null);
    let sawLogOnly = false;
    for (let i = 0; i < 400 && !sawLogOnly; i += 1) { if (has(7171) && logOnly()) sawLogOnly = true; else await sleep(25); }
    await killApi('SIGKILL');
    await startP;
    const crashed = JSON.parse(psql(`SELECT json_build_object('id', id, 'status', status, 'backup', backup_path) FROM policy_test_sessions WHERE host_id = '${host.id}' ORDER BY started_at DESC LIMIT 1`));
    const hitWindow = crashed.status === 'DEPLOYING' && !!crashed.backup;
    if (hitWindow) check('API killed mid-start: the session is left DEPLOYING with a backup, host in log-only mode', logOnly(), brief());
    else note(`the kill landed outside the DEPLOYING window (session ${crashed.status}); the crash is simulated below instead`);
    await startApi();
    const recoveredAtStart = async (id) => { for (let i = 0; i < 40; i += 1) { if (testStatus(id) === 'FAILED') return true; await sleep(500); } return false; };
    if (hitWindow) {
      check('after a restart the API restores it on its own (startup recovery)', await recoveredAtStart(crashed.id), testStatus(crashed.id));
      check('... the host enforces A again (8181 + DROP, no 7171)', has(8181) && /-j DROP/.test(rules()) && !has(7171), brief());
      check('... the session records the interrupted start', /interrupted/.test(psql(`SELECT raw_log_data::text FROM policy_test_sessions WHERE id = '${crashed.id}'`)));
    } else if (crashed.status === 'RUNNING') {
      await stopTest(crashed.id);
    }

    // (b) deterministic: a started test whose row is put back to DEPLOYING is exactly the state of a crash just before
    // the "RUNNING" update (host in log-only mode, backup recorded, host lock free).
    const simulateCrash = async () => {
      const t = await startTest(vT);
      if (t.status !== 201) throw new Error(`test start: ${t.status} ${t.text}`);
      psql(`UPDATE policy_test_sessions SET status = 'DEPLOYING' WHERE id = '${t.json.session.id}'`);
      return t.json.session.id;
    };
    const d1 = await simulateCrash();
    check('simulated crash: host in log-only mode with the test rules', logOnly() && has(7171), brief());
    const releaseHeld = await lock.acquireHostLock(host.id);
    const busy = await stopTest(d1);
    check('Stop while the host lock is held (start still running) answers 409 test_starting', busy.status === 409 && busy.json?.error === 'test_starting', `${busy.status} ${busy.text.slice(0, 100)}`);
    await releaseHeld();
    const s3 = await stopTest(d1);
    check('Stop on the interrupted test restores the backup (was 404 before)', s3.status === 200 && testStatus(d1) === 'FAILED', `${s3.status} ${s3.text.slice(0, 120)}`);
    check('... the host enforces A again', has(8181) && /-j DROP/.test(rules()) && !has(7171), brief());
    const t4 = await startTest(vT);
    check('... and a new policy test can start on the host (it was blocked forever before)', t4.status === 201, `${t4.status}`);
    if (t4.status === 201) await stopTest(t4.json.session.id);

    // Startup recovery, deterministically: crash state, then the API really dies and comes back.
    const d0 = await simulateCrash();
    await killApi('SIGKILL');
    const t0 = Date.now();
    await startApi();
    let atStartup = false;
    // The session row is updated a moment before the API logs the recovery: wait for both.
    const recoveryLogged = () => apiLogText().includes(`Interrupted start of session ${d0}`);
    for (let i = 0; i < 40 && !atStartup; i += 1) { if (testStatus(d0) === 'FAILED' && recoveryLogged()) atStartup = true; else await sleep(500); }
    const secs = Math.round((Date.now() - t0) / 1000);
    check('API killed with a DEPLOYING test and restarted: startup recovery restores it', atStartup, `${testStatus(d0)}, logged ${recoveryLogged()}, after ${secs}s`);
    check('... the host enforces A again', has(8181) && /-j DROP/.test(rules()) && !has(7171), brief());

    const d2 = await simulateCrash();
    let byJob = false;
    for (let i = 0; i < 90 && !byJob; i += 1) { if (testStatus(d2) === 'FAILED') byJob = true; else await sleep(1000); }
    check('without anyone pressing Stop, the expiry job recovers it within its 1-minute tick', byJob, testStatus(d2));
    check('... the host enforces A again', has(8181) && /-j DROP/.test(rules()) && !has(7171), brief());

    const d3 = (await api('POST', '/policy-test/start', { token: op, body: { policyVersionId: vT.id, hostId: host.id, durationMinutes: 30 } })).session.id;
    psql(`UPDATE policy_test_sessions SET status = 'DEPLOYING', backup_path = NULL WHERE id = '${d3}'`);
    await stopTest(d3);
    check('an interrupted test without a recorded backup is just marked FAILED', testStatus(d3) === 'FAILED');
    // (the real host still had the test rules in this artificial state; put A back for the next section)
    check('A redeploys', (await runDeploy(await createDeploy(vA))) === 'SUCCEEDED' && has(8181));

    // ------------------------------------------------------------------------------------------------------------
    console.log('\n4. Expiry decides "superseded" by when the rules were applied');
    const expireNow = (id, action) => psql(`UPDATE deployments SET expires_at = now() - interval '1 second', expiry_action = '${action}' WHERE id = '${id}'`);
    const expiryOf = (id) => psql(`SELECT COALESCE(expiry_status, '') || '|' || COALESCE(expiry_message, '') FROM deployment_hosts WHERE deployment_id = '${id}' AND host_id = '${host.id}'`);
    const waitExpiry = async (id) => { for (let i = 0; i < 90; i += 1) { const e = expiryOf(id); if (e.split('|')[0]) return e; await sleep(1000); } return expiryOf(id); };

    // Create A first, then create and deploy B, then deploy A: the host runs A, although A was CREATED before B.
    const depA = await createDeploy(vA);
    await sleep(1100);
    const depB = await createDeploy(vB);
    check('B (created later) deploys', (await runDeploy(depB)) === 'SUCCEEDED' && has(9191));
    check('A (created earlier) deploys afterwards; the host runs A', (await runDeploy(depA)) === 'SUCCEEDED' && has(8181) && !has(9191), brief());
    expireNow(depB, 'REMOVE');
    const eB = await waitExpiry(depB);
    check('B expires with REMOVE: it is skipped as superseded by A', eB.startsWith('SKIPPED') && eB.includes(depA), eB.slice(0, 140));
    check('... and A\'s rules are still on the host (before: they were removed)', has(8181) && /-j DROP/.test(rules()), brief());

    const depB2 = await createDeploy(vB);
    await sleep(1100);
    const depA2 = await createDeploy(vA);
    check('B2 (created first) deploys', (await runDeploy(depB2)) === 'SUCCEEDED');
    check('A2 (created later) deploys', (await runDeploy(depA2)) === 'SUCCEEDED');
    check('B2 deployed again afterwards; the host runs B', (await runDeploy(await createDeploy(vB))) === 'SUCCEEDED' && has(9191) && !has(8181), brief());
    expireNow(depA2, 'REVERT');
    const eA2 = await waitExpiry(depA2);
    check('A2 expires with REVERT: skipped (replaced by the later B run), no revert deployment', eA2.startsWith('SKIPPED') && psql(`SELECT count(*) FROM deployments WHERE revert_of_deployment_id = '${depA2}'`) === '0', eA2.slice(0, 140));
    check('... B is still enforced', has(9191) && !has(8181), brief());

    // Normal case still works: the deployment that IS on the host expires with REMOVE and its rules are removed.
    const live = await createDeploy(vA);
    check('A deploys once more', (await runDeploy(live)) === 'SUCCEEDED' && has(8181));
    expireNow(live, 'REMOVE');
    const eL = await waitExpiry(live);
    check('the deployment that is live on the host is removed on expiry REMOVE', eL.startsWith('REMOVED') && !/SEGMENTRA-IN/.test(docker('exec', GW, 'iptables', '-S').stdout), eL.slice(0, 120));
  } finally {
    if (hostId) {
      try {
        psql(`UPDATE firewall_audit_sessions SET status = 'CANCELLED' WHERE host_id = '${hostId}' AND status IN ('PENDING','RUNNING')`);
        psql(`UPDATE policy_test_sessions SET status = 'FAILED' WHERE host_id = '${hostId}' AND status IN ('PENDING','DEPLOYING','RUNNING')`);
      } catch { /* best effort */ }
    }
    if (op) for (const id of versions) await raw('POST', `/policy-versions/${id}/archive`, { token: op, body: {} }).catch(() => {});
    if (admin) {
      if (credId) await raw('DELETE', `/ssh-credentials/${credId}`, { token: admin }).catch(() => {});
      if (hostId) await raw('POST', '/hosts/bulk/set-enabled', { token: op, body: { hostIds: [hostId], enabled: false } }).catch(() => {});
      if (executorBefore) await raw('PUT', '/admin/executor-setting', { token: admin, body: { executor: executorBefore } }).catch(() => {});
    }
    await killApi('SIGTERM');
    docker('rm', '-f', '-v', GW);
    docker('network', 'rm', NET);
    forgetHostKey(SSH_PORT);
    if (keyDir) rmSync(keyDir, { recursive: true, force: true });
    await lock.endHostLockPool().catch(() => {});
    await pool.end().catch(() => {});
  }
  const failed = results.filter((r) => !r.pass);
  console.log(`\n[sessions] ${results.length - failed.length}/${results.length} checks passed (API log: ${apiLog})`);
  for (const f of failed) console.log(`  FAILED: ${f.label}`);
  process.exit(failed.length ? 1 : 0);
}
main().catch(async (e) => { console.error(e); console.error(`API log: ${apiLog}\n${apiLogText().slice(-3000)}`); await killApi(); process.exit(1); });
