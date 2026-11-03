#!/usr/bin/env node
// Docker lab for the third round of review findings. Starts ITS OWN API (apps/api/dist, build first) on port 18096 against
// the development database container, a gateway-like container (sshd + iptables + nftables) managed over SSH, and an
// in-process fake Kubernetes API server (HTTPS, self-signed) that implements just the NetworkPolicy calls Segmentra makes.
//   1. switching a host's firewall backend: the deployment is refused while the previous backend's Segmentra rules are
//      active (before: both were enforced and the old default-deny kept dropping what the new policy allowed), the
//      remove-backend-rules endpoint clears them, then the deployment succeeds; both directions;
//   2. recommendations for an IPv6 client are a /128 (before: "<ip>/32", which the compiler turns into a whole /32 network);
//   3. Kubernetes: the applied manifest can be removed while a newer one is only GENERATED (before: refused by both);
//   4. Policy Impact Analysis uses the compiler's address semantics ("any", comma lists, IPv6), so it predicts the DROP
//      the compiled rules enforce (before: "OUT DENY tcp/443 to any" was predicted ALLOW).
// Needs Docker (the container installs nftables with apk, so it needs network access) and the database container.
// Stop any other API on the same database first. Leaves users, a disabled host, a disabled cluster and archived versions.
import { spawn, spawnSync } from 'node:child_process';
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import https from 'node:https';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import crypto from 'node:crypto';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..', '..');
const API_PORT = Number(process.env.SEGMENTRA_TEST_API_PORT ?? 18096);
const apiBase = `http://127.0.0.1:${API_PORT}/api`;
const DATABASE_URL = process.env.DATABASE_URL ?? 'postgres://segmentra:segmentra@127.0.0.1:15432/segmentra';
const JWT_SECRET = process.env.JWT_SECRET ?? (existsSync(join(root, '.dev-jwt-secret')) ? readFileSync(join(root, '.dev-jwt-secret'), 'utf8').trim() : 'segmentra-sessions-lab-secret-0123456789abcdef');
const adminUser = process.env.SEGMENTRA_ADMIN_USER ?? 'admin';
const adminPass = process.env.SEGMENTRA_ADMIN_PASSWORD ?? 'admin123';
const suffix = Date.now().toString(36);
const NET = `segr3-${suffix}`, GW = `segr3-gw-${suffix}`;
const SSH_PORT = 2580 + Math.floor(Math.random() * 90);
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
  const r = await raw('POST', '/admin/users', { token: admin, body: { username, displayName: username, password: 'Round3-pass-123!', roles: [role], isActive: true } });
  if (![201, 409].includes(r.status)) throw new Error(`user ${username}: ${r.status} ${r.text}`);
  return login(username, 'Round3-pass-123!');
}
const dbContainer = () => (docker('ps', '--format', '{{.Names}}').stdout.split('\n').find((n) => /segmentra.*db/i.test(n) && !/swarm/.test(n)) ?? '').trim();
const psql = (sql) => { const r = docker('exec', dbContainer(), 'psql', '-U', 'segmentra', '-d', 'segmentra', '-tAc', sql); if (r.status !== 0) throw new Error(r.stderr); return r.stdout.trim(); };
const sqlStr = (s) => `'${String(s).replace(/'/g, "''")}'`;
function forgetHostKey(port) {
  const kh = join(process.env.HOME ?? '', '.ssh', 'known_hosts');
  if (!existsSync(kh)) return;
  const tmp = join(mkdtempSync(join(tmpdir(), 'segr3-kh-')), 'known_hosts');
  copyFileSync(kh, tmp);
  spawnSync('ssh-keygen', ['-q', '-R', `[127.0.0.1]:${port}`, '-f', tmp], { encoding: 'utf8' });
  if (readFileSync(kh, 'utf8') !== readFileSync(tmp, 'utf8')) writeFileSync(kh, readFileSync(tmp));
  rmSync(dirname(tmp), { recursive: true, force: true });
}

// ---- the API process under test ----
let apiProc = null;
const apiLog = join(mkdtempSync(join(tmpdir(), 'segr3-log-')), 'api.log');
async function startApi() {
  const bundles = join(root, 'data', 'bundles'); mkdirSync(bundles, { recursive: true });
  apiProc = spawn(process.execPath, [join(root, 'apps/api/dist/index.js')], {
    cwd: join(root, 'apps/api'),
    env: { ...process.env, PORT: String(API_PORT), DATABASE_URL, JWT_SECRET, BUNDLES_DIR: bundles, NODE_ENV: 'development' },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  const out = (d) => { try { writeFileSync(apiLog, d, { flag: 'a' }); } catch { /* ignore */ } };
  apiProc.stdout.on('data', out); apiProc.stderr.on('data', out);
  for (let i = 0; i < 240; i += 1) {
    if (apiProc.exitCode !== null || apiProc.signalCode !== null) throw new Error(`the API exited (log: ${apiLog})`);
    try { const r = await fetch(`${apiBase}/health`); if (r.status < 500) return; } catch { /* not up yet */ }
    await sleep(500);
  }
  throw new Error(`the API did not start (log: ${apiLog})`);
}
async function stopApi() {
  if (!apiProc || apiProc.exitCode !== null || apiProc.signalCode !== null) return;
  const exited = new Promise((r) => apiProc.once('exit', r));
  apiProc.kill('SIGTERM');
  await Promise.race([exited, sleep(5000)]);
  if (apiProc.exitCode === null && apiProc.signalCode === null) apiProc.kill('SIGKILL');
}

// ---- fake Kubernetes API server: version, get/list/apply/delete NetworkPolicy ----
function startFakeK8s(certDir) {
  const store = new Map(); // "ns/name" -> object
  const key = join(certDir, 'k.pem'), crt = join(certDir, 'c.pem');
  const gen = spawnSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key, '-out', crt, '-days', '1', '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1'], { encoding: 'utf8' });
  if (gen.status !== 0) throw new Error(`openssl: ${gen.stderr}`);
  const server = https.createServer({ key: readFileSync(key), cert: readFileSync(crt) }, (req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      const send = (code, obj) => { res.writeHead(code, { 'content-type': 'application/json' }); res.end(JSON.stringify(obj)); };
      if (req.headers.authorization !== 'Bearer round3-token') return send(401, { kind: 'Status', message: 'Unauthorized' });
      const url = new URL(req.url, 'https://x');
      if (url.pathname === '/version') return send(200, { gitVersion: 'v1.30.0-fake' });
      const m = /^\/apis\/networking\.k8s\.io\/v1\/namespaces\/([^/]+)\/networkpolicies(?:\/([^/]+))?$/.exec(url.pathname);
      if (!m) return send(404, { kind: 'Status', message: 'not found' });
      const ns = decodeURIComponent(m[1]), name = m[2] ? decodeURIComponent(m[2]) : null;
      const k = `${ns}/${name}`;
      if (req.method === 'GET' && !name) return send(200, { kind: 'NetworkPolicyList', items: [...store.entries()].filter(([x]) => x.startsWith(`${ns}/`)).map(([, v]) => v) });
      if (req.method === 'GET') return store.has(k) ? send(200, store.get(k)) : send(404, { kind: 'Status', code: 404, details: { kind: 'networkpolicies', name } });
      if (req.method === 'PATCH') {
        const manifest = JSON.parse(body || '{}');
        const prev = store.get(k);
        const obj = { ...manifest, metadata: { ...manifest.metadata, namespace: ns, name, uid: prev?.metadata?.uid ?? crypto.randomUUID(), resourceVersion: String(Date.now()) } };
        if (url.searchParams.get('dryRun') !== 'All') store.set(k, obj);
        return send(prev ? 200 : 201, obj);
      }
      if (req.method === 'DELETE') {
        if (!store.has(k)) return send(404, { kind: 'Status', code: 404 });
        const opts = body ? JSON.parse(body) : {};
        if (opts?.preconditions?.uid && opts.preconditions.uid !== store.get(k).metadata.uid) return send(409, { kind: 'Status', code: 409, message: 'uid precondition failed' });
        store.delete(k);
        return send(200, { kind: 'Status', status: 'Success' });
      }
      send(405, { kind: 'Status', message: 'method not allowed' });
    });
  });
  return new Promise((r) => server.listen(0, '127.0.0.1', () => r({ server, store, port: server.address().port, ca: readFileSync(crt, 'utf8') })));
}

async function main() {
  if (docker('info').status !== 0) throw new Error('Docker is not available');
  if (!dbContainer()) throw new Error('the Segmentra database container was not found');
  if (!existsSync(join(root, 'apps/api/dist/index.js'))) throw new Error('build first: npm run build');
  const compiler = await import(pathToFileURL(join(root, 'packages/compiler/dist/index.js')).href);

  let keyDir = null, credId = null, hostId = null, admin = null, op = null, executorBefore = null, clusterId = null, k8s = null;
  const versions = [];
  try {
    await startApi();
    admin = await login(adminUser, adminPass);
    op = await ensureUser(admin, 'r3-operator', 'operator');
    const appr = await ensureUser(admin, 'r3-approver', 'approver');
    executorBefore = (await api('GET', '/admin/executor-setting', { token: admin })).executor;

    docker('build', '-q', '-t', 'segmentra-iot-gw:test', join(here, '..', 'docker-ssh-integration', 'target'));
    docker('network', 'create', NET);
    keyDir = mkdtempSync(join(tmpdir(), 'segr3-key-'));
    spawnSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-f', join(keyDir, 'id_ed25519'), '-C', 'segmentra-round3-test']);
    spawnSync('chmod', ['644', join(keyDir, 'id_ed25519.pub')]);
    const run = docker('run', '-d', '--name', GW, '--network', NET, '--cap-add', 'NET_ADMIN', '-p', `127.0.0.1:${SSH_PORT}:${SSH_PORT}`, '-v', `${keyDir}:/runtime-keys:ro`, '-e', 'TARGET_USER=segmentra', 'segmentra-iot-gw:test');
    if (run.status !== 0) throw new Error(`container: ${run.stderr}`);
    for (let i = 0; i < 30 && docker('exec', GW, 'sh', '-c', 'pgrep sshd >/dev/null').status !== 0; i += 1) await sleep(1000);
    const apk = docker('exec', GW, 'apk', 'add', '--no-cache', 'nftables');
    if (apk.status !== 0) throw new Error(`could not install nftables in the lab container (network access needed): ${apk.stderr}`);
    docker('exec', GW, 'sh', '-c', `printf 'Port 22\\nPort ${SSH_PORT}\\n' >> /etc/ssh/sshd_config && kill -HUP $(pgrep -o sshd)`);
    await sleep(1500);
    let ready = false;
    for (let i = 0; i < 40 && !ready; i += 1) {
      const ipt = docker('exec', GW, 'iptables', '-S').status === 0 && docker('exec', GW, 'nft', 'list', 'tables').status === 0;
      const ssh = spawnSync('ssh', ['-i', join(keyDir, 'id_ed25519'), '-o', 'IdentitiesOnly=yes', '-p', String(SSH_PORT), '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null', '-o', 'LogLevel=ERROR', '-o', 'ConnectTimeout=3', 'segmentra@127.0.0.1', 'sudo -n iptables -S >/dev/null'], { encoding: 'utf8' }).status === 0;
      ready = ipt && ssh;
      if (!ready) await sleep(1000);
    }
    if (!ready) throw new Error('the gateway container did not become usable (iptables, nft and SSH login)');
    const nftTable = () => docker('exec', GW, 'nft', 'list', 'table', 'inet', 'segmentra');
    const nftHas = (port) => { const r = nftTable(); return r.status === 0 && new RegExp(`dport ${port}\\b`).test(r.stdout); };
    const iptHas = (port) => new RegExp(`--dport ${port}\\b`).test(docker('exec', GW, 'iptables', '-S', 'SEGMENTRA-IN').stdout);
    const iptChain = () => docker('exec', GW, 'iptables', '-S', 'SEGMENTRA-IN').status === 0;

    const host = (await api('POST', '/hosts', { token: admin, /* SSH target is admin-only */ body: { hostname: `r3-${suffix}`, mgmtIp: '127.0.0.1', sshPort: SSH_PORT, firewallBackend: 'nftables', enabled: true } })).host;
    hostId = host.id;
    const cred = await api('POST', '/ssh-credentials', { token: admin, body: { name: `r3-${suffix}`, username: 'segmentra', authMethod: 'KEY', privateKeyPem: readFileSync(join(keyDir, 'id_ed25519'), 'utf8'), scopeType: 'HOST', scopeId: host.id } });
    credId = (cred.sshCredential ?? cred.credential ?? cred).id;
    await api('PUT', '/admin/executor-setting', { token: admin, body: { executor: 'ssh' } });
    const ps = (await api('POST', '/policy-sets', { token: op, body: { name: `r3-pol-${suffix}`, scopeType: 'HOST_LIST', hostIds: [host.id] } })).policySet;
    const version = async (rules) => {
      const v = (await api('POST', `/policy-sets/${ps.id}/versions`, { token: op, body: { changeSummary: 'round3', interfaceScopeType: 'ALL_INTERFACES' } })).version;
      versions.push(v.id);
      let i = 10;
      for (const r of rules) {
        await api('POST', `/policy-versions/${v.id}/rules`, { token: op, body: { orderIndex: i, direction: 'IN', action: 'ALLOW', protocol: 'tcp', sourceType: 'CIDR', sourceValue: '10.77.0.0/16', logMode: 'NONE', usePolicyInterfaceScope: true, comment: 'round3', ...r } });
        i += 10;
      }
      await api('POST', `/policy-versions/${v.id}/submit-approval`, { token: op, body: {} });
      await api('POST', `/policy-versions/${v.id}/approve`, { token: appr, body: {} });
      return v;
    };
    const deploy = async (v) => {
      const dep = await api('POST', '/deployments', { token: op, body: { policyVersionId: v.id, mode: 'FULL', targetQuery: { hosts: [host.id], tags: [], vlans: [] } } });
      await api('POST', `/deployments/${dep.deployment.id}/start`, { token: op, body: { acceptReadinessNotes: true } });
      for (let i = 0; i < 60; i += 1) {
        const d = await api('GET', `/deployments/${dep.deployment.id}`, { token: op });
        if (['SUCCEEDED', 'FAILED', 'PARTIAL'].includes(d.deployment.status)) {
          const msg = psql(`SELECT COALESCE(message, '') FROM deployment_hosts WHERE deployment_id = '${dep.deployment.id}' AND host_id = '${host.id}'`);
          const stderrPath = psql(`SELECT COALESCE(stderr_path, '') FROM execution_runs WHERE deployment_id = '${dep.deployment.id}' ORDER BY started_at DESC NULLS LAST LIMIT 1`);
          const stderr = stderrPath && existsSync(resolve(root, 'apps/api', stderrPath)) ? readFileSync(resolve(root, 'apps/api', stderrPath), 'utf8') : (stderrPath && existsSync(stderrPath) ? readFileSync(stderrPath, 'utf8') : '');
          return { status: d.deployment.status, message: msg, stderr };
        }
        await sleep(1500);
      }
      return { status: 'TIMEOUT', message: '', stderr: '' };
    };
    const setBackend = (b) => api('PUT', `/hosts/${host.id}`, { token: op, body: { firewallBackend: b } });
    const removeBackend = (b) => raw('POST', `/hosts/${host.id}/firewall/remove-backend-rules`, { token: op, body: { backend: b } });

    // ------------------------------------------------------------------------------------------------------------
    console.log('\n1. Switching the firewall backend');
    const vA = await version([{ ports: '8181' }]);
    const vB = await version([{ ports: '9191' }]);
    const dA = await deploy(vA);
    check('policy A deploys through nftables', dA.status === 'SUCCEEDED' && nftHas(8181), `${dA.status} ${dA.message}`);
    await setBackend('iptables');
    const dB = await deploy(vB);
    check('after switching the host to iptables, deploying B is REFUSED (old nftables policy still active)', dB.status === 'FAILED' && /another firewall backend/.test(dB.message + dB.stderr), `${dB.status} ${(dB.message || '').slice(0, 160)}`);
    check('... nothing was changed on the host (no iptables chains, nftables A still there)', !iptChain() && nftHas(8181));
    const rmCur = await removeBackend('iptables');
    check('removing the CONFIGURED backend\'s rules is refused (409 current_backend)', rmCur.status === 409 && rmCur.json?.error === 'current_backend', `${rmCur.status}`);
    const rmOld = await removeBackend('nftables');
    check('removing the previous backend\'s (nftables) rules works', rmOld.status === 200 && rmOld.json?.ok === true, `${rmOld.status} ${rmOld.text.slice(0, 120)}`);
    check('... table inet segmentra is gone', nftTable().status !== 0);
    const dB2 = await deploy(vB);
    check('now B deploys through iptables', dB2.status === 'SUCCEEDED' && iptHas(9191), `${dB2.status} ${dB2.message}`);
    check('... and only iptables enforces Segmentra rules (no leftover nftables default-deny)', nftTable().status !== 0);
    await setBackend('nftables');
    const dA2 = await deploy(vA);
    check('switching back to nftables: the deployment is refused while the iptables chains are active', dA2.status === 'FAILED' && /another firewall backend/.test(dA2.message + dA2.stderr) && iptHas(9191) && nftTable().status !== 0, `${dA2.status} ${(dA2.message || '').slice(0, 120)}`);
    const rmIpt = await removeBackend('iptables');
    check('removing the iptables rules works', rmIpt.status === 200 && !iptChain(), `${rmIpt.status} ${rmIpt.text.slice(0, 100)}`);
    const dA3 = await deploy(vA);
    check('... and A deploys through nftables again', dA3.status === 'SUCCEEDED' && nftHas(8181) && !iptChain(), `${dA3.status} ${dA3.message}`);
    const audit = psql(`SELECT count(*) FROM audit_events WHERE entity_id = '${host.id}' AND action = 'HOST_BACKEND_RULES_REMOVED'`);
    check('each removal is in the audit log', Number(audit) >= 2, audit);

    // ------------------------------------------------------------------------------------------------------------
    console.log('\n2. IPv6 recommendations are a single address');
    const flows = [
      { direction: 'IN', sourceIp: '2001:db8:abcd::10', destinationIp: '2001:db8:ffff::1', protocol: 'tcp', destinationPort: 8443, count: 12, firstSeen: new Date().toISOString(), lastSeen: new Date().toISOString() },
      { direction: 'IN', sourceIp: '203.0.113.77', destinationIp: '127.0.0.1', protocol: 'tcp', destinationPort: 8443, count: 12, firstSeen: new Date().toISOString(), lastSeen: new Date().toISOString() }
    ];
    const auditId = psql(`INSERT INTO firewall_audit_sessions (host_id, status, duration_minutes, started_at, scheduled_restore_at, log_data) VALUES ('${host.id}', 'COMPLETED', 5, now(), now(), ${sqlStr(JSON.stringify({ flows }))}::jsonb) RETURNING id`).split('\n')[0];
    const gen = await raw('POST', '/recommendations/generate', { token: op, body: { auditSessionId: auditId, hostId: host.id } });
    const recId = gen.json?.recommendationId;
    const rec = recId ? await api('GET', `/recommendations/${recId}`, { token: op }) : null;
    const recText = JSON.stringify(rec);
    check('a recommendation is generated', gen.status === 201 && !!recId, `${gen.status} ${gen.text.slice(0, 120)}`);
    check('the IPv6 client is recommended as 2001:db8:abcd::10/128', recText.includes('2001:db8:abcd::10/128'));
    check('... not as 2001:db8:abcd::10/32', !recText.includes('2001:db8:abcd::10/32'));
    check('the IPv4 client is still a /32', recText.includes('203.0.113.77/32'));
    check('the compiler keeps the /128 as one address (the old /32 became the whole 2001:db8::/32)',
      JSON.stringify(compiler.parseRuleAddresses('2001:db8:abcd::10/128')) === '["2001:db8:abcd::10/128"]' && JSON.stringify(compiler.parseRuleAddresses('2001:db8:abcd::10/32')) === '["2001:db8::/32"]');

    // ------------------------------------------------------------------------------------------------------------
    console.log('\n3. Policy Impact Analysis matches the compiled rules');
    const vX = await version([
      { direction: 'OUT', action: 'DENY', protocol: 'tcp', ports: '443', sourceType: 'CIDR', sourceValue: 'any', comment: 'no https out' },
      { direction: 'IN', action: 'ALLOW', protocol: 'tcp', ports: '8080', sourceType: 'CIDR', sourceValue: '10.1.0.0/16, 2001:db8:1::/48', comment: 'app' }
    ]);
    const now = new Date().toISOString();
    const f = (direction, sourceIp, destinationIp, port) => ({ direction, sourceIp, destinationIp, protocol: 'tcp', destinationPort: port, count: 3, firstSeen: now, lastSeen: now });
    const testFlows = [
      f('OUT', '127.0.0.1', '93.184.216.34', 443),
      f('OUT', '127.0.0.1', '2606:2800:220:1::1', 443),
      f('IN', '10.1.2.3', '127.0.0.1', 8080),
      f('IN', '2001:db8:1::5', '2001:db8:ffff::1', 8080),
      f('IN', '10.2.0.1', '127.0.0.1', 8080),
      f('OUT', '127.0.0.1', '93.184.216.34', 80)
    ];
    const ptId = psql(`INSERT INTO policy_test_sessions (policy_version_id, host_id, status, duration_minutes, started_at, scheduled_end_at, completed_at, raw_log_data) VALUES ('${vX.id}', '${host.id}', 'COLLECTING', 5, now(), now(), now(), ${sqlStr(JSON.stringify({ entries: [], flows: testFlows }))}::jsonb) RETURNING id`).split('\n')[0];
    const an = (await api('POST', `/policy-test/sessions/${ptId}/analyze`, { token: op, body: {} })).analysis;
    const blocked = an.unexpectedBlocks.map((x) => `${x.flow.destinationIp}:${x.flow.destinationPort}`);
    const allowed = an.matchedFlows.map((x) => `${x.flow.direction === 'IN' ? x.flow.sourceIp : x.flow.destinationIp}:${x.flow.destinationPort}`);
    const defaultDeny = an.unexpectedAllows.map((x) => `${x.flow.sourceIp}:${x.flow.destinationPort}`);
    check('OUT tcp/443 to an IPv4 address hits the "DENY to any" rule (was predicted ALLOW)', blocked.includes('93.184.216.34:443'), JSON.stringify(blocked));
    check('... and to an IPv6 address too', blocked.includes('2606:2800:220:1::1:443'));
    check('IN tcp/8080 from 10.1.2.3 matches the comma-separated CIDR list', allowed.includes('10.1.2.3:8080'), JSON.stringify(allowed));
    check('IN tcp/8080 from 2001:db8:1::5 matches the IPv6 entry of the list', allowed.includes('2001:db8:1::5:8080'));
    check('IN tcp/8080 from 10.2.0.1 (not in the list) falls to default-deny', defaultDeny.includes('10.2.0.1:8080'), JSON.stringify(defaultDeny));
    check('OUT tcp/80 is still allowed by the outbound default', allowed.includes('93.184.216.34:80'));
    await setBackend('iptables');
    const rendered = await api('GET', `/policy-versions/${vX.id}/render/host/${host.id}`, { token: op });
    const outDrop = String(rendered.text ?? rendered.rendered ?? JSON.stringify(rendered)).split('\n').some((l) => /SEGMENTRA-OUT/.test(l) && /--dport 443\b/.test(l) && /-j DROP/.test(l));
    check('the compiled ruleset drops OUT tcp/443 as well (analysis and enforcement agree)', outDrop);
    await setBackend('nftables');

    // ------------------------------------------------------------------------------------------------------------
    console.log('\n4. Kubernetes: removing the applied policy while a newer manifest is only generated');
    k8s = await startFakeK8s(mkdtempSync(join(tmpdir(), 'segr3-k8s-')));
    const cl = await api('POST', '/k8s/clusters', { token: admin, body: { name: `r3-fake-${suffix}`, apiServerUrl: `https://127.0.0.1:${k8s.port}`, authType: 'token', credentials: 'round3-token', caCert: k8s.ca, cni: 'calico', defaultNamespace: 'default' } });
    clusterId = (cl.cluster ?? cl).id;
    const kv = await version([{ ports: '5432' }]);
    const gen1 = (await api('POST', `/k8s/clusters/${clusterId}/deploy-policy`, { token: op, body: { policyVersionId: kv.id, namespace: 'apps', policyName: 'r3-db' } })).networkPolicy;
    const ap1 = await raw('POST', `/k8s/clusters/${clusterId}/network-policies/${gen1.id}/apply`, { token: op, body: {} });
    check('v1 is applied to the (fake) cluster', ap1.status === 200 && k8s.store.has('apps/r3-db'), `${ap1.status} ${ap1.text.slice(0, 120)}`);
    check('... the live object names its record', k8s.store.get('apps/r3-db')?.metadata?.annotations?.['segmentra.io/record-id'] === gen1.id);
    const gen2 = (await api('POST', `/k8s/clusters/${clusterId}/deploy-policy`, { token: op, body: { policyVersionId: kv.id, namespace: 'apps', policyName: 'r3-db' } })).networkPolicy;
    const rm2 = await raw('POST', `/k8s/clusters/${clusterId}/network-policies/${gen2.id}/remove`, { token: op, body: {} });
    check('v2 (only generated) cannot remove anything (409 not_applied)', rm2.status === 409 && rm2.json?.error === 'not_applied', `${rm2.status}`);
    const rm1 = await raw('POST', `/k8s/clusters/${clusterId}/network-policies/${gen1.id}/remove`, { token: op, body: {} });
    check('v1 (applied) CAN be removed although v2 is newer (was refused as superseded)', rm1.status === 200 && rm1.json?.ok === true, `${rm1.status} ${rm1.text.slice(0, 120)}`);
    check('... and the policy is gone from the cluster', !k8s.store.has('apps/r3-db'));
    // Superseded and foreign-owned records still cannot delete the live policy.
    const g3 = (await api('POST', `/k8s/clusters/${clusterId}/deploy-policy`, { token: op, body: { policyVersionId: kv.id, namespace: 'apps', policyName: 'r3-db' } })).networkPolicy;
    await api('POST', `/k8s/clusters/${clusterId}/network-policies/${g3.id}/apply`, { token: op, body: {} });
    const g4 = (await api('POST', `/k8s/clusters/${clusterId}/deploy-policy`, { token: op, body: { policyVersionId: kv.id, namespace: 'apps', policyName: 'r3-db' } })).networkPolicy;
    await api('POST', `/k8s/clusters/${clusterId}/network-policies/${g4.id}/apply`, { token: op, body: {} });
    const uid = k8s.store.get('apps/r3-db')?.metadata?.uid;
    const rm3 = await raw('POST', `/k8s/clusters/${clusterId}/network-policies/${g3.id}/remove`, { token: op, body: {} });
    check('a superseded record (applied, then replaced by a later apply) is still refused (409 superseded)', rm3.status === 409 && rm3.json?.error === 'superseded' && k8s.store.get('apps/r3-db')?.metadata?.uid === uid, `${rm3.status}`);
    k8s.store.get('apps/r3-db').metadata.annotations['segmentra.io/record-id'] = crypto.randomUUID();
    const rm4 = await raw('POST', `/k8s/clusters/${clusterId}/network-policies/${g4.id}/remove`, { token: op, body: {} });
    check('a live object stamped with another record id is not deleted (409 owned_by_other_record)', rm4.status === 409 && rm4.json?.error === 'owned_by_other_record' && k8s.store.has('apps/r3-db'), `${rm4.status}`);
  } finally {
    if (op) for (const id of versions) await raw('POST', `/policy-versions/${id}/archive`, { token: op, body: {} }).catch(() => {});
    if (admin) {
      if (clusterId) await raw('PUT', `/k8s/clusters/${clusterId}`, { token: admin, body: { enabled: false } }).catch(() => {});
      if (credId) await raw('DELETE', `/ssh-credentials/${credId}`, { token: admin }).catch(() => {});
      if (hostId) await raw('POST', '/hosts/bulk/set-enabled', { token: op, body: { hostIds: [hostId], enabled: false } }).catch(() => {});
      if (executorBefore) await raw('PUT', '/admin/executor-setting', { token: admin, body: { executor: executorBefore } }).catch(() => {});
    }
    await stopApi();
    k8s?.server.close();
    docker('rm', '-f', '-v', GW);
    docker('network', 'rm', NET);
    forgetHostKey(SSH_PORT);
    if (keyDir) rmSync(keyDir, { recursive: true, force: true });
  }
  const failed = results.filter((r) => !r.pass);
  console.log(`\n[round3] ${results.length - failed.length}/${results.length} checks passed (API log: ${apiLog})`);
  for (const x of failed) console.log(`  FAILED: ${x.label}`);
  process.exit(failed.length ? 1 : 0);
}
main().catch(async (e) => { console.error(e); console.error(`API log: ${apiLog}`); await stopApi(); process.exit(1); });
