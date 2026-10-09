#!/usr/bin/env node
// Docker Swarm integration test: Segmentra manages the host firewalls of a 3-node swarm lab
// (tests/swarm-lab/lab.sh) through the real API and SSH executor.
//
//   node tests/swarm-lab/run.mjs [--keep] [--reuse]
//     --reuse  use an already running lab instead of creating one
//     --keep   leave the lab running afterwards
//
// Needs a running Segmentra API (default http://localhost:8080/api, admin/admin123; see SEGMENTRA_API,
// SEGMENTRA_ADMIN_USER, SEGMENTRA_ADMIN_PASSWORD) and Docker. Run it against a development stack: it creates
// users, hosts and policy sets (approved versions cannot be deleted; they are archived).
import { spawnSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const { SEGMENTRA_IPTABLES_SH } = await import(new URL('../../packages/executor/dist/iptables-scripts.js', import.meta.url).href);
const keep = process.argv.includes('--keep');
const reuse = process.argv.includes('--reuse');
const apiBase = process.env.SEGMENTRA_API ?? 'http://localhost:8080/api';
const adminUser = process.env.SEGMENTRA_ADMIN_USER ?? 'admin';
const adminPass = process.env.SEGMENTRA_ADMIN_PASSWORD ?? 'admin123';
const suffix = Date.now().toString(36);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const docker = (...a) => spawnSync('docker', a, { encoding: 'utf8' });

const results = [];
function check(label, pass, detail = '') {
  results.push({ label, pass: !!pass });
  console.log(`  ${pass ? 'PASS' : 'FAIL'}  ${label}${detail ? `  (${detail})` : ''}`);
}

// The test blocks on `docker exec` for long stretches, so a pooled keep-alive socket may have been closed by
// the server in the meantime; a reset before any response means the request was not processed: retry.
async function fetchRetry(url, init) {
  for (let attempt = 0; ; attempt += 1) {
    try { return await fetch(url, init); } catch (e) {
      const code = e?.cause?.code ?? e?.code;
      if (attempt < 3 && ['ECONNRESET', 'UND_ERR_SOCKET', 'EPIPE'].includes(code)) { await sleep(300); continue; }
      throw e;
    }
  }
}

async function api(method, path, { token, body } = {}) {
  const res = await fetchRetry(`${apiBase}${path}`, { method, headers: { 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}) }, body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await res.text(); let json; try { json = JSON.parse(text); } catch { json = text; }
  if (!res.ok) throw new Error(`${method} ${path} -> ${res.status}: ${text}`);
  return json;
}
const login = async (u, p) => (await api('POST', '/auth/login', { body: { username: u, password: p } })).token;
async function ensureUser(admin, username, role) {
  const r = await fetchRetry(`${apiBase}/admin/users`, { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${admin}` }, body: JSON.stringify({ username, displayName: username, password: 'LabTest-pass-123!', roles: [role], isActive: true }) });
  if (![201, 409].includes(r.status)) throw new Error(`create user ${username}: ${r.status} ${await r.text()}`);
  return login(username, 'LabTest-pass-123!');
}

// --- traffic probes (from the client containers on the lab network) ---
const nodes = [1, 2, 3].map((i) => ({ i, ip: `172.28.77.1${i}`, port: 2230 + i }));
const requests = (client, ip, port, n = 12) => {
  let ok = 0;
  for (let i = 0; i < n; i += 1) {
    const r = docker('exec', client, 'curl', '-s', '-m', '3', '-o', '/dev/null', '-w', '%{http_code}', `http://${ip}:${port}`);
    if (r.stdout.trim() === '200') ok += 1;
  }
  return ok;
};
const overlayOk = () => {
  const r = docker('exec', 'segswarm-node1', 'docker', 'run', '--rm', '--network', 'lab-overlay', 'alpine:3.20', 'sh', '-c',
    'ok=0; for t in 1 2 3 4 5 6 7 8 9; do wget -q -T 3 -O /dev/null http://web && ok=$((ok+1)); done; echo $ok');
  return Number(r.stdout.trim().split('\n').pop()) || 0;
};
// Run the host-side Segmentra iptables script (the one the SSH executor ships) as root inside a node.
const script = (container, ...args) => spawnSync('docker', ['exec', container, 'sh', '-c', SEGMENTRA_IPTABLES_SH, 'segmentra-iptables', ...args], { encoding: 'utf8' });
const ipt = (container, ...args) => docker('exec', container, 'iptables', ...args).stdout;
const nodesReady = () => (docker('exec', 'segswarm-node1', 'docker', 'node', 'ls', '--format', '{{.Status}}').stdout.match(/Ready/g) ?? []).length;
const expectAll = (label, who, port, want, { onlyNode = null } = {}) => {
  const counts = nodes.filter((n) => !onlyNode || n.i === onlyNode).map((n) => requests(who, n.ip, port));
  const pass = counts.every((c) => (want ? c === 12 : c === 0));
  check(`${label}: ${want ? 'all 12 requests succeed' : 'all requests blocked'} on every node`, pass, `ok per node: ${counts.join('/')}`);
};

async function main() {
  if (!reuse) {
    console.log('Bringing up the Swarm lab (about 40 s)...');
    const up = spawnSync(join(here, 'lab.sh'), ['up'], { encoding: 'utf8' });
    if (up.status !== 0) throw new Error(`lab.sh up failed:\n${up.stdout}\n${up.stderr}`);
  }

  const admin = await login(adminUser, adminPass);
  const op = await ensureUser(admin, 'lab-operator', 'operator');
  const appr = await ensureUser(admin, 'lab-approver', 'approver');
  const executorBefore = (await api('GET', '/admin/executor-setting', { token: admin })).executor;
  await api('PUT', '/admin/executor-setting', { token: admin, body: { executor: 'ssh' } });
  const credIds = [];
  const hosts = [];
  const versions = [];

  try {
    for (const n of nodes) {
      const h = (await api('POST', '/hosts', { token: op, body: {
        hostname: `swarm-node${n.i}-${suffix}`, mgmtIp: '127.0.0.1', sshPort: n.port, firewallBackend: 'iptables', enabled: true,
        swarmCluster: `lab-${suffix}`, swarmRole: n.i === 1 ? 'manager' : 'worker', swarmAddr: n.ip, dockerPublishedPorts: true
      } })).host;
      const c = await api('POST', '/ssh-credentials', { token: admin, body: { name: `lab-${h.hostname}`, username: 'segmentra', authMethod: 'PASSWORD', password: 'segmentra123!', scopeType: 'HOST', scopeId: h.id } });
      credIds.push((c.sshCredential ?? c.credential ?? c).id);
      hosts.push({ ...n, id: h.id, hostname: h.hostname });
    }
    check('hosts store the Swarm profile', hosts.length === 3);
    const h1 = (await api('GET', `/hosts/${hosts[0].id}`, { token: op })).host;
    check('host API returns swarm_cluster, swarm_role, swarm_addr and docker_published_ports',
      h1.swarm_cluster === `lab-${suffix}` && h1.swarm_role === 'manager' && h1.swarm_addr === '172.28.77.11' && h1.docker_published_ports === true);

    const mkVersion = async (name, rules) => {
      const ps = (await api('POST', '/policy-sets', { token: op, body: { name: `${name}-${suffix}`, description: 'swarm lab', scopeType: 'HOST_LIST', hostIds: hosts.map((h) => h.id) } })).policySet;
      const v = (await api('POST', `/policy-sets/${ps.id}/versions`, { token: op, body: { changeSummary: name, interfaceScopeType: 'ALL_INTERFACES' } })).version;
      for (const [i, r] of rules.entries()) await api('POST', `/policy-versions/${v.id}/rules`, { token: op, body: { orderIndex: (i + 1) * 10, direction: 'IN', action: 'ALLOW', logMode: 'NONE', usePolicyInterfaceScope: true, ...r } });
      await api('POST', `/policy-versions/${v.id}/submit-approval`, { token: op, body: {} });
      await api('POST', `/policy-versions/${v.id}/approve`, { token: appr, body: {} });
      versions.push(v.id);
      return v;
    };
    // The lab runs on a busy Docker Desktop VM: a deployment that fails only with a transient SSH error
    // (connection, backend detection, revert scheduling) is retried; real firewall errors are not.
    const TRANSIENT = /SSH connection failed|backend detection failed|could not schedule automatic revert|Connection (reset|closed|timed out)/;
    const deploy = async (versionId) => {
      for (let attempt = 1; ; attempt += 1) {
        const r = await deployOnce(versionId);
        if (r.status === 'SUCCEEDED' || attempt >= 3) return r.status;
        const failures = r.hosts.filter((h) => h.status !== 'SUCCEEDED');
        if (!failures.length || !failures.every((h) => TRANSIENT.test(h.message ?? ''))) return r.status;
        console.log(`  (transient SSH failure on ${failures.map((h) => h.hostname ?? h.host_id).join(', ')}: ${failures[0].message}; retrying)`);
        await sleep(5000);
      }
    };
    const deployOnce = async (versionId) => {
      const created = await api('POST', '/deployments', { token: op, body: { policyVersionId: versionId, mode: 'FULL', targetQuery: { hosts: hosts.map((h) => h.id), tags: [], vlans: [] } } });
      await api('POST', `/deployments/${created.deployment.id}/start`, { token: op, body: {} });
      for (let a = 0; a < 90; a += 1) {
        const d = await api('GET', `/deployments/${created.deployment.id}`, { token: op });
        if (['SUCCEEDED', 'FAILED', 'PARTIAL'].includes(d.deployment.status)) {
          const hs = (await api('GET', `/deployments/${created.deployment.id}/hosts`, { token: op })).hosts;
          return { status: d.deployment.status, hosts: hs };
        }
        await sleep(2000);
      }
      throw new Error('deployment timed out');
    };
    const web = (src, comment) => ({ protocol: 'tcp', ports: '8080', sourceType: 'CIDR', sourceValue: src, comment });

    console.log('\nBaseline (no Segmentra policy yet):');
    expectAll('client50 -> published 8080', 'segswarm-client50', 8080, true);
    expectAll('client51 -> published 8080', 'segswarm-client51', 8080, true);

    console.log('\nv1: allow 8080 from client50 only. The policy does NOT mention any Swarm port:');
    const v1 = await mkVersion('swarm-v1', [web('172.28.77.50/32', 'web client50')]);
    check('deployment of v1 succeeded on all 3 nodes', (await deploy(v1.id)) === 'SUCCEEDED');
    await sleep(3);
    expectAll('allowed client50 -> published 8080', 'segswarm-client50', 8080, true);
    expectAll('client51 (not allowed) -> published 8080', 'segswarm-client51', 8080, false);
    await sleep(25);
    check('all 3 swarm nodes stay Ready', nodesReady() === 3);
    check('overlay network works between the nodes (9/9 requests through the service name)', overlayOk() === 9);
    const fwd = docker('exec', 'segswarm-node1', 'iptables', '-S', 'SEGMENTRA-FWD').stdout;
    check('SEGMENTRA-FWD holds the DNAT-aware rules', /--ctstate DNAT --ctorigdstport 8080/.test(fwd) && /published_default/.test(fwd));
    check('DOCKER-USER jumps to SEGMENTRA-FWD first (Docker keeps DOCKER-USER first in FORWARD)', /^-A DOCKER-USER -j SEGMENTRA-FWD$/m.test(ipt('segswarm-node1', '-S', 'DOCKER-USER')) && ipt('segswarm-node1', '-S', 'DOCKER-USER').split('\n')[1] === '-A DOCKER-USER -j SEGMENTRA-FWD');
    const inChain = docker('exec', 'segswarm-node1', 'iptables', '-S', 'SEGMENTRA-IN').stdout;
    check('manager allows 2377 from both peers; workers do not open it', /swarm_manager/.test(inChain) && !/swarm_manager/.test(docker('exec', 'segswarm-node2', 'iptables', '-S', 'SEGMENTRA-IN').stdout));

    console.log('\nNew published ports are covered automatically:');
    docker('exec', 'segswarm-node1', 'docker', 'service', 'update', '--publish-add', 'published=8090,target=80', 'web');
    await sleep(15);
    const forward = ipt('segswarm-node1', '-S', 'FORWARD').split('\n');
    check('Docker re-inserted its FORWARD jumps above ours, yet DOCKER-USER still runs SEGMENTRA-FWD first',
      forward.indexOf('-A FORWARD -j SEGMENTRA-FWD') > forward.indexOf('-A FORWARD -j DOCKER-USER') && /-A DOCKER-USER -j SEGMENTRA-FWD/.test(ipt('segswarm-node1', '-S', 'DOCKER-USER')));
    expectAll('client50 -> NEW published port 8090 (not in the policy)', 'segswarm-client50', 8090, false);
    expectAll('client50 -> 8080 still allowed', 'segswarm-client50', 8080, true);

    console.log('\nv2: add client51 and the new port, redeploy:');
    const v2 = await mkVersion('swarm-v2', [web('172.28.77.50/32', 'web client50'), web('172.28.77.51/32', 'web client51'), { protocol: 'tcp', ports: '8090', sourceType: 'CIDR', sourceValue: '172.28.77.50/32', comment: 'new port' }]);
    check('deployment of v2 succeeded', (await deploy(v2.id)) === 'SUCCEEDED');
    await sleep(3);
    expectAll('client51 now allowed -> 8080', 'segswarm-client51', 8080, true);
    expectAll('client50 -> 8090 now allowed', 'segswarm-client50', 8090, true);
    expectAll('client51 -> 8090 still blocked', 'segswarm-client51', 8090, false);
    const before = docker('exec', 'segswarm-node1', 'iptables', '-S', 'SEGMENTRA-FWD').stdout;
    await deploy(v2.id);
    check('redeploying the same version leaves identical rules', docker('exec', 'segswarm-node1', 'iptables', '-S', 'SEGMENTRA-FWD').stdout === before);

    console.log('\nExecutor lifecycle on the nodes (the script Segmentra ships over SSH):');
    const du = (c) => /^-A DOCKER-USER -j SEGMENTRA-FWD$/m.test(ipt(c, '-S', 'DOCKER-USER'));
    const bk = script('segswarm-node3', 'backup', 'iptables', '/tmp/lab-backup');
    check('backup records the DOCKER-USER jump', bk.status === 0 && /jump-du=1/.test(docker('exec', 'segswarm-node3', 'cat', '/tmp/lab-backup').stdout), bk.stderr.trim());
    const rm = script('segswarm-node3', 'remove', 'iptables');
    check('remove deletes the chains and both jumps', rm.status === 0 && !du('segswarm-node3') && !/SEGMENTRA/.test(ipt('segswarm-node3', '-S')), rm.stderr.trim());
    check('remove leaves Docker\'s DOCKER-USER chain with its own RETURN', /-A DOCKER-USER -j RETURN/.test(ipt('segswarm-node3', '-S', 'DOCKER-USER')));
    expectAll('after remove: client51 -> published 8090 is open again (node3 only checked below)', 'segswarm-client51', 8090, true, { onlyNode: 3 });
    const rs = script('segswarm-node3', 'restore', 'iptables', '/tmp/lab-backup');
    check('restore brings back the chains and the DOCKER-USER jump', rs.status === 0 && du('segswarm-node3') && /published_default/.test(ipt('segswarm-node3', '-S', 'SEGMENTRA-FWD')), rs.stderr.trim());
    expectAll('after restore: client51 -> 8090 blocked again (node3 only)', 'segswarm-client51', 8090, false, { onlyNode: 3 });

    // Persistence: render Segmentra's live lines into a saved-rules file that already has Docker's chains.
    const harness = SEGMENTRA_IPTABLES_SH.replace(/case "\$mode" in\n  apply\) apply_chains[\s\S]*$/, 'ipt_render; rr=$?; echo "render=$rr"; ipt_merge "$3" > "$4"; exit 0\n');
    const saved = ['*filter', ':INPUT ACCEPT [0:0]', ':FORWARD ACCEPT [0:0]', ':OUTPUT ACCEPT [0:0]', ':DOCKER-USER - [0:0]', ':f2b-sshd - [0:0]',
      '-A INPUT -p tcp -m multiport --dports 22 -j f2b-sshd', '-A DOCKER-USER -j RETURN', '-A f2b-sshd -j RETURN', 'COMMIT', ''].join('\n');
    spawnSync('docker', ['exec', '-i', 'segswarm-node2', 'sh', '-c', 'cat > /tmp/saved.rules'], { input: saved });
    const pr = spawnSync('docker', ['exec', 'segswarm-node2', 'sh', '-c', harness, 'segmentra-iptables', 'check', 'iptables', '/tmp/saved.rules', '/tmp/merged.rules'], { encoding: 'utf8' });
    const merged = docker('exec', 'segswarm-node2', 'cat', '/tmp/merged.rules').stdout;
    const mlines = merged.split('\n');
    check('persistence: the saved file declares DOCKER-USER once and puts the SEGMENTRA-FWD jump before Docker\'s own rule',
      pr.stdout.includes('render=0') && mlines.filter((l) => l.startsWith(':DOCKER-USER ')).length === 1
        && mlines.indexOf('-A DOCKER-USER -j SEGMENTRA-FWD') > -1 && mlines.indexOf('-A DOCKER-USER -j SEGMENTRA-FWD') < mlines.indexOf('-A DOCKER-USER -j RETURN'), pr.stderr.trim());
    check('persistence: other tools\' lines (fail2ban) stay byte-identical', ['-A INPUT -p tcp -m multiport --dports 22 -j f2b-sshd', '-A f2b-sshd -j RETURN', ':f2b-sshd - [0:0]'].every((l) => mlines.includes(l)));
    const valid = spawnSync('docker', ['exec', 'segswarm-node2', 'iptables-restore', '--test', '/tmp/merged.rules'], { encoding: 'utf8' });
    check('persistence: the merged file passes iptables-restore --test', valid.status === 0, valid.stderr.trim());

    console.log('\nControls: each feature makes a difference:');
    for (const h of hosts) await api('PUT', `/hosts/${h.id}`, { token: op, body: { dockerPublishedPorts: false } });
    check('deployment with published-port enforcement OFF succeeded', (await deploy(v2.id)) === 'SUCCEEDED');
    await sleep(3);
    expectAll('enforcement off: client51 reaches 8090 (INPUT rules cannot restrict published ports)', 'segswarm-client51', 8090, true);
    for (const h of hosts) await api('PUT', `/hosts/${h.id}`, { token: op, body: { dockerPublishedPorts: true } });

    for (const h of hosts) await api('PUT', `/hosts/${h.id}`, { token: op, body: { swarmCluster: null } });
    check('deployment WITHOUT the Swarm profile succeeded', (await deploy(v2.id)) === 'SUCCEEDED');
    await sleep(20);
    check('without the Swarm profile the overlay breaks (fewer than 9/9)', overlayOk() < 9, `ok ${overlayOk()}/9`);
    for (const h of hosts) await api('PUT', `/hosts/${h.id}`, { token: op, body: { swarmCluster: `lab-${suffix}`, swarmRole: h.i === 1 ? 'manager' : 'worker', swarmAddr: h.ip } });
    check('re-enabling the Swarm profile and redeploying heals the overlay', (await deploy(v2.id)) === 'SUCCEEDED');
    await sleep(15);
    check('overlay works again (9/9)', overlayOk() === 9);
  } finally {
    for (const id of versions) await api('POST', `/policy-versions/${id}/archive`, { token: op, body: {} }).catch(() => {});
    for (const id of credIds) await api('DELETE', `/ssh-credentials/${id}`, { token: admin }).catch(() => {});
    if (hosts.length) await api('POST', '/hosts/bulk/set-enabled', { token: op, body: { hostIds: hosts.map((h) => h.id), enabled: false } }).catch(() => {});
    await api('PUT', '/admin/executor-setting', { token: admin, body: { executor: executorBefore } }).catch(() => {});
    if (!keep) spawnSync(join(here, 'lab.sh'), ['down'], { encoding: 'utf8' });
  }

  const failed = results.filter((r) => !r.pass);
  console.log(`\n[swarm] ${results.length - failed.length}/${results.length} checks passed`);
  for (const f of failed) console.log(`  FAILED: ${f.label}`);
  process.exit(failed.length ? 1 : 0);
}

main().catch((e) => { console.error(e); spawnSync(join(here, 'lab.sh'), ['down']); process.exit(1); });
