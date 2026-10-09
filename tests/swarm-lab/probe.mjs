#!/usr/bin/env node
// Probe: deploy a Segmentra policy to the three Swarm lab nodes (tests/swarm-lab/lab.sh up) through the
// real API + SSH executor, then measure what the host firewall does to published ports and to the swarm.
// Exploratory: it prints observations; it does not assert.
import { spawnSync } from 'node:child_process';

const apiBase = process.env.SEGMENTRA_API ?? 'http://localhost:8080/api';
const suffix = Date.now().toString(36);
const sh = (...args) => spawnSync('docker', args, { encoding: 'utf8' });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const section = (t) => console.log(`\n== ${t}`);

async function api(method, path, { token, body } = {}) {
  const res = await fetch(`${apiBase}${path}`, { method, headers: { 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}) }, body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await res.text(); let json; try { json = JSON.parse(text); } catch { json = text; }
  if (!res.ok) throw new Error(`${method} ${path} -> ${res.status}: ${text}`);
  return json;
}
const login = async (u, p) => (await api('POST', '/auth/login', { body: { username: u, password: p } })).token;
const ensureUser = async (admin, username, role) => {
  const r = await fetch(`${apiBase}/admin/users`, { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${admin}` }, body: JSON.stringify({ username, displayName: username, password: 'LabTest-pass-123!', roles: [role], isActive: true }) });
  if (![201, 409].includes(r.status)) throw new Error(`user ${username}: ${r.status}`);
  return login(username, 'LabTest-pass-123!');
};

const curl = (client, ip, port) => {
  const r = sh('exec', client, 'curl', '-s', '-m', '3', '-o', '/dev/null', '-w', '%{http_code}', `http://${ip}:${port}`);
  return r.stdout.trim() === '200' ? 'ok' : 'blocked';
};
const mesh = (client, ip, n = 12) => { let ok = 0; for (let i = 0; i < n; i += 1) if (curl(client, ip, 8080) === 'ok') ok += 1; return `${ok}/${n}`; };
const nodes = [1, 2, 3].map((i) => ({ i, name: `swarm-node${i}-${suffix}`, ip: `172.28.77.1${i}`, port: 2230 + i, container: `segswarm-node${i}` }));

const pubTable = () => nodes.map((n) => `node${n.i}:8080  client50 (allowed) ${mesh('segswarm-client50', n.ip)}   client51 (NOT allowed) ${mesh('segswarm-client51', n.ip)}`).join('\n');
const health = async () => {
  await sleep(5);
  console.log(sh('exec', 'segswarm-node1', 'docker', 'node', 'ls', '--format', '{{.Hostname}}={{.Status}}').stdout.trim().replace(/\n/g, '  '));
  const overlay = sh('exec', 'segswarm-node1', 'docker', 'run', '--rm', '--network', 'lab-overlay', 'alpine:3.20', 'sh', '-c', 'for t in 1 2 3 4 5 6 7 8 9; do wget -q -T 3 -O /dev/null http://web && echo -n "ok " || echo -n "FAIL "; done');
  console.log(`overlay requests from node1 to the service: ${overlay.stdout.trim()}`);
};

async function deploy(op, versionId, hostIds) {
  const created = await api('POST', '/deployments', { token: op, body: { policyVersionId: versionId, mode: 'FULL', targetQuery: { hosts: hostIds, tags: [], vlans: [] } } });
  await api('POST', `/deployments/${created.deployment.id}/start`, { token: op, body: {} });
  for (let a = 0; a < 90; a += 1) {
    const d = await api('GET', `/deployments/${created.deployment.id}`, { token: op });
    if (['SUCCEEDED', 'FAILED', 'PARTIAL'].includes(d.deployment.status)) {
      const hosts = (await api('GET', `/deployments/${created.deployment.id}/hosts`, { token: op })).hosts;
      return { status: d.deployment.status, hosts };
    }
    await sleep(2000);
  }
  throw new Error('deployment timed out');
}

const admin = await login('admin', 'admin123');
const op = await ensureUser(admin, 'lab-operator', 'operator');
const appr = await ensureUser(admin, 'lab-approver', 'approver');
const executorBefore = (await api('GET', '/admin/executor-setting', { token: admin })).executor;
await api('PUT', '/admin/executor-setting', { token: admin, body: { executor: 'ssh' } });

try {
  const hosts = [];
  for (const n of nodes) {
    const h = (await api('POST', '/hosts', { token: op, body: { hostname: n.name, mgmtIp: '127.0.0.1', sshPort: n.port, firewallBackend: 'iptables', enabled: true } })).host;
    await api('POST', '/ssh-credentials', { token: admin, body: { name: `lab-${n.name}`, username: 'segmentra', authMethod: 'PASSWORD', password: 'segmentra123!', scopeType: 'HOST', scopeId: h.id } });
    hosts.push({ ...n, id: h.id });
  }
  const mkVersion = async (name, rules) => {
    const ps = (await api('POST', '/policy-sets', { token: op, body: { name: `${name}-${suffix}`, description: 'swarm lab', scopeType: 'HOST_LIST', hostIds: hosts.map((h) => h.id) } })).policySet;
    const v = (await api('POST', `/policy-sets/${ps.id}/versions`, { token: op, body: { changeSummary: name, interfaceScopeType: 'ALL_INTERFACES' } })).version;
    for (const [i, r] of rules.entries()) await api('POST', `/policy-versions/${v.id}/rules`, { token: op, body: { orderIndex: (i + 1) * 10, direction: 'IN', action: 'ALLOW', logMode: 'NONE', usePolicyInterfaceScope: true, ...r } });
    await api('POST', `/policy-versions/${v.id}/submit-approval`, { token: op, body: {} });
    await api('POST', `/policy-versions/${v.id}/approve`, { token: appr, body: {} });
    return v;
  };

  // The policy a Swarm user would write: only client .50 may reach the published service on 8080.
  let v2;
  const v1 = await mkVersion('swarm-web-only-client50', [{ protocol: 'tcp', ports: '8080', sourceType: 'CIDR', sourceValue: '172.28.77.50/32', comment: 'web from client50' }]);

  section('Before deployment');
  for (const c of ['segswarm-client50', 'segswarm-client51']) console.log(`${c} -> node1:8080 ${curl(c, nodes[0].ip, 8080)}`);

  section('Deploy v1 (allow 8080 from client50 only; no Swarm ports)');
  const r1 = await deploy(op, v1.id, hosts.map((h) => h.id));
  console.log('deployment', r1.status, r1.hosts.map((h) => `${h.hostname ?? h.host_id}:${h.status}`).join(' '));
  if (r1.status !== 'SUCCEEDED') console.log(JSON.stringify(r1.hosts.map((h) => h.error_message ?? h.message ?? h), null, 1).slice(0, 1500));

  section('v1: requests ok out of 12, per client and node (client51 is NOT allowed by the policy)');
  console.log(pubTable());
  console.log('node1 INPUT / SEGMENTRA-IN:');
  console.log(sh('exec', 'segswarm-node1', 'sh', '-c', 'iptables -S INPUT; iptables -S SEGMENTRA-IN').stdout.replace(/^/gm, '   '));
  section('v1: Swarm health (ports 2377, 7946, 4789 not allowed)');
  await sleep(25); await health();

  // v2: same, plus the Swarm ports between the nodes.
  const subnet = '172.28.77.0/24';
  v2 = await mkVersion('swarm-web-client50-plus-swarm-ports', [
    { protocol: 'tcp', ports: '8080', sourceType: 'CIDR', sourceValue: '172.28.77.50/32', comment: 'web from client50' },
    { protocol: 'tcp', ports: '2377,7946', sourceType: 'CIDR', sourceValue: subnet, comment: 'swarm mgmt+gossip tcp' },
    { protocol: 'udp', ports: '7946,4789', sourceType: 'CIDR', sourceValue: subnet, comment: 'swarm gossip+vxlan udp' }
  ]);
  section('Deploy v2 (v1 + Swarm ports from the node subnet)');
  const r2 = await deploy(op, v2.id, hosts.map((h) => h.id));
  console.log('deployment', r2.status);
  await sleep(10);
  section('v2: requests ok out of 12 (client51 must be blocked if the firewall covered published ports)');
  console.log(pubTable());
  section('v2: Swarm health'); await health();

  // archive versions; leave lab firewall as deployed unless asked
  for (const v of [v1, typeof v2 !== 'undefined' ? v2 : null].filter(Boolean)) await api('POST', `/policy-versions/${v.id}/archive`, { token: op, body: {} }).catch(() => {});
} finally {
  await api('PUT', '/admin/executor-setting', { token: admin, body: { executor: executorBefore } }).catch(() => {});
  console.log(`\n(executor setting restored to "${executorBefore}")`);
}
