#!/usr/bin/env node
// Kubernetes NetworkPolicy integration test.
//
// Usage: node tests/k8s-integration/run.mjs <kindnet|calico|cilium> [--keep] [--recreate]
//   --keep      leave the kind cluster running afterwards (default: delete it)
//   --recreate  delete and rebuild an existing cluster before testing
//
// Segmentra only GENERATES NetworkPolicy manifests, so this test drives the real API to generate
// one, applies it with kubectl to a kind cluster running the chosen CNI and then verifies with real
// pod-to-pod traffic that the CNI enforces exactly what the policy says.
import { spawn } from 'node:child_process';
import { writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const cni = process.argv[2];
const keep = process.argv.includes('--keep');
const recreate = process.argv.includes('--recreate');
if (!['kindnet', 'calico', 'cilium'].includes(cni)) {
  console.error('usage: run.mjs <kindnet|calico|cilium> [--keep] [--recreate]');
  process.exit(2);
}

const apiBase = process.env.SEGMENTRA_API ?? 'http://localhost:8080/api';
const adminUser = process.env.SEGMENTRA_ADMIN_USER ?? 'admin';
const adminPass = process.env.SEGMENTRA_ADMIN_PASSWORD ?? 'admin123';
const clusterName = `segmentra-${cni}`;
const ctx = `kind-${clusterName}`;
const CALICO_VERSION = process.env.CALICO_VERSION ?? 'v3.30.3';
const CILIUM_VERSION = process.env.CILIUM_VERSION ?? '1.18.1';
const suffix = Date.now().toString(36);

const log = (m) => console.log(`[k8s:${cni}] ${m}`);

function run(cmd, args, { input, allowFailure = false, quiet = true } = {}) {
  return new Promise((resolve, reject) => {
    const p = spawn(cmd, args, { stdio: ['pipe', 'pipe', 'pipe'] });
    let out = '', err = '';
    p.stdout.on('data', (d) => { out += d; if (!quiet) process.stdout.write(d); });
    p.stderr.on('data', (d) => { err += d; if (!quiet) process.stderr.write(d); });
    p.on('error', reject);
    p.on('close', (code) => {
      if (code !== 0 && !allowFailure) reject(new Error(`${cmd} ${args.join(' ')} exited ${code}\n${err || out}`));
      else resolve({ code, out, err });
    });
    if (input !== undefined) p.stdin.end(input); else p.stdin.end();
  });
}
const kubectl = (...args) => run('kubectl', ['--context', ctx, ...args]);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------- Segmentra API ----------
async function api(method, path, { token, body, expect } = {}) {
  const res = await fetch(`${apiBase}${path}`, {
    method,
    headers: { 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body)
  });
  const text = await res.text();
  let json; try { json = JSON.parse(text); } catch { json = text; }
  if (expect ? res.status !== expect : !res.ok) throw new Error(`${method} ${path} -> ${res.status}: ${text}`);
  return json;
}

// ---------- cluster ----------
async function clusterExists() {
  const { out } = await run('kind', ['get', 'clusters']);
  return out.split('\n').includes(clusterName);
}

async function ensureCluster() {
  if (recreate && (await clusterExists())) {
    log('deleting existing cluster (--recreate)');
    await run('kind', ['delete', 'cluster', '--name', clusterName]);
  }
  if (await clusterExists()) { log('reusing existing cluster'); return; }
  log('creating kind cluster (3 nodes)');
  await run('kind', ['create', 'cluster', '--config', join(here, `kind-${cni}.yaml`)]);
  if (cni === 'calico') {
    log(`installing Calico ${CALICO_VERSION}`);
    await kubectl('apply', '-f', `https://raw.githubusercontent.com/projectcalico/calico/${CALICO_VERSION}/manifests/calico.yaml`);
  } else if (cni === 'cilium') {
    log(`installing Cilium ${CILIUM_VERSION}`);
    await run('cilium', ['install', '--context', ctx, '--version', CILIUM_VERSION, '--wait']);
  }
  await kubectl('wait', '--for=condition=Ready', 'nodes', '--all', '--timeout=300s');
}

// ---------- workloads ----------
const NS = 'seg-test';        // policy with specific sources
const NS_OPEN = 'seg-open';   // policy with source "any"
const NS_NONE = 'seg-none';   // policy where every rule resolves to nothing
const NS_CTRL = 'seg-ctrl';   // no policy at all (control)
const TCP_PORTS = [80, 5432, 8080, 8085, 8090, 9000, 9001, 7000];

function serverPod(ns, node) {
  const loops = TCP_PORTS.map((p) => `(while true; do echo ok | nc -l -p ${p}; done) &`).join(' ');
  return `apiVersion: v1
kind: Pod
metadata: { name: server, namespace: ${ns}, labels: { app: server } }
spec:
  nodeName: ${node}
  containers:
    - name: s
      image: busybox:1.36
      command: ["sh", "-c", "${loops} echo '#!/bin/sh' > /tmp/u.sh; echo 'head -c 5' >> /tmp/u.sh; chmod +x /tmp/u.sh; (while true; do nc -u -l -p 5353 -e /tmp/u.sh; done) & wait"]
`;
}
function clientPod(name, node) {
  return `apiVersion: v1
kind: Pod
metadata: { name: ${name}, namespace: seg-clients, labels: { app: client, who: ${name} } }
spec:
  nodeName: ${node}
  containers:
    - name: c
      image: busybox:1.36
      command: ["sleep", "86400"]
`;
}

async function deployWorkloads(nodes) {
  const [w1, w2] = nodes; // server on w1; clients spread across both nodes
  // Always start from fresh pods (listeners are stateful) and no leftover NetworkPolicies.
  await kubectl('delete', 'namespace', NS, NS_OPEN, NS_NONE, NS_CTRL, 'seg-clients', '--ignore-not-found', '--wait=true');
  const ns = [NS, NS_OPEN, NS_NONE, NS_CTRL, 'seg-clients'].map((n) => `apiVersion: v1\nkind: Namespace\nmetadata: { name: ${n} }\n`).join('---\n');
  const docs = [ns, ...[NS, NS_OPEN, NS_NONE, NS_CTRL].map((n) => serverPod(n, w1))];
  // a=cross-node, b=same-node as server, c/d/e/f spread
  const placement = { 'client-a': w2, 'client-b': w1, 'client-c': w2, 'client-d': w1, 'client-e': w2, 'client-f': w1 };
  for (const [n, node] of Object.entries(placement)) docs.push(clientPod(n, node));
  await run('kubectl', ['--context', ctx, 'apply', '-f', '-'], { input: docs.join('---\n') });
  await kubectl('wait', '--for=condition=Ready', 'pod', '--all', '-A', '--field-selector=metadata.namespace!=kube-system', '--timeout=240s').catch(async () => {
    // field-selector on namespaces is not supported by every kubectl; wait per namespace instead
    for (const n of [NS, NS_OPEN, NS_NONE, NS_CTRL, 'seg-clients']) {
      await kubectl('wait', '--for=condition=Ready', 'pod', '--all', '-n', n, '--timeout=240s');
    }
  });
  const podIp = async (n, p) => (await kubectl('get', 'pod', p, '-n', n, '-o', 'jsonpath={.status.podIP}')).out.trim();
  const ips = {};
  for (const c of Object.keys(placement)) ips[c] = await podIp('seg-clients', c);
  const servers = {};
  for (const n of [NS, NS_OPEN, NS_NONE, NS_CTRL]) servers[n] = await podIp(n, 'server');
  return { ips, servers };
}

// ---------- traffic probe ----------
async function probe(client, ip, port, proto = 'tcp') {
  const cmd = proto === 'tcp'
    ? `nc -w 3 ${ip} ${port} </dev/null`
    : `echo ping | nc -u -w 3 ${ip} ${port}`;
  const { out } = await kubectl('exec', client, '-n', 'seg-clients', '--', 'sh', '-c', cmd).catch(() => ({ out: '' }));
  const want = proto === 'tcp' ? 'ok' : 'ping';
  return out.includes(want);
}

// Cilium does not apply ipBlock to cluster-internal pod traffic, so allows expressed as ipBlock
// are expected to be blocked there (Segmentra warns about it); selector peers work everywhere.
const ib = (allow) => (cni === 'cilium' ? false : allow);
const results = [];
function check(label, pass, detail = '') {
  results.push({ label, pass: !!pass });
  console.log(`  ${pass ? 'PASS' : 'FAIL'}  ${label}${detail ? `  (${detail})` : ''}`);
}
async function expectTraffic(label, ns, client, port, proto, shouldAllow, { ips, servers }) {
  let got = await probe(client, servers[ns], port, proto);
  // NetworkPolicy programming is asynchronous; retry the unexpected outcome for a few seconds.
  for (let i = 0; i < 6 && got !== shouldAllow; i += 1) { await sleep(2000); got = await probe(client, servers[ns], port, proto); }
  const pass = got === shouldAllow;
  results.push({ label, pass });
  console.log(`  ${pass ? 'PASS' : 'FAIL'}  ${label}  (expected ${shouldAllow ? 'ALLOW' : 'BLOCK'}, got ${got ? 'ALLOW' : 'BLOCK'})`);
}

// ---------- main ----------
async function main() {
  await ensureCluster();
  const nodes = (await kubectl('get', 'nodes', '-l', '!node-role.kubernetes.io/control-plane', '-o', 'jsonpath={.items[*].metadata.name}')).out.trim().split(/\s+/);
  const env = await deployWorkloads(nodes);
  log(`server IPs ${JSON.stringify(env.servers)}; client IPs ${JSON.stringify(env.ips)}`);
  const { ips } = env;

  // Control: no policy => everything reachable (proves the probes work and nothing blocks by default).
  console.log('Baseline (no NetworkPolicy):');
  for (const c of ['client-a', 'client-b', 'client-f']) {
    await expectTraffic(`baseline ${c} -> :5432`, NS_CTRL, c, 5432, 'tcp', true, env);
  }
  await expectTraffic('baseline client-a -> udp :5353', NS_CTRL, 'client-a', 5353, 'udp', true, env);

  // ----- Segmentra: users, inventory, policy -----
  const admin = (await api('POST', '/auth/login', { body: { username: adminUser, password: adminPass } })).token;
  const mk = async (username, role) => {
    const r = await fetch(`${apiBase}/admin/users`, { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${admin}` },
      body: JSON.stringify({ username, displayName: username, password: 'K8sTest-pass-123!', roles: [role], isActive: true }) });
    if (![201, 409].includes(r.status)) throw new Error(`create user ${username}: ${r.status} ${await r.text()}`);
    return (await api('POST', '/auth/login', { body: { username, password: 'K8sTest-pass-123!' } })).token;
  };
  const op = await mk('k8s-operator', 'operator');
  const appr = await mk('k8s-approver', 'approver');

  // Hosts/tags/VLANs whose addresses are the pod IPs we want to allow.
  const host = async (name, ip) => (await api('POST', '/hosts', { token: op, body: { hostname: `${name}-${suffix}`, mgmtIp: ip, sshPort: 22, firewallBackend: 'iptables', enabled: true } })).host;
  const hostC = await host('k8s-client-c', ips['client-c']);
  const hostE = await host('k8s-client-e', ips['client-e']);
  const tagWeb = (await api('POST', '/tags', { token: op, body: { name: `k8s-web-${suffix}` } })).tag;
  const tagEmpty = (await api('POST', '/tags', { token: op, body: { name: `k8s-empty-${suffix}` } })).tag;
  await api('POST', '/hosts/bulk/assign-tag', { token: op, body: { hostIds: [hostE.id], tagId: tagWeb.id } });
  const vlan = (await api('POST', '/vlans', { token: op, body: { vlanTag: 3000 + Math.floor(Math.random() * 900), name: `k8s-vlan-${suffix}`, subnet: `${ips['client-d']}/32` } })).vlan;

  const createdVersions = [];
  const rule = (orderIndex, o) => ({ orderIndex, direction: 'IN', action: 'ALLOW', logMode: 'NONE', usePolicyInterfaceScope: true, ...o });
  async function approvedVersion(name, rules) {
    const ps = (await api('POST', '/policy-sets', { token: op, body: { name: `${name}-${suffix}`, description: 'k8s integration', scopeType: 'HOST_LIST', hostIds: [hostC.id] } })).policySet;
    const v = (await api('POST', `/policy-sets/${ps.id}/versions`, { token: op, body: { changeSummary: name, interfaceScopeType: 'ALL_INTERFACES' } })).version;
    for (const r of rules) await api('POST', `/policy-versions/${v.id}/rules`, { token: op, body: r });
    await api('POST', `/policy-versions/${v.id}/submit-approval`, { token: op, body: {} });
    await api('POST', `/policy-versions/${v.id}/approve`, { token: appr, body: {} });
    createdVersions.push(v.id);
    return v;
  }

  const vMain = await approvedVersion('k8s-main', [
    rule(10, { protocol: 'tcp', ports: '5432', sourceType: 'CIDR', sourceValue: `${ips['client-a']}/32`, comment: 'cidr-single' }),
    rule(20, { protocol: 'tcp', ports: '8080-8090', sourceType: 'CIDR', sourceValue: ips['client-b'], comment: 'cidr-range-bare-ip' }),
    rule(30, { protocol: 'tcp', ports: '80,9000', sourceType: 'HOST', sourceValue: hostC.id, comment: 'host' }),
    rule(40, { protocol: 'tcp', ports: '9001', sourceType: 'TAG', sourceValue: tagWeb.id, comment: 'tag-with-host' }),
    rule(50, { protocol: 'udp', ports: '5353', sourceType: 'VLAN', sourceValue: String(vlan.id), comment: 'vlan-subnet' }),
    rule(60, { protocol: 'tcp', ports: '7000', sourceType: 'TAG', sourceValue: tagEmpty.id, comment: 'tag-empty' }),
    rule(70, { action: 'DENY', protocol: 'tcp', ports: '22', sourceType: 'CIDR', sourceValue: '10.99.0.0/16', comment: 'deny' }),
    rule(80, { protocol: 'icmp', sourceType: 'CIDR', sourceValue: ips['client-a'], comment: 'icmp' }),
    rule(90, { direction: 'OUT', protocol: 'tcp', ports: '443', sourceType: 'CIDR', sourceValue: '1.1.1.1', comment: 'out' }),
    rule(100, { direction: 'BOTH', protocol: 'tcp', ports: '8085', sourceType: 'CIDR', sourceValue: `${ips['client-e']}/32`, comment: 'both' })
  ]);
  const vOpen = await approvedVersion('k8s-open', [rule(10, { protocol: 'any', sourceType: 'CIDR', sourceValue: 'any', comment: 'any' })]);
  const vNone = await approvedVersion('k8s-none', [rule(10, { protocol: 'tcp', ports: '5432', sourceType: 'TAG', sourceValue: tagEmpty.id, comment: 'empty' })]);

  // Credentials: a kubeconfig (client certificate) for the main cluster record, plus service-account
  // bearer tokens (read-write and read-only) to exercise token auth and RBAC failures.
  const kubeconfig = (await run('kind', ['get', 'kubeconfig', '--name', clusterName])).out;
  const kc = JSON.parse((await kubectl('config', 'view', '--raw', '--minify', '-o', 'json')).out);
  const serverUrl = kc.clusters[0].cluster.server;
  const caPem = Buffer.from(kc.clusters[0].cluster['certificate-authority-data'], 'base64').toString('utf8');
  const rbac = (name, verbs) => `apiVersion: v1
kind: ServiceAccount
metadata: { name: ${name}, namespace: kube-system }
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: { name: ${name} }
rules:
  - apiGroups: ["networking.k8s.io"]
    resources: ["networkpolicies"]
    verbs: [${verbs.map((v) => `"${v}"`).join(', ')}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: { name: ${name} }
roleRef: { apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: ${name} }
subjects: [{ kind: ServiceAccount, name: ${name}, namespace: kube-system }]
`;
  await run('kubectl', ['--context', ctx, 'apply', '-f', '-'], { input: rbac('segmentra-rw', ['get', 'list', 'create', 'update', 'patch', 'delete']) + '---\n' + rbac('segmentra-ro', ['get', 'list']) });
  const tokenRw = (await kubectl('create', 'token', 'segmentra-rw', '-n', 'kube-system', '--duration=1h')).out.trim();
  const tokenRo = (await kubectl('create', 'token', 'segmentra-ro', '-n', 'kube-system', '--duration=1h')).out.trim();

  console.log('\nCluster credentials:');
  const cluster = (await api('POST', '/k8s/clusters', { token: admin, body: { name: `kind-${cni}-${suffix}`, apiServerUrl: 'https://placeholder.invalid:6443', authType: 'kubeconfig', credentials: kubeconfig, description: `kind + ${cni}`, cni, defaultNamespace: NS } })).cluster;
  const tokenCluster = (await api('POST', '/k8s/clusters', { token: admin, body: { name: `kind-${cni}-token-${suffix}`, apiServerUrl: serverUrl, authType: 'service_account', credentials: tokenRw, caCert: caPem, cni, defaultNamespace: NS } })).cluster;
  const roCluster = (await api('POST', '/k8s/clusters', { token: admin, body: { name: `kind-${cni}-ro-${suffix}`, apiServerUrl: serverUrl, authType: 'token', credentials: tokenRo, caCert: caPem, cni, defaultNamespace: NS } })).cluster;
  const listJson = JSON.stringify(await api('GET', '/k8s/clusters', { token: op })) + JSON.stringify(await api('GET', `/k8s/clusters/${cluster.id}`, { token: op }));
  const secretMaterial = [tokenRw, tokenRo, 'client-key-data', 'BEGIN CERTIFICATE', 'credentials_secret_id', 'ca_cert_secret_id'];
  check('credentials/CA/secret ids are never returned by the API', secretMaterial.every((m) => !listJson.includes(m)) && JSON.stringify(cluster).indexOf('client-key-data') < 0 && cluster.has_credentials === true);
  check('kubeconfig replaces the typed API server URL', cluster.api_server_url === serverUrl);
  for (const [label, c] of [['kubeconfig', cluster], ['service-account token', tokenCluster]]) {
    const t = await api('POST', `/k8s/clusters/${c.id}/test-connection`, { token: op });
    check(`test-connection with ${label} credentials`, t.ok === true && /^v\d/.test(t.serverVersion), t.serverVersion);
  }
  // Cloud login plumbing: an EKS-style credential makes Segmentra mint a token and send it. A kind
  // API server cannot validate AWS tokens, so a clean "credentials rejected (401)" proves the whole path.
  const eksCluster = (await api('POST', '/k8s/clusters', { token: admin, body: { name: `kind-${cni}-eks-${suffix}`, apiServerUrl: serverUrl, authType: 'eks', caCert: caPem, cni, defaultNamespace: NS,
    credentials: JSON.stringify({ clusterName: 'demo', region: 'eu-west-1', accessKeyId: 'AKIAIOSFODNN7EXAMPLE', secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' }) } })).cluster;
  const eksTest = await fetch(`${apiBase}/k8s/clusters/${eksCluster.id}/test-connection`, { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${op}` }, body: '{}' });
  const eksBody = await eksTest.json();
  check('EKS login: token minted and sent, API server answers 401 (reported clearly)', eksTest.status === 502 && /401|rejected/i.test(eksBody.message ?? ''), (eksBody.message ?? '').slice(0, 70));
  const eksBad = await fetch(`${apiBase}/k8s/clusters`, { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${admin}` }, body: JSON.stringify({ name: `eksbad-${suffix}`, apiServerUrl: serverUrl, authType: 'eks', credentials: '{"region":"eu-west-1"}' }) });
  check('incomplete EKS credentials are rejected (400)', eksBad.status === 400);
  await api('DELETE', `/k8s/clusters/${eksCluster.id}`, { token: admin });
  const bad = await fetch(`${apiBase}/k8s/clusters`, { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${admin}` }, body: JSON.stringify({ name: `bad-${suffix}`, apiServerUrl: serverUrl, authType: 'kubeconfig', credentials: 'apiVersion: v1\nkind: Config\nclusters: []\n' }) });
  check('invalid kubeconfig is rejected (400)', bad.status === 400);
  const execCfg = kubeconfig.replace(/client-certificate-data:.*\n/, '').replace(/client-key-data:.*\n/, '') + '';
  const bad2 = await fetch(`${apiBase}/k8s/clusters`, { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${admin}` }, body: JSON.stringify({ name: `bad2-${suffix}`, apiServerUrl: serverUrl, authType: 'kubeconfig', credentials: execCfg }) });
  check('kubeconfig without inline credentials is rejected (400)', bad2.status === 400);
  const ssrf = await fetch(`${apiBase}/k8s/clusters`, { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${admin}` }, body: JSON.stringify({ name: `ssrf-${suffix}`, apiServerUrl: 'https://169.254.169.254', authType: 'token', credentials: 'abc' }) });
  check('cloud-metadata API server address is rejected (400)', ssrf.status === 400);
  const opCreate = await fetch(`${apiBase}/k8s/clusters`, { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${op}` }, body: JSON.stringify({ name: `x-${suffix}`, apiServerUrl: serverUrl }) });
  check('operator cannot register clusters or store credentials (403)', opCreate.status === 403);
  // Selector peers: client-f is a labelled workload mapped to tagWeb (which also holds hostE's IP).
  const wl = (await api('POST', `/k8s/clusters/${cluster.id}/workloads`, { token: op, body: { namespace: 'seg-clients', kind: 'Pod', name: 'client-f', labels: { app: 'client', who: 'client-f' } } })).workload;
  await api('POST', `/k8s/workloads/${wl.id}/map-tag`, { token: op, body: { tagId: tagWeb.id } });
  const wlNoLabels = (await api('POST', `/k8s/clusters/${cluster.id}/workloads`, { token: op, body: { namespace: 'seg-clients', kind: 'Pod', name: 'unlabelled' } })).workload;
  await api('POST', `/k8s/workloads/${wlNoLabels.id}/map-tag`, { token: op, body: { tagId: tagEmpty.id } });

  async function generateAndApply(versionId, namespace, policyName) {
    const r = await api('POST', `/k8s/clusters/${cluster.id}/deploy-policy`, { token: op, expect: 201, body: { policyVersionId: versionId, namespace, policyName } });
    const dir = mkdtempSync(join(tmpdir(), 'segmentra-k8s-'));
    const file = join(dir, `${policyName}.json`);
    writeFileSync(file, JSON.stringify(r.networkPolicy.manifest, null, 2));
    const ap = await api('POST', `/k8s/clusters/${cluster.id}/network-policies/${r.networkPolicy.id}/apply`, { token: op, body: {} });
    check(`API apply ${namespace}/${policyName}`, ap.ok === true && ap.networkPolicy.status === 'APPLIED');
    return { ...r, file };
  }

  console.log('\nGenerate + apply policies:');
  const main = await generateAndApply(vMain.id, NS, 'segmentra-main');
  console.log('  warnings:\n   - ' + main.warnings.join('\n   - '));
  console.log('  manifest:\n' + JSON.stringify(main.networkPolicy.manifest.spec, null, 2).replace(/^/gm, '    '));
  await generateAndApply(vOpen.id, NS_OPEN, 'segmentra-open');
  const none = await generateAndApply(vNone.id, NS_NONE, 'segmentra-none');
  results.push({ label: 'warnings: main reports deny/icmp/out/empty-tag', pass: ['deny', 'icmp', 'out', 'tag-empty'].every((k) => main.warnings.some((w) => w.includes(`(${k})`))) });
  const ipBlockWarned = main.warnings.some((w) => w.includes('ipBlock'));
  results.push({ label: `ipBlock/CNI warning is ${cni === 'cilium' ? 'present' : 'absent'} for ${cni}`, pass: cni === 'cilium' ? ipBlockWarned : !ipBlockWarned });
  results.push({ label: 'selector peer generated for labelled workload (TAG)', pass: JSON.stringify(main.networkPolicy.manifest).includes('"who":"client-f"') });
  results.push({ label: 'unlabelled workload is skipped, never an empty podSelector', pass: main.warnings.some((w) => w.includes('has no labels')) && !JSON.stringify(main.networkPolicy.manifest).includes('"podSelector":{}}') });
  results.push({ label: 'empty-source policy has no ingress rules (never widened)', pass: none.networkPolicy.manifest.spec.ingress.length === 0 });
  await sleep(3000);

  console.log(`\nEnforcement in ${NS} (policy segmentra-main):`);
  const T = (label, client, port, proto, allow) => expectTraffic(label, NS, client, port, proto, allow, env);
  await T('client-a (cidr /32, cross-node) -> tcp 5432', 'client-a', 5432, 'tcp', ib(true));
  await T('client-a -> tcp 80 (not granted)', 'client-a', 80, 'tcp', false);
  await T('client-a -> tcp 8080 (not granted)', 'client-a', 8080, 'tcp', false);
  await T('client-b (bare IP, same-node) -> tcp 8080', 'client-b', 8080, 'tcp', ib(true));
  await T('client-b -> tcp 8085 (in range)', 'client-b', 8085, 'tcp', ib(true));
  await T('client-b -> tcp 8090 (range end)', 'client-b', 8090, 'tcp', ib(true));
  await T('client-b -> tcp 5432 (not granted)', 'client-b', 5432, 'tcp', false);
  await T('client-c (HOST) -> tcp 80', 'client-c', 80, 'tcp', ib(true));
  await T('client-c (HOST) -> tcp 9000', 'client-c', 9000, 'tcp', ib(true));
  await T('client-c -> tcp 5432 (not granted)', 'client-c', 5432, 'tcp', false);
  await T('client-e (TAG host ipBlock) -> tcp 9001', 'client-e', 9001, 'tcp', ib(true));
  await T('client-f (TAG labelled workload, selector) -> tcp 9001', 'client-f', 9001, 'tcp', true);
  await T('client-a (not tagged) -> tcp 9001', 'client-a', 9001, 'tcp', false);
  await T('client-e (BOTH) -> tcp 8085', 'client-e', 8085, 'tcp', ib(true));
  await T('client-e -> tcp 5432 (not granted)', 'client-e', 5432, 'tcp', false);
  await T('client-d (VLAN subnet) -> udp 5353', 'client-d', 5353, 'udp', ib(true));
  await T('client-d -> tcp 5353-equivalent tcp 80 (not granted)', 'client-d', 80, 'tcp', false);
  await T('client-a -> udp 5353 (not granted)', 'client-a', 5353, 'udp', false);
  await T('client-f (no rule) -> tcp 5432', 'client-f', 5432, 'tcp', false);
  await T('client-f (no rule) -> tcp 80', 'client-f', 80, 'tcp', false);
  await T('any client -> tcp 7000 (empty TAG rule must not open it)', 'client-a', 7000, 'tcp', false);

  console.log(`\nEnforcement in ${NS_OPEN} (source "any"):`);
  for (const c of ['client-a', 'client-b', 'client-f']) await expectTraffic(`${c} -> tcp 5432 (any)`, NS_OPEN, c, 5432, 'tcp', ib(true), env);
  await expectTraffic('client-f -> udp 5353 (any protocol)', NS_OPEN, 'client-f', 5353, 'udp', ib(true), env);

  console.log(`\nEnforcement in ${NS_NONE} (all rules resolved to nothing => deny all ingress):`);
  for (const c of ['client-a', 'client-f']) await expectTraffic(`${c} -> tcp 5432 (empty source)`, NS_NONE, c, 5432, 'tcp', false, env);

  console.log('\nUpdate: add client-f to the main policy and re-apply:');
  const v2 = await approvedVersion('k8s-main-v2', [
    rule(10, { protocol: 'tcp', ports: '5432', sourceType: 'CIDR', sourceValue: `${ips['client-a']}/32,${ips['client-f']}/32`, comment: 'cidr-list' })
  ]);
  await generateAndApply(v2.id, NS, 'segmentra-main');
  await sleep(3000);
  await T('client-f (added) -> tcp 5432', 'client-f', 5432, 'tcp', ib(true));
  await T('client-b (removed) -> tcp 8080', 'client-b', 8080, 'tcp', false);

  console.log('\nApply safety, drift detection and removal through the API:');
  const nps = (await api('GET', `/k8s/clusters/${cluster.id}/network-policies`, { token: op })).networkPolicies;
  const live = nps.filter((n) => n.policy_name === 'segmentra-main');
  check('older manifests with the same name are marked SUPERSEDED', live.some((n) => n.status === 'SUPERSEDED') && live.filter((n) => n.status === 'APPLIED').length === 1);
  const supersededRow = live.find((n) => n.status === 'SUPERSEDED');
  const reapplyOld = await fetch(`${apiBase}/k8s/clusters/${cluster.id}/network-policies/${supersededRow.id}/apply`, { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${op}` }, body: '{}' });
  check('applying a superseded manifest is refused (409)', reapplyOld.status === 409);
  const current = live.find((n) => n.status === 'APPLIED');
  const chk = (id) => api('POST', `/k8s/clusters/${cluster.id}/network-policies/${id}/check`, { token: op });
  check('check: applied policy is IN_SYNC with the cluster', (await chk(current.id)).state === 'IN_SYNC');
  const onCluster = JSON.parse((await kubectl('get', 'networkpolicy', 'segmentra-main', '-n', NS, '-o', 'json')).out);
  check('policy on the cluster carries the managed-by label', onCluster.metadata.labels['app.kubernetes.io/managed-by'] === 'segmentra');
  await kubectl('patch', 'networkpolicy', 'segmentra-main', '-n', NS, '--type=json', '-p', JSON.stringify([{ op: 'add', path: '/spec/ingress/-', value: { ports: [{ port: 6666, protocol: 'TCP' }] } }]));
  check('check: a hand-edited policy is reported DRIFTED', (await chk(current.id)).state === 'DRIFTED');
  await api('POST', `/k8s/clusters/${cluster.id}/network-policies/${current.id}/apply`, { token: op, body: {} });
  check('re-apply repairs the drift (IN_SYNC)', (await chk(current.id)).state === 'IN_SYNC');

  const dry = await api('POST', `/k8s/clusters/${cluster.id}/network-policies/${current.id}/apply`, { token: op, body: { dryRun: true } });
  check('dry-run validates without changing anything', dry.ok === true && dry.dryRun === true);

  // A same-named policy that was not created by Segmentra must never be overwritten or deleted by default.
  await run('kubectl', ['--context', ctx, 'apply', '-f', '-'], { input: `apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata: { name: handmade, namespace: ${NS} }\nspec:\n  podSelector: { matchLabels: { app: nothing } }\n  policyTypes: [Ingress]\n` });
  const hm = await api('POST', `/k8s/clusters/${cluster.id}/deploy-policy`, { token: op, expect: 201, body: { policyVersionId: vNone.id, namespace: NS, policyName: 'handmade' } });
  const hmApply = await fetch(`${apiBase}/k8s/clusters/${cluster.id}/network-policies/${hm.networkPolicy.id}/apply`, { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${op}` }, body: '{}' });
  check('refuses to overwrite a policy not created by Segmentra (409)', hmApply.status === 409);
  const hmRemove = await fetch(`${apiBase}/k8s/clusters/${cluster.id}/network-policies/${hm.networkPolicy.id}/remove`, { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${op}` }, body: '{}' });
  check('refuses to delete a policy not created by Segmentra (409)', hmRemove.status === 409);
  const stillThere = (await kubectl('get', 'networkpolicy', 'handmade', '-n', NS, '-o', 'jsonpath={.spec.podSelector.matchLabels.app}')).out;
  check('the hand-written policy is untouched', stillThere === 'nothing');
  await kubectl('delete', 'networkpolicy', 'handmade', '-n', NS);

  // RBAC: a read-only token can check but cannot apply; the row records the failure.
  const roRow = (await api('POST', `/k8s/clusters/${roCluster.id}/deploy-policy`, { token: op, expect: 201, body: { policyVersionId: vNone.id, namespace: NS_NONE, policyName: 'ro-test' } })).networkPolicy;
  const roApply = await fetch(`${apiBase}/k8s/clusters/${roCluster.id}/network-policies/${roRow.id}/apply`, { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${op}` }, body: '{}' });
  const roBody = await roApply.json();
  check('read-only service account cannot apply (forbidden is reported)', roApply.status === 502 && /forbidden|403/i.test(roBody.message ?? ''), roBody.message?.slice(0, 80));
  const roList = (await api('GET', `/k8s/clusters/${roCluster.id}/network-policies`, { token: op })).networkPolicies;
  check('failed apply is recorded on the policy (FAILED + error)', roList[0]?.status === 'FAILED' && !!roList[0]?.last_error);
  const missingNs = await api('POST', `/k8s/clusters/${cluster.id}/deploy-policy`, { token: op, expect: 201, body: { policyVersionId: vNone.id, namespace: 'does-not-exist', policyName: 'x' } });
  const mnsApply = await fetch(`${apiBase}/k8s/clusters/${cluster.id}/network-policies/${missingNs.networkPolicy.id}/apply`, { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${op}` }, body: '{}' });
  check('applying into a missing namespace gives a clear 404', mnsApply.status === 404 && /namespace/i.test((await mnsApply.json()).message ?? ''));
  const noCreds = await api('POST', '/k8s/clusters', { token: admin, body: { name: `nocreds-${suffix}`, apiServerUrl: serverUrl } });
  const ncRow = (await api('POST', `/k8s/clusters/${noCreds.cluster.id}/deploy-policy`, { token: op, expect: 201, body: { policyVersionId: vNone.id, namespace: NS, policyName: 'nc' } })).networkPolicy;
  const ncApply = await fetch(`${apiBase}/k8s/clusters/${noCreds.cluster.id}/network-policies/${ncRow.id}/apply`, { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${op}` }, body: '{}' });
  check('cluster without stored credentials cannot be applied to (409)', ncApply.status === 409);

  console.log('\nRemove through the API => open again:');
  const rm = await api('POST', `/k8s/clusters/${cluster.id}/network-policies/${current.id}/remove`, { token: op, body: {} });
  check('API remove deleted the policy from the cluster', rm.ok === true && rm.alreadyAbsent === false);
  const gone = await kubectl('get', 'networkpolicy', 'segmentra-main', '-n', NS).then(() => false, () => true);
  check('policy no longer exists on the cluster', gone);
  check('check: removed policy is MISSING', (await chk(current.id)).state === 'MISSING');
  await sleep(3000);
  await T('client-b (after API remove) -> tcp 5432', 'client-b', 5432, 'tcp', true);

  // Workload housekeeping through the API
  await api('DELETE', `/k8s/workloads/${wl.id}/tags/${tagWeb.id}`, { token: op });
  await api('DELETE', `/k8s/workloads/${wlNoLabels.id}`, { token: op });
  const wls = (await api('GET', `/k8s/clusters/${cluster.id}/workloads`, { token: op })).workloads;
  check('workload unmapped from its tag and another workload deleted', wls.length === 1 && !(wls[0].tag_names ?? []).length);
  await api('DELETE', `/k8s/clusters/${cluster.id}`, { token: admin });
  await api('DELETE', `/k8s/clusters/${tokenCluster.id}`, { token: admin });
  await api('DELETE', `/k8s/clusters/${roCluster.id}`, { token: admin });
  await api('DELETE', `/k8s/clusters/${noCreds.cluster.id}`, { token: admin });

  // Approved versions cannot be deleted (audit trail); archive them so they do not stay active.
  for (const id of createdVersions) await api('POST', `/policy-versions/${id}/archive`, { token: op, body: {} }).catch(() => {});

  const failed = results.filter((r) => !r.pass);
  console.log(`\n[${cni}] ${results.length - failed.length}/${results.length} checks passed`);
  for (const f of failed) console.log(`  FAILED: ${f.label}`);
  if (keep) log(`cluster kept; remove with: kind delete cluster --name ${clusterName}`);
  else await run('kind', ['delete', 'cluster', '--name', clusterName], { allowFailure: true });
  process.exit(failed.length ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });
