#!/usr/bin/env node
// Policy expiry on real distributions, native firewall managers and gateways, with both executors. The real job and real
// expiry dates, real TCP traffic through each firewall. "Reboot" means restarting a container that boots real systemd:
// its network namespace starts empty, so rules can only come back through the distribution's own boot service. It is
// not a kernel reboot. Takes about 15 minutes, more for the first image build.
//
//   npm run test:integration:expiry-matrix [-- --keep] [-- --ssh-only]      (API on http://127.0.0.1:18087)
import { spawn, spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as sleep } from 'node:timers/promises';

const here = dirname(fileURLToPath(import.meta.url));
const composeFile = join(here, 'docker-compose.yml');
const project = 'segmentra-expirymatrix';
const apiBase = 'http://127.0.0.1:18087/api';
const keep = process.argv.includes('--keep');
const CLIENT_IP = '172.31.93.50';
const P1 = 8081, P2 = 8082, P3 = 8083;
// `base`: what the three test ports do with no Segmentra rules. UFW and firewalld deny inbound on their own.
const HOSTS = {
  'deb-ipt': { ip: '172.31.93.11', backend: 'iptables', base: 'open' },
  'deb-nft': { ip: '172.31.93.12', backend: 'nftables', base: 'open' },
  'ubu-ipt': { ip: '172.31.93.13', backend: 'iptables', base: 'open' },
  'ubu-nft': { ip: '172.31.93.14', backend: 'nftables', base: 'open' },
  // Stock /etc/sysconfig/iptables, which ends with REJECT: Segmentra deliberately does not persist here, and says so.
  'roc-ipt': { ip: '172.31.93.15', backend: 'iptables', base: 'open', notPersisted: true },
  // The same, after doing what Segmentra's warning says: save the ruleset to the file, then enable the service.
  'roc-ips': { ip: '172.31.93.19', backend: 'iptables', base: 'open' },
  'roc-nft': { ip: '172.31.93.16', backend: 'nftables', base: 'open' },
  'ubu-ufw': { ip: '172.31.93.17', backend: 'ufw', base: 'blocked' },
  'roc-fwd': { ip: '172.31.93.18', backend: 'firewalld', base: 'blocked' },
  'gw-ipt': { ip: '172.31.93.20', backend: 'iptables', base: 'open', device: '172.31.94.11' },
  'gw-nft': { ip: '172.31.93.21', backend: 'nftables', base: 'open', device: '172.31.94.12' },
};
const PLAIN = Object.keys(HOSTS).filter((h) => !HOSTS[h].device);
const GATEWAYS = Object.keys(HOSTS).filter((h) => HOSTS[h].device);

const results = [];
function check(label, pass, detail = '') {
  results.push({ label, pass: !!pass, detail });
  console.log(`  ${pass ? 'PASS' : 'FAIL'}  ${label}${detail && !pass ? `  (${String(detail).slice(0, 300)})` : ''}`);
}
const docker = (...a) => spawnSync('docker', a, { encoding: 'utf8' });
const dockerAsync = (...a) => new Promise((resolve) => { const c = spawn('docker', a, { stdio: 'ignore' }); c.on('close', resolve); });
const compose = (...a) => docker('compose', '-f', composeFile, '-p', project, ...a);
const container = (h) => `seg-matrix-${h}`;
const inHost = (h, script) => docker('exec', container(h), 'sh', '-c', script);

async function raw(method, path, { token, body } = {}) {
  const request = () => fetch(`${apiBase}${path}`, {
    method,
    headers: { ...(token ? { authorization: `Bearer ${token}` } : {}), ...(body !== undefined ? { 'content-type': 'application/json' } : {}) },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  let res;
  try { res = await request(); } catch { await sleep(500); res = await request(); } // an idle connection closed by the server
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

// ---- real traffic: every port of every host at once, from the client ----
const PROBE = `const net=require('net');const t=JSON.parse(process.argv[1]);const out={};
Promise.all(t.map(([k,h,p])=>new Promise(r=>{const s=net.connect({host:h,port:p});const d=(v)=>{out[k]=v;s.destroy();r()};s.setTimeout(3000);s.on('connect',()=>d('open'));s.on('timeout',()=>d('blocked'));s.on('error',()=>d('blocked'))}))).then(()=>console.log(JSON.stringify(out)));`;
function sweep(hosts) {
  const targets = hosts.flatMap((h) => [P1, P2, P3].map((p) => [`${h}:${p}`, HOSTS[h].device ?? HOSTS[h].ip, p]));
  const out = JSON.parse(docker('exec', 'seg-matrix-client', 'node', '-e', PROBE, JSON.stringify(targets)).stdout);
  return Object.fromEntries(hosts.map((h) => [h, `${P1}=${out[`${h}:${P1}`]} ${P2}=${out[`${h}:${P2}`]} ${P3}=${out[`${h}:${P3}`]}`]));
}
const onlyP1 = `${P1}=open ${P2}=blocked ${P3}=blocked`;
const onlyP2 = `${P1}=blocked ${P2}=open ${P3}=blocked`;
const baseOf = (h) => [P1, P2, P3].map((p) => `${p}=${HOSTS[h].base}`).join(' ');

/** Segmentra's objects in the running firewall and in the files loaded at boot. */
function segmentraPresent(h) {
  const { backend } = HOSTS[h];
  const script = {
    iptables: 'iptables -S 2>/dev/null | grep -c SEGMENTRA',
    nftables: 'nft list tables 2>/dev/null | grep -c segmentra',
    ufw: 'cat /etc/ufw/before.rules /etc/ufw/before6.rules | grep -ci segmentra',
    firewalld: 'ls /etc/firewalld/policies 2>/dev/null | grep -c segmentra',
  }[backend];
  return Number(inHost(h, script).stdout.trim() || 0) > 0;
}
function bootFilesMention(h) {
  const r = inHost(h, 'grep -il segmentra /etc/iptables/rules.v4 /etc/iptables/rules.v6 /etc/sysconfig/iptables /etc/sysconfig/ip6tables /etc/nftables.conf /etc/sysconfig/nftables.conf /etc/nftables.d/segmentra.nft /etc/nftables/segmentra.nft 2>/dev/null | wc -l');
  return Number(r.stdout.trim() || 0) > 0;
}
async function waitBooted(h) {
  for (let i = 0; i < 90; i += 1) {
    const r = inHost(h, 'systemctl is-system-running 2>/dev/null; true').stdout.trim();
    if (r === 'running' || r === 'degraded') {
      if (inHost(h, 'systemctl is-active --quiet ssh 2>/dev/null || systemctl is-active --quiet sshd').status === 0
        && inHost(h, 'systemctl is-active --quiet seg-listen').status === 0) return r;
    }
    await sleep(2000);
  }
  return `timeout: ${inHost(h, 'systemctl --failed --no-legend | head -5').stdout}`;
}
async function reboot(hosts) {
  await Promise.all(hosts.map((h) => dockerAsync('restart', '-t', '15', container(h))));
  await sleep(3000);
  await Promise.all(hosts.map(waitBooted));
  await sleep(3000);
}

async function main() {
  console.log('[matrix] Building and starting the stack (the first build takes several minutes)');
  compose('down', '-v', '--remove-orphans');
  const up = compose('up', '-d', '--build');
  if (up.status !== 0) throw new Error(`docker compose up failed:\n${up.stderr.slice(-2500)}`);
  let healthy = false;
  for (let i = 0; i < 120 && !healthy; i += 1) {
    try { healthy = (await fetch(`${apiBase}/health`)).ok; } catch { /* starting */ }
    if (!healthy) await sleep(2000);
  }
  if (!healthy) throw new Error('the API did not become healthy');

  const keyDir = mkdtempSync(join(tmpdir(), 'segmatrix-'));
  spawnSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-f', join(keyDir, 'id'), '-C', 'segmentra-expiry-matrix']);
  const pub = readFileSync(join(keyDir, 'id.pub'), 'utf8').trim();
  const key = readFileSync(join(keyDir, 'id'), 'utf8');
  rmSync(keyDir, { recursive: true, force: true });

  console.log('\nBooting the hosts');
  for (const h of Object.keys(HOSTS)) {
    const state = await waitBooted(h);
    check(`${h} booted systemd (${state})`, state === 'running' || state === 'degraded', state);
    inHost(h, `echo '${pub}' > /home/segmentra/.ssh/authorized_keys && chown segmentra /home/segmentra/.ssh/authorized_keys && chmod 600 /home/segmentra/.ssh/authorized_keys; rm -f /run/nologin`);
  }
  const ufw = inHost('ubu-ufw', 'ufw allow 22/tcp && ufw --force enable && systemctl enable ufw');
  check('UFW is active with its own default deny', ufw.status === 0 && /active/.test(inHost('ubu-ufw', 'ufw status').stdout), ufw.stderr);
  check('firewalld is active', inHost('roc-fwd', 'firewall-cmd --state').stdout.trim() === 'running', inHost('roc-fwd', 'firewall-cmd --state; systemctl status firewalld --no-pager | tail -5').stdout);
  const advice = inHost('roc-ips', 'iptables-save > /etc/sysconfig/iptables && ip6tables-save > /etc/sysconfig/ip6tables && systemctl enable iptables ip6tables');
  check('roc-ips: the warning\'s advice is followed (ruleset saved, services enabled)', advice.status === 0, advice.stderr);
  const before = sweep(Object.keys(HOSTS));
  for (const h of Object.keys(HOSTS)) check(`${h}: before any policy, ${baseOf(h)}`, before[h] === baseOf(h), before[h]);

  const admin = await login('admin', 'admin123');
  const newUser = async (username, role) => {
    await api('POST', '/admin/users', { token: admin, body: { username, displayName: username, password: 'ExpiryLab-pass-123!', roles: [role], isActive: true } });
    return login(username, 'ExpiryLab-pass-123!');
  };
  const op = await newUser('mx-operator', 'operator');
  const appr = await newUser('mx-approver', 'approver');
  await api('POST', '/ssh-credentials', { token: admin, body: { name: 'matrix', username: 'segmentra', authMethod: 'KEY', privateKeyPem: key, scopeType: 'GLOBAL' } });
  const iotTag = (await api('GET', '/tags', { token: op })).tags.find((t) => t.name === 'iot-gateway');
  for (const [h, info] of Object.entries(HOSTS)) {
    info.id = (await api('POST', '/hosts', { token: admin, body: { hostname: h, mgmtIp: info.ip, sshPort: 22, firewallBackend: info.backend, enabled: true, ...(info.device ? { tagIds: [iotTag.id] } : {}) } })).host.id;
  }
  const assets = {};
  for (const h of GATEWAYS) {
    assets[h] = (await api('POST', '/iot-assets', { token: op, body: { name: `plc-${h}`, assetType: 'plc', ipAddress: HOSTS[h].device, zone: 'line-1', criticality: 'critical', gatewayIds: [HOSTS[h].id] } })).asset;
  }

  let n = 0;
  const hostIds = (hosts) => hosts.map((h) => HOSTS[h].id);
  const addVersion = async (ps, port, gateway) => {
    const v = (await api('POST', `/policy-sets/${ps.id}/versions`, { token: op, body: { changeSummary: `allow ${port}`, interfaceScopeType: 'ALL_INTERFACES' } })).version;
    const rule = { action: 'ALLOW', protocol: 'tcp', ports: String(port), sourceType: 'CIDR', sourceValue: `${CLIENT_IP}/32`, logMode: 'NONE', usePolicyInterfaceScope: true, comment: `allow ${port}` };
    if (gateway) {
      let order = 10;
      for (const h of GATEWAYS) {
        await api('POST', `/policy-versions/${v.id}/rules`, { token: op, body: { ...rule, orderIndex: order, direction: 'FORWARD', destinationType: 'IOT_ASSET', destinationValue: assets[h].id } });
        order += 10;
      }
    } else {
      await api('POST', `/policy-versions/${v.id}/rules`, { token: op, body: { ...rule, orderIndex: 10, direction: 'IN' } });
    }
    await api('POST', `/policy-versions/${v.id}/submit-approval`, { token: op, body: {} });
    await api('POST', `/policy-versions/${v.id}/approve`, { token: appr, body: {} });
    return v;
  };
  const getDep = async (id) => (await api('GET', `/deployments/${id}`, { token: op })).deployment;
  const hostRows = async (id) => (await api('GET', `/deployments/${id}/hosts`, { token: op })).hosts;
  const finished = async (id, seconds = 420) => {
    for (let i = 0; i < seconds / 2; i += 1) {
      const d = await getDep(id);
      if (['SUCCEEDED', 'FAILED', 'PARTIAL', 'EXPIRED', 'CANCELLED'].includes(d.status)) return d;
      await sleep(2000);
    }
    return getDep(id);
  };
  const deploy = async (v, hosts, extra = {}) => {
    const { deployment } = await api('POST', '/deployments', { token: op, body: { policyVersionId: v.id, mode: 'FULL', targetQuery: { hosts: hostIds(hosts), tags: [], vlans: [] }, ...extra } });
    const start = await raw('POST', `/deployments/${deployment.id}/start`, { token: op, body: { acceptReadinessNotes: true } });
    if (start.status >= 400) return { id: deployment.id, final: { status: `refused ${start.status}: ${start.text.slice(0, 200)}` } };
    return { id: deployment.id, final: await finished(deployment.id) };
  };
  const inSeconds = (s) => new Date(Date.now() + s * 1000).toISOString();
  const waitExpired = async (id, seconds = 300) => {
    for (let i = 0; i < seconds / 2; i += 1) {
      const d = await getDep(id);
      if (d.expired && d.expiry_outcome) return d;
      await sleep(2000);
    }
    return getDep(id);
  };
  const outcomeOf = (d) => (typeof d.expiry_outcome === 'string' ? JSON.parse(d.expiry_outcome) : d.expiry_outcome) ?? {};
  const rowFor = async (id, h) => (await hostRows(id)).find((r) => r.host_id === HOSTS[h].id);
  const why = async (id, hosts) => (await hostRows(id)).filter((r) => r.status !== 'SUCCEEDED').map((r) => `${Object.keys(HOSTS).find((h) => HOSTS[h].id === r.host_id)}: ${String(r.message ?? r.status).slice(0, 220)}`).join(' | ');

  /** One executor, one group of hosts: v1, then v2 with REVERT, reboot, then v2 with REMOVE, reboot. */
  const scenario = async (tag, hosts, gateway) => {
    const ps = (await api('POST', '/policy-sets', { token: op, body: { name: `matrix-${++n}`, scopeType: 'HOST_LIST', hostIds: hostIds(hosts) } })).policySet;
    const v1 = await addVersion(ps, P1, gateway);
    const v2 = await addVersion(ps, P2, gateway);

    const first = await deploy(v1, hosts);
    check(`${tag} v1 deploys`, first.final.status === 'SUCCEEDED', `${first.final.status} ${await why(first.id, hosts)}`);
    let t = sweep(hosts);
    for (const h of hosts) check(`${tag} ${h}: v1 enforced`, t[h] === onlyP1, t[h]);
    for (const h of hosts) {
      const r = await rowFor(first.id, h);
      if (HOSTS[h].notPersisted) check(`${tag} ${h}: Segmentra warns the rules will not survive a reboot, naming the stock file`, r?.persistence_status === 'not_persisted' && /saved_rules_block_all/.test(r?.persistence_message ?? ''), `${r?.persistence_status}: ${r?.persistence_message}`);
      else check(`${tag} ${h}: Segmentra reports the rules survive a reboot`, r?.persistence_status === 'persisted', `${r?.persistence_status}: ${r?.persistence_message}`);
    }

    await sleep(1100);
    const dep = await deploy(v2, hosts, { expiresAt: inSeconds(25), expiryAction: 'REVERT' });
    check(`${tag} v2 deploys with a REVERT expiry`, ['SUCCEEDED', 'EXPIRED'].includes(dep.final.status), `${dep.final.status} ${await why(dep.id, hosts)}`);
    t = sweep(hosts);
    for (const h of hosts) check(`${tag} ${h}: v2 enforced`, t[h] === onlyP2, t[h]);
    const d = await waitExpired(dep.id);
    const o = outcomeOf(d);
    check(`${tag} the job starts the revert to v1`, o.result === 'REVERT_STARTED' && o.revertToVersionNumber === v1.version_number, JSON.stringify(o));
    if (o.revertDeploymentId) {
      const rev = await finished(o.revertDeploymentId);
      check(`${tag} the revert deployment succeeds`, rev.status === 'SUCCEEDED', `${rev.status} ${await why(o.revertDeploymentId, hosts)}`);
      await sleep(3000);
      for (const h of hosts) check(`${tag} ${h}: marked REVERTED`, (await rowFor(dep.id, h))?.expiry_status === 'REVERTED', (await rowFor(dep.id, h))?.expiry_message);
    }
    t = sweep(hosts);
    for (const h of hosts) check(`${tag} ${h}: v1 is back, real traffic`, t[h] === onlyP1, t[h]);
    for (const h of hosts) {
      const c = await api('GET', `/compliance/hosts/${HOSTS[h].id}`, { token: op });
      check(`${tag} ${h}: no drift after the revert`, c.status === 'compliant', `${c.status}: ${c.message ?? ''}`);
    }

    await reboot(hosts);
    t = sweep(hosts);
    for (const h of hosts) {
      const c = await api('GET', `/compliance/hosts/${HOSTS[h].id}`, { token: op });
      if (HOSTS[h].notPersisted) {
        check(`${tag} ${h}: as warned, the rules are gone after a reboot (the host is open)`, t[h] === baseOf(h) && !segmentraPresent(h), t[h]);
        check(`${tag} ${h}: Segmentra reports that as drift`, c.status === 'drifted', `${c.status}: ${c.message ?? ''}`);
      } else {
        check(`${tag} ${h}: after a reboot the reverted v1 is enforced`, t[h] === onlyP1, t[h]);
        check(`${tag} ${h}: no drift after the reboot`, c.status === 'compliant', `${c.status}: ${c.message ?? ''}`);
      }
    }

    await sleep(1100);
    const rem = await deploy(v2, hosts, { expiresAt: inSeconds(25), expiryAction: 'REMOVE' });
    check(`${tag} v2 deploys with a REMOVE expiry`, ['SUCCEEDED', 'EXPIRED'].includes(rem.final.status), `${rem.final.status} ${await why(rem.id, hosts)}`);
    const dr = await waitExpired(rem.id);
    check(`${tag} the job removes it from all hosts`, outcomeOf(dr).result === 'REMOVED', JSON.stringify(outcomeOf(dr)));
    t = sweep(hosts);
    for (const h of hosts) check(`${tag} ${h}: rules gone, back to how the host was`, t[h] === baseOf(h) && !segmentraPresent(h), `${t[h]}; present=${segmentraPresent(h)}`);
    for (const h of hosts) check(`${tag} ${h}: removed from the boot configuration`, !bootFilesMention(h));
    await reboot(hosts);
    t = sweep(hosts);
    for (const h of hosts) check(`${tag} ${h}: still gone after a reboot`, t[h] === baseOf(h) && !segmentraPresent(h), `${t[h]}; present=${segmentraPresent(h)}`);
  };

  const executors = process.argv.includes('--ssh-only') ? ['ssh'] : ['ssh', 'ansible'];
  for (const executor of executors) {
    console.log(`\n=== Executor: ${executor} ===`);
    await api('PUT', '/admin/executor-setting', { token: admin, body: { executor } });
    await Promise.all([scenario(`[${executor}]`, PLAIN, false), scenario(`[${executor} gateway]`, GATEWAYS, true)]);
  }
}

main().catch((e) => {
  check(`the run finished without an error: ${e.message}`, false);
}).finally(() => {
  const failed = results.filter((r) => !r.pass);
  console.log(`\n${results.length - failed.length}/${results.length} checks passed`);
  for (const f of failed) console.log(`  FAILED: ${f.label}  (${String(f.detail).slice(0, 300)})`);
  if (keep || failed.length) {
    console.log(`[matrix] Left running to look at. Clean up: docker compose -f tests/expiry-lab/matrix/docker-compose.yml -p ${project} down -v`);
  } else {
    compose('down', '-v', '--remove-orphans');
  }
  process.exitCode = failed.length ? 1 : 0;
});
