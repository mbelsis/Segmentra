#!/usr/bin/env node
// Policy expiry with real kernel reboots on VirtualBox VMs, managed by a disposable Segmentra in Docker, using the real job
// and real expiry dates. Traffic is real, sent between the VMs over a private VirtualBox network. Needs VirtualBox, Vagrant
// and Docker; arm64 boxes (Apple silicon).
//   default:      Debian 12 and Rocky 9 (SELinux as the distribution set it), each the traffic client for the other
//   --lab ubuntu: Ubuntu 24.04 with UFW, nftables and iptables; a Debian VM only sends the traffic
//   --lab rhel:   RHEL 9 with firewalld, iptables and nftables; a Debian VM only sends the traffic. The VM is not created
//                 here: install it with rhel/ks.cfg (it needs your own Red Hat login), see tests/README.md. It is kept.
// Each takes about 30 minutes, plus the box downloads.
//
//   npm run test:integration:expiry-vm [-- --keep] [-- --lab ubuntu|rhel]
import { spawnSync } from 'node:child_process';
import { chmodSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as sleep } from 'node:timers/promises';

const here = dirname(fileURLToPath(import.meta.url));
const composeFile = join(here, '..', 'matrix', 'docker-compose.yml');
const project = 'segmentra-expiryvm';
const apiBase = 'http://127.0.0.1:18087/api';
const keep = process.argv.includes('--keep');
const HOST_FROM_DOCKER = '192.168.65.254'; // host.docker.internal on Docker Desktop: reaches the VMs' forwarded SSH ports
const NET = '192.168.77.0/24';
const P1 = 8081, P2 = 8082, P3 = 8083;
const lab = process.argv.includes('--lab') ? process.argv[process.argv.indexOf('--lab') + 1] : 'default';
if (!['default', 'ubuntu', 'rhel'].includes(lab)) throw new Error(`unknown lab: ${lab}`);
const VMS = lab === 'rhel'
  ? {
    'seg-rhel': { ip: '192.168.77.14', ssh: 22104, peer: 'seg-deb', key: join(here, 'rhel', '.key', 'id') },
    'seg-deb': { ip: '192.168.77.11', ssh: 22101, peer: 'seg-rhel' },
  }
  : lab === 'ubuntu'
  ? {
    'seg-ubu': { ip: '192.168.77.13', ssh: 22103, peer: 'seg-deb' },
    'seg-deb': { ip: '192.168.77.11', ssh: 22101, peer: 'seg-ubu' },
  }
  : {
    'seg-deb': { ip: '192.168.77.11', ssh: 22101, peer: 'seg-roc' },
    'seg-roc': { ip: '192.168.77.12', ssh: 22102, peer: 'seg-deb' },
  };
const ALL = Object.keys(VMS);
// The VMs that get policies. In the ubuntu lab the Debian VM only sends traffic.
const NAMES = lab === 'rhel' ? ['seg-rhel'] : lab === 'ubuntu' ? ['seg-ubu'] : ALL;
const FIRST_BACKENDS = lab === 'rhel' ? { 'seg-rhel': 'firewalld' } : lab === 'ubuntu' ? { 'seg-ubu': 'ufw' } : { 'seg-deb': 'iptables', 'seg-roc': 'firewalld' };

const results = [];
function check(label, pass, detail = '') {
  results.push({ label, pass: !!pass, detail });
  console.log(`  ${pass ? 'PASS' : 'FAIL'}  ${label}${detail && !pass ? `  (${String(detail).slice(0, 400)})` : ''}`);
}
const compose = (...a) => spawnSync('docker', ['compose', '-f', composeFile, '-p', project, ...a], { encoding: 'utf8' });
const vagrant = (env, ...a) => spawnSync('vagrant', a, { cwd: here, encoding: 'utf8', env: { ...process.env, ...env } });

let keyFile = null;
function ssh(vm, script, timeout = 60_000) {
  return spawnSync('ssh', ['-i', VMS[vm].key ?? keyFile, '-p', String(VMS[vm].ssh), '-o', 'IdentitiesOnly=yes', '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null', '-o', 'LogLevel=ERROR', '-o', 'ConnectTimeout=5', 'segmentra@127.0.0.1', script], { encoding: 'utf8', timeout });
}
const sudo = (vm, script, timeout) => ssh(vm, `sudo sh -c ${JSON.stringify(script)}`, timeout);

async function raw(method, path, { token, body } = {}) {
  const request = () => fetch(`${apiBase}${path}`, {
    method,
    headers: { ...(token ? { authorization: `Bearer ${token}` } : {}), ...(body !== undefined ? { 'content-type': 'application/json' } : {}) },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  let res;
  try { res = await request(); } catch { await sleep(500); res = await request(); }
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

// Real traffic from the other VM, over the private network.
const PROBE = (ip) => `python3 -c "
import socket
out=[]
for p in (${P1},${P2},${P3}):
    s=socket.socket(); s.settimeout(3)
    try:
        s.connect(('${ip}',p)); out.append('%d=open'%p)
    except Exception:
        out.append('%d=blocked'%p)
    s.close()
print(' '.join(out))"`;
const traffic = (vm) => ssh(VMS[vm].peer, PROBE(VMS[vm].ip)).stdout.trim();
const onlyP1 = `${P1}=open ${P2}=blocked ${P3}=blocked`;
const onlyP2 = `${P1}=blocked ${P2}=open ${P3}=blocked`;
const baseOf = (backend) => [P1, P2, P3].map((p) => `${p}=${['firewalld', 'ufw'].includes(backend) ? 'blocked' : 'open'}`).join(' ');
function segmentraPresent(vm, backend) {
  const script = {
    iptables: 'iptables -S | grep -c SEGMENTRA',
    nftables: 'nft list tables | grep -c segmentra',
    firewalld: 'ls /etc/firewalld/policies 2>/dev/null | grep -c segmentra',
    ufw: 'cat /etc/ufw/before.rules /etc/ufw/before6.rules | grep -ci segmentra',
  }[backend];
  return Number(sudo(vm, `${script}; true`).stdout.trim() || 0) > 0;
}
const bootId = (vm) => ssh(vm, 'cat /proc/sys/kernel/random/boot_id').stdout.trim();

/** A real reboot: a new kernel boot, proved by the boot id, and the firewall state rebuilt by the OS's own services. */
async function reboot(tag) {
  const before = Object.fromEntries(NAMES.map((vm) => [vm, bootId(vm)]));
  for (const vm of NAMES) ssh(vm, 'sudo systemctl reboot', 15_000);
  await sleep(15_000);
  for (const vm of NAMES) {
    let id = '';
    for (let i = 0; i < 90; i += 1) {
      id = bootId(vm);
      if (id && id !== before[vm] && ssh(vm, 'systemctl is-active --quiet seg-listen').status === 0) break;
      await sleep(3000);
    }
    check(`${tag} ${vm}: the kernel really rebooted (new boot id)`, id && id !== before[vm], `${before[vm]} -> ${id}`);
  }
  await sleep(3000);
}

async function main() {
  const keyDir = mkdtempSync(join(tmpdir(), 'segvm-'));
  keyFile = join(keyDir, 'id');
  spawnSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-f', keyFile, '-C', 'segmentra-expiry-vm']);
  chmodSync(keyFile, 0o600);
  const pub = readFileSync(`${keyFile}.pub`, 'utf8').trim();
  const key = readFileSync(VMS[NAMES[0]].key ?? keyFile, 'utf8');

  console.log('[vm] Creating the two VMs');
  vagrant({}, 'destroy', '-f');
  const up = vagrant({ SEG_PUBKEY: pub }, 'up', '--no-tty', ...ALL.filter((vm) => !VMS[vm].key));
  if (up.status !== 0) throw new Error(`vagrant up failed:\n${up.stdout.slice(-1800)}\n${up.stderr.slice(-1200)}`);
  for (const vm of ALL) check(`${vm}: reachable with the test key (${ssh(vm, 'uname -sr').stdout.trim()})`, ssh(vm, 'true').status === 0, ssh(vm, 'true').stderr);
  if (lab === 'rhel') {
    const facts = ssh('seg-rhel', 'cat /etc/redhat-release; getenforce').stdout.trim().replace(/\n/g, ', ');
    check(`seg-rhel: ${facts}`, /Red Hat Enterprise Linux/.test(facts) && /Enforcing/.test(facts), facts);
    check('seg-rhel is closed by firewalld before any policy', traffic('seg-rhel') === baseOf('firewalld'), traffic('seg-rhel'));
  } else if (lab === 'ubuntu') {
    check('seg-ubu is closed by UFW before any policy', traffic('seg-ubu') === baseOf('ufw') && /Status: active/.test(sudo('seg-ubu', 'ufw status').stdout), traffic('seg-ubu'));
  } else {
    console.log(`  NOTE  Rocky SELinux: ${sudo('seg-roc', 'getenforce').stdout.trim()}`);
    check('seg-deb is open and seg-roc is closed by firewalld before any policy', traffic('seg-deb') === baseOf('iptables') && traffic('seg-roc') === baseOf('firewalld'), `${traffic('seg-deb')}; ${traffic('seg-roc')}`);
  }

  console.log('[vm] Starting a disposable Segmentra in Docker');
  compose('down', '-v', '--remove-orphans');
  const stack = compose('up', '-d', '--build', 'db', 'api', 'ansible-runner');
  if (stack.status !== 0) throw new Error(`docker compose up failed:\n${stack.stderr.slice(-2000)}`);
  let healthy = false;
  for (let i = 0; i < 120 && !healthy; i += 1) {
    try { healthy = (await fetch(`${apiBase}/health`)).ok; } catch { /* starting */ }
    if (!healthy) await sleep(2000);
  }
  if (!healthy) throw new Error('the API did not become healthy');

  const admin = await login('admin', 'admin123');
  const newUser = async (username, role) => {
    await api('POST', '/admin/users', { token: admin, body: { username, displayName: username, password: 'ExpiryLab-pass-123!', roles: [role], isActive: true } });
    return login(username, 'ExpiryLab-pass-123!');
  };
  const op = await newUser('vm-operator', 'operator');
  const appr = await newUser('vm-approver', 'approver');
  await api('POST', '/ssh-credentials', { token: admin, body: { name: 'vm-lab', username: 'segmentra', authMethod: 'KEY', privateKeyPem: key, scopeType: 'GLOBAL' } });
  for (const name of NAMES) {
    const vm = VMS[name];
    vm.record = { hostname: name, mgmtIp: HOST_FROM_DOCKER, sshPort: vm.ssh, enabled: true };
    vm.id = (await api('POST', '/hosts', { token: admin, body: { ...vm.record, firewallBackend: FIRST_BACKENDS[name] } })).host.id;
  }

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
  const why = async (id) => (await hostRows(id)).filter((r) => r.status !== 'SUCCEEDED').map((r) => String(r.message ?? r.status).slice(0, 260)).join(' | ');
  const ids = NAMES.map((vm) => VMS[vm].id);
  const deploy = async (v, extra = {}) => {
    const { deployment } = await api('POST', '/deployments', { token: op, body: { policyVersionId: v.id, mode: 'FULL', targetQuery: { hosts: ids, tags: [], vlans: [] }, ...extra } });
    const start = await raw('POST', `/deployments/${deployment.id}/start`, { token: op, body: { acceptReadinessNotes: true } });
    if (start.status >= 400) return { id: deployment.id, final: { status: `refused ${start.status}: ${start.text.slice(0, 300)}` } };
    return { id: deployment.id, final: await finished(deployment.id) };
  };
  const waitExpired = async (id, seconds = 300) => {
    for (let i = 0; i < seconds / 2; i += 1) {
      const d = await getDep(id);
      if (d.expired && d.expiry_outcome) return d;
      await sleep(2000);
    }
    return getDep(id);
  };
  const outcomeOf = (d) => (typeof d.expiry_outcome === 'string' ? JSON.parse(d.expiry_outcome) : d.expiry_outcome) ?? {};
  const inSeconds = (s) => new Date(Date.now() + s * 1000).toISOString();
  const drift = async (vm) => api('GET', `/compliance/hosts/${VMS[vm].id}`, { token: op });

  let n = 0;
  const round = async (executor, backends) => {
    const tag = `[${executor}]`;
    console.log(`\n=== ${executor}: ${NAMES.map((vm) => `${vm} on ${backends[vm]}`).join(', ')} ===`);
    await api('PUT', '/admin/executor-setting', { token: admin, body: { executor } });
    for (const vm of NAMES) await api('PUT', `/hosts/${VMS[vm].id}`, { token: admin, body: { ...VMS[vm].record, firewallBackend: backends[vm] } });
    const label = (vm) => `${tag} ${vm} (${backends[vm]})`;
    const ps = (await api('POST', '/policy-sets', { token: op, body: { name: `vm-${++n}`, scopeType: 'HOST_LIST', hostIds: ids } })).policySet;
    const version = async (port) => {
      const v = (await api('POST', `/policy-sets/${ps.id}/versions`, { token: op, body: { changeSummary: `allow ${port}`, interfaceScopeType: 'ALL_INTERFACES' } })).version;
      await api('POST', `/policy-versions/${v.id}/rules`, { token: op, body: { orderIndex: 10, direction: 'IN', action: 'ALLOW', protocol: 'tcp', ports: String(port), sourceType: 'CIDR', sourceValue: NET, logMode: 'NONE', usePolicyInterfaceScope: true, comment: `allow ${port}` } });
      await api('POST', `/policy-versions/${v.id}/submit-approval`, { token: op, body: {} });
      await api('POST', `/policy-versions/${v.id}/approve`, { token: appr, body: {} });
      return v;
    };
    const v1 = await version(P1);
    const v2 = await version(P2);

    const first = await deploy(v1);
    check(`${tag} v1 deploys`, first.final.status === 'SUCCEEDED', `${first.final.status} ${await why(first.id)}`);
    for (const vm of NAMES) check(`${label(vm)}: v1 enforced`, traffic(vm) === onlyP1, traffic(vm));
    for (const vm of NAMES.filter((x) => backends[x] === 'firewalld')) {
      const zone = sudo(vm, 'firewall-cmd --zone=public --list-interfaces').stdout.trim();
      check(`${tag} ${vm}: the reload kept NetworkManager's interface bindings`, /enp0s8/.test(zone) && /enp0s9/.test(zone), zone);
    }
    for (const row of await hostRows(first.id)) {
      const vm = NAMES.find((x) => VMS[x].id === row.host_id);
      check(`${label(vm)}: Segmentra reports the rules survive a reboot`, row.persistence_status === 'persisted', `${row.persistence_status}: ${row.persistence_message}`);
    }

    await sleep(1100);
    const dep = await deploy(v2, { expiresAt: inSeconds(25), expiryAction: 'REVERT' });
    check(`${tag} v2 deploys with a REVERT expiry`, ['SUCCEEDED', 'EXPIRED'].includes(dep.final.status), `${dep.final.status} ${await why(dep.id)}`);
    for (const vm of NAMES) check(`${label(vm)}: v2 enforced`, traffic(vm) === onlyP2, traffic(vm));
    const o = outcomeOf(await waitExpired(dep.id));
    check(`${tag} the job starts the revert to v1`, o.result === 'REVERT_STARTED' && o.revertToVersionNumber === v1.version_number, JSON.stringify(o));
    if (o.revertDeploymentId) {
      const rev = await finished(o.revertDeploymentId);
      check(`${tag} the revert deployment succeeds`, rev.status === 'SUCCEEDED', `${rev.status} ${await why(o.revertDeploymentId)}`);
    }
    for (const vm of NAMES) check(`${label(vm)}: v1 is back, real traffic`, traffic(vm) === onlyP1, traffic(vm));

    await reboot(tag);
    for (const vm of NAMES) {
      check(`${label(vm)}: after a real reboot the reverted v1 is enforced`, traffic(vm) === onlyP1, traffic(vm));
      const c = await drift(vm);
      check(`${label(vm)}: no drift after the reboot`, c.status === 'compliant', `${c.status}: ${c.message ?? ''}`);
    }

    await sleep(1100);
    const rem = await deploy(v2, { expiresAt: inSeconds(25), expiryAction: 'REMOVE' });
    check(`${tag} v2 deploys with a REMOVE expiry`, ['SUCCEEDED', 'EXPIRED'].includes(rem.final.status), `${rem.final.status} ${await why(rem.id)}`);
    const r = outcomeOf(await waitExpired(rem.id));
    check(`${tag} the job removes it`, r.result === 'REMOVED', JSON.stringify(r));
    for (const vm of NAMES) check(`${label(vm)}: rules gone, back to how the host was`, traffic(vm) === baseOf(backends[vm]) && !segmentraPresent(vm, backends[vm]), `${traffic(vm)}; present=${segmentraPresent(vm, backends[vm])}`);
    await reboot(tag);
    for (const vm of NAMES) check(`${label(vm)}: still gone after a real reboot`, traffic(vm) === baseOf(backends[vm]) && !segmentraPresent(vm, backends[vm]), `${traffic(vm)}; present=${segmentraPresent(vm, backends[vm])}`);
  };

  await round('ssh', FIRST_BACKENDS);
  await round('ansible', FIRST_BACKENDS);

  if (lab === 'rhel') {
    const move = sudo('seg-rhel', 'dnf install -y -q iptables-services nftables && systemctl disable --now firewalld && iptables-save > /etc/sysconfig/iptables && ip6tables-save > /etc/sysconfig/ip6tables && systemctl enable iptables ip6tables', 400_000);
    check('seg-rhel moves from firewalld to iptables, saving the ruleset first as Segmentra advises', move.status === 0, move.stderr);
    await round('ssh', { 'seg-rhel': 'iptables' });
    await round('ansible', { 'seg-rhel': 'iptables' });
    const off = sudo('seg-rhel', 'systemctl disable --now iptables ip6tables', 60_000);
    check('seg-rhel: the iptables services are switched off to move to nftables', off.status === 0, off.stderr);
    await round('ssh', { 'seg-rhel': 'nftables' });
    await round('ansible', { 'seg-rhel': 'nftables' });
    return;
  }

  if (lab === 'ubuntu') {
    // Installing iptables-persistent removes ufw (the packages conflict), so nftables comes first.
    const off = sudo('seg-ubu', 'ufw --force disable && systemctl disable ufw', 60_000);
    check('seg-ubu: UFW is switched off to move to nftables', off.status === 0, off.stderr);
    await round('ssh', { 'seg-ubu': 'nftables' });
    await round('ansible', { 'seg-ubu': 'nftables' });
    const ipt = sudo('seg-ubu', 'echo iptables-persistent iptables-persistent/autosave_v4 boolean false | debconf-set-selections; echo iptables-persistent iptables-persistent/autosave_v6 boolean false | debconf-set-selections; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends iptables-persistent', 240_000);
    check('seg-ubu: iptables-persistent is installed to move to iptables', ipt.status === 0, ipt.stderr);
    await round('ssh', { 'seg-ubu': 'iptables' });
    await round('ansible', { 'seg-ubu': 'iptables' });
    return;
  }

  // Rocky moves from firewalld to iptables, following Segmentra's advice for the stock iptables-services file.
  const move = sudo('seg-roc', 'systemctl disable --now firewalld && iptables-save > /etc/sysconfig/iptables && ip6tables-save > /etc/sysconfig/ip6tables && systemctl enable iptables ip6tables', 60_000);
  check('seg-roc moves from firewalld to iptables, saving the ruleset first as Segmentra advises', move.status === 0, move.stderr);
  const second = { 'seg-deb': 'nftables', 'seg-roc': 'iptables' };
  await round('ssh', second);
  await round('ansible', second);
}

main().catch((e) => {
  check(`the run finished without an error: ${e.message}`, false);
}).finally(() => {
  const failed = results.filter((r) => !r.pass);
  console.log(`\n${results.length - failed.length}/${results.length} checks passed`);
  for (const f of failed) console.log(`  FAILED: ${f.label}  (${String(f.detail).slice(0, 400)})`);
  if (keep || failed.length) {
    console.log(`[vm] Left running to look at. Clean up: (cd tests/expiry-lab/vm && vagrant destroy -f) and docker compose -f tests/expiry-lab/matrix/docker-compose.yml -p ${project} down -v`);
  } else {
    vagrant({}, 'destroy', '-f');
    compose('down', '-v', '--remove-orphans');
  }
  if (keyFile && !(keep || failed.length)) rmSync(dirname(keyFile), { recursive: true, force: true });
  process.exitCode = failed.length ? 1 : 0;
});
