import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { compileHostPolicy } from '../packages/compiler/dist/index.js';
import { DETECT_FIREWALL_BACKEND, SEGMENTRA_MANAGER_PY, hashLiveRuleset, runSshDeployment, removeSegmentraPolicy, startAuditSession, checkHostReadiness, readHostFirewallRules } from '../packages/executor/dist/index.js';

const image = 'segmentra-native-firewall-test';
const suffix = `${process.pid}-${Date.now()}`;
const network = `segmentra-native-${suffix}`;
const containers = [];
const keep = process.argv.includes('--keep');
const runtime = mkdtempSync(join(tmpdir(), 'segmentra-native-'));
const privateKeyPath = join(runtime, 'id_ed25519');
function docker(...args) {
  return execFileSync('docker', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 120_000, maxBuffer: 4 * 1024 * 1024 }).trim();
}
function write(container, path, content) {
  execFileSync('docker', ['exec', '-i', container, 'tee', path], { input: content, stdio: ['pipe', 'ignore', 'pipe'], timeout: 30_000 });
}
function report(container, message) {
  console.log(message);
  docker('exec', container, 'python3', '-c',
    'import sys; message=sys.argv[1]+"\\n"; open("/var/backups/segmentra/test-results.log","a").write(message); open("/proc/1/fd/1","w").write(message)', message);
}
async function waitReady(container) {
  for (let attempt = 0; attempt < 40; attempt++) {
    try { docker('exec', container, 'test', '-e', '/run/manager-ready'); return; } catch { /* still starting */ }
    await new Promise(resolve => setTimeout(resolve, 500));
  }
  throw new Error(`Native manager did not start: ${docker('logs', container)}`);
}
function input(backend) {
  return {
    host: { id: 'test', hostname: backend, mgmtIp: null, sshPort: 22, firewallBackend: backend, interfaces: [] },
    policyInterfaceScope: { type: 'ALL_INTERFACES' }, baseline: { mgmtSshCidrs: [] }, sets: {},
    rules: [{ orderIndex: 1, direction: 'IN', action: 'ALLOW', protocol: 'tcp', ports: '5432', sourceType: 'CIDR', sourceValue: 'any', remote: { kind: 'CIDR' }, usePolicyInterfaceScope: true, logMode: 'NONE' }]
  };
}

let networkCreated = false;
try {
  execFileSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-f', privateKeyPath]);
  docker('build', '-t', image, 'tests/native-firewall');
  docker('network', 'create', '--ipv6', '--subnet', `fd42:7365:${(process.pid % 65535).toString(16)}:${(Date.now() % 65535).toString(16)}::/64`, network);
  networkCreated = true;
  for (const backend of process.argv.includes('--ufw') ? ['ufw'] : ['firewalld', 'ufw']) {
    const sshOptions = { knownHostsPath: join(runtime, `${backend}.known_hosts`), timeoutMs: 30_000 };
    const container = `segmentra-native-${backend}-${suffix}`;
    containers.push(container);
    docker('run', '-d', '--name', container, '--network', network, '--cap-add=NET_ADMIN', '--cap-add=NET_RAW',
      '-p', '127.0.0.1::22', '-v', `${runtime}:/runtime-keys:ro`, '-e', `MANAGER=${backend}`, image);
    await waitReady(container);
    report(container, `${backend}: integration test started at ${new Date().toISOString()}`);
    assert.equal(docker('exec', container, 'sh', '-c', DETECT_FIREWALL_BACKEND), backend);
    const port = Number(docker('port', container, '22/tcp').split(':').at(-1));
    const host = { hostname: backend, ip: '127.0.0.1', port, username: 'segmentra', authMethod: 'key', privateKeyPath, backend };
    const readiness = await checkHostReadiness({ ...host, backend: 'auto' }, sshOptions);
    assert.equal(readiness.ready, true, JSON.stringify(readiness));
    assert.equal(readiness.backend, backend);
    write(container, '/var/backups/segmentra/segmentra-manager.py', SEGMENTRA_MANAGER_PY);
    write(container, '/etc/segmentra.policy', compileHostPolicy(input(backend)).text);
    const command = mode => docker('exec', container, 'python3', '/var/backups/segmentra/segmentra-manager.py', backend, mode,
      ...(mode === 'apply' ? ['/etc/segmentra.policy'] : ['backup', 'restore'].includes(mode) ? ['/var/backups/segmentra/test-backup.json'] : []));

    // Administrator-managed rules/configuration must survive every operation.
    if (backend === 'firewalld') {
      docker('exec', container, 'firewall-cmd', '--permanent', '--zone=public', '--add-port=9999/tcp');
      docker('exec', container, 'firewall-cmd', '--reload');
    } else {
      docker('exec', container, 'ufw', 'allow', '9999/tcp');
    }
    command('backup');
    const policyFilePath = join(runtime, `${backend}.policy`);
    writeFileSync(policyFilePath, compileHostPolicy(input(backend)).text, { mode: 0o600 });
    const deploy = async () => {
      const [result] = await runSshDeployment({ hosts: [{ ...host, policyFilePath }], knownHostsPath: sshOptions.knownHostsPath, commandTimeoutMs: sshOptions.timeoutMs, rollbackTimeoutSec: 120 });
      assert.equal(result.success, true, JSON.stringify(result));
      assert.equal(result.persistence?.status, 'persisted', JSON.stringify(result));
      return result;
    };
    const applied = await deploy();
    const initial = command('read');
    assert.equal(JSON.parse(initial).present, true);
    const baseline = hashLiveRuleset(backend, initial);
    assert.equal(applied.liveRulesHash, baseline);
    const readback = await readHostFirewallRules({ ...host, backend: 'auto' }, sshOptions);
    assert.equal(readback.rulesHash, baseline);

    // Learning must fail before touching the permanent ACL or live enforcement.
    const learning = await startAuditSession(host, '/var/log/segmentra-learning.log', sshOptions);
    assert.equal(learning.success, false);
    assert.match(learning.stderr, /Learning sessions are not supported/);
    assert.throws(() => compileHostPolicy({ ...input(backend), logOnlyMode: true }), /learning mode is not supported/);
    assert.equal(hashLiveRuleset(backend, command('read')), baseline);
    assert.match(command('persist'), /status=persisted/);
    report(container, `${backend}: SSH readiness, deployment, readback and safe learning-mode rejection passed`);

    if (backend === 'firewalld') {
      docker('exec', container, 'firewall-cmd', '--zone=public', '--add-port=7777/tcp');
      assert.throws(() => command('apply'), /unsaved runtime/);
      assert.match(docker('exec', container, 'firewall-cmd', '--zone=public', '--query-port=7777/tcp'), /yes/);
      assert.equal(hashLiveRuleset(backend, command('read')), baseline);
      docker('exec', container, 'firewall-cmd', '--zone=public', '--remove-port=7777/tcp');
    }

    // Native reload must retain Segmentra rules without an SSH connection/control plane.
    docker('exec', container, backend === 'firewalld' ? 'firewall-cmd' : 'ufw', backend === 'firewalld' ? '--reload' : 'reload');
    assert.equal(hashLiveRuleset(backend, command('read')), baseline);

    // Restart destroys the network namespace's live rules. Only the native boot loader
    // reactivates them; no Segmentra helper runs in the container entrypoint.
    docker('exec', container, 'rm', '-f', '/run/manager-ready');
    docker('restart', '-t', '2', container);
    await waitReady(container);
    // Docker Desktop can assign a new ephemeral published port after restart.
    host.port = Number(docker('port', container, '22/tcp').split(':').at(-1));
    sshOptions.knownHostsPath = join(runtime, `${backend}-${host.port}.known_hosts`);
    assert.equal(hashLiveRuleset(backend, command('read')), baseline);
    assert.match(command('persist'), /status=persisted/);

    // Check real traffic from a separate container, not just generated syntax.
    const server = 'import socket,select; sockets=[]\nfor family,host in ((socket.AF_INET,"0.0.0.0"),(socket.AF_INET6,"::")):\n for port in (5432,5433):\n  s=socket.socket(family); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n  if family==socket.AF_INET6: s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)\n  s.bind((host,port)); s.listen(); sockets.append(s)\nwhile True:\n for s in select.select(sockets,[],[])[0]:\n  c,_=s.accept(); c.close()';
    docker('exec', '-d', container, 'python3', '-c', server);
    await new Promise(resolve => setTimeout(resolve, 300));
    const address = docker('inspect', '--format', `{{(index .NetworkSettings.Networks "${network}").IPAddress}}`, container);
    const client = 'import socket,sys\nfor port,expected in ((5432,True),(5433,False)):\n try:\n  s=socket.create_connection((sys.argv[1],port),timeout=2); s.close(); actual=True\n except OSError: actual=False\n assert actual==expected,(port,actual,expected)';
    docker('run', '--rm', '--network', network, '--entrypoint', 'python3', image, '-c', client, address);
    const address6 = docker('inspect', '--format', `{{(index .NetworkSettings.Networks "${network}").GlobalIPv6Address}}`, container);
    assert.ok(address6);
    docker('run', '--rm', '--network', network, '--entrypoint', 'python3', image, '-c', client, address6);

    // A live administrator edit is drift; restore only Segmentra's saved state.
    if (backend === 'firewalld') {
      docker('exec', container, 'firewall-cmd', '--policy=segmentra-in', '--add-port=5555/tcp');
    } else {
      docker('exec', container, 'iptables', '-I', 'SEGMENTRA-IN', '1', '-p', 'tcp', '--dport', '5555', '-j', 'DROP');
    }
    assert.notEqual(hashLiveRuleset(backend, command('read')), baseline);
    command('restore');
    assert.equal(JSON.parse(command('read')).present, false);
    await deploy();
    const removed = await removeSegmentraPolicy({ ...host, backend: 'auto' }, sshOptions);
    assert.equal(removed.success, true, JSON.stringify(removed));
    assert.equal(removed.persistence?.status, 'removed', JSON.stringify(removed));
    assert.equal(JSON.parse(command('read')).present, false);
    // Once Segmentra is removed, native administrator allows govern traffic again.
    if (backend === 'firewalld') {
      docker('exec', container, 'firewall-cmd', '--permanent', '--zone=public', '--add-port=5433/tcp');
      docker('exec', container, 'firewall-cmd', '--reload');
    } else {
      docker('exec', container, 'ufw', 'allow', '5433/tcp');
    }
    const removalClient = 'import socket,sys; s=socket.create_connection((sys.argv[1],5433),timeout=2); s.close()';
    docker('run', '--rm', '--network', network, '--entrypoint', 'python3', image, '-c', removalClient, address);
    docker('run', '--rm', '--network', network, '--entrypoint', 'python3', image, '-c', removalClient, address6);
    const admin = docker('exec', container, backend === 'firewalld' ? 'firewall-cmd' : 'ufw',
      ...(backend === 'firewalld' ? ['--permanent', '--zone=public', '--query-port=9999/tcp'] : ['status']));
    assert.match(admin, backend === 'firewalld' ? /yes/ : /9999/);
    docker('exec', container, 'rm', '-f', '/run/manager-ready');
    docker('restart', '-t', '2', container);
    await waitReady(container);
    assert.equal(JSON.parse(command('read')).present, false);
    report(container, `${backend}: apply, native reload, restart persistence, drift, rollback, removal and administrator-rule preservation passed`);
    if (keep) {
      host.port = Number(docker('port', container, '22/tcp').split(':').at(-1));
      sshOptions.knownHostsPath = join(runtime, `${backend}-${host.port}.known_hosts`);
      await deploy();
      assert.equal(hashLiveRuleset(backend, command('read')), baseline);
      docker('exec', '-d', container, 'python3', '-c', server);
      await new Promise(resolve => setTimeout(resolve, 300));
      docker('run', '--rm', '--network', network, '--entrypoint', 'python3', image, '-c', client, address);
      docker('run', '--rm', '--network', network, '--entrypoint', 'python3', image, '-c', client, address6);
      report(container, `${backend}: PASS; sample ACL redeployed for inspection (SSH 22 and TCP 5432 allowed, TCP 5433 blocked); completed at ${new Date().toISOString()}`);
    }
  }
} finally {
  if (keep && networkCreated) {
    console.log(`Kept containers: ${containers.join(', ')}`);
    console.log(`Kept network: ${network}; temporary SSH keys and policy files: ${runtime}`);
    console.log('Test results are in each container log and /var/backups/segmentra/test-results.log.');
  } else {
    for (const container of containers) {
      try { docker('rm', '-f', container); } catch { /* preserve original failure */ }
    }
    if (networkCreated) docker('network', 'rm', network);
    rmSync(runtime, { recursive: true, force: true });
  }
}
