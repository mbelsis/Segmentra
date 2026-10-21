#!/usr/bin/env node
// OT gateway integration test: a Debian gateway between an IT and an OT network, two Debian OT
// devices behind it (see docker-compose.yml). Through the real API: the gateway host (tag
// iot-gateway), the two assets assigned to it, a policy with FORWARD rules, deployment over SSH,
// and then real TCP/ICMP traffic from the IT clients through the gateway, protection coverage,
// ARP-based discovery, drift, unassigning a device, and policy removal.
//
//   node tests/ot-gateway-lab/run.mjs [--keep]      (API on http://127.0.0.1:18081)
import { spawn } from 'node:child_process';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, '..', '..');
const composeFile = path.join(here, 'docker-compose.yml');
const projectName = 'segmentra-ot';
const apiBase = 'http://127.0.0.1:18081/api';
const keepStack = process.argv.includes('--keep');

const GW = { it: '172.31.10.2', ot: '172.31.20.2' };
const PLC = '172.31.20.11';
const RTU = '172.31.20.12';
const HMI = '172.31.10.50';

const results = [];
const log = (m) => console.log(`[ot-lab] ${m}`);
function check(label, pass, detail = '') {
  results.push({ label, pass: !!pass });
  console.log(`  ${pass ? 'PASS' : 'FAIL'}  ${label}${detail ? `  (${detail})` : ''}`);
}

function run(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { cwd: repoRoot, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '', stderr = '';
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });
    child.on('error', reject);
    child.on('close', (code) => {
      if (code === 0 || options.allowFailure) resolve({ code: code ?? 0, stdout, stderr });
      else reject(new Error(`${command} ${args.join(' ')} failed (${code})\n${stderr || stdout}`));
    });
  });
}
const compose = (...a) => run('docker', ['compose', '-f', composeFile, '-p', projectName, ...a]);
const composeAllow = (...a) => run('docker', ['compose', '-f', composeFile, '-p', projectName, ...a], { allowFailure: true });
const exec = (service, cmd) => compose('exec', '-T', service, 'sh', '-c', cmd);
const execAllow = (service, cmd) => composeAllow('exec', '-T', service, 'sh', '-c', cmd);

async function api(method, p, { token, body, allow } = {}) {
  const res = await fetch(apiBase + p, {
    method,
    headers: { 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body)
  });
  const text = await res.text();
  let json; try { json = JSON.parse(text); } catch { json = { raw: text }; }
  if (!res.ok && !allow) throw new Error(`${method} ${p} -> ${res.status} ${text.slice(0, 500)}`);
  return { status: res.status, ...json };
}
const login = async (u, p) => (await api('POST', '/auth/login', { body: { username: u, password: p } })).token;

async function startStack() {
  log('Building and starting the OT gateway lab');
  await composeAllow('down', '-v', '--remove-orphans');
  await compose('up', '-d', '--build', 'db', 'gateway', 'plc-1', 'rtu-2', 'hmi', 'eng');
  await compose('build', 'api');
  await compose('run', '--rm', 'api', 'npm', 'run', 'migrate:up', '-w', '@segmentra/db');
  await compose('run', '--rm', 'api', 'npm', 'run', 'seed', '-w', '@segmentra/db');
  await compose('up', '-d', 'api');
  for (let i = 0; i < 60; i += 1) {
    try { if ((await fetch(`${apiBase}/health`)).ok) return; } catch { /* retry */ }
    await delay(2000);
  }
  throw new Error('API did not become healthy');
}

// --- traffic helpers --------------------------------------------------------------------------
async function listen(service, ...ports) {
  await exec(service, `pkill -x nc 2>/dev/null; ${ports.map((p) => `(nc -l -k -p ${p} >/dev/null 2>&1 &)`).join('; ')}; sleep 0.3`);
}
async function tcp(from, ip, port) {
  return (await execAllow(from, `nc -z -w 2 ${ip} ${port}`)).code === 0;
}
async function ping(from, ip) {
  return (await execAllow(from, `ping -c 1 -W 1 ${ip} >/dev/null`)).code === 0;
}
async function fwdRules() {
  return (await execAllow('gateway', 'iptables -S SEGMENTRA-FWD')).stdout;
}
async function counter(match) {
  const { stdout } = await exec('gateway', 'iptables -L SEGMENTRA-FWD -v -n -x');
  const line = stdout.split('\n').find((l) => l.includes(match));
  return line ? Number(line.trim().split(/\s+/)[0]) : -1;
}

async function deploy(token, versionId, hostId) {
  const dep = await api('POST', '/deployments', { token, body: { policyVersionId: versionId, mode: 'FULL', targetQuery: { hosts: [hostId], tags: [], vlans: [] } } });
  await api('POST', `/deployments/${dep.deployment.id}/start`, { token, body: {} });
  for (let i = 0; i < 60; i += 1) {
    const d = await api('GET', `/deployments/${dep.deployment.id}`, { token });
    if (['SUCCEEDED', 'FAILED', 'PARTIAL'].includes(d.deployment.status)) return { id: dep.deployment.id, status: d.deployment.status };
    await delay(2000);
  }
  return { id: dep.deployment.id, status: 'TIMEOUT' };
}

async function main() {
  await run('docker', ['version']);
  await startStack();

  const admin = await login('admin', 'admin123');
  const mk = async (username, role) => {
    await api('POST', '/admin/users', { token: admin, body: { username, displayName: username, password: 'OtLab-pass-123!', roles: [role], isActive: true }, allow: true });
    return login(username, 'OtLab-pass-123!');
  };
  const op = await mk('ot-operator', 'operator');
  const appr = await mk('ot-approver', 'approver');

  // Management network = IT network, so the gateway's SSH baseline allows the API and the clients.
  const vlan = await api('POST', '/vlans', { token: admin, body: { vlanTag: 10, name: 'it-mgmt', description: 'IT / management network', subnet: '172.31.10.0/24' } });
  await api('PUT', '/admin/management-vlan-setting', { token: admin, body: { vlanId: vlan.vlan.id } });
  await api('PUT', '/admin/executor-setting', { token: admin, body: { executor: 'ssh' } });
  await api('POST', '/ssh-credentials', { token: admin, body: { name: 'ot-lab-password', username: 'segmentra', authMethod: 'PASSWORD', password: 'segmentra123!', scopeType: 'GLOBAL' } });

  console.log('\nLab topology');
  await listen('plc-1', 502, 102);
  await listen('rtu-2', 502, 20000, 102);
  check('hmi reaches plc-1 Modbus (502) and S7 (102) through the gateway before any policy', await tcp('hmi', PLC, 502) && await tcp('hmi', PLC, 102));
  check('hmi reaches rtu-2 DNP3 (20000) and Modbus (502) through the gateway before any policy', await tcp('hmi', RTU, 20000) && await tcp('hmi', RTU, 502));
  check('the traffic really goes through the gateway (traceroute-free: the gateway forwards, devices default-route to it)', /172\.31\.20\.2/.test((await exec('plc-1', 'ip route show default')).stdout) && /1/.test((await exec('gateway', 'cat /proc/sys/net/ipv4/ip_forward')).stdout));

  console.log('\nInventory: gateway host and OT assets');
  const iotTag = (await api('GET', '/tags', { token: op })).tags.find((t) => t.name === 'iot-gateway');
  const gw = (await api('POST', '/hosts', { token: op, body: { hostname: 'ot-gw', mgmtIp: GW.it, sshPort: 22, firewallBackend: 'iptables', enabled: true, tagIds: [iotTag.id] } })).host;
  const readiness = await api('POST', `/host-readiness/hosts/${gw.id}/check`, { token: op });
  check('readiness on the gateway over SSH: no errors, iptables found', (readiness.errors ?? []).length === 0 && /iptables/.test(readiness.iptablesVersion ?? ''), readiness.iptablesVersion);
  const plc = (await api('POST', '/iot-assets', { token: op, body: { name: 'plc-1', assetType: 'plc', vendor: 'Siemens', model: 'S7-1500', ipAddress: PLC, zone: 'line-1', criticality: 'critical', gatewayIds: [gw.id] } })).asset;
  const rtu = (await api('POST', '/iot-assets', { token: op, body: { name: 'rtu-2', assetType: 'other', vendor: 'Schneider', model: 'SCADAPack', ipAddress: RTU, zone: 'line-1', criticality: 'high', gatewayIds: [gw.id] } })).asset;
  const cov = async () => { const r = await api('GET', '/iot-assets/coverage', { token: op }); return { r, by: (n) => r.assets.find((a) => a.name === n) }; };
  let c = await cov();
  check('both assets are GATEWAY_NOT_DEPLOYED before the first deployment', c.by('plc-1')?.state === 'GATEWAY_NOT_DEPLOYED' && c.by('rtu-2')?.state === 'GATEWAY_NOT_DEPLOYED', `${c.by('plc-1')?.state} ${c.by('rtu-2')?.state}`);

  console.log('\nDiscovery from the gateway (ARP neighbours)');
  const disc = await api('POST', '/iot-assets/discover', { token: op, body: { gatewayId: gw.id } });
  const found = (ip) => disc.devices?.find((d) => d.ip === ip);
  check('the gateway neighbour table lists both OT devices as known assets', found(PLC)?.status === 'known' && found(RTU)?.status === 'known', JSON.stringify(disc.devices?.map((d) => `${d.ip}:${d.status}`)));

  console.log('\nPolicy with FORWARD rules (scope: tag iot-gateway)');
  const ps = (await api('POST', '/policy-sets', { token: op, body: { name: 'OT gateway policy', description: 'HMI to PLC Modbus, SCADA to RTU DNP3, no Modbus to the RTU', scopeType: 'TAG', scopeTagId: iotTag.id } })).policySet;
  const v = (await api('POST', `/policy-sets/${ps.id}/versions`, { token: op, body: { changeSummary: 'initial OT rules', interfaceScopeType: 'ALL_INTERFACES' } })).version;
  const rule = (orderIndex, action, protocol, ports, sourceValue, destinationValue, comment, logMode = 'NONE') => api('POST', `/policy-versions/${v.id}/rules`, {
    token: op,
    body: { orderIndex, direction: 'FORWARD', action, protocol, ports, sourceType: 'CIDR', sourceValue, destinationType: 'IOT_ASSET', destinationValue, logMode, comment, usePolicyInterfaceScope: true }
  });
  await rule(10, 'ALLOW', 'tcp', '502', `${HMI}/32`, plc.id, 'hmi-modbus-to-plc');
  await rule(20, 'ALLOW', 'tcp', '20000', `${HMI}/32`, rtu.id, 'scada-dnp3-to-rtu');
  await rule(30, 'DENY', 'tcp', '502', '172.31.10.0/24', rtu.id, 'no-modbus-to-rtu', 'LOG');
  await api('POST', `/policy-versions/${v.id}/submit-approval`, { token: op, body: {} });
  await api('POST', `/policy-versions/${v.id}/approve`, { token: appr, body: {} });
  const d1 = await deploy(op, v.id, gw.id);
  check('the policy deploys to the gateway over SSH', d1.status === 'SUCCEEDED', d1.status);
  const fwd = await fwdRules();
  check('SEGMENTRA-FWD holds the three FORWARD rules and the default deny for both protected devices',
    /-A SEGMENTRA-FWD -s 172\.31\.10\.50\/32 -d 172\.31\.20\.11\/32 -p tcp -m tcp --dport 502 [^\n]*-j RETURN/.test(fwd)
    && /-A SEGMENTRA-FWD -s 172\.31\.10\.50\/32 -d 172\.31\.20\.12\/32 -p tcp -m tcp --dport 20000 [^\n]*-j RETURN/.test(fwd)
    && /-A SEGMENTRA-FWD -s 172\.31\.10\.0\/24 -d 172\.31\.20\.12\/32 -p tcp -m tcp --dport 502 [^\n]*-j DROP/.test(fwd)
    && /-A SEGMENTRA-FWD -d 172\.31\.20\.11\/32 [^\n]*protected_default_deny[^\n]*-j DROP/.test(fwd)
    && /-A SEGMENTRA-FWD -d 172\.31\.20\.12\/32 [^\n]*protected_default_deny[^\n]*-j DROP/.test(fwd),
    fwd.split('\n').filter((l) => /-A SEGMENTRA-FWD/.test(l)).length + ' rules');
  check('the FORWARD jump exists exactly once and the FORWARD policy is untouched', (await exec('gateway', 'iptables -S FORWARD')).stdout.split('\n').filter((l) => l === '-A FORWARD -j SEGMENTRA-FWD').length === 1 && /^-P FORWARD ACCEPT/m.test((await exec('gateway', 'iptables -S FORWARD')).stdout));

  console.log('\nLive traffic through the gateway');
  check('hmi -> plc-1 Modbus 502 is allowed', await tcp('hmi', PLC, 502));
  check('hmi -> plc-1 S7 102 is blocked (default deny for a protected device)', !(await tcp('hmi', PLC, 102)));
  check('eng-ws -> plc-1 Modbus 502 is blocked (only the HMI may)', !(await tcp('eng', PLC, 502)));
  check('hmi -> rtu-2 DNP3 20000 is allowed', await tcp('hmi', RTU, 20000));
  const before = await counter('no-modbus-to-rtu');
  check('hmi -> rtu-2 Modbus 502 is blocked by the explicit DENY rule', !(await tcp('hmi', RTU, 502)));
  const after = await counter('no-modbus-to-rtu');
  check('the DENY rule counter increased', after > before, `${before} -> ${after}`);
  check('eng-ws -> rtu-2 DNP3 20000 is blocked', !(await tcp('eng', RTU, 20000)));
  check('ping hmi -> plc-1 is blocked (ICMP not allowed to a protected device)', !(await ping('hmi', PLC)));
  check('plc-1 -> rtu-2 Modbus on the OT network itself is not filtered (not routed through the gateway)', await tcp('plc-1', RTU, 502));
  check('the gateway itself still accepts SSH from the IT network (management baseline)', await tcp('hmi', GW.it, 22));
  check('the DENY rule with log mode LOG has a LOG rule in front of its DROP', /-A SEGMENTRA-FWD -s 172\.31\.10\.0\/24 -d 172\.31\.20\.12\/32 -p tcp -m tcp --dport 502 [^\n]*-j LOG --log-prefix "SEGMENTRA: DENY no-modbus-t: "/.test(fwd));
  // The container cannot read its own kernel log; the Docker host kernel ring buffer has the lines.
  const ring = await run('docker', ['run', '--rm', '--privileged', '--net=host', 'alpine:3.20', 'sh', '-c', 'dmesg 2>/dev/null | grep -c "SEGMENTRA: DENY no-modbus-t: .*DST=172.31.20.12"'], { allowFailure: true });
  check('the blocked Modbus attempts were logged by the kernel', Number(ring.stdout.trim()) > 0, `${ring.stdout.trim()} lines in the Docker host kernel log`);

  console.log('\nCoverage, active rules and drift');
  c = await cov();
  check('both assets are PROTECTED', c.by('plc-1').state === 'PROTECTED' && c.by('rtu-2').state === 'PROTECTED');
  check('plc-1 lists Modbus/TCP from the HMI as allowed and flags it as cleartext', c.by('plc-1').rules.some((r) => r.action === 'ALLOW' && r.ports === '502' && r.services.includes('Modbus/TCP') && r.from === `${HMI}/32`) && c.by('plc-1').cleartextAllowed.includes('Modbus/TCP'));
  check('rtu-2 lists the DNP3 allow and the Modbus deny', c.by('rtu-2').rules.some((r) => r.action === 'ALLOW' && r.ports === '20000') && c.by('rtu-2').rules.some((r) => r.action === 'DENY' && r.ports === '502'));
  const active = await api('GET', `/troubleshoot/hosts/${gw.id}/policies`, { token: op });
  check('Active Rules for the gateway show the current deployment with its FORWARD rules', active.policies.some((p) => p.current && p.rules.some((r) => r.direction === 'FORWARD')));
  const comp1 = await api('GET', `/compliance/hosts/${gw.id}`, { token: op });
  check('the gateway is compliant after the deployment', comp1.status === 'compliant', comp1.status);
  // Delete the HMI->PLC allow exactly as iptables prints it (the comment is quoted in -S output).
  await exec('gateway', `eval "iptables $(iptables -S SEGMENTRA-FWD | grep -- '-d ${PLC}/32 -p tcp' | grep -- '--dport 502' | sed 's/^-A/-D/')"`);
  const comp2 = await api('GET', `/compliance/hosts/${gw.id}`, { token: op });
  check('deleting a FORWARD rule by hand is reported as drift', comp2.status === 'drifted', comp2.status);
  check('and the HMI really lost Modbus access', !(await tcp('hmi', PLC, 502)));
  const d2 = await deploy(op, v.id, gw.id);
  check('redeploying restores the rule and the access', d2.status === 'SUCCEEDED' && (await tcp('hmi', PLC, 502)) && (await api('GET', `/compliance/hosts/${gw.id}`, { token: op })).status === 'compliant');

  console.log('\nUnassigning a device from the gateway');
  await api('DELETE', `/iot-assets/${rtu.id}/gateways/${gw.id}`, { token: op });
  c = await cov();
  check('rtu-2 is NO_GATEWAY and plc-1 stays PROTECTED (coverage)', c.by('rtu-2').state === 'NO_GATEWAY' && c.by('plc-1').state === 'PROTECTED', `${c.by('rtu-2').state}`);
  check('until the gateway is redeployed, rtu-2 is still default-denied on the gateway', !(await tcp('hmi', RTU, 102)));
  const d3 = await deploy(op, v.id, gw.id);
  check('after the redeployment rtu-2 is no longer default-denied (other ports pass) while the explicit DENY still blocks Modbus', d3.status === 'SUCCEEDED' && (await tcp('hmi', RTU, 102)) && !(await tcp('hmi', RTU, 502)));
  check('plc-1 is still protected', !(await tcp('hmi', PLC, 102)) && (await tcp('hmi', PLC, 502)));

  console.log('\nPolicy removal');
  const expDep = await api('POST', '/deployments', { token: op, body: { policyVersionId: v.id, mode: 'FULL', targetQuery: { hosts: [gw.id], tags: [], vlans: [] }, expiresAt: new Date(Date.now() + 70_000).toISOString(), expiryAction: 'REMOVE' }, allow: true });
  if (expDep.status < 300) {
    await api('POST', `/deployments/${expDep.deployment.id}/start`, { token: op, body: {} });
    let st = '';
    for (let i = 0; i < 90; i += 1) { st = (await api('GET', `/deployments/${expDep.deployment.id}`, { token: op })).deployment.status; if (st === 'EXPIRED') break; await delay(2000); }
    check('a deployment with a one-minute expiry and REMOVE is marked EXPIRED', st === 'EXPIRED', st);
    check('SEGMENTRA-FWD and the FORWARD jump are gone and all traffic to the devices passes again', !/SEGMENTRA-FWD/.test((await execAllow('gateway', 'iptables -S')).stdout) && (await tcp('hmi', PLC, 102)) && (await tcp('eng', RTU, 502)));
  } else {
    check('deployment expiry could not be requested through the API', false, `${expDep.status} ${JSON.stringify(expDep).slice(0, 200)}`);
  }

  const failed = results.filter((r) => !r.pass);
  console.log(`\n${results.length - failed.length}/${results.length} checks passed`);
  if (failed.length > 0) throw new Error(`failed: ${failed.map((f) => f.label).join('; ')}`);
}

main().then(async () => {
  log('OT gateway integration test completed successfully');
  if (keepStack) log('Leaving the lab running (--keep); API on http://127.0.0.1:18081');
  else { log('Tearing down the lab'); await composeAllow('down', '-v', '--remove-orphans'); }
}).catch(async (e) => {
  console.error(e.message);
  process.exitCode = 1;
  if (!keepStack) await composeAllow('down', '-v', '--remove-orphans');
});
