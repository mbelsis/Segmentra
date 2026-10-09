#!/usr/bin/env node
// IoT/OT integration test against a running Segmentra API (default http://localhost:8080/api, admin/admin123; see SEGMENTRA_API,
// SEGMENTRA_ADMIN_USER, SEGMENTRA_ADMIN_PASSWORD) and Docker. It builds a real IoT gateway (a container with sshd and iptables) and two
// "devices" on a private network, so the gateway has a real ARP table, and checks: the protocol catalog and the service shorthand in policy
// documents, passive discovery over SSH, the vendor list, protection coverage through a real deployment, and the compliance report.
// Run it against a development stack: it creates users, hosts, assets and policy sets (approved versions are archived), and removes the
// containers and the test vendor entry at the end.
import { spawnSync } from 'node:child_process';
import { copyFileSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const apiBase = process.env.SEGMENTRA_API ?? 'http://localhost:8080/api';
const adminUser = process.env.SEGMENTRA_ADMIN_USER ?? 'admin';
const adminPass = process.env.SEGMENTRA_ADMIN_PASSWORD ?? 'admin123';
const suffix = Date.now().toString(36);
const NET = `segiot-${suffix}`, GW = `segiot-gw-${suffix}`, D1 = `segiot-d1-${suffix}`, D2 = `segiot-d2-${suffix}`;
const SSH_PORT = 2290 + Math.floor(Math.random() * 90);
const FIXTURE_VENDOR = 'Siemens AG (segmentra test fixture)';
const results = [];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const docker = (...a) => spawnSync('docker', a, { encoding: 'utf8' });
function check(label, pass, detail = '') {
  results.push({ label, pass: !!pass });
  console.log(`  ${pass ? 'PASS' : 'FAIL'}  ${label}${detail ? `  (${detail})` : ''}`);
}
async function raw(method, path, { token, body, type } = {}) {
  const headers = { ...(token ? { authorization: `Bearer ${token}` } : {}) };
  let payload;
  if (body !== undefined) { if (typeof body === 'string') { headers['content-type'] = type ?? 'text/plain'; payload = body; } else { headers['content-type'] = 'application/json'; payload = JSON.stringify(body); } }
  const res = await fetch(`${apiBase}${path}`, { method, headers, body: payload });
  const text = await res.text(); let json = null; try { json = JSON.parse(text); } catch { /* not json */ }
  return { status: res.status, text, json };
}
const api = async (m, p, o) => { const r = await raw(m, p, o); if (r.status >= 400) throw new Error(`${m} ${p} -> ${r.status}: ${r.text}`); return r.json; };
const login = async (u, p) => (await api('POST', '/auth/login', { body: { username: u, password: p } })).token;
async function ensureUser(admin, username, role) {
  const r = await raw('POST', '/admin/users', { token: admin, body: { username, displayName: username, password: 'IotTest-pass-123!', roles: [role], isActive: true } });
  if (![201, 409].includes(r.status)) throw new Error(`user ${username}: ${r.status} ${r.text}`);
  return login(username, 'IotTest-pass-123!');
}
function forgetHostKey(port) {
  const kh = process.env.SEGMENTRA_KNOWN_HOSTS || join(process.env.HOME ?? '', '.ssh', 'known_hosts');
  if (!existsSync(kh)) return;
  const tmp = join(mkdtempSync(join(tmpdir(), 'segiot-kh-')), 'known_hosts');
  copyFileSync(kh, tmp);
  spawnSync('ssh-keygen', ['-q', '-R', `[127.0.0.1]:${port}`, '-f', tmp], { encoding: 'utf8' });
  if (readFileSync(kh, 'utf8') !== readFileSync(tmp, 'utf8')) writeFileSync(kh, readFileSync(tmp));
  rmSync(dirname(tmp), { recursive: true, force: true });
}
const dbContainer = () => (docker('ps', '--format', '{{.Names}}').stdout.split('\n').find((n) => /segmentra.*db/i.test(n) && !/swarm/.test(n)) ?? '').trim();
const psql = (sql) => spawnSync('docker', ['exec', dbContainer(), 'psql', '-U', 'segmentra', '-d', 'segmentra', '-tAc', sql], { encoding: 'utf8' });

async function main() {
  if (docker('info').status !== 0) throw new Error('Docker is not available');
  const admin = await login(adminUser, adminPass);
  const op = await ensureUser(admin, 'iot-operator', 'operator');
  const appr = await ensureUser(admin, 'iot-approver', 'approver');
  const viewer = await ensureUser(admin, 'iot-viewer', 'viewer');
  const executorBefore = (await api('GET', '/admin/executor-setting', { token: admin })).executor;
  const versions = []; let credId = null; const hostIds = [];
  let ouiInserted = false;

  try {
    console.log('Protocol catalog and policy-as-code services');
    const cat = await raw('GET', '/iot-assets/protocols', { token: viewer });
    check('a viewer can read the protocol catalog; Modbus/TCP is tcp 502 and flagged cleartext', cat.status === 200 && cat.json.protocols.length >= 30 && (() => { const m = cat.json.protocols.find((p) => p.id === 'modbus-tcp'); return m.transports[0].ports === '502' && m.security === 'cleartext'; })());
    check('the catalog needs a token (401)', (await raw('GET', '/iot-assets/protocols')).status === 401);

    const tagName = `iot-src-${suffix}`;
    await api('POST', '/tags', { token: op, body: { name: tagName } });
    const doc = (name, rules, scope) => ({ apiVersion: 'segmentra.io/v1', kind: 'PolicySet', metadata: { name }, spec: { scope: scope ?? { type: 'TAG', tag: tagName }, rules } });
    const imp = (d, q = '?dryRun=true') => raw('POST', `/policy-sets/import${q}`, { token: op, body: d });
    const svc = await imp(doc(`iot-svc-${suffix}`, [{ action: 'ALLOW', service: 'modbus-tcp', source: '10.20.0.0/24', comment: 'hmi' }]));
    check('service: modbus-tcp expands to tcp/502', svc.status === 200 && svc.json.diff.added.length === 1 && /tcp\/502/.test(svc.json.diff.added[0]), svc.json?.diff?.added?.[0]);
    const dnp = await imp(doc(`iot-dnp-${suffix}`, [{ order: 10, action: 'ALLOW', service: 'dnp3', source: '10.20.0.0/24' }]));
    check('a service with two transports (DNP3) becomes two rules', dnp.status === 200 && dnp.json.diff.added.length === 2 && dnp.json.diff.added.some((a) => /tcp\/20000/.test(a)) && dnp.json.diff.added.some((a) => /udp\/20000/.test(a)));
    const both = await imp(doc(`iot-bad-${suffix}`, [{ action: 'ALLOW', service: 'modbus-tcp', protocol: 'tcp', source: '10.0.0.0/8' }]));
    check('service together with protocol is rejected with its path', both.status === 400 && both.json.problems.some((p) => p.path === 'spec.rules[0].service'));
    const unk = await imp(doc(`iot-bad-${suffix}`, [{ action: 'ALLOW', service: 'nope', source: '10.0.0.0/8' }]));
    check('an unknown service lists the known ones', unk.status === 400 && /known services: modbus-tcp/.test(unk.json.problems[0].message));
    const none = await imp(doc(`iot-bad-${suffix}`, [{ action: 'ALLOW', source: '10.0.0.0/8' }]));
    check('a rule with neither protocol nor service is rejected', none.status === 400 && none.json.problems.some((p) => /protocol/.test(p.message)));
    const clash = await imp(doc(`iot-bad-${suffix}`, [{ order: 10, action: 'ALLOW', service: 'dnp3', source: '10.0.0.0/8' }, { order: 11, action: 'ALLOW', protocol: 'tcp', ports: '80', source: '10.0.0.0/8' }]));
    check('consecutive orders used by a two-transport service collide with an explicit rule', clash.status === 400 && clash.json.problems.some((p) => /more than once/.test(p.message)));
    const real = await imp(doc(`iot-svc-${suffix}`, [{ action: 'ALLOW', service: 'mqtt', source: '10.20.0.0/24' }]), '');
    versions.push(real.json.versionId);
    const exp = await raw('GET', `/policy-sets/${real.json.policySetId}/export?format=json`, { token: op });
    const expDoc = JSON.parse(exp.text);
    check('an export uses explicit protocol and ports, and importing it again is a no-op', expDoc.spec.rules[0].protocol === 'tcp' && expDoc.spec.rules[0].ports === '1883' && !('service' in expDoc.spec.rules[0]) && (await imp(expDoc, '')).json.action === 'unchanged');

    console.log('\nThe gateway lab (real SSH, real ARP table)');
    docker('build', '-q', '-t', 'segmentra-iot-gw:test', join(here, '..', 'docker-ssh-integration', 'target'));
    docker('network', 'create', NET);
    // sshd listens on 22 and on the published port: Segmentra's management baseline allows the host's configured SSH port, and the
    // lockout protection (correctly) reverts a deployment after which it can no longer reach that port.
    const run = docker('run', '-d', '--name', GW, '--network', NET, '--cap-add', 'NET_ADMIN', '-p', `127.0.0.1:${SSH_PORT}:${SSH_PORT}`, '-e', 'TARGET_USER=segmentra', '-e', 'TARGET_PASSWORD=segmentra123!', 'segmentra-iot-gw:test');
    if (run.status !== 0) throw new Error(`gateway container: ${run.stderr}`);
    for (const d of [D1, D2]) docker('run', '-d', '--name', d, '--network', NET, 'alpine:3.20', 'sleep', '3600');
    const ipOf = (c) => docker('inspect', '-f', `{{(index .NetworkSettings.Networks "${NET}").IPAddress}}`, c).stdout.trim();
    const macOf = (c) => docker('inspect', '-f', `{{(index .NetworkSettings.Networks "${NET}").MacAddress}}`, c).stdout.trim();
    const gwIp = ipOf(GW), d1Ip = ipOf(D1), d2Ip = ipOf(D2);
    for (let i = 0; i < 30 && docker('exec', GW, 'sh', '-c', 'pgrep sshd >/dev/null').status !== 0; i += 1) await sleep(1000);
    docker('exec', GW, 'sh', '-c', `printf 'Port 22\\nPort ${SSH_PORT}\\n' >> /etc/ssh/sshd_config && kill -HUP $(pgrep -o sshd)`);
    await sleep(1500);
    for (const d of [D1, D2]) docker('exec', d, 'ping', '-c', '1', '-W', '2', gwIp);
    check('the lab is up: gateway and two devices with addresses', !!(gwIp && d1Ip && d2Ip), `${gwIp} ${d1Ip} ${d2Ip}`);

    const iotTag = (await api('GET', '/tags', { token: op })).tags.find((t) => t.name === 'iot-gateway');
    const gw = (await api('POST', '/hosts', { token: op, body: { hostname: `iot-gw-${suffix}`, mgmtIp: '127.0.0.1', sshPort: SSH_PORT, firewallBackend: 'iptables', enabled: true, tagIds: [iotTag.id] } })).host;
    hostIds.push(gw.id);
    const cred = await api('POST', '/ssh-credentials', { token: admin, body: { name: `iot-${suffix}`, username: 'segmentra', authMethod: 'PASSWORD', password: 'segmentra123!', scopeType: 'HOST', scopeId: gw.id } });
    credId = (cred.sshCredential ?? cred.credential ?? cred).id;
    const plainHost = (await api('POST', '/hosts', { token: op, body: { hostname: `iot-plain-${suffix}`, mgmtIp: '127.0.0.1', sshPort: SSH_PORT, enabled: true } })).host;
    hostIds.push(plainHost.id);

    console.log('\nPassive discovery');
    check('a viewer cannot discover (403)', (await raw('POST', '/iot-assets/discover', { token: viewer, body: { gatewayId: gw.id } })).status === 403);
    check('a host without the iot-gateway tag is refused (404)', (await raw('POST', '/iot-assets/discover', { token: op, body: { gatewayId: plainHost.id } })).status === 404);
    const disc = await raw('POST', '/iot-assets/discover', { token: op, body: { gatewayId: gw.id } });
    const dev = (ip) => disc.json?.devices?.find((d) => d.ip === ip);
    check('the gateway\'s neighbour table is read over SSH and lists both devices as new candidates', disc.status === 200 && dev(d1Ip)?.status === 'candidate' && dev(d2Ip)?.status === 'candidate', `${disc.status} ${disc.json?.counts ? JSON.stringify(disc.json.counts) : disc.text.slice(0, 150)}`);
    check('MAC addresses match the containers', dev(d1Ip)?.mac === macOf(D1).toLowerCase() && dev(d2Ip)?.mac === macOf(D2).toLowerCase());
    check('without a vendor list the reason is given (locally administered address) and the type is "other"', !dev(d1Ip)?.vendor && /locally administered/.test(dev(d1Ip)?.vendorNote ?? '') && dev(d1Ip)?.suggestedType === 'other');

    console.log('\nVendor list');
    check('an operator cannot import the vendor list (403)', (await raw('POST', '/iot-assets/oui', { token: op, body: 'x', type: 'text/csv' })).status === 403);
    check('garbage is rejected (400)', (await raw('POST', '/iot-assets/oui', { token: admin, body: 'this is not an oui list', type: 'text/csv' })).status === 400);
    const prefix = macOf(D1).toLowerCase().replace(/:/g, '').slice(0, 6).toUpperCase();
    const csv = `Registry,Assignment,Organization Name,Organization Address\r\nMA-L,${prefix},"${FIXTURE_VENDOR}","Somewhere, Test"\r\n`;
    const ouiRes = await raw('POST', '/iot-assets/oui', { token: admin, body: csv, type: 'text/csv' });
    ouiInserted = ouiRes.status === 201;
    check('the IEEE CSV (with a quoted comma) is imported', ouiRes.status === 201 && ouiRes.json.imported === 1);
    check('anyone can read the vendor list size', (await raw('GET', '/iot-assets/oui/status', { token: viewer })).json.entries >= 1);
    const disc2 = await raw('POST', '/iot-assets/discover', { token: op, body: { gatewayId: gw.id } });
    const d1b = disc2.json.devices.find((d) => d.ip === d1Ip);
    check('the vendor is now named and the type suggested from it', d1b.vendor === FIXTURE_VENDOR && d1b.suggestedType === 'plc', `${d1b.vendor} ${d1b.suggestedType}`);

    console.log('\nReview and add');
    const bad = await raw('POST', '/iot-assets/discover/import', { token: op, body: { gatewayId: gw.id, devices: [{ ip: d1Ip, mac: d1b.mac, name: `plc-line-${suffix}`, assetType: 'plc', criticality: 'critical', zone: 'line-1', iface: d1b.iface }, { ip: '999.1.1.1', mac: 'aa:bb:cc:dd:ee:01' }, { ip: d2Ip, mac: 'not-a-mac' }] } });
    check('the reviewed device is created; invalid entries are skipped with a reason', bad.status === 201 && bad.json.created.length === 1 && bad.json.skipped.length === 2 && bad.json.skipped.some((s) => /invalid IP/.test(s.reason)) && bad.json.skipped.some((s) => /invalid MAC/.test(s.reason)));
    const created = (await api('GET', '/iot-assets', { token: op })).assets.find((a) => a.name === `plc-line-${suffix}`);
    check('the asset has the MAC, IP, vendor, zone, discovery source and its gateway', created && created.mac_address === d1b.mac && created.ip_address === d1Ip && created.vendor === FIXTURE_VENDOR && created.zone === 'line-1' && created.discovered_by === `gateway-neighbors:iot-gw-${suffix}` && created.gateways.some((g) => g.id === gw.id));
    const again = await raw('POST', '/iot-assets/discover/import', { token: op, body: { gatewayId: gw.id, devices: [{ ip: d1Ip, mac: d1b.mac }] } });
    check('adding it again is skipped as already registered', again.json.created.length === 0 && /already registered/.test(again.json.skipped[0].reason));
    const disc3 = await raw('POST', '/iot-assets/discover', { token: op, body: { gatewayId: gw.id } });
    check('discovery now shows it as a known asset', disc3.json.devices.find((d) => d.ip === d1Ip)?.status === 'known' && disc3.json.devices.find((d) => d.ip === d1Ip)?.assetName === `plc-line-${suffix}`);
    const d2 = (await raw('POST', '/iot-assets/discover/import', { token: op, body: { gatewayId: gw.id, devices: [{ ip: d2Ip, mac: dev(d2Ip).mac, name: `sensor-${suffix}` }] } })).json.created[0];

    console.log('\nProtection coverage');
    const noGw = (await api('POST', '/iot-assets', { token: op, body: { name: `cov-nogw-${suffix}`, ipAddress: '192.0.2.150', zone: 'line-1' } })).asset;
    const noIp = (await api('POST', '/iot-assets', { token: op, body: { name: `cov-noip-${suffix}`, zone: 'line-2', gatewayIds: [gw.id] } })).asset;
    const cov = async () => { const r = await raw('GET', '/iot-assets/coverage', { token: viewer }); return { r, by: (n) => r.json.assets.find((a) => a.name === n) }; };
    let c = await cov();
    check('states before any deployment: no gateway / no IP / gateway not deployed', c.by(`cov-nogw-${suffix}`).state === 'NO_GATEWAY' && c.by(`cov-noip-${suffix}`).state === 'NO_IP' && c.by(`plc-line-${suffix}`).state === 'GATEWAY_NOT_DEPLOYED');
    check('the summary and the zones add up', c.r.json.summary.NO_GATEWAY >= 1 && c.r.json.zones.some((z) => z.zone === 'line-1' && z.assets >= 2));

    await api('PUT', '/admin/executor-setting', { token: admin, body: { executor: 'ssh' } });
    const ps = (await api('POST', '/policy-sets', { token: op, body: { name: `iot-gwpol-${suffix}`, scopeType: 'HOST_LIST', hostIds: [gw.id] } })).policySet;
    const v = (await api('POST', `/policy-sets/${ps.id}/versions`, { token: op, body: { changeSummary: 'iot test', interfaceScopeType: 'ALL_INTERFACES' } })).version;
    versions.push(v.id);
    const rule = (o, x) => api('POST', `/policy-versions/${v.id}/rules`, { token: op, body: { orderIndex: o, direction: 'FORWARD', action: 'ALLOW', logMode: 'NONE', usePolicyInterfaceScope: true, destinationType: 'IOT_ASSET', destinationValue: created.id, ...x } });
    await rule(10, { protocol: 'tcp', ports: '502', sourceType: 'CIDR', sourceValue: '10.20.0.0/24', comment: 'hmi modbus' });
    await rule(20, { protocol: 'tcp', ports: '8883', sourceType: 'CIDR', sourceValue: '10.30.0.5', comment: 'broker tls' });
    await api('POST', `/policy-versions/${v.id}/submit-approval`, { token: op, body: {} });
    await api('POST', `/policy-versions/${v.id}/approve`, { token: appr, body: {} });
    const deploy = async () => {
      const dep = await api('POST', '/deployments', { token: op, body: { policyVersionId: v.id, mode: 'FULL', targetQuery: { hosts: [gw.id], tags: [], vlans: [] } } });
      await api('POST', `/deployments/${dep.deployment.id}/start`, { token: op, body: {} });
      for (let i = 0; i < 60; i += 1) { const d = await api('GET', `/deployments/${dep.deployment.id}`, { token: op }); if (['SUCCEEDED', 'FAILED', 'PARTIAL'].includes(d.deployment.status)) return d.deployment.status; await sleep(2000); }
      return 'TIMEOUT';
    };
    const status = await deploy();
    check('the gateway policy deploys over SSH', status === 'SUCCEEDED', status);
    const fwd = docker('exec', GW, 'iptables', '-S', 'SEGMENTRA-FWD').stdout;
    check('the gateway enforces the FORWARD rules for the asset IP (iptables)', new RegExp(`-d ${d1Ip.replace(/\./g, '\\.')}`).test(fwd) && /--dport 502/.test(fwd) && /--dport 8883/.test(fwd), fwd.split('\n').filter((l) => /dport/.test(l)).join(' | ').slice(0, 160));
    c = await cov();
    const plc = c.by(`plc-line-${suffix}`);
    check('the asset is now PROTECTED', plc.state === 'PROTECTED' && plc.gateways[0].status === 'deployed', plc.state);
    check('what is allowed to reach it is listed with service names', plc.rules.some((r) => r.action === 'ALLOW' && r.ports === '502' && r.services.includes('Modbus/TCP') && r.from === '10.20.0.0/24') && plc.rules.some((r) => r.ports === '8883' && r.services.includes('MQTT over TLS')));
    check('cleartext protocols are flagged, encrypted ones are not', plc.cleartextAllowed.includes('Modbus/TCP') && !plc.cleartextAllowed.includes('MQTT over TLS'), plc.cleartextAllowed.join(','));
    check('the other asset on the same gateway still has no rule of its own', c.by(`sensor-${suffix}`).rules.length === 0);

    await api('PUT', `/iot-assets/${created.id}`, { token: op, body: { zone: 'line-1b' } });
    c = await cov();
    check('changing the asset after the deployment makes it DEPLOY PENDING', c.by(`plc-line-${suffix}`).state === 'PENDING_DEPLOY');
    check('a redeployment makes it PROTECTED again', (await deploy()) === 'SUCCEEDED' && (await cov()).by(`plc-line-${suffix}`).state === 'PROTECTED');

    console.log('\nCompliance report');
    const rep = await raw('POST', '/compliance/reports', { token: op, body: { title: `iot ${suffix}` } });
    const rj = (await raw('GET', `/compliance/reports/${rep.json.id}`, { token: viewer })).json;
    const iot = rj.content.evidence.iot;
    check('the report carries the coverage summary and the asset rows', iot.coverage.summary.PROTECTED >= 1 && iot.coverageRows.rows.some((a) => a.name === `plc-line-${suffix}` && a.state === 'PROTECTED' && /Modbus/.test(a.cleartext)) && iot.coverageRows.rows.some((a) => a.name === `cov-nogw-${suffix}` && a.state === 'NO_GATEWAY'));
    const m = rj.content.metrics.find((x) => x.id === 'iot_coverage');
    check('the IoT coverage measurement is "attention" while assets are unprotected', m.status === 'attention' && /protected/.test(m.detail));
    check('the ISO A.8.22 and SOC 2 CC6.6 controls cite it', ['iso-27001-2022', 'soc2'].every((id) => rj.content.frameworks.find((f) => f.id === id).controls.some((ct) => ct.metrics.some((x) => x.id === 'iot_coverage'))));
    const csvRes = await fetch(`${apiBase}/compliance/reports/${rep.json.id}?format=csv&dataset=iot_coverage`, { headers: { authorization: `Bearer ${viewer}` } });
    const csvText = await csvRes.text();
    check('the iot_coverage CSV dataset lists the assets with their state', csvRes.status === 200 && csvText.startsWith('name,type,criticality,zone,ip,state,gateways,cleartext') && csvText.includes(`plc-line-${suffix}`) && csvText.includes('PROTECTED'));
    const htmlRes = await fetch(`${apiBase}/compliance/reports/${rep.json.id}?format=html`, { headers: { authorization: `Bearer ${viewer}` } });
    const html = await htmlRes.text();
    check('the printable report has an IoT / OT protection section with the zones', /IoT \/ OT protection/.test(html) && html.includes('line-1b'));
    void noGw; void noIp; void d2;
  } finally {
    for (const id of versions) await raw('POST', `/policy-versions/${id}/archive`, { token: op, body: {} });
    if (credId) await raw('DELETE', `/ssh-credentials/${credId}`, { token: admin });
    if (hostIds.length) await raw('POST', '/hosts/bulk/set-enabled', { token: op, body: { hostIds, enabled: false } });
    await raw('PUT', '/admin/executor-setting', { token: admin, body: { executor: executorBefore } });
    // remove the assets the test created (Docker reuses addresses and derives MACs from them, so leftovers would make a rerun see "known" devices)
    const leftovers = (await raw('GET', '/iot-assets', { token: op })).json?.assets ?? [];
    for (const a of leftovers.filter((x) => /^(plc-line|sensor|cov-nogw|cov-noip)-/.test(x.name) && x.name.endsWith(suffix))) await raw('DELETE', `/iot-assets/${a.id}`, { token: op });
    for (const c of [GW, D1, D2]) docker('rm', '-f', '-v', c);
    docker('network', 'rm', NET);
    if (ouiInserted && dbContainer()) psql(`DELETE FROM oui_vendors WHERE vendor = '${FIXTURE_VENDOR}'`);
    // the lab's SSH host key is new each run: forget the entry Segmentra recorded for the test port. Work on a copy:
    // `ssh-keygen -R` would overwrite the user's known_hosts.old backup.
    forgetHostKey(SSH_PORT);
  }

  const failed = results.filter((r) => !r.pass);
  console.log(`\n[iot] ${results.length - failed.length}/${results.length} checks passed`);
  for (const f of failed) console.log(`  FAILED: ${f.label}`);
  process.exit(failed.length ? 1 : 0);
}
main().catch((e) => { console.error(e); process.exit(1); });
