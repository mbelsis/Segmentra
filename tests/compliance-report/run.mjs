#!/usr/bin/env node
// Compliance report integration test against a running Segmentra API (default http://localhost:8080/api, admin/admin123;
// see SEGMENTRA_API, SEGMENTRA_ADMIN_USER, SEGMENTRA_ADMIN_PASSWORD). It builds a small fixture (an unmanaged host, IoT assets with
// and without a gateway, hostile names) and checks that the reports reflect it. The tamper check edits a stored report through
// `docker exec <db container> psql` and is skipped when that container cannot be found. Run it against a development stack.
import { spawnSync } from 'node:child_process';

const apiBase = process.env.SEGMENTRA_API ?? 'http://localhost:8080/api';
const adminUser = process.env.SEGMENTRA_ADMIN_USER ?? 'admin';
const adminPass = process.env.SEGMENTRA_ADMIN_PASSWORD ?? 'admin123';
const suffix = Date.now().toString(36);
const results = [];
function check(label, pass, detail = '') {
  results.push({ label, pass: !!pass });
  console.log(`  ${pass ? 'PASS' : 'FAIL'}  ${label}${detail ? `  (${detail})` : ''}`);
}
async function raw(method, path, { token, body } = {}) {
  const res = await fetch(`${apiBase}${path}`, { method, headers: { ...(token ? { authorization: `Bearer ${token}` } : {}), ...(body !== undefined ? { 'content-type': 'application/json' } : {}) }, body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await res.text(); let json = null; try { json = JSON.parse(text); } catch { /* not json */ }
  return { status: res.status, text, json, headers: res.headers };
}
const api = async (m, p, o) => { const r = await raw(m, p, o); if (r.status >= 400) throw new Error(`${m} ${p} -> ${r.status}: ${r.text}`); return r.json; };
const login = async (u, p) => (await api('POST', '/auth/login', { body: { username: u, password: p } })).token;
async function ensureUser(admin, username, role) {
  const r = await raw('POST', '/admin/users', { token: admin, body: { username, displayName: username, password: 'CrTest-pass-123!', roles: [role], isActive: true } });
  if (![201, 409].includes(r.status)) throw new Error(`user ${username}: ${r.status} ${r.text}`);
  return login(username, 'CrTest-pass-123!');
}
const dbContainer = () => (spawnSync('docker', ['ps', '--format', '{{.Names}}'], { encoding: 'utf8' }).stdout.split('\n').find((n) => /segmentra.*db/i.test(n) && !/swarm/.test(n)) ?? '').trim();
const psql = (sql) => spawnSync('docker', ['exec', dbContainer(), 'psql', '-U', 'segmentra', '-d', 'segmentra', '-tAc', sql], { encoding: 'utf8' });

async function main() {
  const admin = await login(adminUser, adminPass);
  const op = await ensureUser(admin, 'cr-operator', 'operator');
  const appr = await ensureUser(admin, 'cr-approver', 'approver');
  const viewer = await ensureUser(admin, 'cr-viewer', 'viewer');
  const gen = (token, body = {}) => raw('POST', '/compliance/reports', { token, body });
  const get = (token, id, q = '') => raw('GET', `/compliance/reports/${id}${q}`, { token });
  const ev = (r) => r.json.content.evidence;
  const metric = (r, id) => r.json.content.metrics.find((m) => m.id === id);

  console.log('Generate and read');
  const base = await gen(op, { title: `baseline ${suffix}` });
  check('generating a report returns 201 with id, SHA-256 and a summary of four frameworks', base.status === 201 && /^[0-9a-f]{64}$/.test(base.json.sha256) && base.json.summary.frameworks.length === 4, `${base.status}`);
  const baseRead = await get(viewer, base.json.id);
  check('a viewer can read it; the integrity check passes', baseRead.status === 200 && baseRead.json.integrity.verified === true && baseRead.json.integrity.sha256 === base.json.sha256);
  const c0 = baseRead.json.content;
  check('the report carries the disclaimer and the framework controls', /not an audit opinion/.test(c0.disclaimer) && c0.frameworks.every((f) => f.controls.length >= 5));
  check('controls Segmentra cannot evidence are marked "gap" with the reason', c0.frameworks.find((f) => f.id === 'pci-dss-4').controls.find((c) => c.id === '1.3.2').status === 'gap' && c0.frameworks.find((f) => f.id === 'hipaa').controls.some((c) => c.status === 'gap' && c.gap));
  check('the report is listed', (await api('GET', '/compliance/reports', { token: viewer })).reports.some((r) => r.id === base.json.id));

  console.log('\nValidation, roles and immutability');
  check('an unknown framework is a 400', (await gen(op, { frameworks: ['nope'] })).status === 400);
  check('a period with from after to is a 400', (await gen(op, { from: '2026-02-01T00:00:00Z', to: '2026-01-01T00:00:00Z' })).status === 400);
  check('a period longer than three years is a 400', (await gen(op, { from: '2020-01-01T00:00:00Z', to: '2026-01-01T00:00:00Z' })).status === 400);
  check('thresholds out of range are a 400', (await gen(op, { staleDays: 0 })).status === 400);
  check('a viewer cannot generate (403)', (await gen(viewer)).status === 403);
  check('no token is a 401', (await gen(undefined)).status === 401);
  check('an approver can generate, but not the live SSH drift check (403)', (await gen(appr, { title: `approver ${suffix}` })).status === 201 && (await gen(appr, { liveDrift: true })).status === 403);
  check('only the requested frameworks are included', (await gen(op, { frameworks: ['soc2'] })).status === 201 && (await get(op, (await api('GET', '/compliance/reports', { token: op })).reports.find((r) => r.frameworks.join() === 'soc2').id)).json.content.frameworks.length === 1);
  check('reports cannot be changed or deleted (no such routes)', (await raw('DELETE', `/compliance/reports/${base.json.id}`, { token: admin })).status === 404 && (await raw('PUT', `/compliance/reports/${base.json.id}`, { token: admin, body: {} })).status === 404);
  check('an unknown report is a 404', (await get(op, '00000000-0000-0000-0000-000000000000')).status === 404);

  console.log('\nThe report reflects the data');
  const ts = Date.now();
  const unmanaged = (await api('POST', '/hosts', { token: op, body: { hostname: `cr-unmanaged-${suffix}`, mgmtIp: '192.0.2.77', enabled: true } })).host;
  const gwTag = (await api('GET', '/tags', { token: op })).tags.find((t) => t.name === 'iot-gateway');
  const gw = (await api('POST', '/hosts', { token: op, body: { hostname: `cr-gw-${suffix}`, mgmtIp: '192.0.2.78', enabled: true, tagIds: gwTag ? [gwTag.id] : [] } })).host;
  const hostile = `cr-<img src=x onerror=alert(1)>-${suffix}`;
  const formula = `=HYPERLINK("http://evil.example","x")-${suffix}`;
  const a1 = (await api('POST', '/iot-assets', { token: op, body: { name: hostile, assetType: 'plc', criticality: 'critical', ipAddress: '192.0.2.201', zone: 'cell-1' } })).asset;
  const a2 = (await api('POST', '/iot-assets', { token: op, body: { name: formula, assetType: 'sensor', criticality: 'low', ipAddress: '192.0.2.202' } })).asset;
  const a3 = (await api('POST', '/iot-assets', { token: op, body: { name: `cr-protected-${suffix}`, assetType: 'hmi', criticality: 'high', ipAddress: '192.0.2.203', gatewayIds: [gw.id] } })).asset;
  const after = await gen(op, { title: `after fixture ${suffix}` });
  const A = await get(op, after.json.id);
  const E = ev(A), E0 = ev(baseRead);
  check('the two new hosts (no deployment yet) are counted as unmanaged and named', E.inventory.unmanaged === E0.inventory.unmanaged + 2 && ['cr-unmanaged-', 'cr-gw-'].every((n) => E.inventory.hosts.rows.some((h) => h.hostname === `${n}${suffix}` && h.state === 'unmanaged')), `${E0.inventory.unmanaged} -> ${E.inventory.unmanaged}`);
  check('coverage drops and is flagged "attention"', metric(A, 'coverage').status === 'attention' && /without a successful deployment/.test(metric(A, 'coverage').detail));
  check('the control that depends on coverage turns to "attention" with the evidence listed', (() => { const c = A.json.content.frameworks.find((f) => f.id === 'pci-dss-4').controls.find((x) => x.id === '1.2.1'); return c.status === 'attention' && c.metrics.some((m) => m.id === 'coverage' && m.status === 'attention'); })());
  const names = E.iot.unprotected.rows.map((a) => a.name);
  check('IoT assets without a gateway are listed; the protected one is not', names.includes(hostile) && names.includes(formula) && !names.includes(`cr-protected-${suffix}`), `${E.iot.unprotected.rows.length} unprotected of ${E.iot.assets}`);
  check('IoT counts increase by the fixture', E.iot.assets === E0.iot.assets + 3 && E.iot.unprotected.rows.length === E0.iot.unprotected.rows.length + 2);
  check('the IoT measurement is "attention"', metric(A, 'iot_unprotected').status === 'attention');
  await api('POST', `/iot-assets/${a1.id}/gateways`, { token: op, body: { gatewayIds: [gw.id] } });
  const healed = await get(op, (await gen(op)).json.id);
  check('assigning a gateway removes the asset from the unprotected list in the next report', !ev(healed).iot.unprotected.rows.some((a) => a.name === hostile) && ev(healed).iot.unprotected.rows.some((a) => a.name === formula));
  check('the earlier report is unchanged (snapshots are point-in-time)', (await get(op, after.json.id)).json.content.evidence.iot.unprotected.rows.some((a) => a.name === hostile) && (await get(op, after.json.id)).json.integrity.verified);

  console.log('\nPeriod and thresholds');
  const old = await get(op, (await gen(op, { from: '2020-01-01T00:00:00Z', to: '2020-01-02T00:00:00Z' })).json.id);
  check('a period with no activity reports no audit events, changes or deployments', ev(old).audit.events === 0 && ev(old).changes.versionsTouched === 0 && ev(old).deployments.total === 0 && metric(old, 'audit_events').status === 'attention');
  const tight = await get(op, (await gen(op, { inactiveUserDays: 1, staleDays: 1, reviewDays: 1 })).json.id);
  check('tighter thresholds are recorded and change the findings', tight.json.content.parameters.reviewDays === 1 && ev(tight).policy.notReviewed.rows.length >= ev(baseRead).policy.notReviewed.rows.length);

  console.log('\nHTML and CSV');
  const html = await get(op, after.json.id, '?format=html');
  check('HTML is served with a restrictive Content-Security-Policy', html.status === 200 && /text\/html/.test(html.headers.get('content-type')) && /default-src 'none'/.test(html.headers.get('content-security-policy')) && html.headers.get('x-content-type-options') === 'nosniff');
  check('HTML shows the disclaimer, the hash and the control tables', /not an audit opinion/.test(html.text) && html.text.includes(after.json.sha256) && /PCI DSS/.test(html.text) && /Not covered/.test(html.text) && /integrity <span class="b ok">verified/.test(html.text));
  check('hostile names are escaped in HTML (no live tag)', html.text.includes('&lt;img src=x onerror=alert(1)&gt;') && !html.text.includes('<img src=x'));
  const csvControls = await get(op, after.json.id, '?format=csv&dataset=controls');
  check('the controls CSV has a header and one row per control', csvControls.status === 200 && /text\/csv/.test(csvControls.headers.get('content-type')) && csvControls.text.startsWith('framework,control,title,status,evidence,gap') && csvControls.text.trim().split('\r\n').length === 1 + A.json.content.frameworks.reduce((n, f) => n + f.controls.length, 0));
  const csvIot = await get(op, after.json.id, '?format=csv&dataset=iot_assets');
  check('CSV cells that start like a formula are neutralised', csvIot.text.includes(`'=HYPERLINK(`) && !/^=HYPERLINK/m.test(csvIot.text) && !csvIot.text.split('\r\n').some((l) => l.startsWith('=')));
  const csvAudit = await get(op, after.json.id, '?format=csv&dataset=audit_events');
  check('the audit-event CSV is rebuilt from the audit log for the period and has the events of the fixture', csvAudit.status === 200 && csvAudit.text.startsWith('timestamp,actor,action,entity_type,entity_id,ip,metadata') && csvAudit.text.includes('HOST_CREATE') && csvAudit.text.includes(`cr-unmanaged-${suffix}`));
  check('a report\'s own generation is audited after its period ends (so it is not in its own audit list)', (await api('GET', '/audit?action=COMPLIANCE_REPORT_GENERATE', { token: op })).events.some((e) => e.entity_id === after.json.id));
  check('an unknown dataset or format is a 400', (await get(op, after.json.id, '?format=csv&dataset=nope')).status === 400 && (await get(op, after.json.id, '?format=xml')).status === 400);

  console.log('\nIntegrity');
  if (!dbContainer()) {
    console.log('  SKIP  tamper detection (no segmentra database container found)');
  } else {
    const id = base.json.id;
    psql(`UPDATE compliance_reports SET content = jsonb_set(content, '{generatedBy}', '"mallory"') WHERE id = '${id}'`);
    const tampered = await get(op, id);
    const tamperedHtml = await get(op, id, '?format=html');
    check('a stored report that was altered is reported as not intact (JSON and HTML)', tampered.json.integrity.verified === false && /MISMATCH/.test(tamperedHtml.text));
    psql(`UPDATE compliance_reports SET content = jsonb_set(content, '{generatedBy}', to_jsonb('${c0.generatedBy}'::text)) WHERE id = '${id}'`);
    check('restoring the original content makes it verify again', (await get(op, id)).json.integrity.verified === true);
  }

  console.log(`\n(created ${Date.now() - ts} ms of fixture; test data stays in the development database)`);
  const failed = results.filter((r) => !r.pass);
  console.log(`\n[compliance-report] ${results.length - failed.length}/${results.length} checks passed`);
  for (const f of failed) console.log(`  FAILED: ${f.label}`);
  process.exit(failed.length ? 1 : 0);
}
main().catch((e) => { console.error(e); process.exit(1); });
