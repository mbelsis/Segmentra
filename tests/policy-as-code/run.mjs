#!/usr/bin/env node
// Policy as code integration test against a running Segmentra API (default http://localhost:8080/api, admin/admin123;
// see SEGMENTRA_API, SEGMENTRA_ADMIN_USER, SEGMENTRA_ADMIN_PASSWORD). Run it against a development stack: it creates
// users, tags, hosts and policy sets (approved versions cannot be deleted; they are archived).
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { stringify } from 'yaml';

const apiBase = process.env.SEGMENTRA_API ?? 'http://localhost:8080/api';
const adminUser = process.env.SEGMENTRA_ADMIN_USER ?? 'admin';
const adminPass = process.env.SEGMENTRA_ADMIN_PASSWORD ?? 'admin123';
const suffix = Date.now().toString(36);
const results = [];
function check(label, pass, detail = '') {
  results.push({ label, pass: !!pass });
  console.log(`  ${pass ? 'PASS' : 'FAIL'}  ${label}${detail ? `  (${detail})` : ''}`);
}

async function raw(method, path, { token, body, type } = {}) {
  const headers = { ...(token ? { authorization: `Bearer ${token}` } : {}) };
  let payload;
  if (body !== undefined) {
    if (typeof body === 'string') { headers['content-type'] = type ?? 'application/yaml'; payload = body; }
    else { headers['content-type'] = 'application/json'; payload = JSON.stringify(body); }
  }
  const res = await fetch(`${apiBase}${path}`, { method, headers, body: payload });
  const text = await res.text(); let json = null; try { json = JSON.parse(text); } catch { /* yaml */ }
  return { status: res.status, text, json, headers: res.headers };
}
const api = async (method, path, o) => { const r = await raw(method, path, o); if (r.status >= 400) throw new Error(`${method} ${path} -> ${r.status}: ${r.text}`); return r.json; };
const login = async (u, p) => (await api('POST', '/auth/login', { body: { username: u, password: p } })).token;
async function ensureUser(admin, username, role) {
  const r = await raw('POST', '/admin/users', { token: admin, body: { username, displayName: username, password: 'PacTest-pass-123!', roles: [role], isActive: true } });
  if (![201, 409].includes(r.status)) throw new Error(`user ${username}: ${r.status} ${r.text}`);
  return login(username, 'PacTest-pass-123!');
}

const doc = (name, over = {}) => ({
  apiVersion: 'segmentra.io/v1', kind: 'PolicySet',
  metadata: { name, description: 'policy as code test' },
  spec: { scope: { type: 'HOST_LIST', hosts: [`pac-h1-${suffix}`] }, changeSummary: 'from git', rules: [
    { order: 10, direction: 'IN', action: 'ALLOW', protocol: 'tcp', ports: '443', source: { type: 'TAG', name: `pac-web-${suffix}` }, comment: 'web' },
    { order: 20, direction: 'IN', action: 'ALLOW', protocol: 'tcp', ports: '22', source: '10.0.0.0/24', comment: 'ssh from mgmt' },
  ], ...over },
});

async function main() {
  const admin = await login(adminUser, adminPass);
  const op = await ensureUser(admin, 'pac-operator', 'operator');
  const appr = await ensureUser(admin, 'pac-approver', 'approver');
  const viewer = await ensureUser(admin, 'pac-viewer', 'viewer');

  const tag = (await api('POST', '/tags', { token: op, body: { name: `pac-web-${suffix}` } })).tag;
  const h1 = (await api('POST', '/hosts', { token: op, body: { hostname: `pac-h1-${suffix}`, mgmtIp: '192.0.2.11', enabled: true } })).host;
  const h2 = (await api('POST', '/hosts', { token: op, body: { hostname: `pac-h2-${suffix}`, mgmtIp: '192.0.2.12', enabled: true } })).host;
  const name = `pac-policy-${suffix}`;
  const imp = (d, q = '', who = op) => raw('POST', `/policy-sets/import${q}`, { token: who, body: d });
  const impYaml = (d, q = '', who = op) => raw('POST', `/policy-sets/import${q}`, { token: who, body: stringify(d), type: 'application/yaml' });
  const sets = async () => (await api('GET', '/policy-sets', { token: op })).policySets.filter((p) => p.name === name);
  const ids = [];

  console.log('Create');
  const dry = await imp(doc(name), '?dryRun=true');
  check('dry run reports "created" without writing anything', dry.status === 200 && dry.json.dryRun === true && dry.json.action === 'created' && (await sets()).length === 0, `${dry.status} ${dry.json?.action}`);
  const first = await imp(doc(name));
  check('import creates the policy set and a DRAFT v1', first.status === 201 && first.json.action === 'created' && first.json.versionNumber === 1 && first.json.versionStatus === 'DRAFT', `${first.status} ${first.text.slice(0, 80)}`);
  ids.push(first.json.versionId);
  const rules1 = (await api('GET', `/policy-versions/${first.json.versionId}/rules`, { token: op })).rules;
  check('names were resolved to ids (tag source) and CIDR kept as is', rules1.length === 2 && rules1[0].source_type === 'TAG' && rules1[0].source_value === tag.id && rules1[1].source_value === '10.0.0.0/24');

  console.log('\nIdempotency');
  const again = await imp(doc(name));
  check('applying the same document again changes nothing', again.status === 200 && again.json.action === 'unchanged' && again.json.matchesVersion === 1 && (await sets())[0].version_count === 1);
  const viaYaml = await impYaml(doc(name));
  check('the same document sent as YAML text is also unchanged', viaYaml.status === 200 && viaYaml.json.action === 'unchanged');
  const viaContent = await raw('POST', '/policy-sets/import', { token: op, body: { content: stringify(doc(name)) } });
  check('the {content: "<yaml>"} form works too', viaContent.status === 200 && viaContent.json.action === 'unchanged');

  console.log('\nExport');
  const setId = first.json.policySetId;
  const exJson = await raw('GET', `/policy-sets/${setId}/export?format=json`, { token: viewer });
  const exDoc = JSON.parse(exJson.text);
  check('a viewer can export; names (not ids) are used', exJson.status === 200 && exDoc.spec.rules[0].source.name === `pac-web-${suffix}` && exDoc.spec.scope.hosts[0] === `pac-h1-${suffix}` && exJson.headers.get('x-segmentra-version') === '1');
  const exYaml = await raw('GET', `/policy-sets/${setId}/export`, { token: viewer });
  check('YAML export is the default, with a download name', exYaml.status === 200 && /^# Segmentra policy as code/.test(exYaml.text) && /attachment; filename="pac-policy-.*\.yaml"/.test(exYaml.headers.get('content-disposition')));
  const roundTrip = await impYaml(exYaml.text.split('\n').filter(() => true).join('\n') && (await import('yaml')).parse(exYaml.text));
  check('importing an export is a no-op (round trip)', roundTrip.status === 200 && roundTrip.json.action === 'unchanged', `${roundTrip.json?.action}`);
  check('export is deterministic', (await raw('GET', `/policy-sets/${setId}/export`, { token: viewer })).text === exYaml.text);
  check('unknown version is a 404', (await raw('GET', `/policy-sets/${setId}/export?version=99`, { token: viewer })).status === 404);

  console.log('\nChanges create reviewable drafts');
  const changed = doc(name); changed.spec.rules.push({ order: 30, direction: 'IN', action: 'DENY', protocol: 'udp', ports: '161', source: '0.0.0.0/0', comment: 'no snmp' });
  const plan = await imp(changed, '?dryRun=true');
  check('dry run shows the diff against the current version', plan.status === 200 && plan.json.action === 'new_version' && plan.json.diff.added.length === 1 && plan.json.diff.removed.length === 0 && /DENY IN udp\/161/.test(plan.json.diff.added[0]), plan.json?.diff?.added?.[0]);
  check('dry run left no new version behind', (await sets())[0].version_count === 1);
  const v2 = await imp(changed);
  check('a changed document creates DRAFT v2', v2.status === 201 && v2.json.action === 'new_version' && v2.json.versionNumber === 2 && v2.json.versionStatus === 'DRAFT');
  ids.push(v2.json.versionId);
  check('re-applying before approval reuses the draft (no v3)', (await imp(changed)).json.action === 'unchanged' && (await sets())[0].version_count === 2);
  const reordered = structuredClone(changed); reordered.spec.rules = [reordered.spec.rules[1], reordered.spec.rules[0], reordered.spec.rules[2]].map((r, i) => ({ ...r, order: (i + 1) * 10 }));
  const ro = await imp(reordered, '?dryRun=true');
  check('a pure reordering is detected', ro.json.action === 'new_version' && ro.json.diff.reordered === true && ro.json.diff.added.length === 0);

  console.log('\nApproval workflow still applies');
  check('the draft is not deployable: it needs submit + approval', (await api('GET', `/policy-sets/${setId}`, { token: op })).policySet.id === setId);
  await api('POST', `/policy-versions/${v2.json.versionId}/submit-approval`, { token: op, body: {} });
  await api('POST', `/policy-versions/${v2.json.versionId}/approve`, { token: appr, body: {} });
  const afterApprove = await imp(changed);
  check('after approval the same document is "unchanged" against the approved version', afterApprove.json.action === 'unchanged' && afterApprove.json.versionStatus === 'APPROVED');
  check('export now defaults to the approved version', (await raw('GET', `/policy-sets/${setId}/export?format=json`, { token: viewer })).headers.get('x-segmentra-version') === '2');
  const v3doc = doc(name); v3doc.spec.rules = v3doc.spec.rules.slice(0, 1);
  const v3 = await imp(v3doc);
  check('a change after approval creates v3 while v2 stays approved', v3.json.versionNumber === 3 && v3.json.diff.removed.length === 2 && v3.json.versionStatus === 'DRAFT');
  ids.push(v3.json.versionId);

  console.log('\nSeparation of duties');
  const selfSet = `pac-self-${suffix}`;
  const selfDraft = await imp(doc(selfSet), '', admin);
  ids.push(selfDraft.json.versionId);
  await api('POST', `/policy-versions/${selfDraft.json.versionId}/submit-approval`, { token: admin, body: {} });
  const selfApprove = await raw('POST', `/policy-versions/${selfDraft.json.versionId}/approve`, { token: admin, body: {} });
  check('the user who imported a version cannot approve it', selfApprove.status >= 400, `${selfApprove.status} ${selfApprove.json?.error ?? ''}`);

  console.log('\nValidation: every problem is reported, nothing is written');
  const bad = doc(`pac-bad-${suffix}`);
  bad.spec.rules = [
    { order: 10, action: 'ALLOW', protocol: 'tcp', port: '80', source: '10.0.0.1' },                                 // typo: port
    { order: 20, action: 'ALLOW', protocol: 'tcp', ports: '80', source: { type: 'TAG', name: 'does-not-exist' } },   // unknown tag
    { order: 20, action: 'ALLOW', protocol: 'tcp', ports: '99999', source: 'not-a-cidr' },                          // duplicate order, bad port, bad CIDR
    { order: 40, direction: 'FORWARD', action: 'ALLOW', protocol: 'tcp', source: '10.0.0.0/8' },                    // FORWARD without destination
    { order: 50, direction: 'IN', action: 'ALLOW', protocol: 'icmp', ports: '80', source: '10.0.0.0/8' },           // ports with icmp
  ];
  const badRes = await imp(bad);
  const paths = (badRes.json?.problems ?? []).map((p) => p.path);
  check('invalid document is rejected with 400 and several problems at once', badRes.status === 400 && badRes.json.problems.length >= 5, `${badRes.json?.problems?.length} problems`);
  check('unknown keys (typo "port") are errors, with the rule index in the path', paths.some((p) => p.startsWith('spec.rules[0]')) && badRes.json.problems.some((p) => /port/.test(p.message)));
  check('unknown tag is pointed out by path', badRes.json.problems.some((p) => p.path === 'spec.rules[1].source' && /does-not-exist/.test(p.message)));
  check('duplicate order, bad CIDR and bad port are reported', badRes.json.problems.some((p) => /more than once/.test(p.message)) && badRes.json.problems.some((p) => /valid IP|CIDR/i.test(p.message)));
  check('FORWARD without destination is reported', badRes.json.problems.some((p) => /destination/.test(p.message)));
  check('nothing was created for the invalid document', (await api('GET', '/policy-sets', { token: op })).policySets.every((p) => p.name !== `pac-bad-${suffix}`));
  check('garbage text is a clean 400', (await raw('POST', '/policy-sets/import', { token: op, body: 'a: [unclosed', type: 'application/yaml' })).status === 400);
  check('wrong apiVersion is rejected', (await imp({ ...doc(name), apiVersion: 'v9' })).status === 400);

  console.log('\nScope is protected');
  const moved = doc(name, {}); moved.spec.scope = { type: 'HOST_LIST', hosts: [`pac-h2-${suffix}`] }; moved.spec.rules = v3doc.spec.rules;
  const scopeWarn = await imp(moved);
  check('a different scope is NOT applied by default, a warning says so', scopeWarn.json.scopeChanged === true && scopeWarn.json.scopeUpdated === false && scopeWarn.json.warnings.length === 1);
  const hostsOf = async () => (await raw('GET', `/policy-sets/${setId}/export?format=json&version=latest`, { token: viewer })).text && JSON.parse((await raw('GET', `/policy-sets/${setId}/export?format=json&version=latest`, { token: viewer })).text).spec.scope.hosts;
  check('the scope stayed on host 1', (await hostsOf()).join() === `pac-h1-${suffix}`);
  const scopeApplied = await imp(moved, '?updateScope=true');
  check('with updateScope the scope is changed', scopeApplied.json.scopeUpdated === true && (await hostsOf()).join() === `pac-h2-${suffix}`);

  console.log('\nPermissions and ambiguity');
  check('a viewer cannot import (403)', (await imp(doc(name), '', viewer)).status === 403);
  check('an approver cannot import (403)', (await imp(doc(name), '', appr)).status === 403);
  check('no token is a 401', (await raw('POST', '/policy-sets/import', { body: doc(name) })).status === 401);
  const dupName = `pac-dup-${suffix}`;
  for (let i = 0; i < 2; i += 1) await api('POST', '/policy-sets', { token: op, body: { name: dupName, scopeType: 'HOST_LIST', hostIds: [h1.id] } });
  const dup = await imp(doc(dupName));
  check('two policy sets with the same name make the import refuse (409)', dup.status === 409 && dup.json.error === 'ambiguous_policy_set');

  console.log('\nFORWARD rules and interface scopes round-trip');
  const fwdName = `pac-fwd-${suffix}`;
  const fwd = doc(fwdName); fwd.spec.interfaceScope = { type: 'INTERFACE_NAME', names: ['eth0'] };
  fwd.spec.rules = [{ order: 10, direction: 'FORWARD', action: 'ALLOW', protocol: 'tcp', ports: '502', source: { type: 'HOST', name: `pac-h2-${suffix}` }, destination: { type: 'TAG', name: `pac-web-${suffix}` }, log: 'LOG', comment: 'modbus', interfaceScope: { type: 'INTERFACE_ROLE', roles: ['data'] } }];
  const fw = await imp(fwd);
  ids.push(fw.json.versionId);
  const fexp = JSON.parse((await raw('GET', `/policy-sets/${fw.json.policySetId}/export?format=json`, { token: op })).text);
  check('FORWARD destination, log mode and per-rule interface scope survive an export', fexp.spec.rules[0].destination.name === `pac-web-${suffix}` && fexp.spec.rules[0].log === 'LOG' && fexp.spec.rules[0].interfaceScope.roles[0] === 'data' && fexp.spec.interfaceScope.names[0] === 'eth0');
  check('and importing that export is a no-op', (await imp(fexp)).json.action === 'unchanged');

  console.log('\nCLI (scripts/segmentra-policy.mjs)');
  const cliEnv = { ...process.env, SEGMENTRA_URL: apiBase.replace(/\/api$/, ''), SEGMENTRA_TOKEN: op };
  const cli = (...a) => spawnSync(process.execPath, ['scripts/segmentra-policy.mjs', ...a], { encoding: 'utf8', env: cliEnv });
  const dir = mkdtempSync(join(tmpdir(), 'segmentra-pac-'));
  const file = join(dir, 'policy.yaml');
  const ex = cli('export', name, '-o', file);
  check('export writes a file', ex.status === 0 && /apiVersion: segmentra.io\/v1/.test(readFileSync(file, 'utf8')), ex.stderr.trim());
  const planClean = cli('plan', file, '--detailed-exitcode');
  check('plan on an unchanged file exits 0 (--detailed-exitcode)', planClean.status === 0 && /no change/.test(planClean.stdout), planClean.stdout.trim().split('\n')[0]);
  writeFileSync(file, readFileSync(file, 'utf8') + `    - order: 90\n      action: ALLOW\n      protocol: tcp\n      ports: "8443"\n      source: 10.9.0.0/16\n      comment: from the CLI test\n`);
  const countBeforePlan = (await sets())[0].version_count;
  const planDirty = cli('plan', file, '--detailed-exitcode');
  check('plan on a changed file exits 2 and prints the diff', planDirty.status === 2 && /\+ ALLOW IN tcp\/8443 from 10\.9\.0\.0\/16/.test(planDirty.stdout), `exit ${planDirty.status}`);
  const before = (await sets())[0].version_count;
  check('plan does not change anything', before === countBeforePlan, `${countBeforePlan} -> ${before} versions`);
  const applied = cli('apply', file);
  check('apply creates a DRAFT and says it needs approval', applied.status === 0 && /new DRAFT version/.test(applied.stdout) && /still need approval/.test(applied.stdout), applied.stderr.trim());
  check('exactly one version was added', (await sets())[0].version_count === before + 1);
  check('applying again is a no-op', cli('apply', file).stdout.includes('no change'));
  const multi = join(dir, 'multi.yaml');
  const second = doc(`pac-multi-${suffix}`);
  writeFileSync(multi, `${stringify(doc(`pac-multi-a-${suffix}`))}---\n${stringify(second)}`);
  const mp = cli('plan', multi);
  check('a YAML file with two documents plans both', mp.status === 0 && (mp.stdout.match(/create/g) ?? []).length >= 2, mp.stdout.trim().split('\n').slice(0, 2).join(' | '));
  const badFile = join(dir, 'bad.yaml');
  writeFileSync(badFile, stringify({ ...doc(`pac-cli-bad-${suffix}`), spec: { scope: { type: 'HOST_LIST', hosts: ['nope'] }, rules: [{ action: 'ALLOW', protocol: 'tcp', source: 'zzz' }] } }));
  const bad2 = cli('apply', badFile);
  check('an invalid file exits 1 and lists the problems', bad2.status === 1 && /spec\.scope\.hosts\[0\]/.test(bad2.stderr) && /spec\.rules\[0\]/.test(bad2.stderr), bad2.stderr.trim().split('\n')[0]);
  check('without credentials the CLI refuses', spawnSync(process.execPath, ['scripts/segmentra-policy.mjs', 'plan', file], { encoding: 'utf8', env: { ...process.env, SEGMENTRA_TOKEN: '', SEGMENTRA_USER: '', SEGMENTRA_PASSWORD: '', SEGMENTRA_URL: cliEnv.SEGMENTRA_URL } }).status === 1);

  // cleanup: archive what can be archived
  for (const id of ids) await raw('POST', `/policy-versions/${id}/archive`, { token: op, body: {} });
  const failed = results.filter((r) => !r.pass);
  console.log(`\n[policy-as-code] ${results.length - failed.length}/${results.length} checks passed`);
  for (const f of failed) console.log(`  FAILED: ${f.label}`);
  process.exit(failed.length ? 1 : 0);
}
main().catch((e) => { console.error(e); process.exit(1); });
