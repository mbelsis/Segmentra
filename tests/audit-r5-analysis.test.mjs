// Audit round 5: tag-rule regex safety and tag semantics, learning/recommendation parsing and sources,
// policy-test analyzer, safety check management SSH, excessive-rules audit, policy diff.
// Pure helpers plus service functions run against a stubbed pg pool.
// Run after `npm run build`: node --test tests/audit-r5-analysis.test.mjs
// (R5_API_DIST=<dir> points the test at another compiled apps/api dist.)
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { pathToFileURL } from 'node:url';

process.env.DATABASE_URL ||= 'postgres://segmentra:unused@127.0.0.1:1/unused';
process.env.JWT_SECRET ||= 'audit-r5-analysis-test-secret-0123456789abcdef';

const DIST = process.env.R5_API_DIST
  ? pathToFileURL(process.env.R5_API_DIST.replace(/\/?$/, '/')).href
  : new URL('../apps/api/dist/', import.meta.url).href;
const load = (p) => import(new URL(p, DIST).href);

const { pool } = await load('db/pool.js');
const tagEngine = await load('services/tag-rule-engine.js');
const { parseFirewallLogs, groupCommunicationFlows, parseLogTimestamp, normalizeProtocol } = await load('services/log-parser.js');
const { recommendedRuleProblems, resolveIpToEntity } = await load('services/recommendation-engine.js');
const { managementSshSources } = await load('services/safety-check.js');
const { flowMatchesRule, ruleInterfaceNames, analyzePolicyTest } = await load('services/policy-test-analyzer.js');
const { classifySourceBreadth, sensitivePortsCovered, describeAddressCount } = await load('services/excessive-rules-audit.js');
const { describeScope, describeRuleScope } = await load('services/policy-diff.js');

/** Stub pool.query: `handler(sql, params)` returns { rows } or undefined (= empty). */
function stubPool(handler = () => undefined) {
  const calls = [];
  const q = async (sql, params = []) => {
    const text = typeof sql === 'string' ? sql : sql.text;
    calls.push({ sql: text, params });
    const r = (await handler(text, params)) ?? {};
    return { rows: r.rows ?? [], rowCount: r.rowCount ?? (r.rows ?? []).length };
  };
  pool.query = q;
  pool.connect = async () => ({ query: q, release() {} });
  return calls;
}

// ---------------------------------------------------------------------------
// 1. ReDoS
// ---------------------------------------------------------------------------

test('regex: stacked / chained overlapping quantifiers are rejected statically', () => {
  const bad = [
    '^\\w*\\w*\\w*\\w*\\w*\\w*\\w*\\w*!$',
    'a?'.repeat(30) + 'a'.repeat(30),
    'a?a?a',
    '^\\w*a\\w*a\\w*a\\w*!',
    '.*a.*b.*',
    '(a+)+$',
    '(a|aa)+',
    '((a+)?)+',
    '(\\w*\\w*\\w*)?x',
    '\\d'.repeat(1) + '+'.concat('\\d?'.repeat(11)),
  ];
  for (const p of bad) assert.ok(tagEngine.regexDangerReason(p), `should reject ${p}`);
});

test('regex: ordinary hostname patterns are accepted', () => {
  const ok = [
    '^web-\\d+$', '^(www\\.)?[a-z]+\\.example\\.com$', '^web(-\\d+)?$', '.*foo.*', 'prod', '^(db|web)-\\d{2,3}-[a-z]+$',
    '^[a-z0-9-]+\\.prod\\.', '\\d+\\.\\d+\\.\\d+\\.\\d+', '(?:a|b)?c', '^(?<n>web)\\d*$', '^\\w+@\\w+$', '^10\\.0\\.',
  ];
  for (const p of ok) assert.equal(tagEngine.validateRegexPattern(p), null, p);
});

test('regex: evaluation runs off-thread with a hard time budget', () => {
  const evil = 'a?'.repeat(30) + 'a'.repeat(30);
  const t0 = Date.now();
  const r = tagEngine.regexTestBatch(evil, ['a'.repeat(30)], 100);
  const elapsed = Date.now() - t0;
  assert.deepEqual(r, { ok: false, reason: 'timeout' });
  assert.ok(elapsed < 1000, `took ${elapsed} ms`);
  // The engine recovers (fresh worker) for the next pattern.
  assert.deepEqual(tagEngine.regexTestBatch('^web', ['web-1', 'db-1']), { ok: true, results: [true, false] });
  // The matcher treats a timed-out / statically rejected pattern as matching nothing.
  const m = new tagEngine.RegexMatcher();
  assert.equal(m.test(evil, 'a'.repeat(30)), false);
  assert.ok(m.problems.length > 0);
});

// ---------------------------------------------------------------------------
// 2. Tag semantics
// ---------------------------------------------------------------------------

const host = (o = {}) => ({
  id: 'h1', hostname: 'web-1', mgmt_ip: '10.0.0.1', vlan_id: null, vlan_tag: null, os_family: 'linux',
  environment: null, firewall_backend: null, tag_ids: ['t-web', 't-db'], tag_names: ['web', 'db'], ...o,
});
const tagCond = (operator, value) => ({ logic: 'AND', conditions: [{ field: 'tag', operator, value }] });

test('tag conditions are set-based (per tag name, not the comma-joined list)', () => {
  const h = host();
  assert.equal(tagEngine.evaluateCriteria(tagCond('equals', 'web'), h), true);
  assert.equal(tagEngine.evaluateCriteria(tagCond('equals', 'web,db'), h), false);
  assert.equal(tagEngine.evaluateCriteria(tagCond('not_equals', 'web'), h), false);
  assert.equal(tagEngine.evaluateCriteria(tagCond('not_equals', 'cache'), h), true);
  assert.equal(tagEngine.evaluateCriteria(tagCond('contains', 'd'), h), true);
  assert.equal(tagEngine.evaluateCriteria(tagCond('contains', ','), h), false);
  assert.equal(tagEngine.evaluateCriteria(tagCond('matches', '^db$'), h), true);
  assert.equal(tagEngine.evaluateCriteria(tagCond('matches', 'web,db'), h), false);
  assert.equal(tagEngine.evaluateCriteria(tagCond('not_equals', 'web'), host({ tag_names: [], tag_ids: [] })), true);
});

test('rule conditions never see tags the same rule assigned; chains through other rules work', () => {
  const names = new Map([['T', 'T'], ['X', 'X'], ['Y', 'Y']]);
  const rules = [
    { id: 'self', tag_id: 'T', enabled: true, criteria: tagCond('has_tag', 'T') },
    { id: 'byName', tag_id: 'X', enabled: true, criteria: { logic: 'AND', conditions: [{ field: 'hostname', operator: 'matches', value: '^web' }] } },
    { id: 'chain', tag_id: 'Y', enabled: true, criteria: tagCond('has_tag', 'X') },
    { id: 'neg', tag_id: 'Y', enabled: true, criteria: tagCond('not_equals', 'Y') },
  ];
  // The host still carries T from a previous run of the "self" rule.
  const h = host({ tag_ids: ['T'], tag_names: ['T'], tags: [{ id: 'T', name: 'T', source: 'rule', ruleId: 'self' }] });
  const r = tagEngine.computeRuleMatches(rules, [h], names, new tagEngine.RegexMatcher());
  assert.equal(r.matchedByRule.get('self').size, 0, 'has_tag T -> T must not keep itself alive');
  assert.equal(r.matchedByRule.get('byName').size, 1);
  assert.equal(r.matchedByRule.get('chain').size, 1, 'chained via the tag another rule assigns');
  // "neg" assigns Y but "chain" also assigns Y, which "neg" sees → it does not match; deterministic.
  assert.equal(r.matchedByRule.get('neg').size, 0);
  assert.deepEqual(r.unconverged, []);

  // A manual tag satisfies a has_tag condition.
  const manual = host({ tag_ids: ['T'], tag_names: ['T'], tags: [{ id: 'T', name: 'T', source: 'manual', ruleId: null }] });
  const r2 = tagEngine.computeRuleMatches([rules[0]], [manual], names, new tagEngine.RegexMatcher());
  assert.equal(r2.matchedByRule.get('self').size, 1);
});

test('tag-rule validation rejects slow regexes and stays synchronous', () => {
  const problems = tagEngine.validateCriteria({ logic: 'AND', conditions: [{ field: 'hostname', operator: 'matches', value: '^\\w*\\w*\\w*!$' }] });
  assert.ok(Array.isArray(problems) && problems.length === 1);
  assert.deepEqual(tagEngine.validateCriteria({ logic: 'AND', conditions: [{ field: 'hostname', operator: 'matches', value: '^web-\\d+$' }] }), []);
});

// ---------------------------------------------------------------------------
// 4 / 9. Log parsing
// ---------------------------------------------------------------------------

test('log parser: IGMP numeric protocol, ICMP error inner header, FORWARD flows', () => {
  const lines = [
    'Nov  1 10:00:00 h kernel: [123.4] FW-AUDIT: ALLOW: catch-all: IN=eth0 OUT= MAC=01:00 SRC=10.0.0.1 DST=224.0.0.1 LEN=32 TOS=0x00 PREC=0xC0 TTL=1 ID=0 DF PROTO=2',
    'Nov  1 10:00:01 h kernel: FW-AUDIT: ALLOW: catch-all: IN=eth0 OUT= MAC=aa SRC=10.0.0.9 DST=10.0.0.2 LEN=88 PROTO=ICMP TYPE=3 CODE=3 [SRC=10.0.0.2 DST=10.0.0.9 LEN=60 PROTO=UDP SPT=53 DPT=40000 LEN=40 ]',
    'Nov  1 10:00:02 h kernel: FW-AUDIT: ALLOW: catch-all: IN=eth0 OUT=eth1 SRC=10.20.0.5 DST=192.168.50.10 PROTO=TCP SPT=40000 DPT=502',
    'Nov  1 10:00:03 h kernel: FW-AUDIT: ALLOW: catch-all: IN=eth0 OUT= SRC=fe80::1 DST=ff02::1 LEN=72 PROTO=ICMPv6 TYPE=135',
  ];
  const e = parseFirewallLogs(lines.join('\n'));
  assert.equal(e[0].protocol, 'igmp');
  assert.equal(e[0].destinationPort, undefined);
  assert.equal(e[1].protocol, 'icmp');
  assert.equal(e[1].sourceIp, '10.0.0.9');
  assert.equal(e[1].destinationPort, undefined);
  assert.equal(e[1].sourcePort, undefined);
  assert.equal(e[3].protocol, 'icmp');
  const flows = groupCommunicationFlows(e);
  const fwd = flows.find((f) => f.direction === 'FORWARD');
  assert.ok(fwd, 'forwarded flows are kept');
  assert.equal(fwd.inInterface, 'eth0');
  assert.equal(fwd.outInterface, 'eth1');
  assert.equal(normalizeProtocol('6'), 'tcp');
  assert.equal(normalizeProtocol('47'), 'gre');
});

test('log timestamps compare as points in time with year inference', () => {
  const now = new Date(2026, 0, 5, 12, 0, 0); // 5 Jan 2026
  const dec = parseLogTimestamp('Dec 31 23:00:00', now);
  const jan = parseLogTimestamp('Jan  2 01:00:00', now);
  assert.equal(new Date(dec).getFullYear(), 2025);
  assert.equal(new Date(jan).getFullYear(), 2026);
  assert.ok(jan > dec);
  assert.equal(parseLogTimestamp('2026-11-01T10:00:00.123+0100'), Date.parse('2026-11-01T10:00:00.123+01:00'));
  assert.equal(parseLogTimestamp('garbage'), null);

  const now2 = new Date(2026, 11, 15);
  const e = parseFirewallLogs([
    'Dec  1 10:00:00 h kernel: FW-AUDIT: ALLOW: catch-all: IN=eth0 OUT= SRC=10.0.0.5 DST=10.0.0.2 PROTO=TCP SPT=5000 DPT=443',
    'Nov 30 10:00:00 h kernel: FW-AUDIT: ALLOW: catch-all: IN=eth0 OUT= SRC=10.0.0.5 DST=10.0.0.2 PROTO=TCP SPT=5000 DPT=443',
    'Nov  9 10:00:00 h kernel: FW-AUDIT: ALLOW: catch-all: IN=eth0 OUT= SRC=10.0.0.5 DST=10.0.0.2 PROTO=TCP SPT=5000 DPT=443',
  ].join('\n'));
  const [flow] = groupCommunicationFlows(e, now2);
  assert.equal(flow.count, 3);
  assert.equal(flow.firstSeen, 'Nov  9 10:00:00');
  assert.equal(flow.lastSeen, 'Dec  1 10:00:00');
});

// ---------------------------------------------------------------------------
// 3 / 4. Recommendations
// ---------------------------------------------------------------------------

test('recommended rules use the rule-route validation', () => {
  const base = { direction: 'IN', action: 'ALLOW', protocol: 'tcp', ports: '443', sourceType: 'CIDR', sourceValue: '10.0.0.5/32', comment: 'ok' };
  assert.deepEqual(recommendedRuleProblems(base), []);
  assert.ok(recommendedRuleProblems({ ...base, protocol: 'igmp', ports: null }).length > 0);
  assert.ok(recommendedRuleProblems({ ...base, protocol: 'icmp', ports: '53' }).length > 0);
  assert.ok(recommendedRuleProblems({ ...base, sourceValue: '10.0.0.5/33' }).length > 0);
  assert.ok(recommendedRuleProblems({ ...base, direction: 'FORWARD' }).length > 0);
  assert.ok(recommendedRuleProblems({ ...base, comment: 'say "hi"' }).length > 0);
});

test('recommendation source is the observed address, HOST only for an exact mgmt_ip match', async () => {
  const HOST_ID = '11111111-1111-4111-8111-111111111111';
  stubPool((sql, params) => {
    if (/FROM hosts h WHERE h\.mgmt_ip = \$1::inet/.test(sql)) return params[0] === '10.0.0.10' ? { rows: [{ id: HOST_ID, hostname: 'web-1' }] } : { rows: [] };
    if (/FROM tags t JOIN host_tags/.test(sql)) return { rows: [{ name: 'all-linux' }] };
    if (/FROM host_interfaces hi/.test(sql)) return params[0] === '10.0.1.7' ? { rows: [{ host_id: HOST_ID, hostname: 'web-1', name: 'eth1' }] } : { rows: [] };
    if (/FROM vlans/.test(sql)) return { rows: [{ id: 'v1', name: 'servers', subnet: '10.0.0.0/16' }] };
  });
  const a = await resolveIpToEntity('10.0.0.10');
  assert.equal(a.type, 'HOST');
  assert.equal(a.value, HOST_ID);
  const b = await resolveIpToEntity('10.0.1.7');
  assert.deepEqual([b.type, b.value], ['CIDR', '10.0.1.7/32']);
  assert.match(b.context, /eth1 of web-1/);
  const c = await resolveIpToEntity('10.0.2.2');
  assert.deepEqual([c.type, c.value], ['CIDR', '10.0.2.2/32']);
  assert.match(c.context, /VLAN servers/);
  const d = await resolveIpToEntity('2001:db8::5');
  assert.deepEqual([d.type, d.value], ['CIDR', '2001:db8::5/128']);
  assert.equal(await resolveIpToEntity('unknown'), null);
});

// ---------------------------------------------------------------------------
// 5 / 6. Analyzer and safety check
// ---------------------------------------------------------------------------

test('management SSH sources mirror the compiler fallbacks per family', () => {
  assert.deepEqual(managementSshSources(['10.0.0.0/24'], '2001:db8::5').sources, ['10.0.0.0/24', '::/0']);
  assert.deepEqual(managementSshSources(['10.0.0.0/24'], '10.0.0.5').sources, ['10.0.0.0/24']);
  assert.deepEqual(managementSshSources([], '10.0.0.5').sources, ['0.0.0.0/0', '::/0']);
  assert.deepEqual(managementSshSources(['fd00::/64'], '10.0.0.5/32').sources, ['fd00::/64', '0.0.0.0/0']);
});

test('analyzer interface scope: match / no / uncertain like the compiler', () => {
  const ifs = [{ name: 'eth0', role: 'mgmt', enabled: true }, { name: 'eth1', role: 'data', enabled: true }];
  const rule = { direction: 'IN', action: 'ALLOW', protocol: 'tcp', ports: '443', use_policy_interface_scope: false, interface_scope_type: 'INTERFACE_ROLE', interface_scope_roles: ['data'] };
  const names = ruleInterfaceNames(rule, { type: 'ALL_INTERFACES' }, ifs);
  assert.deepEqual(names, ['eth1']);
  const flow = { direction: 'IN', sourceIp: '10.0.0.5', destinationIp: '10.0.0.2', protocol: 'tcp', destinationPort: 443, count: 1, firstSeen: '', lastSeen: '' };
  assert.equal(flowMatchesRule({ ...flow, inInterface: 'eth1' }, rule, null, names), 'match');
  assert.equal(flowMatchesRule({ ...flow, inInterface: 'eth0' }, rule, null, names), 'no');
  assert.equal(flowMatchesRule(flow, rule, null, names), 'uncertain');
  // A rule without a stored scope (use_policy false, type null) follows the policy scope.
  assert.deepEqual(ruleInterfaceNames({ use_policy_interface_scope: false, interface_scope_type: null }, { type: 'INTERFACE_ROLE', roles: ['mgmt'] }, ifs), ['eth0']);
  // FORWARD rules match forwarded flows by source and destination.
  const fwd = { direction: 'FORWARD', action: 'ALLOW', protocol: 'tcp', ports: '502' };
  const fflow = { ...flow, direction: 'FORWARD', sourceIp: '10.20.0.5', destinationIp: '192.168.50.10', destinationPort: 502 };
  assert.equal(flowMatchesRule(fflow, fwd, ['10.20.0.0/16'], null, ['192.168.50.0/24']), 'match');
  assert.equal(flowMatchesRule(fflow, fwd, ['10.20.0.0/16'], null, ['192.168.60.0/24']), 'no');
  assert.equal(flowMatchesRule(fflow, rule, null, null), 'no');
});

test('analyzePolicyTest: VLAN sources are member mgmt_ips, IPv6 mgmt SSH fallback, FORWARD flows evaluated', async () => {
  const VLAN = '22222222-2222-4222-8222-222222222222';
  const flows = [
    // VLAN subnet address that is not a member host's mgmt_ip → default deny (compiler semantics)
    { direction: 'IN', sourceIp: '10.5.0.99', destinationIp: '10.0.0.2', protocol: 'tcp', destinationPort: 8080, count: 1, firstSeen: '', lastSeen: '', inInterface: 'eth0' },
    { direction: 'IN', sourceIp: '10.5.0.10', destinationIp: '10.0.0.2', protocol: 'tcp', destinationPort: 8080, count: 1, firstSeen: '', lastSeen: '', inInterface: 'eth0' },
    // SSH over IPv6 from anywhere: allowed by the compiler's fallbackV6 (mgmt_ip is IPv6, mgmt VLAN v4-only)
    { direction: 'IN', sourceIp: '2001:db8::99', destinationIp: '2001:db8::5', protocol: 'tcp', destinationPort: 22, count: 1, firstSeen: '', lastSeen: '', inInterface: 'eth0' },
    // forwarded to a protected device without FORWARD rule → would be blocked
    { direction: 'FORWARD', sourceIp: '10.20.0.5', destinationIp: '192.168.50.10', protocol: 'tcp', destinationPort: 502, count: 1, firstSeen: '', lastSeen: '', inInterface: 'eth0', outInterface: 'eth1' },
  ];
  let saved = null;
  stubPool((sql, params) => {
    if (/FROM policy_test_sessions/.test(sql)) return { rows: [{ id: 's', host_id: 'h', policy_version_id: 'v', raw_log_data: { flows } }] };
    if (/FROM policy_rules/.test(sql)) return { rows: [{ id: 'r1', order_index: 1, direction: 'IN', action: 'ALLOW', protocol: 'tcp', ports: '8080', source_type: 'VLAN', source_value: VLAN, use_policy_interface_scope: true }] };
    if (/FROM policy_versions/.test(sql)) return { rows: [{ interface_scope_type: 'ALL_INTERFACES' }] };
    if (/SELECT ssh_port, mgmt_ip FROM hosts/.test(sql)) return { rows: [{ ssh_port: 22, mgmt_ip: '2001:db8::5' }] };
    if (/FROM host_interfaces/.test(sql)) return { rows: [{ name: 'eth0', role: 'data', enabled: true }] };
    if (/FROM hosts WHERE vlan_id = \$1/.test(sql)) return { rows: [{ mgmt_ip: '10.5.0.10' }] };
    if (/FROM vlans WHERE id/.test(sql)) return { rows: [{ subnet: '10.5.0.0/16' }] };
    if (/iot_asset_gateways/.test(sql)) return { rows: [{ ip: '192.168.50.10' }] };
    if (/management_vlan_id/.test(sql)) return { rows: [{ subnet: '10.0.0.0/24' }] };
    if (/UPDATE policy_test_sessions/.test(sql)) saved = params;
  });
  const r = await analyzePolicyTest('s');
  assert.equal(r.summary.totalFlows, 4);
  assert.equal(r.summary.forwarded, 1);
  assert.deepEqual(r.unexpectedAllows.map((x) => x.flow.sourceIp).sort(), ['10.20.0.5', '10.5.0.99']);
  assert.ok(r.matchedFlows.some((m) => m.flow.sourceIp === '10.5.0.10'));
  assert.ok(r.matchedFlows.some((m) => m.flow.sourceIp === '2001:db8::99' && /management SSH/.test(m.matchedRule.comment)));
  assert.ok(saved);
});

// ---------------------------------------------------------------------------
// 7. Excessive rules audit
// ---------------------------------------------------------------------------

test('excessive-rules audit: wide-open detection, range containment, IPv6 counts', () => {
  for (const v of ['any', '*', '0.0.0.0/0', '::/0', '10.0.0.1/32, ::/0', '0.0.0.0/1', '2000::/3']) {
    assert.equal(classifySourceBreadth(v).kind, 'wide', v);
  }
  assert.equal(classifySourceBreadth('10.0.0.0/8').kind, 'broad');
  assert.equal(classifySourceBreadth('2001:db8::/32').kind, 'broad');
  assert.equal(classifySourceBreadth('10.1.0.0/16').kind, 'narrow');
  assert.ok(sensitivePortsCovered('1-65535').includes(27017));
  assert.ok(sensitivePortsCovered('20-30000').includes(9200));
  assert.deepEqual(sensitivePortsCovered('443,8000-8079'), []);
  assert.deepEqual(sensitivePortsCovered('5432'), [5432]);
  assert.equal(describeAddressCount(4, 8), '16,777,216');
  assert.equal(describeAddressCount(6, 32), '2^96');
});

// ---------------------------------------------------------------------------
// 8. Policy diff scope
// ---------------------------------------------------------------------------

test('policy diff: null policy scope is INTERFACE_ROLE, rule scope falls back to the policy scope', () => {
  assert.equal(describeScope(null, null, null), 'INTERFACE_ROLE:');
  assert.notEqual(describeScope(null, null, null), describeScope('ALL_INTERFACES', null, null));
  assert.equal(describeRuleScope({ use_policy_interface_scope: true, interface_scope_type: 'ALL_INTERFACES' }), null);
  assert.equal(describeRuleScope({ use_policy_interface_scope: false, interface_scope_type: null }), null);
  assert.equal(describeRuleScope({ use_policy_interface_scope: false, interface_scope_type: 'INTERFACE_NAME', interface_scope_names: ['b', 'a'] }), 'INTERFACE_NAME:a,b');
});
