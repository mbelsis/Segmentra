import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';
import { compileHostPolicy, CompileError } from '../packages/compiler/dist/index.js';
import { SEGMENTRA_MANAGER_PY, hashLiveRuleset, parsePersistenceOutput, persistSnippet } from '../packages/executor/dist/index.js';

export function policyInput(backend) {
  return {
    host: { id: 'test', hostname: 'test', mgmtIp: '192.0.2.10', sshPort: 2222, firewallBackend: backend, interfaces: [] },
    policyInterfaceScope: { type: 'ALL_INTERFACES' },
    baseline: { mgmtSshCidrs: ['192.0.2.0/24', '2001:db8::/64'] },
    sets: { database_clients: ['198.51.100.0/24', '2001:db8:1::/64'] },
    rules: [{ orderIndex: 1, direction: 'IN', action: 'ALLOW', protocol: 'tcp', ports: '5432,8000-8002',
      sourceType: 'TAG', sourceValue: 'clients', remote: { kind: 'SET', setName: 'database_clients' },
      usePolicyInterfaceScope: true, logMode: 'LOG_RATE_LIMITED' },
    { orderIndex: 2, direction: 'OUT', action: 'DENY', protocol: 'tcp', ports: '23', sourceType: 'CIDR', sourceValue: 'any',
      remote: { kind: 'CIDR' }, usePolicyInterfaceScope: true, logMode: 'NONE' },
    { orderIndex: 3, direction: 'FORWARD', action: 'ALLOW', protocol: 'tcp', ports: '502', sourceType: 'CIDR', sourceValue: 'any',
      remote: { kind: 'CIDR' }, destinationType: 'CIDR', destinationValue: '203.0.113.50', destination: { kind: 'CIDR' }, usePolicyInterfaceScope: true, logMode: 'NONE' }],
    protectedDestinations: ['203.0.113.50', '2001:db8:2::50']
  };
}

test('firewalld compiles permanent native policies with ordered IPv4/IPv6 rules', () => {
  const output = compileHostPolicy(policyInput('firewalld'));
  const manifest = JSON.parse(output.text);
  assert.deepEqual(Object.keys(manifest.policies), ['segmentra-in', 'segmentra-out', 'segmentra-fwd']);
  assert.match(manifest.policies['segmentra-in'], /target="DROP"/);
  assert.match(manifest.policies['segmentra-in'], /port="2222"/);
  assert.match(manifest.policies['segmentra-in'], /family="ipv6"/);
  assert.match(manifest.policies['segmentra-in'], /port="8000-8002"/);
  assert.match(manifest.policies['segmentra-out'], /<drop\/>/);
  assert.match(manifest.policies['segmentra-fwd'], /destination address="203.0.113.50"/);
  const priorities = [...manifest.policies['segmentra-in'].matchAll(/<rule[^>]*priority="(-?\d+)"/g)].map(match => Number(match[1]));
  assert.deepEqual(priorities, [...new Set(priorities)].sort((a, b) => a - b));
});

test('UFW compiles authoritative allows for both address families', () => {
  const output = JSON.parse(compileHostPolicy(policyInput('ufw')).text);
  const raw = compileHostPolicy(policyInput('iptables'));
  assert.match(output.ipv4, /--dports 5432,8000:8002 .* -j ACCEPT/);
  assert.match(output.ipv6, /--icmpv6-type neighbour-solicitation .* -j ACCEPT/);
  assert.match(raw.text, /--dports 5432,8000:8002 .* -j RETURN/);
  assert.match(output.ipv4, /:SEGMENTRA-FWD/);
  assert.match(output.ipv4, /-A SEGMENTRA-FWD .*--dport 502 .* -j ACCEPT/);
  assert.match(raw.text, /-A SEGMENTRA-FWD .*--dport 502 .* -j RETURN/);
});

test('native managers reject unsafe widening and persistent learning mode', () => {
  const scoped = policyInput('firewalld');
  scoped.policyInterfaceScope = { type: 'INTERFACE_NAME', names: ['eth0'] };
  assert.throws(() => compileHostPolicy(scoped), /require ALL_INTERFACES/);
  for (const backend of ['firewalld', 'ufw']) {
    assert.throws(() => compileHostPolicy({ ...policyInput(backend), logOnlyMode: true }), /learning mode is not supported/);
    const bad = policyInput(backend);
    bad.rules[0].ports = '5432; rm -rf /';
    assert.throws(() => compileHostPolicy(bad), CompileError);
  }
});

test('native manager drift includes permanent and live state', () => {
  const state = { backend: 'firewalld', present: true, permanent: { 'segmentra-in': '<policy/>' }, runtime: [] };
  const baseline = hashLiveRuleset('firewalld', JSON.stringify(state));
  assert.notEqual(baseline, hashLiveRuleset('firewalld', JSON.stringify({ ...state, permanent: {} })));
  assert.notEqual(baseline, hashLiveRuleset('firewalld', JSON.stringify({ ...state, present: false })));
  const persistence = parsePersistenceOutput('SEGMENTRA_PERSIST status=persisted method=ufw distro=unsupported family=ufw state=in_sync');
  assert.equal(persistence.method, 'ufw');
  assert.equal(persistence.status, 'persisted');
  assert.doesNotMatch(persistSnippet('ufw', 'persist'), /\|\| :/);
});

test('native helper preserves administrator UFW rules and validates both families', () => {
  const checks = String.raw`
import json, sys
data = json.load(sys.stdin)
scope = {'__name__': 'segmentra_test'}
exec(data['helper'], scope)
assert scope['normalize_iptables']('-A SEGMENTRA-IN -p ipv6-icmp -m icmp6 --icmpv6-type neighbour-solicitation -j ACCEPT') == scope['normalize_iptables']('-A SEGMENTRA-IN -p ipv6-icmp -m icmp6 --icmpv6-type 135 -j ACCEPT')
objects = [{'rule': {'family': 'inet', 'table': 'firewalld', 'chain': 'filter_IN_policy_segmentra-in', 'handle': 1, 'expr': [{'accept': None}]}}, {'rule': {'family': 'inet', 'table': 'firewalld', 'chain': 'filter_IN_policy_segmentra-in', 'handle': 2, 'expr': [{'drop': None}]}}]
scope['run'] = lambda *args, **kwargs: json.dumps({'nftables': objects})
first = scope['kernel_state']('firewalld')
objects.reverse()
assert first != scope['kernel_state']('firewalld'), 'Rule reordering was hidden from drift'
before_handle_change = scope['kernel_state']('firewalld')
objects[0]['rule']['handle'] = 999
assert before_handle_change == scope['kernel_state']('firewalld'), 'Handles are not enforcement state'
original = '# administrator header\n*filter\n:ufw-before-input - [0:0]\n:ufw-before-output - [0:0]\n:ufw-before-forward - [0:0]\n-A ufw-before-input -s 10.0.0.0/8 -j ACCEPT\nCOMMIT\n# administrator footer\n'
for fragment in (data['policy']['ipv4'], data['policy']['ipv6']):
    managed = scope['ufw_block'](fragment)
    applied = scope['replace_block'](original, managed)
    assert '-A ufw-before-input -s 10.0.0.0/8 -j ACCEPT' in applied
    assert applied.index('SEGMENTRA-IN') < applied.index('-s 10.0.0.0/8')
    assert scope['replace_block'](applied, managed) == applied
    assert scope['replace_block'](applied, '') == original
    changed = applied.replace('# administrator footer', '# updated administrator footer')
    assert '# updated administrator footer' in scope['replace_block'](changed, '')
try:
    scope['replace_block'](original + scope['BEGIN'], '')
    raise AssertionError('Malformed markers accepted')
except RuntimeError:
    pass
`;
  const result = spawnSync('python3', ['-c', checks], { input: JSON.stringify({ helper: SEGMENTRA_MANAGER_PY, policy: JSON.parse(compileHostPolicy(policyInput('ufw')).text) }), encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
});
