// Regression tests for the code-review findings (compiler scope, drift hooks, ...). Run: npm run test:review-fixes
import assert from 'node:assert/strict';
import { test } from 'node:test';

import { compileHostPolicy } from '../packages/compiler/dist/index.js';
import { extractSegmentraState, hashLiveRuleset } from '../packages/executor/dist/index.js';

const rule = (o = {}) => ({
  orderIndex: 10, direction: 'IN', action: 'ALLOW', protocol: 'tcp', ports: '8080', sourceType: 'CIDR',
  sourceValue: '10.1.0.0/16', logMode: 'NONE', usePolicyInterfaceScope: true, remote: { kind: 'CIDR' }, ...o
});
const input = (o = {}) => ({
  host: { id: '1', hostname: 'h1', mgmtIp: '10.0.0.5', sshPort: 22, firewallBackend: 'iptables',
    interfaces: [{ name: 'eth0', role: 'LAN', enabled: true }, { name: 'eth1', role: 'WAN', enabled: false }] },
  policyInterfaceScope: { type: 'ALL_INTERFACES' }, rules: [rule()], sets: {}, baseline: { mgmtSshCidrs: ['10.0.0.0/24'] }, ...o
});

// --- 1. interface scope that resolves to nothing must not become "all interfaces" ---
for (const backend of ['iptables', 'nftables', 'ufw']) {
  test(`${backend}: a role scope that matches no enabled interface is refused`, () => {
    const i = input({ host: { ...input().host, firewallBackend: backend }, policyInterfaceScope: { type: 'INTERFACE_ROLE', roles: ['DMZ'] } });
    assert.throws(() => compileHostPolicy(i), /matches no interface/);
  });
  test(`${backend}: a disabled interface does not satisfy a role scope`, () => {
    const i = input({ host: { ...input().host, firewallBackend: backend }, policyInterfaceScope: { type: 'INTERFACE_ROLE', roles: ['WAN'] } });
    assert.throws(() => compileHostPolicy(i), /matches no interface/);
  });
  test(`${backend}: a per-rule scope with an empty role list is refused`, () => {
    const i = input({ host: { ...input().host, firewallBackend: backend }, rules: [rule({ usePolicyInterfaceScope: false, interfaceScope: { type: 'INTERFACE_ROLE', roles: [] } })] });
    assert.throws(() => compileHostPolicy(i), /matches no interface/);
  });
  test(`${backend}: a matching role scope still compiles and is restricted to that interface`, () => {
    const out = compileHostPolicy(input({ host: { ...input().host, firewallBackend: backend }, policyInterfaceScope: { type: 'INTERFACE_ROLE', roles: ['LAN'] } })).text;
    assert.ok(out.includes('eth0'), 'interface name present');
  });
}
test('ALL_INTERFACES still compiles for hosts with no interface data', () => {
  assert.ok(compileHostPolicy(input({ host: { ...input().host, interfaces: [] } })).text.includes('SEGMENTRA-IN'));
});

// --- 2. drift: the hook jumps must be exactly what Segmentra installs ---
const save = (inputJump = '-A INPUT -j SEGMENTRA-IN', extraInput = []) => [
  '*filter', ':INPUT ACCEPT [0:0]', ':FORWARD ACCEPT [0:0]', ':OUTPUT ACCEPT [0:0]', ':SEGMENTRA-IN - [0:0]', ':SEGMENTRA-OUT - [0:0]',
  ...extraInput, inputJump, '-A OUTPUT -j SEGMENTRA-OUT', '-A SEGMENTRA-IN -p tcp -m tcp --dport 22 -j RETURN', '-A SEGMENTRA-IN -j DROP', 'COMMIT', ''
].join('\n');
const base = hashLiveRuleset('iptables', save());
test('drift: the installed jump is present and stable', () => {
  assert.equal(extractSegmentraState('iptables', save()).present, true);
  assert.equal(hashLiveRuleset('iptables', save()), base);
});
test('drift: a source-restricted INPUT jump is not "present" and changes the hash', () => {
  const s = save('-A INPUT -s 10.0.0.0/8 -j SEGMENTRA-IN');
  assert.equal(extractSegmentraState('iptables', s).present, false);
  assert.notEqual(hashLiveRuleset('iptables', s), base);
});
test('drift: an interface- or protocol-restricted jump is not "present"', () => {
  for (const j of ['-A INPUT -i eth0 -j SEGMENTRA-IN', '-A INPUT -p tcp -j SEGMENTRA-IN', '-A INPUT -m conntrack --ctstate NEW -j SEGMENTRA-IN']) {
    assert.equal(extractSegmentraState('iptables', save(j)).present, false, j);
  }
});
test('drift: an unconditional ACCEPT ahead of the jump shadows it', () => {
  const s = save('-A INPUT -j SEGMENTRA-IN', ['-A INPUT -j ACCEPT']);
  assert.equal(extractSegmentraState('iptables', s).present, false);
  assert.notEqual(hashLiveRuleset('iptables', s), base);
});
test('drift: other tools\' conditional rules ahead of the jump (fail2ban, Docker) are not drift', () => {
  const s = save('-A INPUT -j SEGMENTRA-IN', ['-A INPUT -p tcp -m multiport --dports 22 -j f2b-sshd', '-A INPUT -i lo -j ACCEPT']);
  assert.equal(extractSegmentraState('iptables', s).present, true);
  assert.equal(hashLiveRuleset('iptables', s), base);
});
