import assert from 'node:assert/strict';
import { test } from 'node:test';

import { compileHostPolicy } from '../packages/compiler/dist/index.js';

const rule = (o = {}) => ({
  orderIndex: 10, direction: 'IN', action: 'ALLOW', protocol: 'tcp', ports: '8080', sourceType: 'CIDR',
  sourceValue: '172.28.77.50/32', logMode: 'NONE', usePolicyInterfaceScope: true, remote: { kind: 'CIDR' }, ...o
});
const input = (o = {}) => ({
  host: { id: '1', hostname: 'n1', mgmtIp: '10.0.0.5', sshPort: 22, firewallBackend: 'iptables', interfaces: [] },
  policyInterfaceScope: { type: 'ALL_INTERFACES' }, rules: [rule()], sets: {}, baseline: { mgmtSshCidrs: ['10.0.0.0/24'] }, ...o
});
const lines = (text) => text.split('\n');
const peers = ['172.28.77.12', '172.28.77.13'];

test('output is byte-identical when neither Swarm nor published-port support is enabled', () => {
  const plain = compileHostPolicy(input());
  assert.equal(compileHostPolicy(input({ swarm: null, dockerPublishedPorts: false })).text, plain.text);
  assert.ok(!plain.text.includes('swarm'));
  assert.ok(!plain.text.includes('SEGMENTRA-FWD'));
  const nft = compileHostPolicy(input({ host: { ...input().host, firewallBackend: 'nftables' } }));
  assert.ok(!nft.text.includes('chain forward'));
});

test('iptables: a manager allows 2377, 7946 tcp/udp and 4789/udp from each peer, ahead of policy rules', () => {
  const out = compileHostPolicy(input({ swarm: { role: 'manager', peerCidrs: peers } })).text;
  for (const p of peers) {
    for (const m of ['-p tcp -s ' + p + ' --dport 2377', '-p tcp -s ' + p + ' --dport 7946', '-p udp -s ' + p + ' --dport 7946', '-p udp -s ' + p + ' --dport 4789']) {
      assert.ok(out.includes(m), `missing ${m}`);
    }
  }
  const l = lines(out);
  const firstSwarm = l.findIndex((x) => x.includes('segmentra:swarm_'));
  const firstRule = l.findIndex((x) => x.includes('segmentra:rule10'));
  const deflt = l.findIndex((x) => x.includes('segmentra:default') && x.includes('-A SEGMENTRA-IN'));
  assert.ok(firstSwarm > 0 && firstSwarm < firstRule && firstRule < deflt);
  assert.ok(!out.includes('SEGMENTRA-FWD'), 'Swarm alone does not enable forwarding filters');
});

test('a worker does not open 2377; encrypted overlays also allow ESP', () => {
  const worker = compileHostPolicy(input({ swarm: { role: 'worker', peerCidrs: peers } })).text;
  assert.ok(!worker.includes('--dport 2377'));
  assert.ok(worker.includes('--dport 7946') && worker.includes('--dport 4789'));
  assert.ok(!worker.includes('-p esp'));
  const enc = compileHostPolicy(input({ swarm: { role: 'worker', peerCidrs: ['172.28.77.12'], encryptedOverlay: true } })).text;
  assert.ok(enc.includes('-p esp -s 172.28.77.12'));
});

test('peers are split by family and deduplicated; a single node gets no peer rules', () => {
  const sw = { role: 'manager', peerCidrs: ['172.28.77.12', '172.28.77.12', 'fd00::12'] };
  const out = compileHostPolicy(input({ swarm: sw }));
  assert.equal(lines(out.text).filter((x) => x.includes('swarm_manager')).length, 1);
  assert.ok(out.ip6tablesRules.includes('-p tcp -s fd00::12 --dport 2377'));
  assert.ok(!out.ip6tablesRules.includes('172.28.77.12'));
  const alone = compileHostPolicy(input({ swarm: { role: 'manager', peerCidrs: [] } })).text;
  assert.ok(!alone.includes('swarm_'));
  assert.throws(() => compileHostPolicy(input({ swarm: { role: 'manager', peerCidrs: ['not-an-ip'] } })), /Swarm peer address/);
});

test('nftables: Swarm ports are allowed from the peers set', () => {
  const out = compileHostPolicy(input({ host: { ...input().host, firewallBackend: 'nftables' }, swarm: { role: 'manager', peerCidrs: peers } })).text;
  assert.ok(out.includes('ip saddr { 172.28.77.12, 172.28.77.13 } tcp dport 2377 accept comment "swarm_manager"'));
  assert.ok(out.includes('udp dport 4789 accept comment "swarm_vxlan"'));
});

test('iptables: published ports are matched on the original destination port in SEGMENTRA-FWD', () => {
  const out = compileHostPolicy(input({ dockerPublishedPorts: true, rules: [rule(), rule({ orderIndex: 20, ports: '9000-9010', sourceValue: '10.1.0.0/16' }), rule({ orderIndex: 30, action: 'DENY', ports: '8081', sourceValue: '10.9.0.0/16' })] })).text;
  const fwd = lines(out).filter((x) => x.startsWith('-A SEGMENTRA-FWD'));
  assert.ok(fwd.some((x) => x.includes('-p tcp -s 172.28.77.50/32 -m conntrack --ctstate DNAT --ctorigdstport 8080') && x.endsWith('-j RETURN')));
  assert.ok(fwd.some((x) => x.includes('--ctorigdstport 9000:9010') && x.includes('-s 10.1.0.0/16')));
  assert.ok(fwd.some((x) => x.includes('--ctorigdstport 8081') && x.endsWith('-j DROP')));
  const dflt = fwd.find((x) => x.includes('published_default'));
  assert.match(dflt, /^-A SEGMENTRA-FWD -m conntrack --ctstate DNAT -m comment .* -j DROP$/);
  // Docker's own bridges are exempt (one -i per rule: iptables allows a single --in-interface), and
  // replies of allowed connections pass first.
  for (const br of ['docker0', 'docker_gwbridge', 'br-+']) {
    const ex = fwd.find((x) => x.includes(`-i ${br} `));
    assert.ok(ex && ex.includes('--ctstate DNAT') && ex.endsWith('-j RETURN'), `exemption for ${br}`);
    assert.ok(fwd.indexOf(ex) < fwd.indexOf(dflt));
  }
  for (const x of fwd) assert.ok((x.match(/ -i /g) ?? []).length <= 1, `at most one -i: ${x}`);
  assert.ok(fwd[0].includes('--ctstate ESTABLISHED,RELATED'));
  assert.ok(fwd.indexOf(dflt) > fwd.findIndex((x) => x.includes('--ctorigdstport 8080')));
});

test('published ports: default ACCEPT hands unmatched traffic back, log-only mode skips it, ICMP rules are ignored', () => {
  const accept = compileHostPolicy(input({ dockerPublishedPorts: true, defaultInputAction: 'ACCEPT' })).text;
  assert.match(lines(accept).find((x) => x.includes('published_default')), /-j RETURN$/);
  const logOnly = compileHostPolicy(input({ dockerPublishedPorts: true, logOnlyMode: true })).text;
  assert.ok(!logOnly.includes('ctstate DNAT'));
  const icmp = compileHostPolicy(input({ dockerPublishedPorts: true, rules: [rule({ protocol: 'icmp', ports: null })] })).text;
  assert.ok(!icmp.includes('published rule10'));
});

test('published ports: rules without ports match all DNAT traffic from that source; OUT rules are not copied', () => {
  const out = compileHostPolicy(input({ dockerPublishedPorts: true, rules: [rule({ protocol: 'any', ports: null }), rule({ orderIndex: 20, direction: 'OUT' })] })).text;
  const fwd = lines(out).filter((x) => x.startsWith('-A SEGMENTRA-FWD') && x.includes('published rule'));
  assert.equal(fwd.length, 1);
  assert.ok(fwd[0].includes('-s 172.28.77.50/32 -m conntrack --ctstate DNAT') && !fwd[0].includes('--ctorigdstport') && !fwd[0].includes(' -p '));
});

test('published ports: interface-scoped rules keep their interface', () => {
  const scoped = compileHostPolicy(input({
    host: { ...input().host, interfaces: [{ name: 'eth0', role: 'WAN', enabled: true }] },
    policyInterfaceScope: { type: 'INTERFACE_NAME', names: ['eth0'] }
  }));
  const withPorts = compileHostPolicy({ ...input({ host: { ...input().host, interfaces: [{ name: 'eth0', role: 'WAN', enabled: true }] }, policyInterfaceScope: { type: 'INTERFACE_NAME', names: ['eth0'] }, dockerPublishedPorts: true }) }).text;
  assert.ok(lines(withPorts).some((x) => x.startsWith('-A SEGMENTRA-FWD') && x.includes('-i eth0') && x.includes('--ctorigdstport 8080')));
  assert.ok(scoped.text.length > 0);
});

test('nftables: published ports use ct original proto-dst in the forward chain', () => {
  const out = compileHostPolicy(input({ host: { ...input().host, firewallBackend: 'nftables' }, dockerPublishedPorts: true })).text;
  assert.ok(out.includes('chain forward'));
  assert.ok(out.includes('ct status dnat ip saddr 172.28.77.50/32 meta l4proto tcp ct original proto-dst { 8080 } accept comment "published rule10"'));
  assert.ok(out.includes('ct status dnat iifname != "docker0" iifname != "docker_gwbridge" iifname != "br-*" drop comment "published_default"'));
});

test('firewalld and UFW refuse Docker published-port enforcement instead of silently ignoring it', () => {
  const on = (firewallBackend, extra) => input({ host: { ...input().host, firewallBackend }, ...extra });
  assert.throws(() => compileHostPolicy(on('firewalld', { swarm: { role: 'worker', peerCidrs: [] } })), /firewalld is not supported/);
  assert.throws(() => compileHostPolicy(on('firewalld', { dockerPublishedPorts: true })), /firewalld is not supported/);
  assert.throws(() => compileHostPolicy(on('ufw', { dockerPublishedPorts: true })), /UFW is not supported/);
  assert.doesNotThrow(() => compileHostPolicy(on('ufw', { swarm: { role: 'worker', peerCidrs: ['10.0.0.2'] } })));
  assert.doesNotThrow(() => compileHostPolicy(on('firewalld', {})));
});
