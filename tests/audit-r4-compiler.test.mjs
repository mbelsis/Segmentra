import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { test } from 'node:test';

import { compileHostPolicy, truncateUtf8 } from '../packages/compiler/dist/index.js';

const rule = (o = {}) => ({
  orderIndex: 10, direction: 'IN', action: 'ALLOW', protocol: 'tcp', ports: '8080', sourceType: 'CIDR',
  sourceValue: '172.28.77.50/32', logMode: 'NONE', usePolicyInterfaceScope: true, remote: { kind: 'CIDR' }, ...o
});
const input = (o = {}) => ({
  host: { id: '1', hostname: 'n1', mgmtIp: '10.0.0.5', sshPort: 22, firewallBackend: 'iptables', interfaces: [] },
  policyInterfaceScope: { type: 'ALL_INTERFACES' }, rules: [rule()], sets: {}, baseline: { mgmtSshCidrs: ['10.0.0.0/24'] }, ...o
});
const nftHost = { id: '1', hostname: 'n1', mgmtIp: '10.0.0.5', sshPort: 22, firewallBackend: 'nftables', interfaces: [] };
const fwdRule = (o = {}) => rule({
  orderIndex: 50, direction: 'FORWARD', sourceValue: '10.20.0.0/16', ports: '502',
  destinationType: 'CIDR', destinationValue: '192.168.50.0/24', destination: { kind: 'CIDR' }, ...o
});
const bytes = (s) => Buffer.byteLength(s, 'utf8');
const lines = (t) => t.split('\n');
const sha = (t) => crypto.createHash('sha256').update(t, 'utf8').digest('hex');

const COMMENTS = {
  greek: 'Επιτρέπεται η πρόσβαση από το δίκτυο παραγωγής προς τον ελεγκτή της γραμμής Α και τον διακομιστή ιστορικού δεδομένων',
  cjk: '允许生产网络访问生产线控制器和历史数据服务器，仅限工作时间内的维护窗口使用，其他时间一律拒绝访问请求谢谢',
  emoji: '🔥🚀 allow 👩‍💻 ops ' + '🧱'.repeat(60)
};

/** Valid UTF-8 round trip and no lone surrogates: no code point was split. */
function assertWhole(s, what) {
  assert.equal(Buffer.from(s, 'utf8').toString('utf8'), s, `${what}: broken code point`);
  assert.ok(!/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(s), `${what}: lone surrogate`);
  assert.ok(!s.includes('�'), `${what}: replacement char`);
}

test('truncateUtf8 cuts by bytes on code point boundaries', () => {
  assert.equal(truncateUtf8('abc', 10), 'abc');
  assert.equal(truncateUtf8('αβγ', 5), 'αβ'); // 2 bytes each
  assert.equal(truncateUtf8('中文字', 7), '中文'); // 3 bytes each
  assert.equal(truncateUtf8('a🔥b', 4), 'a'); // the 4-byte emoji does not fit after "a" in 4 bytes
  assert.equal(truncateUtf8('a🔥b', 5), 'a🔥');
  for (const [k, v] of Object.entries(COMMENTS)) {
    for (let n = 0; n < 60; n++) {
      const t = truncateUtf8(v, n);
      assert.ok(bytes(t) <= n, `${k}@${n}`);
      assertWhole(t, `${k}@${n}`);
    }
  }
});

for (const [kind, comment] of Object.entries(COMMENTS)) {
  test(`iptables (${kind}): --comment <= 255 bytes, --log-prefix <= 29 bytes, no split code points`, () => {
    for (const extra of [{}, { logOnlyMode: true }]) {
      const rules = [rule({ comment, logMode: 'LOG' }), rule({ orderIndex: 20, direction: 'BOTH', comment, logMode: 'LOG_RATE_LIMITED' }), fwdRule({ comment, logMode: 'LOG' })];
      const out = compileHostPolicy(input({ rules, dockerPublishedPorts: !extra.logOnlyMode, ...extra }));
      let comments = 0;
      let prefixes = 0;
      for (const text of [out.text, out.ip6tablesRules]) {
        for (const m of text.matchAll(/--comment "([^"]*)"/g)) { comments++; assert.ok(bytes(m[1]) <= 255, m[1]); assertWhole(m[1], 'comment'); }
        for (const m of text.matchAll(/--log-prefix "([^"]*)"/g)) { prefixes++; assert.ok(bytes(m[1]) <= 29, `${bytes(m[1])}: ${m[1]}`); assertWhole(m[1], 'log prefix'); }
      }
      assert.ok(comments > 0 && prefixes > 0);
      // The user's comment text actually made it into the (truncated) comment and log prefix.
      const first = [...comment][0];
      assert.ok(out.text.includes(`--comment "segmentra:rule10 ${first}`));
      assert.ok(out.text.includes(`--log-prefix "SEGMENTRA: ALLOW ${first}`) || out.text.includes(`--log-prefix "FW-AUDIT: ALLOW ${first}`));
    }
  });

  test(`nftables (${kind}): comment <= 128 bytes, log prefix < 128 bytes, no split code points`, () => {
    for (const extra of [{}, { logOnlyMode: true }]) {
      const rules = [rule({ comment, logMode: 'LOG' }), rule({ orderIndex: 20, direction: 'OUT', comment, logMode: 'LOG' }), fwdRule({ comment, logMode: 'LOG' })];
      const text = compileHostPolicy(input({ host: nftHost, rules, dockerPublishedPorts: !extra.logOnlyMode, ...extra })).text;
      let comments = 0;
      let prefixes = 0;
      for (const m of text.matchAll(/comment "([^"]*)"/g)) { comments++; assert.ok(bytes(m[1]) <= 128, `${bytes(m[1])}: ${m[1]}`); assertWhole(m[1], 'comment'); }
      for (const m of text.matchAll(/log prefix "([^"]*)"/g)) { prefixes++; assert.ok(bytes(m[1]) <= 127, `${bytes(m[1])}: ${m[1]}`); assertWhole(m[1], 'log prefix'); }
      assert.ok(comments > 0 && prefixes > 0);
    }
  });
}

test('iptables: published-port rules only match DNAT traffic leaving via a Docker bridge', () => {
  const out = compileHostPolicy(input({ dockerPublishedPorts: true, rules: [rule(), rule({ orderIndex: 20, action: 'DENY', ports: '8081', sourceValue: '10.9.0.0/16' }), fwdRule()] }));
  for (const text of [out.text, out.ip6tablesRules]) {
    const fwd = lines(text).filter((x) => x.startsWith('-A SEGMENTRA-FWD'));
    const dnat = fwd.filter((x) => x.includes('--ctstate DNAT'));
    assert.ok(dnat.length > 0);
    for (const x of dnat) {
      assert.match(x, / -o (docker0|docker_gwbridge|br-\+) /, `not restricted to Docker egress: ${x}`);
      assert.ok((x.match(/ -o /g) ?? []).length === 1 && (x.match(/ -i /g) ?? []).length <= 1, x);
    }
    // No catch-all DNAT verdict without -o: a non-Docker DNAT'd packet (libvirt, gateway port forward)
    // falls through to the user's FORWARD rules.
    assert.ok(!fwd.some((x) => x.includes('published_default') && !x.includes(' -o ')));
  }
  const fwd4 = lines(out.text).filter((x) => x.startsWith('-A SEGMENTRA-FWD'));
  assert.ok(fwd4.some((x) => x.includes('segmentra:fwd50') && x.includes('-d 192.168.50.0/24') && x.endsWith('-j RETURN')));
});

test('nftables: published-port rules sit in their own chain, reached only for Docker egress', () => {
  const text = compileHostPolicy(input({ host: nftHost, dockerPublishedPorts: true, rules: [rule(), fwdRule()] })).text;
  const l = lines(text).map((x) => x.trim());
  const pubChain = l.indexOf('chain published_ports {');
  const fwdChain = l.indexOf('chain forward {');
  assert.ok(pubChain > 0 && fwdChain > pubChain, 'published chain declared before the forward chain');
  const fwdBody = l.slice(fwdChain, l.indexOf('}', fwdChain));
  const pubBody = l.slice(pubChain, l.indexOf('}', pubChain));
  assert.deepEqual(fwdBody.filter((x) => x.includes('jump published_ports')), [
    'oifname "docker0" ct status dnat jump published_ports comment "published_dispatch"',
    'oifname "docker_gwbridge" ct status dnat jump published_ports comment "published_dispatch"',
    'oifname "br-*" ct status dnat jump published_ports comment "published_dispatch"'
  ]);
  // The forward chain has no unrestricted DNAT verdict any more.
  assert.ok(!fwdBody.some((x) => x.startsWith('ct status dnat')));
  assert.ok(pubBody.some((x) => x.includes('published_default')));
  assert.ok(pubBody.some((x) => x.includes('ct original proto-dst { 8080 } accept')));
  assert.ok(fwdBody.some((x) => x.includes('ip daddr 192.168.50.0/24') && x.endsWith('accept')));
  // Without published ports there is no extra chain.
  assert.ok(!compileHostPolicy(input({ host: nftHost, rules: [rule(), fwdRule()] })).text.includes('published_ports'));
  assert.ok(!compileHostPolicy(input({ host: nftHost, dockerPublishedPorts: true, logOnlyMode: true })).text.includes('published_ports'));
});

test('iptables sha256 covers the ip6tables fragment too', () => {
  const a = compileHostPolicy(input({ rules: [rule({ sourceValue: 'fd00::1' })] }));
  const b = compileHostPolicy(input({ rules: [rule({ sourceValue: 'fd00::2' })] }));
  assert.equal(a.text, b.text, 'IPv4 fragment is identical');
  assert.notEqual(a.ip6tablesRules, b.ip6tablesRules);
  assert.notEqual(a.sha256, b.sha256);
  assert.equal(a.sha256, sha(`${a.text}\n#ip6\n${a.ip6tablesRules}`));
  // Other backends hash their single text unchanged.
  const n = compileHostPolicy(input({ host: nftHost }));
  assert.equal(n.sha256, sha(n.text));
});

test('IoT destination CIDR sets compile to the full network (both families)', () => {
  const r = fwdRule({ sourceValue: 'any', destinationType: 'IOT_ASSET', destinationValue: 'x', destination: { kind: 'SET', setName: 'dst_iot_x' } });
  const sets = { dst_iot_x: ['192.168.10.0/24', '192.168.20.7', 'fd00:10::/64'] };
  const ipt = compileHostPolicy(input({ rules: [r], sets }));
  assert.ok(ipt.text.includes('-d 192.168.10.0/24') && ipt.text.includes('-d 192.168.20.7'));
  assert.ok(ipt.ip6tablesRules.includes('-d fd00:10::/64'));
  const nft = compileHostPolicy(input({ host: nftHost, rules: [r], sets })).text;
  assert.ok(nft.includes('elements = { 192.168.10.0/24, 192.168.20.7 }'));
});

test('api ip-utils: destination addresses keep CIDRs, IoT validation is strict', async (t) => {
  let ip;
  try {
    ip = await import('../apps/api/src/services/ip-utils.ts');
  } catch {
    t.skip('this Node version cannot import TypeScript directly');
    return;
  }
  const { normalizeDestinationAddress: norm, isStrictIpOrCidr: strict } = ip;
  assert.equal(norm('192.168.10.0/24'), '192.168.10.0/24');
  assert.equal(norm(' 192.168.10.5 '), '192.168.10.5');
  assert.equal(norm('10.0.0.5/32'), '10.0.0.5');
  assert.equal(norm('fd00::1/128'), 'fd00::1');
  assert.equal(norm('fd00::/64'), 'fd00::/64');
  for (const bad of ['', null, 'plc-1', '10.0.0.300', '10.0.0.0/33', 'fe80::1%eth0', '10.0.0.1, 10.0.0.2']) assert.equal(norm(bad), null, String(bad));
  for (const good of ['192.168.50.10', '192.168.50.0/24', '2001:db8::1', '2001:db8::/48']) assert.ok(strict(good), good);
  for (const bad of ['fe80::1%eth0', 'host.example', '1.2.3.4/x', '1.2.3']) assert.ok(!strict(bad), bad);
});
