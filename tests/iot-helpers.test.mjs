import assert from 'node:assert/strict';
import { test } from 'node:test';

import { PROTOCOLS, expandService, parsePortRanges, servicesForRule } from '../apps/api/dist/services/iot-protocols.js';
import { isLocallyAdministered, normalizeMac, ouiPrefix, parseNeighbors, parseOuiList, suggestAssetType } from '../apps/api/dist/services/iot-discovery.js';

test('the catalog is consistent: unique ids, valid ports, every entry documented', () => {
  assert.equal(new Set(PROTOCOLS.map((p) => p.id)).size, PROTOCOLS.length);
  for (const p of PROTOCOLS) {
    assert.ok(p.name && p.note && p.transports.length > 0, p.id);
    assert.ok(['cleartext', 'encrypted', 'mixed'].includes(p.security), p.id);
    for (const t of p.transports) {
      assert.ok(t.protocol === 'tcp' || t.protocol === 'udp', p.id);
      assert.ok(parsePortRanges(t.ports)?.length, `${p.id} ports ${t.ports}`);
    }
  }
  const ports = (id) => PROTOCOLS.find((p) => p.id === id).transports.map((t) => `${t.protocol}/${t.ports}`).join(' ');
  assert.equal(ports('modbus-tcp'), 'tcp/502');
  assert.equal(ports('bacnet-ip'), 'udp/47808');
  assert.equal(ports('mqtt-tls'), 'tcp/8883');
  assert.equal(ports('dnp3'), 'tcp/20000 udp/20000');
});

test('port specs: ranges, lists, invalid input', () => {
  assert.deepEqual(parsePortRanges('80, 443,8000-8100'), [[80, 80], [443, 443], [8000, 8100]]);
  assert.deepEqual(parsePortRanges(''), []);
  assert.deepEqual(parsePortRanges(null), []);
  for (const bad of ['0', '65536', '90-80', 'a', '80,', '1-2-3']) assert.equal(parsePortRanges(bad), null, bad);
});

test('servicesForRule names the services a rule covers by default port, honouring the protocol', () => {
  const ids = (p, ports) => servicesForRule(p, ports).map((s) => s.id);
  assert.deepEqual(ids('tcp', '502'), ['modbus-tcp']);
  assert.deepEqual(ids('udp', '502'), [], 'Modbus/TCP is TCP only');
  assert.deepEqual(ids('tcp', '502,1883'), ['modbus-tcp', 'mqtt']);
  assert.deepEqual(ids('tcp', '100-110'), ['iso-tsap', 'dicom'].sort((a, b) => ids('tcp', '100-110').indexOf(a) - ids('tcp', '100-110').indexOf(b)));
  assert.deepEqual(ids('any', '161'), ['snmp']);
  assert.deepEqual(ids('udp', '34962-34964'), ['profinet'], 'a range entry is named only when fully covered');
  assert.deepEqual(ids('udp', '34962'), []);
  assert.deepEqual(ids('tcp', null), [], 'all ports names nothing');
  assert.deepEqual(ids('icmp', '502'), []);
  assert.deepEqual(ids('tcp', '1-65535'), [], 'a very wide range is not labelled');
  assert.deepEqual(ids('tcp', 'garbage'), []);
  assert.deepEqual(ids('tcp', '102').concat(ids('tcp', '104')), ['iso-tsap', 'dicom']);
});

test('expandService yields one entry per transport', () => {
  assert.deepEqual(expandService('modbus-tcp'), [{ protocol: 'tcp', ports: '502' }]);
  assert.deepEqual(expandService('dnp3'), [{ protocol: 'tcp', ports: '20000' }, { protocol: 'udp', ports: '20000' }]);
  assert.equal(expandService('nope'), null);
});

test('MAC normalisation', () => {
  assert.equal(normalizeMac('AA-BB-CC-DD-EE-0F'), 'aa:bb:cc:dd:ee:0f');
  assert.equal(normalizeMac('aabb.ccdd.ee0f'), 'aa:bb:cc:dd:ee:0f');
  assert.equal(normalizeMac('aa:bb:cc'), null);
  assert.equal(ouiPrefix('00:1b:1b:aa:bb:cc'), '001b1b');
  assert.equal(isLocallyAdministered('02:42:ac:11:00:02'), true);
  assert.equal(isLocallyAdministered('00:1b:1b:aa:bb:cc'), false);
});

test('parseNeighbors reads ip neigh and /proc/net/arp output and drops unusable entries', () => {
  const text = [
    '192.168.10.21 dev eth1 lladdr 00:1b:1b:aa:bb:cc REACHABLE',
    '192.168.10.22 dev eth1 lladdr 00:0e:8c:11:22:33 STALE',
    '192.168.10.23 dev eth1  FAILED',
    '192.168.10.24 dev eth1  INCOMPLETE',
    '192.168.10.25 dev eth1 lladdr 01:00:5e:00:00:fb PERMANENT',
    '192.168.10.1 dev eth0 lladdr 52:54:00:12:34:56 router REACHABLE',
    'fe80::1 dev eth1 lladdr 00:1b:1b:aa:bb:cc router STALE',
    '2001:db8::10 dev eth1 lladdr 00:90:e8:01:02:03 REACHABLE',
    '169.254.1.1 dev eth1 lladdr 00:1b:1b:aa:bb:dd REACHABLE',
    '---',
    'IP address       HW type     Flags       HW address            Mask     Device',
    '192.168.10.21    0x1         0x2         00:1b:1b:aa:bb:cc     *        eth1',
    '192.168.10.30    0x1         0x2         00:80:f4:aa:bb:cc     *        eth1',
    '192.168.10.31    0x1         0x0         00:00:00:00:00:00     *        eth1',
    '',
  ].join('\n');
  const got = parseNeighbors(text);
  assert.deepEqual(got.map((n) => n.ip), ['192.168.10.1', '192.168.10.21', '192.168.10.22', '192.168.10.30', '2001:db8::10']);
  assert.equal(got.find((n) => n.ip === '192.168.10.21').state, 'REACHABLE', 'ip neigh wins over arp');
  assert.equal(got.find((n) => n.ip === '192.168.10.30').iface, 'eth1');
  assert.deepEqual(parseNeighbors(''), []);
});

test('the OUI list parses the IEEE csv (quoted commas) and txt formats', () => {
  const csv = 'Registry,Assignment,Organization Name,Organization Address\r\nMA-L,001B1B,"Siemens AG","Gleiwitzer Str. 555, Nuernberg DE"\r\nMA-L,000EEC,Port Mojo Inc.,x\r\nMA-L,ZZZZZZ,Bad,x\r\n';
  assert.deepEqual(parseOuiList(csv), [{ prefix: '001b1b', vendor: 'Siemens AG' }, { prefix: '000eec', vendor: 'Port Mojo Inc.' }]);
  const txt = '00-1B-1B   (hex)\t\tSiemens AG\n001B1B     (base 16)\t\tSiemens AG\n00-0A-0B   (hex)   Some Vendor, Inc.\n';
  assert.deepEqual(parseOuiList(txt), [{ prefix: '001b1b', vendor: 'Siemens AG' }, { prefix: '000a0b', vendor: 'Some Vendor, Inc.' }]);
});

test('type suggestions come from the vendor name and default to "other"', () => {
  assert.equal(suggestAssetType('Siemens AG'), 'plc');
  assert.equal(suggestAssetType('Rockwell Automation'), 'plc');
  assert.equal(suggestAssetType('AXIS Communications AB'), 'camera');
  assert.equal(suggestAssetType('Hewlett Packard'), 'printer');
  assert.equal(suggestAssetType('Johnson Controls'), 'hvac');
  assert.equal(suggestAssetType('Acme Widgets'), 'other');
  assert.equal(suggestAssetType(null), 'other');
});
