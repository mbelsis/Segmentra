import pg from 'pg';

const { Client } = pg;
const client = new Client({ connectionString: process.env.DATABASE_URL || 'postgres://segmentra:segmentra@127.0.0.1:15432/segmentra' });
await client.connect();

const adminRes = await client.query("SELECT id FROM users WHERE username='admin'");
const adminId = adminRes.rows[0].id;

// === VLANs ===
const vlans = [
  { tag: 10, name: 'Management', desc: 'Management and monitoring', subnet: '10.0.10.0/24' },
  { tag: 20, name: 'Production Web', desc: 'Production web tier', subnet: '10.0.20.0/24' },
  { tag: 30, name: 'Production App', desc: 'Production application tier', subnet: '10.0.30.0/24' },
  { tag: 40, name: 'Production DB', desc: 'Production database tier', subnet: '10.0.40.0/24' },
  { tag: 50, name: 'DMZ', desc: 'Demilitarized zone - public facing', subnet: '10.0.50.0/24' },
  { tag: 100, name: 'Development', desc: 'Development environment', subnet: '10.0.100.0/24' },
];
const vlanIds = {};
for (const v of vlans) {
  const res = await client.query(
    `INSERT INTO vlans (vlan_tag, name, description, subnet) VALUES ($1,$2,$3,$4) ON CONFLICT (vlan_tag) DO UPDATE SET name = EXCLUDED.name, description = EXCLUDED.description, subnet = EXCLUDED.subnet RETURNING id`,
    [v.tag, v.name, v.desc, v.subnet]
  );
  if (res.rows[0]) vlanIds[v.name] = res.rows[0].id;
  else {
    const existing = await client.query(`SELECT id FROM vlans WHERE vlan_tag=$1`, [v.tag]);
    vlanIds[v.name] = existing.rows[0]?.id;
  }
}
console.log(`Created ${vlans.length} VLANs`);

// === Tags ===
const tagDefs = [
  ['web-server', 'Web-facing HTTP/HTTPS servers'],
  ['app-server', 'Application tier backend services'],
  ['db-server', 'PostgreSQL and other database servers'],
  ['monitoring', 'Prometheus, Grafana, Alertmanager'],
  ['load-balancer', 'HAProxy/Nginx reverse proxies in DMZ'],
  ['cache-server', 'Redis/Memcached caching layer'],
  ['ci-cd', 'Jenkins, GitLab runners, build servers'],
  ['bastion', 'SSH jump hosts for secure access'],
  ['dns', 'Internal DNS resolvers'],
  ['mail-server', 'SMTP relay and mail services'],
  ['production', 'Production environment hosts'],
  ['development', 'Development environment hosts'],
  ['dmz', 'DMZ network zone hosts'],
  ['linux-rhel', 'Red Hat Enterprise Linux family'],
  ['linux-ubuntu', 'Ubuntu/Debian family'],
];
const tagIds = {};
for (const [name, desc] of tagDefs) {
  const res = await client.query(
    `INSERT INTO tags (name, description) VALUES ($1, $2) ON CONFLICT DO NOTHING RETURNING id`,
    [name, desc]
  );
  if (res.rows[0]) tagIds[name] = res.rows[0].id;
  else {
    const existing = await client.query(`SELECT id FROM tags WHERE name=$1`, [name]);
    tagIds[name] = existing.rows[0]?.id;
  }
}
console.log(`Created ${tagDefs.length} tags`);

// === Hosts ===
const hosts = [
  // Web tier (4 servers)
  { hostname: 'web-prod-01.acme.corp', ip: '10.0.20.10', vlan: 'Production Web', backend: 'nftables', os: 'ubuntu', env: 'production', tags: ['web-server', 'production', 'linux-ubuntu'] },
  { hostname: 'web-prod-02.acme.corp', ip: '10.0.20.11', vlan: 'Production Web', backend: 'nftables', os: 'ubuntu', env: 'production', tags: ['web-server', 'production', 'linux-ubuntu'] },
  { hostname: 'web-prod-03.acme.corp', ip: '10.0.20.12', vlan: 'Production Web', backend: 'nftables', os: 'ubuntu', env: 'production', tags: ['web-server', 'production', 'linux-ubuntu'] },
  { hostname: 'web-prod-04.acme.corp', ip: '10.0.20.13', vlan: 'Production Web', backend: 'nftables', os: 'ubuntu', env: 'production', tags: ['web-server', 'production', 'linux-ubuntu'] },
  // App tier (4 servers)
  { hostname: 'app-prod-01.acme.corp', ip: '10.0.30.10', vlan: 'Production App', backend: 'nftables', os: 'rhel', env: 'production', tags: ['app-server', 'production', 'linux-rhel'] },
  { hostname: 'app-prod-02.acme.corp', ip: '10.0.30.11', vlan: 'Production App', backend: 'nftables', os: 'rhel', env: 'production', tags: ['app-server', 'production', 'linux-rhel'] },
  { hostname: 'app-prod-03.acme.corp', ip: '10.0.30.12', vlan: 'Production App', backend: 'nftables', os: 'rhel', env: 'production', tags: ['app-server', 'production', 'linux-rhel'] },
  { hostname: 'app-prod-04.acme.corp', ip: '10.0.30.13', vlan: 'Production App', backend: 'iptables', os: 'centos', env: 'production', tags: ['app-server', 'production', 'linux-rhel'] },
  // Database tier (3 servers)
  { hostname: 'db-prod-01.acme.corp', ip: '10.0.40.10', vlan: 'Production DB', backend: 'nftables', os: 'rhel', env: 'production', tags: ['db-server', 'production', 'linux-rhel'] },
  { hostname: 'db-prod-02.acme.corp', ip: '10.0.40.11', vlan: 'Production DB', backend: 'nftables', os: 'rhel', env: 'production', tags: ['db-server', 'production', 'linux-rhel'] },
  { hostname: 'db-replica-01.acme.corp', ip: '10.0.40.12', vlan: 'Production DB', backend: 'nftables', os: 'rhel', env: 'production', tags: ['db-server', 'production', 'linux-rhel'] },
  // DMZ (3 servers)
  { hostname: 'lb-dmz-01.acme.corp', ip: '10.0.50.10', vlan: 'DMZ', backend: 'nftables', os: 'ubuntu', env: 'production', tags: ['load-balancer', 'dmz', 'production', 'linux-ubuntu'] },
  { hostname: 'lb-dmz-02.acme.corp', ip: '10.0.50.11', vlan: 'DMZ', backend: 'nftables', os: 'ubuntu', env: 'production', tags: ['load-balancer', 'dmz', 'production', 'linux-ubuntu'] },
  { hostname: 'proxy-dmz-01.acme.corp', ip: '10.0.50.20', vlan: 'DMZ', backend: 'nftables', os: 'ubuntu', env: 'production', tags: ['web-server', 'dmz', 'production', 'linux-ubuntu'] },
  // Infrastructure (6 servers)
  { hostname: 'bastion-01.acme.corp', ip: '10.0.10.5', vlan: 'Management', backend: 'nftables', os: 'ubuntu', env: 'production', tags: ['bastion', 'production', 'linux-ubuntu'] },
  { hostname: 'monitor-01.acme.corp', ip: '10.0.10.20', vlan: 'Management', backend: 'nftables', os: 'ubuntu', env: 'production', tags: ['monitoring', 'production', 'linux-ubuntu'] },
  { hostname: 'monitor-02.acme.corp', ip: '10.0.10.21', vlan: 'Management', backend: 'nftables', os: 'ubuntu', env: 'production', tags: ['monitoring', 'production', 'linux-ubuntu'] },
  { hostname: 'dns-01.acme.corp', ip: '10.0.10.53', vlan: 'Management', backend: 'nftables', os: 'rhel', env: 'production', tags: ['dns', 'production', 'linux-rhel'] },
  { hostname: 'dns-02.acme.corp', ip: '10.0.10.54', vlan: 'Management', backend: 'nftables', os: 'rhel', env: 'production', tags: ['dns', 'production', 'linux-rhel'] },
  { hostname: 'mail-01.acme.corp', ip: '10.0.10.25', vlan: 'Management', backend: 'iptables', os: 'rhel', env: 'production', tags: ['mail-server', 'production', 'linux-rhel'] },
  // Cache tier (2 servers)
  { hostname: 'cache-prod-01.acme.corp', ip: '10.0.30.50', vlan: 'Production App', backend: 'nftables', os: 'ubuntu', env: 'production', tags: ['cache-server', 'production', 'linux-ubuntu'] },
  { hostname: 'cache-prod-02.acme.corp', ip: '10.0.30.51', vlan: 'Production App', backend: 'nftables', os: 'ubuntu', env: 'production', tags: ['cache-server', 'production', 'linux-ubuntu'] },
  // CI/CD (2 servers)
  { hostname: 'jenkins-01.acme.corp', ip: '10.0.100.10', vlan: 'Development', backend: 'nftables', os: 'ubuntu', env: 'development', tags: ['ci-cd', 'development', 'linux-ubuntu'] },
  { hostname: 'gitlab-runner-01.acme.corp', ip: '10.0.100.11', vlan: 'Development', backend: 'nftables', os: 'ubuntu', env: 'development', tags: ['ci-cd', 'development', 'linux-ubuntu'] },
  // Dev hosts (3 servers)
  { hostname: 'web-dev-01.acme.corp', ip: '10.0.100.20', vlan: 'Development', backend: 'nftables', os: 'ubuntu', env: 'development', tags: ['web-server', 'development', 'linux-ubuntu'] },
  { hostname: 'app-dev-01.acme.corp', ip: '10.0.100.30', vlan: 'Development', backend: 'nftables', os: 'rhel', env: 'development', tags: ['app-server', 'development', 'linux-rhel'] },
  { hostname: 'db-dev-01.acme.corp', ip: '10.0.100.40', vlan: 'Development', backend: 'nftables', os: 'rhel', env: 'development', tags: ['db-server', 'development', 'linux-rhel'] },
];

let hostCount = 0;
for (const h of hosts) {
  const res = await client.query(
    `INSERT INTO hosts (hostname, mgmt_ip, ssh_port, environment, os_family, firewall_backend, vlan_id, enabled)
     VALUES ($1,$2,22,$3,$4,$5,$6,true) ON CONFLICT (hostname) DO NOTHING RETURNING id`,
    [h.hostname, h.ip, h.env, h.os, h.backend, vlanIds[h.vlan]]
  );
  if (res.rows[0]) {
    hostCount++;
    const hostId = res.rows[0].id;
    for (const t of h.tags) {
      if (tagIds[t]) {
        await client.query(`INSERT INTO host_tags (host_id, tag_id, source) VALUES ($1,$2,'manual') ON CONFLICT DO NOTHING`, [hostId, tagIds[t]]);
      }
    }
    await client.query(
      `INSERT INTO host_interfaces (host_id, name, role, ip_address, enabled) VALUES ($1,'eth0','management',$2,true)`,
      [hostId, h.ip]
    );
    if (h.vlan !== 'Management') {
      await client.query(
        `INSERT INTO host_interfaces (host_id, name, role, ip_address, enabled) VALUES ($1,'eth1','data',$2,true)`,
        [hostId, h.ip]
      );
    }
  }
}
console.log(`Created ${hostCount} hosts with tags and interfaces`);

// === Helper to create policy ===
async function createPolicy(name, desc, scopeTagName, status, changeSummary, scopeType, scopeRoles, rules) {
  const ps = await client.query(
    `INSERT INTO policy_sets (name, description, scope_type, scope_tag_id, created_by) VALUES ($1,$2,'TAG',$3,$4) RETURNING id`,
    [name, desc, tagIds[scopeTagName], adminId]
  );
  const psId = ps.rows[0].id;

  const pv = await client.query(
    `INSERT INTO policy_versions (policy_set_id, version_number, status, change_summary, created_by, interface_scope_type, interface_scope_roles)
     VALUES ($1,1,$2,$3,$4,$5,$6) RETURNING id`,
    [psId, status, changeSummary, adminId, scopeType, scopeRoles]
  );
  const pvId = pv.rows[0].id;

  for (const r of rules) {
    await client.query(
      `INSERT INTO policy_rules (policy_version_id, order_index, direction, action, protocol, ports, source_type, source_value, log_mode, comment)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
      [pvId, r.idx, r.dir, r.action, r.proto, r.ports, r.srcType, r.srcVal, r.log || 'NONE', r.comment]
    );
  }
  console.log(`Created "${name}" policy (${rules.length} rules, ${status})`);
}

// === Policy 1: Web Server Firewall ===
await createPolicy(
  'Web Server Firewall',
  'Standard firewall rules for all web-facing servers — allows HTTP/HTTPS inbound, controlled outbound to DB and cache',
  'web-server', 'APPROVED',
  'Initial web server policy with HTTP/HTTPS access and controlled backend connectivity',
  'INTERFACE_ROLE', '{data}',
  [
    { idx: 0, dir: 'IN', action: 'ALLOW', proto: 'tcp', ports: '80,443', srcType: 'CIDR', srcVal: '0.0.0.0/0', comment: 'Allow HTTP/HTTPS from anywhere' },
    { idx: 1, dir: 'IN', action: 'ALLOW', proto: 'tcp', ports: '8080', srcType: 'TAG', srcVal: tagIds['load-balancer'], comment: 'Allow proxy traffic from load balancers' },
    { idx: 2, dir: 'IN', action: 'ALLOW', proto: 'tcp', ports: '22', srcType: 'TAG', srcVal: tagIds['bastion'], comment: 'Allow SSH from bastion hosts only' },
    { idx: 3, dir: 'IN', action: 'ALLOW', proto: 'tcp', ports: '9100,9090', srcType: 'TAG', srcVal: tagIds['monitoring'], comment: 'Allow Prometheus metrics scraping' },
    { idx: 4, dir: 'IN', action: 'ALLOW', proto: 'icmp', ports: null, srcType: 'CIDR', srcVal: '10.0.0.0/8', comment: 'Allow ICMP from internal network' },
    { idx: 5, dir: 'OUT', action: 'ALLOW', proto: 'tcp', ports: '5432', srcType: 'TAG', srcVal: tagIds['db-server'], comment: 'Allow outbound PostgreSQL to database tier' },
    { idx: 6, dir: 'OUT', action: 'ALLOW', proto: 'tcp', ports: '6379', srcType: 'TAG', srcVal: tagIds['cache-server'], comment: 'Allow outbound Redis to cache tier' },
    { idx: 7, dir: 'OUT', action: 'ALLOW', proto: 'tcp', ports: '53', srcType: 'TAG', srcVal: tagIds['dns'], comment: 'Allow outbound DNS' },
    { idx: 8, dir: 'OUT', action: 'ALLOW', proto: 'udp', ports: '53', srcType: 'TAG', srcVal: tagIds['dns'], comment: 'Allow outbound DNS (UDP)' },
  ]
);

// === Policy 2: Database Server Firewall ===
await createPolicy(
  'Database Server Firewall',
  'Strict access control for PostgreSQL database servers — only app/web tiers and replication allowed',
  'db-server', 'APPROVED',
  'Restrict database access to app and web tiers only, with inter-node replication',
  'INTERFACE_ROLE', '{data}',
  [
    { idx: 0, dir: 'IN', action: 'ALLOW', proto: 'tcp', ports: '5432', srcType: 'TAG', srcVal: tagIds['app-server'], comment: 'Allow PostgreSQL from application tier' },
    { idx: 1, dir: 'IN', action: 'ALLOW', proto: 'tcp', ports: '5432', srcType: 'TAG', srcVal: tagIds['web-server'], comment: 'Allow PostgreSQL from web tier (direct queries)' },
    { idx: 2, dir: 'IN', action: 'DENY', proto: 'tcp', ports: '5432', srcType: 'CIDR', srcVal: '0.0.0.0/0', log: 'LOG', comment: 'Deny PostgreSQL from all other sources' },
    { idx: 3, dir: 'IN', action: 'ALLOW', proto: 'tcp', ports: '22', srcType: 'TAG', srcVal: tagIds['bastion'], comment: 'Allow SSH from bastion hosts only' },
    { idx: 4, dir: 'IN', action: 'ALLOW', proto: 'tcp', ports: '9100,9187', srcType: 'TAG', srcVal: tagIds['monitoring'], comment: 'Allow Prometheus and pg_exporter metrics' },
    { idx: 5, dir: 'IN', action: 'ALLOW', proto: 'tcp', ports: '5432', srcType: 'TAG', srcVal: tagIds['db-server'], comment: 'Allow replication between database nodes' },
    { idx: 6, dir: 'IN', action: 'ALLOW', proto: 'icmp', ports: null, srcType: 'CIDR', srcVal: '10.0.0.0/8', comment: 'Allow ICMP from internal network' },
    { idx: 7, dir: 'OUT', action: 'ALLOW', proto: 'tcp', ports: '53', srcType: 'TAG', srcVal: tagIds['dns'], comment: 'Allow outbound DNS' },
    { idx: 8, dir: 'OUT', action: 'ALLOW', proto: 'udp', ports: '53', srcType: 'TAG', srcVal: tagIds['dns'], comment: 'Allow outbound DNS (UDP)' },
  ]
);

// === Policy 3: DMZ Firewall ===
await createPolicy(
  'DMZ Firewall',
  'Public-facing zone with strict ingress/egress controls — only HTTP/HTTPS inbound, controlled forwarding to internal web tier',
  'dmz', 'APPROVED',
  'DMZ policy: HTTP/HTTPS inbound, controlled outbound to web tier, block DB access',
  'ALL_INTERFACES', null,
  [
    { idx: 0, dir: 'IN', action: 'ALLOW', proto: 'tcp', ports: '80,443', srcType: 'CIDR', srcVal: '0.0.0.0/0', comment: 'Allow HTTP/HTTPS from internet' },
    { idx: 1, dir: 'IN', action: 'ALLOW', proto: 'tcp', ports: '22', srcType: 'TAG', srcVal: tagIds['bastion'], comment: 'Allow SSH from bastion only' },
    { idx: 2, dir: 'IN', action: 'ALLOW', proto: 'tcp', ports: '9100', srcType: 'TAG', srcVal: tagIds['monitoring'], comment: 'Allow Prometheus metrics collection' },
    { idx: 3, dir: 'IN', action: 'DENY', proto: 'tcp', ports: '22', srcType: 'CIDR', srcVal: '0.0.0.0/0', log: 'LOG', comment: 'Block SSH from anywhere else (log attempts)' },
    { idx: 4, dir: 'OUT', action: 'ALLOW', proto: 'tcp', ports: '80,443,8080', srcType: 'TAG', srcVal: tagIds['web-server'], comment: 'Allow forwarding to internal web servers' },
    { idx: 5, dir: 'OUT', action: 'ALLOW', proto: 'tcp', ports: '53', srcType: 'TAG', srcVal: tagIds['dns'], comment: 'Allow DNS resolution' },
    { idx: 6, dir: 'OUT', action: 'ALLOW', proto: 'udp', ports: '53', srcType: 'TAG', srcVal: tagIds['dns'], comment: 'Allow DNS resolution (UDP)' },
    { idx: 7, dir: 'OUT', action: 'ALLOW', proto: 'udp', ports: '123', srcType: 'CIDR', srcVal: '10.0.10.0/24', comment: 'Allow NTP to management network' },
    { idx: 8, dir: 'OUT', action: 'DENY', proto: 'any', ports: null, srcType: 'CIDR', srcVal: '10.0.40.0/24', log: 'LOG', comment: 'Block all direct access to database tier' },
  ]
);

// === Policy 4: Monitoring Infrastructure (DRAFT) ===
await createPolicy(
  'Monitoring Infrastructure',
  'Allow monitoring servers to scrape metrics from all production hosts and send alerts via mail',
  'monitoring', 'DRAFT',
  'Monitoring policy - pending review before first deployment',
  'ALL_INTERFACES', null,
  [
    { idx: 0, dir: 'IN', action: 'ALLOW', proto: 'tcp', ports: '9090', srcType: 'CIDR', srcVal: '10.0.10.0/24', comment: 'Prometheus UI from management network' },
    { idx: 1, dir: 'IN', action: 'ALLOW', proto: 'tcp', ports: '3000', srcType: 'CIDR', srcVal: '10.0.10.0/24', comment: 'Grafana dashboard from management network' },
    { idx: 2, dir: 'IN', action: 'ALLOW', proto: 'tcp', ports: '9093', srcType: 'CIDR', srcVal: '10.0.10.0/24', comment: 'Alertmanager from management network' },
    { idx: 3, dir: 'IN', action: 'ALLOW', proto: 'tcp', ports: '22', srcType: 'TAG', srcVal: tagIds['bastion'], comment: 'SSH from bastion hosts' },
    { idx: 4, dir: 'IN', action: 'ALLOW', proto: 'icmp', ports: null, srcType: 'CIDR', srcVal: '10.0.0.0/8', comment: 'Allow ICMP from internal' },
    { idx: 5, dir: 'OUT', action: 'ALLOW', proto: 'tcp', ports: '9100,9090,9187,9200', srcType: 'CIDR', srcVal: '10.0.0.0/8', comment: 'Scrape exporters from all internal hosts' },
    { idx: 6, dir: 'OUT', action: 'ALLOW', proto: 'tcp', ports: '25,587', srcType: 'TAG', srcVal: tagIds['mail-server'], comment: 'Send alert emails via mail server' },
    { idx: 7, dir: 'OUT', action: 'ALLOW', proto: 'tcp', ports: '443', srcType: 'CIDR', srcVal: '0.0.0.0/0', comment: 'HTTPS outbound for PagerDuty/Slack webhooks' },
    { idx: 8, dir: 'OUT', action: 'ALLOW', proto: 'tcp', ports: '53', srcType: 'TAG', srcVal: tagIds['dns'], comment: 'DNS resolution' },
    { idx: 9, dir: 'OUT', action: 'ALLOW', proto: 'udp', ports: '53', srcType: 'TAG', srcVal: tagIds['dns'], comment: 'DNS resolution (UDP)' },
  ]
);

// =====================================================================
// === SSH Credentials (demo keys — NOT real private keys) ===
// =====================================================================
import crypto from 'node:crypto';

// Helper: create encrypted secret (simplified — uses a dummy KEK for demo)
async function createDemoSecret(name, type, plaintext) {
  // Use a simple encryption for demo data (in production, SEGMENTRA_KEK_B64 is used)
  const iv = crypto.randomBytes(12);
  const key = crypto.randomBytes(32);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  const blob = Buffer.concat([iv, authTag, encrypted]);

  const res = await client.query(
    `INSERT INTO secret_store (name, type, encrypted_blob, is_active) VALUES ($1,$2,$3,true) RETURNING id`,
    [name, type, blob]
  );
  return res.rows[0].id;
}

const demoPrivateKey = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtz
c2gtZWQyNTUxOQAAACDdemokeydemokeydemokeydemokeydemoAAABAAAABHNz
aC1lZDI1NTE5AAAAINhpc19pc19hX2RlbW9fa2V5X25vdF9yZWFsAA==
-----END OPENSSH PRIVATE KEY-----`;

const sshCreds = [
  { name: 'Production Global Key', username: 'segmentra', scope: 'GLOBAL', scopeId: null },
  { name: 'DMZ Deploy Key', username: 'deploy', scope: 'TAG', scopeTag: 'dmz' },
  { name: 'Development Key', username: 'dev-deploy', scope: 'TAG', scopeTag: 'development' },
];

for (const cred of sshCreds) {
  const keySecretId = await createDemoSecret(`${cred.name}_key`, 'SSH_KEY', demoPrivateKey);
  const scopeId = cred.scopeTag ? tagIds[cred.scopeTag] : null;
  await client.query(
    `INSERT INTO ssh_credentials (name, username, private_key_secret_id, scope_type, scope_id)
     VALUES ($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING`,
    [cred.name, cred.username, keySecretId, cred.scope, scopeId]
  );
}
console.log(`Created ${sshCreds.length} SSH credentials (demo keys)`);

// =====================================================================
// === OT/IoT Assets ===
// =====================================================================
const iotVlanRes = await client.query(`SELECT id FROM vlans WHERE vlan_tag = 50`);
const iotVlanId = iotVlanRes.rows[0]?.id || vlanIds['DMZ'];

const iotAssets = [
  // Manufacturing floor
  { name: 'PLC-Assembly-Line-1', type: 'plc', vendor: 'Siemens', model: 'S7-1500', firmware: 'V2.9.4', mac: '00:1A:2B:3C:4D:01', ip: '10.0.60.10', zone: 'Level 1', criticality: 'critical' },
  { name: 'PLC-Assembly-Line-2', type: 'plc', vendor: 'Siemens', model: 'S7-1500', firmware: 'V2.9.4', mac: '00:1A:2B:3C:4D:02', ip: '10.0.60.11', zone: 'Level 1', criticality: 'critical' },
  { name: 'HMI-Floor-Control-01', type: 'hmi', vendor: 'Siemens', model: 'TP1900 Comfort', firmware: 'V16.0', mac: '00:1A:2B:3C:4E:01', ip: '10.0.60.20', zone: 'Level 2', criticality: 'high' },
  { name: 'HMI-Floor-Control-02', type: 'hmi', vendor: 'Rockwell', model: 'PanelView Plus 7', firmware: 'V12.0', mac: '00:1A:2B:3C:4E:02', ip: '10.0.60.21', zone: 'Level 2', criticality: 'high' },
  // Building systems
  { name: 'HVAC-Controller-Main', type: 'hvac', vendor: 'Honeywell', model: 'Spyder LON', firmware: 'V3.1.2', mac: '00:1A:2B:3C:5A:01', ip: '10.0.61.10', zone: 'Level 0', criticality: 'medium' },
  { name: 'HVAC-Controller-Warehouse', type: 'hvac', vendor: 'Honeywell', model: 'Spyder LON', firmware: 'V3.1.2', mac: '00:1A:2B:3C:5A:02', ip: '10.0.61.11', zone: 'Level 0', criticality: 'medium' },
  // Security cameras
  { name: 'Camera-Entrance-Main', type: 'camera', vendor: 'Axis', model: 'P1448-LE', firmware: 'V10.12.114', mac: '00:40:8C:1A:2B:01', ip: '10.0.62.10', zone: 'Level 0', criticality: 'medium' },
  { name: 'Camera-Warehouse-01', type: 'camera', vendor: 'Axis', model: 'M3106-L Mk II', firmware: 'V10.12.114', mac: '00:40:8C:1A:2B:02', ip: '10.0.62.11', zone: 'Level 0', criticality: 'low' },
  { name: 'Camera-Parking-01', type: 'camera', vendor: 'Hikvision', model: 'DS-2CD2143G2-I', firmware: 'V5.7.1', mac: '00:40:8C:1A:2B:03', ip: '10.0.62.12', zone: 'Level 0', criticality: 'low' },
  // Sensors
  { name: 'Temp-Sensor-Datacenter', type: 'sensor', vendor: 'Paessler', model: 'PRTG Probe', firmware: 'V22.4', mac: '00:1A:2B:3C:6A:01', ip: '10.0.61.50', zone: 'Level 0', criticality: 'medium' },
  { name: 'Power-Meter-PDU-01', type: 'sensor', vendor: 'APC', model: 'AP8981', firmware: 'V6.9.6', mac: '00:1A:2B:3C:6A:02', ip: '10.0.61.51', zone: 'Level 0', criticality: 'medium' },
  // Printers
  { name: 'Printer-Office-Floor3', type: 'printer', vendor: 'HP', model: 'LaserJet Enterprise M609', firmware: 'V2549A', mac: '00:1A:2B:3C:7A:01', ip: '10.0.63.10', zone: 'Level 3', criticality: 'low' },
  { name: 'Printer-Warehouse', type: 'printer', vendor: 'Zebra', model: 'ZT620', firmware: 'V8.0.2', mac: '00:1A:2B:3C:7A:02', ip: '10.0.63.11', zone: 'Level 3', criticality: 'low' },
];

let iotCount = 0;
for (const a of iotAssets) {
  const res = await client.query(
    `INSERT INTO iot_assets (name, asset_type, vendor, model, firmware_version, mac_address, ip_address, vlan_id, zone, criticality, fingerprint, enabled)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,true) ON CONFLICT DO NOTHING RETURNING id`,
    [a.name, a.type, a.vendor, a.model, a.firmware, a.mac, a.ip, iotVlanId, a.zone, a.criticality, JSON.stringify({ protocols: [] })]
  );
  if (res.rows[0]) iotCount++;
}
console.log(`Created ${iotCount} IoT/OT assets`);

// IoT flow collectors
await client.query(
  `INSERT INTO flow_collectors (name, description, type, listen_address, listen_port, config, enabled)
   VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING`,
  ['NetFlow Collector - Core Switch', 'Collects NetFlow v9 from core switch stack', 'netflow_v9', '0.0.0.0', 2055, JSON.stringify({ samplingRate: 1000 }), false]
);
await client.query(
  `INSERT INTO flow_collectors (name, description, type, listen_address, listen_port, config, enabled)
   VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING`,
  ['sFlow Collector - OT Network', 'Collects sFlow from OT network switches', 'sflow', '0.0.0.0', 6343, JSON.stringify({ samplingRate: 500 }), false]
);
console.log('Created 2 flow collectors');

// IoT enforcement points
await client.query(
  `INSERT INTO enforcement_points (name, description, type, vendor, model, mgmt_ip, enabled)
   VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING`,
  ['OT-Gateway-FW-01', 'Gateway firewall between OT and IT networks', 'gateway_firewall', 'Linux', 'Ubuntu 22.04 nftables', '10.0.60.1', true]
);
await client.query(
  `INSERT INTO enforcement_points (name, description, type, vendor, model, mgmt_ip, enabled)
   VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING`,
  ['Core-Switch-OT', 'Cisco Catalyst switch for OT network segmentation', 'switch_acl', 'Cisco', 'Catalyst 9300', '10.0.60.2', true]
);
console.log('Created 2 enforcement points');

// =====================================================================
// === Kubernetes Clusters ===
// =====================================================================
const k8sClusters = [
  { name: 'Production EKS', desc: 'AWS EKS production cluster (us-east-1)', url: 'https://k8s-prod.acme.corp:6443', auth: 'service_account', ns: 'default' },
  { name: 'Staging GKE', desc: 'GCP GKE staging cluster for pre-prod testing', url: 'https://k8s-staging.acme.corp:6443', auth: 'kubeconfig', ns: 'staging' },
];

const clusterIds = {};
for (const c of k8sClusters) {
  const res = await client.query(
    `INSERT INTO k8s_clusters (name, description, api_server_url, auth_type, default_namespace, enabled, created_by)
     VALUES ($1,$2,$3,$4,$5,true,$6) ON CONFLICT DO NOTHING RETURNING id`,
    [c.name, c.desc, c.url, c.auth, c.ns, adminId]
  );
  if (res.rows[0]) clusterIds[c.name] = res.rows[0].id;
}
console.log(`Created ${k8sClusters.length} Kubernetes clusters`);

// Add workloads to production cluster
if (clusterIds['Production EKS']) {
  const cid = clusterIds['Production EKS'];
  const workloads = [
    { ns: 'frontend', kind: 'Deployment', name: 'nginx-ingress', labels: { app: 'nginx', tier: 'frontend', env: 'production' }, ips: ['10.244.1.10', '10.244.1.11'] },
    { ns: 'frontend', kind: 'Deployment', name: 'react-app', labels: { app: 'react-app', tier: 'frontend', env: 'production' }, ips: ['10.244.1.20', '10.244.1.21', '10.244.1.22'] },
    { ns: 'frontend', kind: 'Service', name: 'react-app-svc', labels: { app: 'react-app', tier: 'frontend' }, ips: [], svcIp: '10.96.10.1', svcPorts: [{ port: 80, targetPort: 3000, protocol: 'TCP' }] },
    { ns: 'backend', kind: 'Deployment', name: 'api-gateway', labels: { app: 'api-gateway', tier: 'backend', env: 'production' }, ips: ['10.244.2.10', '10.244.2.11'] },
    { ns: 'backend', kind: 'Deployment', name: 'user-service', labels: { app: 'user-service', tier: 'backend', env: 'production' }, ips: ['10.244.2.20'] },
    { ns: 'backend', kind: 'Deployment', name: 'order-service', labels: { app: 'order-service', tier: 'backend', env: 'production' }, ips: ['10.244.2.30', '10.244.2.31'] },
    { ns: 'backend', kind: 'Service', name: 'api-gateway-svc', labels: { app: 'api-gateway', tier: 'backend' }, ips: [], svcIp: '10.96.20.1', svcPorts: [{ port: 8080, targetPort: 8080, protocol: 'TCP' }] },
    { ns: 'data', kind: 'StatefulSet', name: 'postgresql', labels: { app: 'postgresql', tier: 'data', env: 'production' }, ips: ['10.244.3.10', '10.244.3.11'] },
    { ns: 'data', kind: 'StatefulSet', name: 'redis-cluster', labels: { app: 'redis', tier: 'data', env: 'production' }, ips: ['10.244.3.20', '10.244.3.21', '10.244.3.22'] },
    { ns: 'data', kind: 'Service', name: 'postgresql-svc', labels: { app: 'postgresql', tier: 'data' }, ips: [], svcIp: '10.96.30.1', svcPorts: [{ port: 5432, targetPort: 5432, protocol: 'TCP' }] },
    { ns: 'monitoring', kind: 'DaemonSet', name: 'node-exporter', labels: { app: 'node-exporter', tier: 'monitoring' }, ips: ['10.244.0.5', '10.244.1.5', '10.244.2.5', '10.244.3.5'] },
    { ns: 'monitoring', kind: 'Deployment', name: 'prometheus', labels: { app: 'prometheus', tier: 'monitoring' }, ips: ['10.244.0.10'] },
    { ns: 'monitoring', kind: 'Deployment', name: 'grafana', labels: { app: 'grafana', tier: 'monitoring' }, ips: ['10.244.0.20'] },
  ];

  for (const w of workloads) {
    await client.query(
      `INSERT INTO k8s_workloads (cluster_id, namespace, kind, name, labels, pod_ips, service_cluster_ip, service_ports, status)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'active') ON CONFLICT DO NOTHING`,
      [cid, w.ns, w.kind, w.name, JSON.stringify(w.labels), w.ips.length > 0 ? w.ips : null, w.svcIp || null, w.svcPorts ? JSON.stringify(w.svcPorts) : null]
    );
  }
  console.log(`Created ${workloads.length} K8s workloads in Production EKS`);
}

// =====================================================================
// === Topology Views ===
// =====================================================================
const topoRes = await client.query(
  `INSERT INTO topology_views (name, description, layout_data, created_by)
   VALUES ($1,$2,$3,$4) RETURNING id`,
  ['Production Network Architecture', 'Three-tier web application flow: DMZ → Web → App → DB', JSON.stringify({ nodes: [], edges: [] }), adminId]
);
const topoId = topoRes.rows[0].id;

// Add flows representing the production architecture
const topoFlows = [
  { srcType: 'TAG', srcVal: tagIds['dmz'], tgtType: 'TAG', tgtVal: tagIds['web-server'], action: 'ALLOW', proto: 'tcp', ports: '80,443,8080', comment: 'DMZ load balancers forward to web tier' },
  { srcType: 'TAG', srcVal: tagIds['web-server'], tgtType: 'TAG', tgtVal: tagIds['app-server'], action: 'ALLOW', proto: 'tcp', ports: '8080,8443', comment: 'Web tier calls application APIs' },
  { srcType: 'TAG', srcVal: tagIds['app-server'], tgtType: 'TAG', tgtVal: tagIds['db-server'], action: 'ALLOW', proto: 'tcp', ports: '5432', comment: 'App tier queries PostgreSQL databases' },
  { srcType: 'TAG', srcVal: tagIds['web-server'], tgtType: 'TAG', tgtVal: tagIds['cache-server'], action: 'ALLOW', proto: 'tcp', ports: '6379', comment: 'Web tier reads from Redis cache' },
  { srcType: 'TAG', srcVal: tagIds['app-server'], tgtType: 'TAG', tgtVal: tagIds['cache-server'], action: 'ALLOW', proto: 'tcp', ports: '6379', comment: 'App tier reads/writes Redis cache' },
  { srcType: 'TAG', srcVal: tagIds['monitoring'], tgtType: 'TAG', tgtVal: tagIds['web-server'], action: 'ALLOW', proto: 'tcp', ports: '9100', comment: 'Prometheus scrapes web server metrics' },
  { srcType: 'TAG', srcVal: tagIds['monitoring'], tgtType: 'TAG', tgtVal: tagIds['db-server'], action: 'ALLOW', proto: 'tcp', ports: '9100,9187', comment: 'Prometheus scrapes DB metrics + pg_exporter' },
  { srcType: 'TAG', srcVal: tagIds['bastion'], tgtType: 'TAG', tgtVal: tagIds['web-server'], action: 'ALLOW', proto: 'tcp', ports: '22', comment: 'Bastion SSH to web servers' },
  { srcType: 'TAG', srcVal: tagIds['bastion'], tgtType: 'TAG', tgtVal: tagIds['db-server'], action: 'ALLOW', proto: 'tcp', ports: '22', comment: 'Bastion SSH to database servers' },
  { srcType: 'CIDR', srcVal: '0.0.0.0/0', tgtType: 'TAG', tgtVal: tagIds['dmz'], action: 'ALLOW', proto: 'tcp', ports: '80,443', comment: 'Internet traffic to DMZ' },
  { srcType: 'TAG', srcVal: tagIds['dmz'], tgtType: 'TAG', tgtVal: tagIds['db-server'], action: 'DENY', proto: 'any', ports: null, comment: 'Block direct DMZ to DB access' },
];

for (const f of topoFlows) {
  await client.query(
    `INSERT INTO topology_flows (topology_view_id, source_type, source_value, target_type, target_value, direction, action, protocol, ports, comment)
     VALUES ($1,$2,$3,$4,$5,'BOTH',$6,$7,$8,$9)`,
    [topoId, f.srcType, f.srcVal, f.tgtType, f.tgtVal, f.action, f.proto, f.ports, f.comment]
  );
}
console.log(`Created topology view with ${topoFlows.length} flows`);

// Second topology: OT Network
const topoOtRes = await client.query(
  `INSERT INTO topology_views (name, description, layout_data, created_by)
   VALUES ($1,$2,$3,$4) RETURNING id`,
  ['OT Network Segmentation', 'Purdue model zones: Level 0 (sensors) → Level 1 (PLCs) → Level 2 (HMIs) → Level 3 (IT/DMZ)', JSON.stringify({ nodes: [], edges: [] }), adminId]
);
const topoOtId = topoOtRes.rows[0].id;

const otFlows = [
  { srcType: 'CIDR', srcVal: '10.0.60.20/32', tgtType: 'CIDR', tgtVal: '10.0.60.10/32', action: 'ALLOW', proto: 'tcp', ports: '502', comment: 'HMI-01 → PLC-01: Modbus/TCP' },
  { srcType: 'CIDR', srcVal: '10.0.60.21/32', tgtType: 'CIDR', tgtVal: '10.0.60.11/32', action: 'ALLOW', proto: 'tcp', ports: '502', comment: 'HMI-02 → PLC-02: Modbus/TCP' },
  { srcType: 'CIDR', srcVal: '10.0.61.10/32', tgtType: 'CIDR', tgtVal: '10.0.60.10/31', action: 'ALLOW', proto: 'udp', ports: '47808', comment: 'HVAC controller → PLCs: BACnet' },
  { srcType: 'CIDR', srcVal: '10.0.10.0/24', tgtType: 'CIDR', tgtVal: '10.0.62.0/24', action: 'ALLOW', proto: 'tcp', ports: '554,80', comment: 'Management → Cameras: RTSP + HTTP' },
  { srcType: 'CIDR', srcVal: '10.0.60.0/24', tgtType: 'CIDR', tgtVal: '10.0.30.0/24', action: 'DENY', proto: 'any', ports: null, comment: 'Block OT → App tier (air gap)' },
];

for (const f of otFlows) {
  await client.query(
    `INSERT INTO topology_flows (topology_view_id, source_type, source_value, target_type, target_value, direction, action, protocol, ports, comment)
     VALUES ($1,$2,$3,$4,$5,'BOTH',$6,$7,$8,$9)`,
    [topoOtId, f.srcType, f.srcVal, f.tgtType, f.tgtVal, f.action, f.proto, f.ports, f.comment]
  );
}
console.log(`Created OT topology view with ${otFlows.length} flows`);

// =====================================================================
// === Summary ===
// =====================================================================
await client.end();
console.log('\n========================================');
console.log('Demo data seeded successfully!');
console.log('========================================');
console.log(`  VLANs:              6 (Management, Prod Web, Prod App, Prod DB, DMZ, Development)`);
console.log(`  Tags:               ${tagDefs.length}`);
console.log(`  Hosts:              ${hostCount} (with tags and interfaces)`);
console.log(`  Policies:           4 (Web Server, Database, DMZ = APPROVED; Monitoring = DRAFT)`);
console.log(`  SSH Credentials:    ${sshCreds.length} (demo keys — not real)`);
console.log(`  IoT/OT Assets:      ${iotCount} (PLCs, HMIs, HVAC, cameras, sensors, printers)`);
console.log(`  Flow Collectors:    2 (NetFlow v9, sFlow)`);
console.log(`  Enforcement Points: 2 (gateway firewall, switch ACL)`);
console.log(`  K8s Clusters:       ${k8sClusters.length} (Production EKS, Staging GKE)`);
console.log(`  K8s Workloads:      13 (deployments, statefulsets, daemonsets, services)`);
console.log(`  Topology Views:     2 (Production Network, OT Network)`);
console.log('========================================');
