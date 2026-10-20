-- ============================================================================
-- Segmentra demo dataset
-- ============================================================================
-- Realistic sample data to explore the UI on a fresh installation: VLANs, tags,
-- ten Linux hosts, four policy sets (some with several versions in different
-- lifecycle states), an OT/IoT gateway protecting six devices, deployments in
-- several states and an audit trail.
--
-- Load it with:   npm run db:demo            (uses DATABASE_URL, refuses NODE_ENV=production)
-- or directly:    psql "$DATABASE_URL" -f packages/db/demo/demo-data.sql
--
-- Requirements: migrations applied and `npm run db:seed` run first (roles, the
-- admin user and the system tags). The script is idempotent: every row has a
-- fixed id and is inserted with ON CONFLICT DO NOTHING, so re-running it is a
-- no-op. Nothing here can reach a real machine: the hosts have no SSH
-- credentials, so deployments, readiness and compliance checks fail honestly
-- until you point the inventory at real servers.
--
-- Demo users (password for all three: SegmentraDemo2026!):
--   maria.p  operator    nikos.k  approver    ana.v  viewer
-- ============================================================================

BEGIN;

-- ----------------------------------------------------------------------------
-- Users (attribution for policies, approvals and deployments)
-- ----------------------------------------------------------------------------
INSERT INTO users (id, username, display_name, email, is_active, password_hash, created_at, last_login_at) VALUES
  ('aaaaaaaa-0000-4000-8000-000000000001', 'maria.p', 'Maria Papadopoulou', 'maria.p@example.com', true,
   '$2b$12$dmmUuluZCjVUxUV3HAtaU.veHdjBIzyDyTM99MwS0Sg8fbcjtnE8u', now() - interval '40 days', now() - interval '1 day'),
  ('aaaaaaaa-0000-4000-8000-000000000002', 'nikos.k', 'Nikos Karalis', 'nikos.k@example.com', true,
   '$2b$12$dmmUuluZCjVUxUV3HAtaU.veHdjBIzyDyTM99MwS0Sg8fbcjtnE8u', now() - interval '40 days', now() - interval '2 days'),
  ('aaaaaaaa-0000-4000-8000-000000000003', 'ana.v', 'Ana Vidal', 'ana.v@example.com', true,
   '$2b$12$dmmUuluZCjVUxUV3HAtaU.veHdjBIzyDyTM99MwS0Sg8fbcjtnE8u', now() - interval '30 days', now() - interval '5 days')
ON CONFLICT DO NOTHING;

INSERT INTO user_roles (user_id, role_id)
SELECT u.id, r.id FROM (VALUES
  ('maria.p', 'operator'),
  ('nikos.k', 'approver'),
  ('ana.v',   'viewer')
) AS m(username, role)
JOIN users u ON u.username = m.username
JOIN roles r ON r.name = m.role
ON CONFLICT DO NOTHING;

-- ----------------------------------------------------------------------------
-- VLANs (OT zones are modelled as VLANs too)
-- ----------------------------------------------------------------------------
INSERT INTO vlans (id, vlan_tag, name, description, subnet) VALUES
  ('bbbbbbbb-0000-4000-8000-000000000100', 100, 'management',  'Management network: bastion, monitoring, gateways', '10.10.0.0/24'),
  ('bbbbbbbb-0000-4000-8000-000000000110', 110, 'application', 'Web and application servers',                      '10.20.10.0/24'),
  ('bbbbbbbb-0000-4000-8000-000000000120', 120, 'database',    'Database servers',                                 '10.20.20.0/24'),
  ('bbbbbbbb-0000-4000-8000-000000000200', 200, 'ot-floor',    'OT floor: PLCs, HMIs, cameras behind ot-gw-01',    '192.168.50.0/24')
ON CONFLICT DO NOTHING;

-- ----------------------------------------------------------------------------
-- Tags (iot-gateway and bastion are system tags created by the seed; kept here
-- so the dataset also loads on a database where the seed was skipped)
-- ----------------------------------------------------------------------------
INSERT INTO tags (id, name, description, is_system) VALUES
  ('cccccccc-0000-4000-8000-000000000001', 'web',         'Public-facing web servers (nginx)',          false),
  ('cccccccc-0000-4000-8000-000000000002', 'app',         'Application servers (API, workers)',         false),
  ('cccccccc-0000-4000-8000-000000000003', 'database',    'PostgreSQL servers',                         false),
  ('cccccccc-0000-4000-8000-000000000004', 'monitoring',  'Prometheus / Grafana / backup pollers',      false),
  ('cccccccc-0000-4000-8000-000000000005', 'production',  'Production environment',                     false),
  ('cccccccc-0000-4000-8000-000000000006', 'staging',     'Staging environment',                        false),
  ('cccccccc-0000-4000-8000-000000000007', 'scada',       'SCADA / engineering workstations allowed into the OT floor', false),
  ('cccccccc-0000-4000-8000-000000000008', 'iot-gateway', 'IoT/OT gateway firewall hosts',              true),
  ('cccccccc-0000-4000-8000-000000000009', 'bastion',     'SSH jump hosts for secure access',           true)
ON CONFLICT DO NOTHING;

-- ----------------------------------------------------------------------------
-- Hosts
-- ----------------------------------------------------------------------------
INSERT INTO hosts (id, hostname, mgmt_ip, ssh_port, environment, os_family, firewall_backend, vlan_id, enabled, created_at, updated_at) VALUES
  ('11111111-0000-4000-8000-000000000001', 'bastion-01', '10.10.0.5',    22, 'production', 'ubuntu', 'nftables', 'bbbbbbbb-0000-4000-8000-000000000100', true, now() - interval '35 days', now() - interval '20 days'),
  ('11111111-0000-4000-8000-000000000002', 'web-01',     '10.20.10.11',  22, 'production', 'ubuntu', 'nftables', 'bbbbbbbb-0000-4000-8000-000000000110', true, now() - interval '34 days', now() - interval '12 days'),
  ('11111111-0000-4000-8000-000000000003', 'web-02',     '10.20.10.12',  22, 'production', 'ubuntu', 'nftables', 'bbbbbbbb-0000-4000-8000-000000000110', true, now() - interval '34 days', now() - interval '12 days'),
  ('11111111-0000-4000-8000-000000000004', 'app-01',     '10.20.10.21',  22, 'production', 'rhel',   'iptables', 'bbbbbbbb-0000-4000-8000-000000000110', true, now() - interval '33 days', now() - interval '15 days'),
  ('11111111-0000-4000-8000-000000000005', 'app-02',     '10.20.10.22',  22, 'production', 'rhel',   'iptables', 'bbbbbbbb-0000-4000-8000-000000000110', true, now() - interval '33 days', now() - interval '15 days'),
  ('11111111-0000-4000-8000-000000000006', 'db-01',      '10.20.20.31',  22, 'production', 'debian', 'nftables', 'bbbbbbbb-0000-4000-8000-000000000120', true, now() - interval '33 days', now() - interval '10 days'),
  ('11111111-0000-4000-8000-000000000007', 'mon-01',     '10.10.0.20',   22, 'production', 'ubuntu', 'nftables', 'bbbbbbbb-0000-4000-8000-000000000100', true, now() - interval '30 days', now() - interval '9 days'),
  ('11111111-0000-4000-8000-000000000008', 'ot-gw-01',   '10.10.0.50',   22, 'production', 'debian', 'nftables', 'bbbbbbbb-0000-4000-8000-000000000100', true, now() - interval '21 days', now() - interval '5 days'),
  ('11111111-0000-4000-8000-000000000009', 'scada-01',   '10.20.10.40',  22, 'production', 'rhel',   'iptables', 'bbbbbbbb-0000-4000-8000-000000000110', true, now() - interval '21 days', now() - interval '7 days'),
  ('11111111-0000-4000-8000-000000000010', 'web-stg-01', '10.20.10.111', 22, 'staging',    'ubuntu', 'auto',     'bbbbbbbb-0000-4000-8000-000000000110', true, now() - interval '18 days', now() - interval '3 days')
ON CONFLICT DO NOTHING;

INSERT INTO host_tags (host_id, tag_id, source)
SELECT h.id, t.id, 'manual' FROM (VALUES
  ('bastion-01', 'bastion'),     ('bastion-01', 'production'),
  ('web-01',     'web'),         ('web-01',     'production'),
  ('web-02',     'web'),         ('web-02',     'production'),
  ('app-01',     'app'),         ('app-01',     'production'),
  ('app-02',     'app'),         ('app-02',     'production'),
  ('db-01',      'database'),    ('db-01',      'production'),
  ('mon-01',     'monitoring'),  ('mon-01',     'production'),
  ('ot-gw-01',   'iot-gateway'), ('ot-gw-01',   'production'),
  ('scada-01',   'scada'),       ('scada-01',   'app'),        ('scada-01', 'production'),
  ('web-stg-01', 'web'),         ('web-stg-01', 'staging')
) AS m(hostname, tag)
JOIN hosts h ON h.hostname = m.hostname
JOIN tags t ON t.name = m.tag
ON CONFLICT DO NOTHING;

-- Interfaces: the gateway has a management leg and an OT leg; the others a single data interface
INSERT INTO host_interfaces (id, host_id, name, role, ip_address, cidr, vlan_id, is_primary, enabled) VALUES
  ('dddddddd-0000-4000-8000-000000000001', '11111111-0000-4000-8000-000000000008', 'eth0', 'mgmt', '10.10.0.50',   24, 'bbbbbbbb-0000-4000-8000-000000000100', true,  true),
  ('dddddddd-0000-4000-8000-000000000002', '11111111-0000-4000-8000-000000000008', 'eth1', 'ot',   '192.168.50.1', 24, 'bbbbbbbb-0000-4000-8000-000000000200', false, true),
  ('dddddddd-0000-4000-8000-000000000003', '11111111-0000-4000-8000-000000000002', 'ens18', 'data', '10.20.10.11', 24, 'bbbbbbbb-0000-4000-8000-000000000110', true, true),
  ('dddddddd-0000-4000-8000-000000000004', '11111111-0000-4000-8000-000000000003', 'ens18', 'data', '10.20.10.12', 24, 'bbbbbbbb-0000-4000-8000-000000000110', true, true),
  ('dddddddd-0000-4000-8000-000000000005', '11111111-0000-4000-8000-000000000006', 'ens18', 'data', '10.20.20.31', 24, 'bbbbbbbb-0000-4000-8000-000000000120', true, true),
  ('dddddddd-0000-4000-8000-000000000006', '11111111-0000-4000-8000-000000000001', 'eth0',  'mgmt', '10.10.0.5',   24, 'bbbbbbbb-0000-4000-8000-000000000100', true, true)
ON CONFLICT DO NOTHING;

-- ----------------------------------------------------------------------------
-- IoT / OT assets behind ot-gw-01
-- ----------------------------------------------------------------------------
INSERT INTO iot_assets (id, name, description, asset_type, vendor, model, firmware_version, mac_address, ip_address, vlan_id, zone, criticality, fingerprint, discovered_by, enabled, created_at, updated_at) VALUES
  ('eeeeeeee-0000-4000-8000-000000000001', 'plc-line-a', 'Main PLC of production line A', 'plc', 'Siemens', 'SIMATIC S7-1500', 'V2.9.4',
   '00:1B:1B:4A:12:7C', '192.168.50.10', 'bbbbbbbb-0000-4000-8000-000000000200', 'Plant floor A', 'critical',
   '{"open_ports": [102, 80, 443], "protocols": ["s7comm", "https"]}', 'manual', true, now() - interval '20 days', now() - interval '20 days'),
  ('eeeeeeee-0000-4000-8000-000000000002', 'plc-line-b', 'PLC of packaging line B', 'plc', 'Schneider Electric', 'Modicon M340', '3.40',
   '00:80:F4:21:9B:01', '192.168.50.11', 'bbbbbbbb-0000-4000-8000-000000000200', 'Plant floor B', 'high',
   '{"open_ports": [502, 80], "protocols": ["modbus-tcp", "http"]}', 'manual', true, now() - interval '20 days', now() - interval '20 days'),
  ('eeeeeeee-0000-4000-8000-000000000003', 'hmi-line-a', 'Operator panel for line A', 'hmi', 'Siemens', 'SIMATIC HMI KTP900', '17.0.0.2',
   '00:1B:1B:5C:33:10', '192.168.50.20', 'bbbbbbbb-0000-4000-8000-000000000200', 'Plant floor A', 'high',
   '{"open_ports": [102, 5900], "protocols": ["s7comm", "vnc"]}', 'manual', true, now() - interval '20 days', now() - interval '20 days'),
  ('eeeeeeee-0000-4000-8000-000000000004', 'cam-dock-1', 'IP camera covering the loading dock', 'camera', 'Hikvision', 'DS-2CD2143G2', 'V5.7.3',
   '44:19:B6:7E:02:A1', '192.168.50.30', 'bbbbbbbb-0000-4000-8000-000000000200', 'Loading dock', 'medium',
   '{"open_ports": [80, 554, 8000], "protocols": ["rtsp", "http"]}', 'discovery', true, now() - interval '12 days', now() - interval '12 days'),
  ('eeeeeeee-0000-4000-8000-000000000005', 'hvac-ctrl-1', 'HVAC controller for hall A', 'hvac', 'Trane', 'Tracer SC+', '5.5.1',
   '00:1E:C0:AA:12:01', '192.168.50.40', 'bbbbbbbb-0000-4000-8000-000000000200', 'Plant floor A', 'medium',
   '{"open_ports": [80, 443, 4840, 47808], "protocols": ["bacnet", "opc-ua", "https"]}', 'manual', true, now() - interval '19 days', now() - interval '19 days'),
  ('eeeeeeee-0000-4000-8000-000000000006', 'badge-reader-1', 'Access-control reader at the dock door', 'other', 'HID Global', 'VertX EVO V1000', '3.7.1.106',
   '00:06:8E:10:22:33', '192.168.50.50', 'bbbbbbbb-0000-4000-8000-000000000200', 'Loading dock', 'low',
   '{"open_ports": [4050, 80], "protocols": ["http"]}', 'discovery', true, now() - interval '12 days', now() - interval '12 days')
ON CONFLICT DO NOTHING;

INSERT INTO iot_asset_gateways (asset_id, host_id, assigned_at)
SELECT a.id, '11111111-0000-4000-8000-000000000008', now() - interval '11 days'
FROM iot_assets a
WHERE a.id IN (
  'eeeeeeee-0000-4000-8000-000000000001', 'eeeeeeee-0000-4000-8000-000000000002', 'eeeeeeee-0000-4000-8000-000000000003',
  'eeeeeeee-0000-4000-8000-000000000004', 'eeeeeeee-0000-4000-8000-000000000005', 'eeeeeeee-0000-4000-8000-000000000006')
ON CONFLICT DO NOTHING;

-- ----------------------------------------------------------------------------
-- Policy sets, versions and rules
--   source_value / destination_value hold the id of the tag / VLAN / host / IoT
--   asset, or a CIDR. Tag ids are looked up by name because the seed may already
--   have created the system tags with other ids. Rules are evaluated in order_index order.
-- ----------------------------------------------------------------------------
INSERT INTO policy_sets (id, name, description, scope_type, scope_tag_id, scope_vlan_id, created_by, created_at) VALUES
  ('22222222-0000-4000-8000-000000000001', 'Web tier ingress',    'What may reach the public web servers',                    'TAG',       (SELECT id FROM tags WHERE name='web'), NULL, 'aaaaaaaa-0000-4000-8000-000000000001', now() - interval '20 days'),
  ('22222222-0000-4000-8000-000000000002', 'Database tier',       'PostgreSQL only from the application tier and monitoring', 'TAG',       (SELECT id FROM tags WHERE name='database'), NULL, 'aaaaaaaa-0000-4000-8000-000000000001', now() - interval '15 days'),
  ('22222222-0000-4000-8000-000000000003', 'OT floor gateway',    'Forwarding rules on ot-gw-01 protecting the OT floor',      'HOST_LIST', NULL, NULL, 'aaaaaaaa-0000-4000-8000-000000000001', now() - interval '9 days'),
  ('22222222-0000-4000-8000-000000000004', 'Management baseline', 'SSH and SNMP on the management VLAN',                       'VLAN',      NULL, 'bbbbbbbb-0000-4000-8000-000000000100', 'aaaaaaaa-0000-4000-8000-000000000001', now() - interval '4 days')
ON CONFLICT DO NOTHING;

INSERT INTO policy_set_hosts (policy_set_id, host_id) VALUES
  ('22222222-0000-4000-8000-000000000003', '11111111-0000-4000-8000-000000000008')
ON CONFLICT DO NOTHING;

INSERT INTO policy_versions (id, policy_set_id, version_number, status, change_summary, created_by, created_at,
                             submitted_by, submitted_at, submission_note, approved_by, approved_at,
                             interface_scope_type, is_high_risk) VALUES
  -- Web tier ingress: v1 deployed, v2 draft
  ('33333333-0000-4000-8000-000000000011', '22222222-0000-4000-8000-000000000001', 1, 'DEPLOYED',
   'Initial web tier policy: public HTTP/HTTPS, SSH from bastion, monitoring',
   'aaaaaaaa-0000-4000-8000-000000000001', now() - interval '20 days',
   'aaaaaaaa-0000-4000-8000-000000000001', now() - interval '19 days 6 hours', 'Replaces the hand-written iptables rules on web-01/web-02.',
   'aaaaaaaa-0000-4000-8000-000000000002', now() - interval '19 days', 'ALL_INTERFACES', false),
  ('33333333-0000-4000-8000-000000000012', '22222222-0000-4000-8000-000000000001', 2, 'DRAFT',
   'Add partner API access on 8443 from the partner VPN range',
   'aaaaaaaa-0000-4000-8000-000000000001', now() - interval '2 days',
   NULL, NULL, NULL, NULL, NULL, 'ALL_INTERFACES', false),
  -- Database tier: v1 deployed, v2 waiting for approval
  ('33333333-0000-4000-8000-000000000021', '22222222-0000-4000-8000-000000000002', 1, 'DEPLOYED',
   'PostgreSQL from the app tier, exporters for monitoring, default deny',
   'aaaaaaaa-0000-4000-8000-000000000001', now() - interval '15 days',
   'aaaaaaaa-0000-4000-8000-000000000001', now() - interval '14 days 12 hours', NULL,
   'aaaaaaaa-0000-4000-8000-000000000002', now() - interval '14 days', 'ALL_INTERFACES', false),
  ('33333333-0000-4000-8000-000000000022', '22222222-0000-4000-8000-000000000002', 2, 'PENDING_APPROVAL',
   'Allow the backup agent on mon-01 to pull dumps over SSH',
   'aaaaaaaa-0000-4000-8000-000000000001', now() - interval '1 day 5 hours',
   'aaaaaaaa-0000-4000-8000-000000000001', now() - interval '1 day', 'Needed for the nightly pg_dump job moving to mon-01 next week.',
   NULL, NULL, 'ALL_INTERFACES', false),
  -- OT floor gateway: v1 deployed
  ('33333333-0000-4000-8000-000000000031', '22222222-0000-4000-8000-000000000003', 1, 'DEPLOYED',
   'Only SCADA may talk to the PLCs; RTSP from management; block everything else into VLAN 200',
   'aaaaaaaa-0000-4000-8000-000000000001', now() - interval '9 days',
   'aaaaaaaa-0000-4000-8000-000000000001', now() - interval '8 days 20 hours', 'Reviewed with the OT team; PLC vendor ports confirmed.',
   'aaaaaaaa-0000-4000-8000-000000000002', now() - interval '8 days', 'ALL_INTERFACES', true),
  -- Management baseline: v1 approved, deployment scheduled
  ('33333333-0000-4000-8000-000000000041', '22222222-0000-4000-8000-000000000004', 1, 'APPROVED',
   'SSH within the management VLAN, SNMP from mon-01, default deny',
   'aaaaaaaa-0000-4000-8000-000000000001', now() - interval '4 days',
   'aaaaaaaa-0000-4000-8000-000000000001', now() - interval '3 days 10 hours', NULL,
   'aaaaaaaa-0000-4000-8000-000000000002', now() - interval '3 days', 'ALL_INTERFACES', false)
ON CONFLICT DO NOTHING;

INSERT INTO policy_rules (id, policy_version_id, order_index, direction, action, protocol, ports, source_type, source_value, destination_type, destination_value, log_mode, comment) VALUES
  -- Web tier ingress v1
  ('44444444-0000-4000-8000-000000000101', '33333333-0000-4000-8000-000000000011', 0, 'IN', 'ALLOW', 'tcp', '22',     'TAG',  (SELECT id::text FROM tags WHERE name='bastion'), NULL, NULL, 'NONE',             'SSH from the bastion hosts'),
  ('44444444-0000-4000-8000-000000000102', '33333333-0000-4000-8000-000000000011', 1, 'IN', 'ALLOW', 'tcp', '80,443', 'CIDR', '0.0.0.0/0',                            NULL, NULL, 'NONE',             'Public HTTP and HTTPS'),
  ('44444444-0000-4000-8000-000000000103', '33333333-0000-4000-8000-000000000011', 2, 'IN', 'ALLOW', 'tcp', '9100',   'TAG',  (SELECT id::text FROM tags WHERE name='monitoring'), NULL, NULL, 'NONE',             'Prometheus node exporter'),
  ('44444444-0000-4000-8000-000000000104', '33333333-0000-4000-8000-000000000011', 3, 'IN', 'ALLOW', 'icmp', NULL,    'VLAN', 'bbbbbbbb-0000-4000-8000-000000000100', NULL, NULL, 'NONE',             'Ping from the management VLAN'),
  ('44444444-0000-4000-8000-000000000105', '33333333-0000-4000-8000-000000000011', 4, 'IN', 'DENY',  'any',  NULL,    'CIDR', '0.0.0.0/0',                            NULL, NULL, 'LOG_RATE_LIMITED', 'Default deny, logged'),
  -- Web tier ingress v2 (draft): v1 plus the partner API
  ('44444444-0000-4000-8000-000000000111', '33333333-0000-4000-8000-000000000012', 0, 'IN', 'ALLOW', 'tcp', '22',     'TAG',  (SELECT id::text FROM tags WHERE name='bastion'), NULL, NULL, 'NONE',             'SSH from the bastion hosts'),
  ('44444444-0000-4000-8000-000000000112', '33333333-0000-4000-8000-000000000012', 1, 'IN', 'ALLOW', 'tcp', '80,443', 'CIDR', '0.0.0.0/0',                            NULL, NULL, 'NONE',             'Public HTTP and HTTPS'),
  ('44444444-0000-4000-8000-000000000113', '33333333-0000-4000-8000-000000000012', 2, 'IN', 'ALLOW', 'tcp', '8443',   'CIDR', '203.0.113.0/24',                       NULL, NULL, 'LOG',              'Partner API over the partner VPN range'),
  ('44444444-0000-4000-8000-000000000114', '33333333-0000-4000-8000-000000000012', 3, 'IN', 'ALLOW', 'tcp', '9100',   'TAG',  (SELECT id::text FROM tags WHERE name='monitoring'), NULL, NULL, 'NONE',             'Prometheus node exporter'),
  ('44444444-0000-4000-8000-000000000115', '33333333-0000-4000-8000-000000000012', 4, 'IN', 'ALLOW', 'icmp', NULL,    'VLAN', 'bbbbbbbb-0000-4000-8000-000000000100', NULL, NULL, 'NONE',             'Ping from the management VLAN'),
  ('44444444-0000-4000-8000-000000000116', '33333333-0000-4000-8000-000000000012', 5, 'IN', 'DENY',  'any',  NULL,    'CIDR', '0.0.0.0/0',                            NULL, NULL, 'LOG_RATE_LIMITED', 'Default deny, logged'),
  -- Database tier v1
  ('44444444-0000-4000-8000-000000000201', '33333333-0000-4000-8000-000000000021', 0, 'IN', 'ALLOW', 'tcp', '22',        'TAG',  (SELECT id::text FROM tags WHERE name='bastion'), NULL, NULL, 'NONE', 'SSH from the bastion hosts'),
  ('44444444-0000-4000-8000-000000000202', '33333333-0000-4000-8000-000000000021', 1, 'IN', 'ALLOW', 'tcp', '5432',      'TAG',  (SELECT id::text FROM tags WHERE name='app'), NULL, NULL, 'NONE', 'PostgreSQL from the application tier'),
  ('44444444-0000-4000-8000-000000000203', '33333333-0000-4000-8000-000000000021', 2, 'IN', 'ALLOW', 'tcp', '9100,9187', 'TAG',  (SELECT id::text FROM tags WHERE name='monitoring'), NULL, NULL, 'NONE', 'Node and postgres exporters'),
  ('44444444-0000-4000-8000-000000000204', '33333333-0000-4000-8000-000000000021', 3, 'IN', 'DENY',  'any',  NULL,       'CIDR', '0.0.0.0/0',                            NULL, NULL, 'LOG',  'Default deny, logged'),
  -- Database tier v2 (pending approval): v1 plus SSH from mon-01
  ('44444444-0000-4000-8000-000000000211', '33333333-0000-4000-8000-000000000022', 0, 'IN', 'ALLOW', 'tcp', '22',        'TAG',  (SELECT id::text FROM tags WHERE name='bastion'), NULL, NULL, 'NONE', 'SSH from the bastion hosts'),
  ('44444444-0000-4000-8000-000000000212', '33333333-0000-4000-8000-000000000022', 1, 'IN', 'ALLOW', 'tcp', '22',        'HOST', '11111111-0000-4000-8000-000000000007', NULL, NULL, 'LOG',  'Backup agent on mon-01 (nightly pg_dump)'),
  ('44444444-0000-4000-8000-000000000213', '33333333-0000-4000-8000-000000000022', 2, 'IN', 'ALLOW', 'tcp', '5432',      'TAG',  (SELECT id::text FROM tags WHERE name='app'), NULL, NULL, 'NONE', 'PostgreSQL from the application tier'),
  ('44444444-0000-4000-8000-000000000214', '33333333-0000-4000-8000-000000000022', 3, 'IN', 'ALLOW', 'tcp', '9100,9187', 'TAG',  (SELECT id::text FROM tags WHERE name='monitoring'), NULL, NULL, 'NONE', 'Node and postgres exporters'),
  ('44444444-0000-4000-8000-000000000215', '33333333-0000-4000-8000-000000000022', 4, 'IN', 'DENY',  'any',  NULL,       'CIDR', '0.0.0.0/0',                            NULL, NULL, 'LOG',  'Default deny, logged'),
  -- OT floor gateway v1 (FORWARD rules carry an explicit destination)
  ('44444444-0000-4000-8000-000000000301', '33333333-0000-4000-8000-000000000031', 0, 'IN',      'ALLOW', 'tcp', '22',   'TAG',  (SELECT id::text FROM tags WHERE name='bastion'), NULL,        NULL,                                   'NONE', 'SSH to the gateway from the bastion hosts'),
  ('44444444-0000-4000-8000-000000000302', '33333333-0000-4000-8000-000000000031', 1, 'FORWARD', 'ALLOW', 'tcp', '102',  'HOST', '11111111-0000-4000-8000-000000000009', 'IOT_ASSET', 'eeeeeeee-0000-4000-8000-000000000001', 'NONE', 'S7comm from scada-01 to the line A PLC'),
  ('44444444-0000-4000-8000-000000000303', '33333333-0000-4000-8000-000000000031', 2, 'FORWARD', 'ALLOW', 'tcp', '502',  'HOST', '11111111-0000-4000-8000-000000000009', 'IOT_ASSET', 'eeeeeeee-0000-4000-8000-000000000002', 'NONE', 'Modbus/TCP from scada-01 to the line B PLC'),
  ('44444444-0000-4000-8000-000000000304', '33333333-0000-4000-8000-000000000031', 3, 'FORWARD', 'ALLOW', 'tcp', '4840', 'HOST', '11111111-0000-4000-8000-000000000009', 'IOT_ASSET', 'eeeeeeee-0000-4000-8000-000000000005', 'NONE', 'OPC UA from scada-01 to the HVAC controller'),
  ('44444444-0000-4000-8000-000000000305', '33333333-0000-4000-8000-000000000031', 4, 'FORWARD', 'ALLOW', 'tcp', '554',  'VLAN', 'bbbbbbbb-0000-4000-8000-000000000100', 'IOT_ASSET', 'eeeeeeee-0000-4000-8000-000000000004', 'NONE', 'RTSP video from the management VLAN to the dock camera'),
  ('44444444-0000-4000-8000-000000000306', '33333333-0000-4000-8000-000000000031', 5, 'FORWARD', 'DENY',  'any', NULL,   'CIDR', '0.0.0.0/0',                            'VLAN',      'bbbbbbbb-0000-4000-8000-000000000200', 'LOG',  'Block everything else into the OT floor'),
  ('44444444-0000-4000-8000-000000000307', '33333333-0000-4000-8000-000000000031', 6, 'IN',      'DENY',  'any', NULL,   'CIDR', '0.0.0.0/0',                            NULL,        NULL,                                   'LOG',  'Default deny on the gateway itself'),
  -- Management baseline v1
  ('44444444-0000-4000-8000-000000000401', '33333333-0000-4000-8000-000000000041', 0, 'IN', 'ALLOW', 'tcp', '22',  'CIDR', '10.10.0.0/24',                         NULL, NULL, 'NONE',             'SSH within the management VLAN'),
  ('44444444-0000-4000-8000-000000000402', '33333333-0000-4000-8000-000000000041', 1, 'IN', 'ALLOW', 'udp', '161', 'HOST', '11111111-0000-4000-8000-000000000007', NULL, NULL, 'NONE',             'SNMP polling from mon-01'),
  ('44444444-0000-4000-8000-000000000403', '33333333-0000-4000-8000-000000000041', 2, 'IN', 'DENY',  'any', NULL,  'CIDR', '0.0.0.0/0',                            NULL, NULL, 'LOG_RATE_LIMITED', 'Default deny, logged')
ON CONFLICT DO NOTHING;

-- ----------------------------------------------------------------------------
-- Deployments
--   applied_hash: hash of the compiled artifact; applied_live_hash: "v2:" + hash
--   of the live ruleset read back after the deployment (used for drift checks).
-- ----------------------------------------------------------------------------
INSERT INTO deployments (id, policy_version_id, mode, target_query, target_count, created_by, created_at, started_at, finished_at, status,
                         requires_approval, canary_size, batch_size, scheduled_at, progress, notes) VALUES
  -- Web tier v1, first attempt: web-02 unreachable
  ('55555555-0000-4000-8000-000000000001', '33333333-0000-4000-8000-000000000011', 'FULL',
   jsonb_build_object('tags', jsonb_build_array((SELECT id FROM tags WHERE name='web'))), 3, 'aaaaaaaa-0000-4000-8000-000000000001',
   now() - interval '13 days', now() - interval '13 days' + interval '1 minute', now() - interval '13 days' + interval '6 minutes', 'PARTIAL',
   false, NULL, NULL, NULL,
   '{"phase": "complete", "checked": 3, "totalToCheck": 3, "deployed": 2, "totalToDeploy": 3, "warnings": ["web-02: ssh connect timed out"]}',
   'First rollout of the web tier policy'),
  -- Web tier v1, retry: all three succeeded (this is the active policy on the web hosts)
  ('55555555-0000-4000-8000-000000000002', '33333333-0000-4000-8000-000000000011', 'FULL',
   jsonb_build_object('tags', jsonb_build_array((SELECT id FROM tags WHERE name='web'))), 3, 'aaaaaaaa-0000-4000-8000-000000000001',
   now() - interval '12 days', now() - interval '12 days' + interval '1 minute', now() - interval '12 days' + interval '4 minutes', 'SUCCEEDED',
   false, NULL, NULL, NULL,
   '{"phase": "complete", "checked": 3, "totalToCheck": 3, "deployed": 3, "totalToDeploy": 3, "warnings": []}',
   'Retry after fixing the SSH credential on web-02'),
  -- Database tier v1, canary of one host
  ('55555555-0000-4000-8000-000000000003', '33333333-0000-4000-8000-000000000021', 'CANARY',
   jsonb_build_object('tags', jsonb_build_array((SELECT id FROM tags WHERE name='database'))), 1, 'aaaaaaaa-0000-4000-8000-000000000001',
   now() - interval '10 days', now() - interval '10 days' + interval '1 minute', now() - interval '10 days' + interval '3 minutes', 'SUCCEEDED',
   true, 1, NULL, NULL,
   '{"phase": "complete", "checked": 1, "totalToCheck": 1, "deployed": 1, "totalToDeploy": 1, "warnings": []}',
   NULL),
  -- OT floor gateway v1
  ('55555555-0000-4000-8000-000000000004', '33333333-0000-4000-8000-000000000031', 'FULL',
   '{"hosts": ["11111111-0000-4000-8000-000000000008"]}', 1, 'aaaaaaaa-0000-4000-8000-000000000001',
   now() - interval '5 days', now() - interval '5 days' + interval '1 minute', now() - interval '5 days' + interval '3 minutes', 'SUCCEEDED',
   true, NULL, NULL, NULL,
   '{"phase": "complete", "checked": 1, "totalToCheck": 1, "deployed": 1, "totalToDeploy": 1, "warnings": []}',
   'High-risk policy: approved by nikos.k before the maintenance window'),
  -- Management baseline v1: scheduled for the next maintenance window
  ('55555555-0000-4000-8000-000000000005', '33333333-0000-4000-8000-000000000041', 'PROGRESSIVE',
   '{"vlans": ["bbbbbbbb-0000-4000-8000-000000000100"]}', 4, 'aaaaaaaa-0000-4000-8000-000000000001',
   now() - interval '3 days', NULL, NULL, 'SCHEDULED',
   false, NULL, 2, date_trunc('day', now()) + interval '1 day 2 hours',
   '{"phase": "queued", "checked": 0, "totalToCheck": 4, "deployed": 0, "totalToDeploy": 4, "warnings": []}',
   'Roll out in batches of two during the 02:00 window')
ON CONFLICT DO NOTHING;

UPDATE deployments SET approved_by = 'aaaaaaaa-0000-4000-8000-000000000002', approved_at = started_at - interval '30 seconds'
WHERE id IN ('55555555-0000-4000-8000-000000000003', '55555555-0000-4000-8000-000000000004') AND approved_by IS NULL;

INSERT INTO deployment_hosts (deployment_id, host_id, status, started_at, finished_at, message, applied_hash, applied_live_hash, persistence_status, persistence_method, persistence_message) VALUES
  -- first web rollout
  ('55555555-0000-4000-8000-000000000001', '11111111-0000-4000-8000-000000000002', 'SUCCEEDED', now() - interval '13 days' + interval '2 minutes', now() - interval '13 days' + interval '3 minutes', NULL,
   encode(sha256('web-tier-v1-artifact'::bytea), 'hex'), 'v2:' || encode(sha256('web-tier-v1-live-web-01-old'::bytea), 'hex'), 'persisted', 'nftables.service', NULL),
  ('55555555-0000-4000-8000-000000000001', '11111111-0000-4000-8000-000000000003', 'FAILED',    now() - interval '13 days' + interval '2 minutes', now() - interval '13 days' + interval '5 minutes',
   'ssh: connect to host 10.20.10.12 port 22: Connection timed out', NULL, NULL, NULL, NULL, NULL),
  ('55555555-0000-4000-8000-000000000001', '11111111-0000-4000-8000-000000000010', 'SUCCEEDED', now() - interval '13 days' + interval '3 minutes', now() - interval '13 days' + interval '4 minutes', NULL,
   encode(sha256('web-tier-v1-artifact'::bytea), 'hex'), 'v2:' || encode(sha256('web-tier-v1-live-web-stg-01-old'::bytea), 'hex'), 'persisted', 'nftables.service', NULL),
  -- web retry (active)
  ('55555555-0000-4000-8000-000000000002', '11111111-0000-4000-8000-000000000002', 'SUCCEEDED', now() - interval '12 days' + interval '2 minutes', now() - interval '12 days' + interval '3 minutes', NULL,
   encode(sha256('web-tier-v1-artifact'::bytea), 'hex'), 'v2:' || encode(sha256('web-tier-v1-live-web-01'::bytea), 'hex'), 'persisted', 'nftables.service', NULL),
  ('55555555-0000-4000-8000-000000000002', '11111111-0000-4000-8000-000000000003', 'SUCCEEDED', now() - interval '12 days' + interval '2 minutes', now() - interval '12 days' + interval '3 minutes', NULL,
   encode(sha256('web-tier-v1-artifact'::bytea), 'hex'), 'v2:' || encode(sha256('web-tier-v1-live-web-02'::bytea), 'hex'), 'persisted', 'nftables.service', NULL),
  ('55555555-0000-4000-8000-000000000002', '11111111-0000-4000-8000-000000000010', 'SUCCEEDED', now() - interval '12 days' + interval '3 minutes', now() - interval '12 days' + interval '4 minutes', NULL,
   encode(sha256('web-tier-v1-artifact'::bytea), 'hex'), 'v2:' || encode(sha256('web-tier-v1-live-web-stg-01'::bytea), 'hex'), 'persisted', 'nftables.service', NULL),
  -- database canary (active on db-01)
  ('55555555-0000-4000-8000-000000000003', '11111111-0000-4000-8000-000000000006', 'SUCCEEDED', now() - interval '10 days' + interval '1 minute', now() - interval '10 days' + interval '2 minutes', NULL,
   encode(sha256('database-tier-v1-artifact'::bytea), 'hex'), 'v2:' || encode(sha256('database-tier-v1-live-db-01'::bytea), 'hex'), 'persisted', 'nftables.service', NULL),
  -- OT gateway (active on ot-gw-01)
  ('55555555-0000-4000-8000-000000000004', '11111111-0000-4000-8000-000000000008', 'SUCCEEDED', now() - interval '5 days' + interval '1 minute', now() - interval '5 days' + interval '2 minutes', NULL,
   encode(sha256('ot-gateway-v1-artifact'::bytea), 'hex'), 'v2:' || encode(sha256('ot-gateway-v1-live-ot-gw-01'::bytea), 'hex'), 'persisted', 'nftables.service', NULL),
  -- scheduled management rollout: nothing applied yet
  ('55555555-0000-4000-8000-000000000005', '11111111-0000-4000-8000-000000000001', 'PENDING', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL),
  ('55555555-0000-4000-8000-000000000005', '11111111-0000-4000-8000-000000000007', 'PENDING', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL),
  ('55555555-0000-4000-8000-000000000005', '11111111-0000-4000-8000-000000000008', 'PENDING', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL),
  ('55555555-0000-4000-8000-000000000005', '11111111-0000-4000-8000-000000000009', 'PENDING', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)
ON CONFLICT DO NOTHING;

INSERT INTO execution_runs (id, deployment_id, executor_type, command, exit_code, started_at, finished_at, status) VALUES
  ('66666666-0000-4000-8000-000000000001', '55555555-0000-4000-8000-000000000001', 'ssh', 'ssh-direct apply (3 hosts)', 1, now() - interval '13 days' + interval '1 minute', now() - interval '13 days' + interval '6 minutes', 'FAILED'),
  ('66666666-0000-4000-8000-000000000002', '55555555-0000-4000-8000-000000000002', 'ssh', 'ssh-direct apply (3 hosts)', 0, now() - interval '12 days' + interval '1 minute', now() - interval '12 days' + interval '4 minutes', 'SUCCEEDED'),
  ('66666666-0000-4000-8000-000000000003', '55555555-0000-4000-8000-000000000003', 'ssh', 'ssh-direct apply (1 host, canary)', 0, now() - interval '10 days' + interval '1 minute', now() - interval '10 days' + interval '3 minutes', 'SUCCEEDED'),
  ('66666666-0000-4000-8000-000000000004', '55555555-0000-4000-8000-000000000004', 'ssh', 'ssh-direct apply (1 host)', 0, now() - interval '5 days' + interval '1 minute', now() - interval '5 days' + interval '3 minutes', 'SUCCEEDED')
ON CONFLICT DO NOTHING;

-- ----------------------------------------------------------------------------
-- Audit trail
-- ----------------------------------------------------------------------------
INSERT INTO audit_events (id, actor_user_id, action, entity_type, entity_id, "timestamp", ip_address, metadata) VALUES
  ('77777777-0000-4000-8000-000000000001', 'aaaaaaaa-0000-4000-8000-000000000001', 'HOST_CREATE', 'host', '11111111-0000-4000-8000-000000000001', now() - interval '35 days', '10.10.0.77', '{"hostname": "bastion-01"}'),
  ('77777777-0000-4000-8000-000000000002', 'aaaaaaaa-0000-4000-8000-000000000001', 'HOST_BULK_IMPORT', 'host', '11111111-0000-4000-8000-000000000002', now() - interval '34 days', '10.10.0.77', '{"imported": 6, "failed": 0}'),
  ('77777777-0000-4000-8000-000000000003', 'aaaaaaaa-0000-4000-8000-000000000001', 'TAG_CREATE', 'tag', (SELECT id FROM tags WHERE name='web'), now() - interval '34 days', '10.10.0.77', '{"name": "web"}'),
  ('77777777-0000-4000-8000-000000000004', 'aaaaaaaa-0000-4000-8000-000000000001', 'POLICY_SET_CREATE', 'policy_set', '22222222-0000-4000-8000-000000000001', now() - interval '20 days', '10.10.0.77', '{"name": "Web tier ingress", "scopeType": "TAG"}'),
  ('77777777-0000-4000-8000-000000000005', 'aaaaaaaa-0000-4000-8000-000000000001', 'POLICY_SUBMIT', 'policy_version', '33333333-0000-4000-8000-000000000011', now() - interval '19 days 6 hours', '10.10.0.77', '{"versionNumber": 1, "policySetName": "Web tier ingress"}'),
  ('77777777-0000-4000-8000-000000000006', 'aaaaaaaa-0000-4000-8000-000000000002', 'POLICY_APPROVE', 'policy_version', '33333333-0000-4000-8000-000000000011', now() - interval '19 days', '10.10.0.81', '{"by": "nikos.k", "isHighRisk": false, "decision": "APPROVED", "decidedBy": "nikos.k"}'),
  ('77777777-0000-4000-8000-000000000007', 'aaaaaaaa-0000-4000-8000-000000000001', 'DEPLOYMENT_STARTED', 'deployment', '55555555-0000-4000-8000-000000000001', now() - interval '13 days' + interval '1 minute', '10.10.0.77', '{"mode": "FULL", "targetCount": 3}'),
  ('77777777-0000-4000-8000-000000000008', 'aaaaaaaa-0000-4000-8000-000000000001', 'DEPLOYMENT_FAILED', 'deployment', '55555555-0000-4000-8000-000000000001', now() - interval '13 days' + interval '6 minutes', '10.10.0.77', '{"status": "PARTIAL", "failedHosts": ["web-02"]}'),
  ('77777777-0000-4000-8000-000000000009', 'aaaaaaaa-0000-4000-8000-000000000001', 'DEPLOYMENT_STARTED', 'deployment', '55555555-0000-4000-8000-000000000002', now() - interval '12 days' + interval '1 minute', '10.10.0.77', '{"mode": "FULL", "targetCount": 3}'),
  ('77777777-0000-4000-8000-000000000010', 'aaaaaaaa-0000-4000-8000-000000000001', 'DEPLOYMENT_COMPLETED', 'deployment', '55555555-0000-4000-8000-000000000002', now() - interval '12 days' + interval '4 minutes', '10.10.0.77', '{"status": "SUCCEEDED", "succeeded": 3, "failed": 0}'),
  ('77777777-0000-4000-8000-000000000011', 'aaaaaaaa-0000-4000-8000-000000000002', 'POLICY_APPROVE', 'policy_version', '33333333-0000-4000-8000-000000000021', now() - interval '14 days', '10.10.0.81', '{"by": "nikos.k", "isHighRisk": false, "decision": "APPROVED", "decidedBy": "nikos.k"}'),
  ('77777777-0000-4000-8000-000000000012', 'aaaaaaaa-0000-4000-8000-000000000001', 'DEPLOYMENT_COMPLETED', 'deployment', '55555555-0000-4000-8000-000000000003', now() - interval '10 days' + interval '3 minutes', '10.10.0.77', '{"status": "SUCCEEDED", "succeeded": 1, "failed": 0, "mode": "CANARY"}'),
  ('77777777-0000-4000-8000-000000000013', 'aaaaaaaa-0000-4000-8000-000000000001', 'IOT_ASSET_CREATE', 'iot_asset', 'eeeeeeee-0000-4000-8000-000000000001', now() - interval '20 days', '10.10.0.77', '{"name": "plc-line-a", "assetType": "plc"}'),
  ('77777777-0000-4000-8000-000000000014', 'aaaaaaaa-0000-4000-8000-000000000001', 'IOT_ASSET_BULK_IMPORT', 'iot_asset', 'eeeeeeee-0000-4000-8000-000000000004', now() - interval '12 days', '10.10.0.77', '{"imported": 2, "total": 2, "source": "discovery"}'),
  ('77777777-0000-4000-8000-000000000015', 'aaaaaaaa-0000-4000-8000-000000000002', 'POLICY_APPROVE', 'policy_version', '33333333-0000-4000-8000-000000000031', now() - interval '8 days', '10.10.0.81', '{"by": "nikos.k", "isHighRisk": true, "decision": "APPROVED", "decidedBy": "nikos.k"}'),
  ('77777777-0000-4000-8000-000000000016', 'aaaaaaaa-0000-4000-8000-000000000001', 'DEPLOYMENT_COMPLETED', 'deployment', '55555555-0000-4000-8000-000000000004', now() - interval '5 days' + interval '3 minutes', '10.10.0.77', '{"status": "SUCCEEDED", "succeeded": 1, "failed": 0}'),
  ('77777777-0000-4000-8000-000000000017', 'aaaaaaaa-0000-4000-8000-000000000002', 'POLICY_APPROVE', 'policy_version', '33333333-0000-4000-8000-000000000041', now() - interval '3 days', '10.10.0.81', '{"by": "nikos.k", "isHighRisk": false, "decision": "APPROVED", "decidedBy": "nikos.k"}'),
  ('77777777-0000-4000-8000-000000000018', 'aaaaaaaa-0000-4000-8000-000000000001', 'POLICY_SUBMIT', 'policy_version', '33333333-0000-4000-8000-000000000022', now() - interval '1 day', '10.10.0.77', '{"versionNumber": 2, "policySetName": "Database tier"}')
ON CONFLICT DO NOTHING;

COMMIT;
