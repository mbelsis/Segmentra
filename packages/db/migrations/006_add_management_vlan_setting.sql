-- Up Migration
-- Add management VLAN setting for baseline SSH access
INSERT INTO system_settings (key, value, description)
VALUES ('management_vlan_id', '', 'VLAN ID for baseline management SSH access (empty = disabled)')
ON CONFLICT (key) DO NOTHING;

-- Down Migration
DELETE FROM system_settings WHERE key='management_vlan_id';
