-- Removes everything that packages/db/demo/demo-data.sql inserted (matched by the fixed demo ids
-- and the demo user names). Tags created by the demo are removed only when no other host, asset or
-- policy still uses them; the system tags (iot-gateway, bastion) are always kept.
--   npm run db:demo -- --remove
BEGIN;

DELETE FROM audit_events      WHERE id::text LIKE '77777777-0000-4000-8000-%';
DELETE FROM execution_runs    WHERE id::text LIKE '66666666-0000-4000-8000-%';
DELETE FROM deployment_hosts  WHERE deployment_id::text LIKE '55555555-0000-4000-8000-%';
DELETE FROM deployment_artifacts WHERE deployment_id::text LIKE '55555555-0000-4000-8000-%';
DELETE FROM deployments       WHERE id::text LIKE '55555555-0000-4000-8000-%';
DELETE FROM policy_rules      WHERE policy_version_id::text LIKE '33333333-0000-4000-8000-%';
DELETE FROM policy_versions   WHERE id::text LIKE '33333333-0000-4000-8000-%';
DELETE FROM policy_set_hosts  WHERE policy_set_id::text LIKE '22222222-0000-4000-8000-%';
DELETE FROM policy_sets       WHERE id::text LIKE '22222222-0000-4000-8000-%';
DELETE FROM iot_asset_gateways WHERE asset_id::text LIKE 'eeeeeeee-0000-4000-8000-%';
DELETE FROM iot_asset_tags    WHERE asset_id::text LIKE 'eeeeeeee-0000-4000-8000-%';
DELETE FROM iot_assets        WHERE id::text LIKE 'eeeeeeee-0000-4000-8000-%';
DELETE FROM host_interfaces   WHERE id::text LIKE 'dddddddd-0000-4000-8000-%';
DELETE FROM host_tags         WHERE host_id::text LIKE '11111111-0000-4000-8000-%';
DELETE FROM hosts             WHERE id::text LIKE '11111111-0000-4000-8000-%';
DELETE FROM vlans             WHERE id::text LIKE 'bbbbbbbb-0000-4000-8000-%';
DELETE FROM tags t
 WHERE t.id::text LIKE 'cccccccc-0000-4000-8000-%'
   AND t.is_system = false
   AND NOT EXISTS (SELECT 1 FROM host_tags ht WHERE ht.tag_id = t.id)
   AND NOT EXISTS (SELECT 1 FROM iot_asset_tags it WHERE it.tag_id = t.id)
   AND NOT EXISTS (SELECT 1 FROM policy_sets ps WHERE ps.scope_tag_id = t.id);
DELETE FROM user_roles WHERE user_id IN (SELECT id FROM users WHERE id::text LIKE 'aaaaaaaa-0000-4000-8000-%');
DELETE FROM users             WHERE id::text LIKE 'aaaaaaaa-0000-4000-8000-%';

COMMIT;
