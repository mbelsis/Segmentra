-- Prevent duplicate VLANs by adding unique constraint on vlan_tag

-- First deduplicate if any exist
-- The kept VLAN is chosen deterministically: prefer one that has a subnet
-- configured, then the lowest id (vlans has no created_at column). Every
-- reference to a duplicate is repointed to the keeper before deletion.
DO $$
DECLARE
  r RECORD;
  keeper_id uuid;
  dup_ids uuid[];
BEGIN
  FOR r IN SELECT vlan_tag FROM vlans GROUP BY vlan_tag HAVING COUNT(*) > 1 LOOP
    SELECT id INTO keeper_id FROM vlans WHERE vlan_tag = r.vlan_tag
      ORDER BY (subnet IS NULL OR subnet = ''), id ASC LIMIT 1;
    SELECT array_agg(id) INTO dup_ids FROM vlans WHERE vlan_tag = r.vlan_tag AND id <> keeper_id;

    UPDATE hosts SET vlan_id = keeper_id WHERE vlan_id = ANY(dup_ids);
    UPDATE host_interfaces SET vlan_id = keeper_id WHERE vlan_id = ANY(dup_ids);
    UPDATE policy_sets SET scope_vlan_id = keeper_id WHERE scope_vlan_id = ANY(dup_ids);
    UPDATE iot_assets SET vlan_id = keeper_id WHERE vlan_id = ANY(dup_ids);
    -- management VLAN setting stores the VLAN id as text
    UPDATE system_settings SET value = keeper_id::text
      WHERE key = 'management_vlan_id' AND value = ANY(SELECT unnest(dup_ids)::text);

    DELETE FROM vlans WHERE id = ANY(dup_ids);
  END LOOP;
END $$;

-- Add unique constraint (skip if already exists)
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'vlans_vlan_tag_unique') THEN
    ALTER TABLE vlans ADD CONSTRAINT vlans_vlan_tag_unique UNIQUE (vlan_tag);
  END IF;
END $$;
