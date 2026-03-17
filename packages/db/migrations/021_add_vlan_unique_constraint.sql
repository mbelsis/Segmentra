-- Prevent duplicate VLANs by adding unique constraint on vlan_tag

-- First deduplicate if any exist
DO $$
DECLARE
  r RECORD;
  keeper_id uuid;
BEGIN
  FOR r IN SELECT vlan_tag FROM vlans GROUP BY vlan_tag HAVING COUNT(*) > 1 LOOP
    SELECT id INTO keeper_id FROM vlans WHERE vlan_tag = r.vlan_tag ORDER BY id ASC LIMIT 1;
    UPDATE hosts SET vlan_id = keeper_id WHERE vlan_id IN (SELECT id FROM vlans WHERE vlan_tag = r.vlan_tag AND id != keeper_id);
    UPDATE iot_assets SET vlan_id = keeper_id WHERE vlan_id IN (SELECT id FROM vlans WHERE vlan_tag = r.vlan_tag AND id != keeper_id);
    DELETE FROM vlans WHERE vlan_tag = r.vlan_tag AND id != keeper_id;
  END LOOP;
END $$;

-- Add unique constraint (skip if already exists)
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'vlans_vlan_tag_unique') THEN
    ALTER TABLE vlans ADD CONSTRAINT vlans_vlan_tag_unique UNIQUE (vlan_tag);
  END IF;
END $$;
