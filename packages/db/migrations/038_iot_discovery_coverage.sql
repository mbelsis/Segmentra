-- Up Migration
-- IoT/OT: when an asset was assigned to a gateway (to tell "assigned but not deployed yet" from "protected"), and the
-- IEEE OUI vendor list used to name devices found on a gateway (imported by an admin; Segmentra ships no vendor data).
ALTER TABLE iot_asset_gateways ADD COLUMN IF NOT EXISTS assigned_at timestamptz;
UPDATE iot_asset_gateways g SET assigned_at = COALESCE((SELECT a.created_at FROM iot_assets a WHERE a.id = g.asset_id), now()) WHERE assigned_at IS NULL;
ALTER TABLE iot_asset_gateways ALTER COLUMN assigned_at SET DEFAULT now();
ALTER TABLE iot_asset_gateways ALTER COLUMN assigned_at SET NOT NULL;

CREATE TABLE IF NOT EXISTS oui_vendors (
  prefix text PRIMARY KEY CHECK (prefix ~ '^[0-9a-f]{6}$'),
  vendor text NOT NULL
);

-- Down Migration
DROP TABLE IF EXISTS oui_vendors;
ALTER TABLE iot_asset_gateways DROP COLUMN IF EXISTS assigned_at;
