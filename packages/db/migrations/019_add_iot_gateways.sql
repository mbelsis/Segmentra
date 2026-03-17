-- Link IoT assets to gateway hosts from the main inventory
-- Gateways are regular hosts tagged "iot-gateway" that protect IoT devices

CREATE TABLE IF NOT EXISTS iot_asset_gateways (
  asset_id uuid NOT NULL REFERENCES iot_assets(id) ON DELETE CASCADE,
  host_id uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  PRIMARY KEY (asset_id, host_id)
);

CREATE INDEX IF NOT EXISTS idx_iot_asset_gateways_host ON iot_asset_gateways(host_id);
CREATE INDEX IF NOT EXISTS idx_iot_asset_gateways_asset ON iot_asset_gateways(asset_id);
