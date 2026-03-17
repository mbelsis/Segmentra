-- Add is_system flag to tags to protect built-in tags from deletion

ALTER TABLE tags ADD COLUMN IF NOT EXISTS is_system boolean NOT NULL DEFAULT false;

-- Mark system tags (create if not exists)
INSERT INTO tags (name, description, is_system) VALUES ('iot-gateway', 'IoT/OT gateway firewall hosts', true) ON CONFLICT (name) DO UPDATE SET is_system = true, description = EXCLUDED.description;
INSERT INTO tags (name, description, is_system) VALUES ('bastion', 'SSH jump hosts for secure access', true) ON CONFLICT (name) DO UPDATE SET is_system = true, description = EXCLUDED.description;
