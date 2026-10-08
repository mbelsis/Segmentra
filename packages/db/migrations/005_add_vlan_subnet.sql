-- Up Migration
-- Add subnet column to vlans table
ALTER TABLE vlans
ADD COLUMN IF NOT EXISTS subnet text;

-- Down Migration
ALTER TABLE vlans DROP COLUMN IF EXISTS subnet;
