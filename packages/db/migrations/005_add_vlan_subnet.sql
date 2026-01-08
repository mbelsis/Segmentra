-- Add subnet column to vlans table
ALTER TABLE vlans
ADD COLUMN IF NOT EXISTS subnet text;

