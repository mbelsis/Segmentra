-- Up Migration
-- FORWARD rules (traffic routed THROUGH a host, e.g. an IoT/OT gateway) with an explicit
-- destination. Every statement is idempotent.
--
-- direction: 'IN' | 'OUT' | 'BOTH' | 'FORWARD' (no CHECK constraint existed on direction;
--            one is added here so invalid values never reach the compiler).
-- destination_type / destination_value: required for FORWARD rules, NULL otherwise.
--   destination_type: 'CIDR' | 'TAG' | 'VLAN' | 'HOST' | 'IOT_ASSET'
--   destination_value: CIDR string, or the id (uuid) of the tag / vlan / host / iot asset.

ALTER TABLE policy_rules ADD COLUMN IF NOT EXISTS destination_type text;
ALTER TABLE policy_rules ADD COLUMN IF NOT EXISTS destination_value text;

ALTER TABLE policy_template_rules ADD COLUMN IF NOT EXISTS destination_type text;
ALTER TABLE policy_template_rules ADD COLUMN IF NOT EXISTS destination_value text;

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['policy_rules', 'policy_template_rules'] LOOP
    IF NOT EXISTS (
      SELECT 1 FROM pg_constraint WHERE conrelid = t::regclass AND conname = t || '_direction_check'
    ) THEN
      -- Normalize anything unexpected before the constraint is added (never expected to match).
      EXECUTE format(
        'UPDATE %I SET direction = ''IN'' WHERE direction IS NULL OR direction NOT IN (''IN'', ''OUT'', ''BOTH'', ''FORWARD'')', t
      );
      EXECUTE format(
        'ALTER TABLE %I ADD CONSTRAINT %I CHECK (direction IN (''IN'', ''OUT'', ''BOTH'', ''FORWARD''))',
        t, t || '_direction_check'
      );
    END IF;

    IF NOT EXISTS (
      SELECT 1 FROM pg_constraint WHERE conrelid = t::regclass AND conname = t || '_destination_check'
    ) THEN
      EXECUTE format(
        'ALTER TABLE %I ADD CONSTRAINT %I CHECK ('
        '(direction = ''FORWARD'' AND destination_type IN (''CIDR'', ''TAG'', ''VLAN'', ''HOST'', ''IOT_ASSET'') AND destination_value IS NOT NULL AND destination_value <> '''')'
        ' OR (direction <> ''FORWARD'' AND destination_type IS NULL AND destination_value IS NULL))',
        t, t || '_destination_check'
      );
    END IF;
  END LOOP;
END $$;
