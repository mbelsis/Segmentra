-- Up Migration
-- 1) Forward EVERY audit event to SIEM, however it was inserted.
-- 2) Encrypt integration / notification channel config (API keys, webhook URLs and tokens,
--    auth headers) in secret_store. Every statement is idempotent.

-- 1) SIEM forwarding ---------------------------------------------------------------------
-- An AFTER INSERT trigger on audit_events sends pg_notify('segmentra_audit', <id>). Each API
-- process LISTENs on one dedicated connection (apps/api/src/services/siem-audit-listener.ts),
-- claims the row with
--   UPDATE audit_events SET siem_forwarded_at = now() WHERE id = $1 AND siem_forwarded_at IS NULL
-- and only the replica whose UPDATE returned the row sends it, so several API replicas never
-- forward the same event twice. NOTIFY is delivered on commit, so rolled-back inserts are never
-- forwarded.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
     WHERE table_schema = current_schema() AND table_name = 'audit_events' AND column_name = 'siem_forwarded_at'
  ) THEN
    ALTER TABLE audit_events ADD COLUMN siem_forwarded_at timestamptz;
    -- Rows that existed before this migration are treated as already handled (events written
    -- through the audit service were forwarded directly by the old code). Runs only when the
    -- column is created, so re-running this file never marks new events.
    UPDATE audit_events SET siem_forwarded_at = now();
  END IF;
END $$;

-- Used by the bounded catch-up sweep (events not yet forwarded in the last N minutes).
CREATE INDEX IF NOT EXISTS idx_audit_events_siem_pending
  ON audit_events (timestamp) WHERE siem_forwarded_at IS NULL;

CREATE OR REPLACE FUNCTION segmentra_audit_notify() RETURNS trigger AS $$
BEGIN
  PERFORM pg_notify('segmentra_audit', NEW.id::text);
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_events_siem_notify ON audit_events;
CREATE TRIGGER audit_events_siem_notify
  AFTER INSERT ON audit_events
  FOR EACH ROW EXECUTE FUNCTION segmentra_audit_notify();

-- 2) Encrypted integration / notification config ----------------------------------------
-- The full config object is stored encrypted (AES-256-GCM, app key) in secret_store with type
-- 'INTEGRATION_CONFIG' / 'NOTIFICATION_CONFIG'. The plain `config` column keeps only a masked
-- copy for display. SQL cannot encrypt with the application key, so existing plaintext rows are
-- encrypted by the API at startup (apps/api/src/services/config-secrets.ts,
-- migratePlaintextConfigs): rows with config_secret_id IS NULL and a non-empty config.
ALTER TABLE integrations
  ADD COLUMN IF NOT EXISTS config_secret_id uuid REFERENCES secret_store(id) ON DELETE SET NULL;
ALTER TABLE notification_channels
  ADD COLUMN IF NOT EXISTS config_secret_id uuid REFERENCES secret_store(id) ON DELETE SET NULL;

-- Down Migration
DROP TRIGGER IF EXISTS audit_events_siem_notify ON audit_events;
DROP FUNCTION IF EXISTS segmentra_audit_notify();
DROP INDEX IF EXISTS idx_audit_events_siem_pending;
ALTER TABLE audit_events DROP COLUMN IF EXISTS siem_forwarded_at;
-- Note: dropping config_secret_id loses the only full copy of encrypted configs; re-enter
-- secrets after a down migration.
ALTER TABLE notification_channels DROP COLUMN IF EXISTS config_secret_id;
ALTER TABLE integrations DROP COLUMN IF EXISTS config_secret_id;
