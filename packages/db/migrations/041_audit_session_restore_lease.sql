-- Restore lease for firewall learning sessions (services/audit-scheduler.ts). A restore claims the session by setting
-- a fresh token and an expiry; it re-checks the token once it holds the host lock, so the scheduler does not restore the
-- same session twice while a run is waiting for the lock. Previously the claim pushed scheduled_restore_at out instead.
ALTER TABLE firewall_audit_sessions ADD COLUMN IF NOT EXISTS restore_lease_token text;
ALTER TABLE firewall_audit_sessions ADD COLUMN IF NOT EXISTS restore_lease_until timestamptz;
