-- Up Migration
-- Automated inventory discovery: profiles (what to scan, when, which tag to apply),
-- target sets (SSH credential + networks + port) and run history. Every statement is idempotent.

CREATE TABLE IF NOT EXISTS discovery_profiles (
  id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  name text NOT NULL UNIQUE,
  enabled boolean NOT NULL DEFAULT true,
  -- NULL = manual runs only; otherwise run every N minutes.
  schedule_interval_minutes integer CHECK (schedule_interval_minutes IS NULL OR schedule_interval_minutes BETWEEN 1 AND 525600),
  default_tag_name text NOT NULL DEFAULT 'new-server',
  next_run_at timestamptz,
  last_run_at timestamptz,
  created_by uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_discovery_profiles_due
  ON discovery_profiles(next_run_at)
  WHERE enabled AND schedule_interval_minutes IS NOT NULL;

-- A target set: one credential + one or more networks (CIDRs and/or VLAN subnets) + SSH port.
-- ssh_credential_id is ON DELETE RESTRICT: a credential still used by discovery cannot be
-- removed silently (the profile would otherwise lose a target set without anyone noticing).
-- vlan_ids is a plain uuid[] (no FK); VLANs that were deleted or have no subnet are skipped at run time.
CREATE TABLE IF NOT EXISTS discovery_targets (
  id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  profile_id uuid NOT NULL REFERENCES discovery_profiles(id) ON DELETE CASCADE,
  position integer NOT NULL DEFAULT 0,
  ssh_credential_id uuid NOT NULL REFERENCES ssh_credentials(id) ON DELETE RESTRICT,
  ssh_port integer NOT NULL DEFAULT 22 CHECK (ssh_port BETWEEN 1 AND 65535),
  cidrs text[] NOT NULL DEFAULT '{}',
  vlan_ids uuid[] NOT NULL DEFAULT '{}',
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_discovery_targets_profile ON discovery_targets(profile_id);

CREATE TABLE IF NOT EXISTS discovery_runs (
  id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  profile_id uuid NOT NULL REFERENCES discovery_profiles(id) ON DELETE CASCADE,
  trigger text NOT NULL CHECK (trigger IN ('manual', 'scheduled')),
  status text NOT NULL DEFAULT 'RUNNING' CHECK (status IN ('RUNNING', 'SUCCEEDED', 'FAILED')),
  started_at timestamptz NOT NULL DEFAULT now(),
  finished_at timestamptz,
  addresses_scanned integer NOT NULL DEFAULT 0,
  ssh_open integer NOT NULL DEFAULT 0,
  login_ok integer NOT NULL DEFAULT 0,
  imported integer NOT NULL DEFAULT 0,
  already_present integer NOT NULL DEFAULT 0,
  login_failed integer NOT NULL DEFAULT 0,
  -- Per-address results (only addresses with an open SSH port; capped by the API).
  results jsonb NOT NULL DEFAULT '[]'::jsonb,
  error text,
  created_by uuid REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_discovery_runs_profile_started ON discovery_runs(profile_id, started_at DESC);

-- At most one RUNNING run per profile: starting a second one fails atomically with a unique violation.
CREATE UNIQUE INDEX IF NOT EXISTS uq_discovery_runs_one_running
  ON discovery_runs(profile_id) WHERE status = 'RUNNING';
