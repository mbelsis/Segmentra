ALTER TABLE policy_rules
  ADD COLUMN IF NOT EXISTS direction text NOT NULL DEFAULT 'IN';


