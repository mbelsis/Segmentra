-- Add tag rules for automatic host tagging

CREATE TABLE IF NOT EXISTS tag_rules (
  id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  tag_id uuid NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
  name text NOT NULL,
  description text,
  enabled boolean NOT NULL DEFAULT true,
  priority integer NOT NULL DEFAULT 0,
  criteria jsonb NOT NULL DEFAULT '{"conditions": [], "logic": "AND"}',
  created_by uuid REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS tag_rule_results (
  tag_rule_id uuid NOT NULL REFERENCES tag_rules(id) ON DELETE CASCADE,
  host_id uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  matched boolean NOT NULL DEFAULT false,
  evaluated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tag_rule_id, host_id)
);

ALTER TABLE host_tags ADD COLUMN IF NOT EXISTS source text NOT NULL DEFAULT 'manual';
ALTER TABLE host_tags ADD COLUMN IF NOT EXISTS source_rule_id uuid REFERENCES tag_rules(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_tag_rules_tag_id ON tag_rules(tag_id);
CREATE INDEX IF NOT EXISTS idx_tag_rules_enabled ON tag_rules(enabled) WHERE enabled = true;
CREATE INDEX IF NOT EXISTS idx_tag_rule_results_host_id ON tag_rule_results(host_id);
CREATE INDEX IF NOT EXISTS idx_host_tags_source ON host_tags(source);
