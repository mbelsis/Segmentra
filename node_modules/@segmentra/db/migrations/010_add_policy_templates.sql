-- Add policy templates for reusable policy blueprints

CREATE TABLE IF NOT EXISTS policy_templates (
  id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  name text NOT NULL,
  description text,
  category text,
  target_tag_id uuid REFERENCES tags(id) ON DELETE SET NULL,
  auto_apply boolean NOT NULL DEFAULT false,
  interface_scope_type text NOT NULL DEFAULT 'INTERFACE_ROLE',
  interface_scope_roles text[],
  interface_scope_names text[],
  created_by uuid REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS policy_template_rules (
  id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  policy_template_id uuid NOT NULL REFERENCES policy_templates(id) ON DELETE CASCADE,
  order_index integer NOT NULL DEFAULT 0,
  direction text NOT NULL DEFAULT 'IN',
  action text NOT NULL DEFAULT 'ALLOW',
  protocol text NOT NULL DEFAULT 'tcp',
  ports text,
  source_type text NOT NULL DEFAULT 'CIDR',
  source_value text NOT NULL DEFAULT '0.0.0.0/0',
  log_mode text NOT NULL DEFAULT 'NONE',
  comment text,
  use_policy_interface_scope boolean NOT NULL DEFAULT true,
  interface_scope_type text,
  interface_scope_roles text[],
  interface_scope_names text[],
  created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE policy_sets ADD COLUMN IF NOT EXISTS source_template_id uuid REFERENCES policy_templates(id) ON DELETE SET NULL;
ALTER TABLE policy_versions ADD COLUMN IF NOT EXISTS source_template_id uuid REFERENCES policy_templates(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_policy_templates_target_tag_id ON policy_templates(target_tag_id);
CREATE INDEX IF NOT EXISTS idx_policy_templates_auto_apply ON policy_templates(auto_apply) WHERE auto_apply = true;
CREATE INDEX IF NOT EXISTS idx_policy_template_rules_template_id ON policy_template_rules(policy_template_id);
