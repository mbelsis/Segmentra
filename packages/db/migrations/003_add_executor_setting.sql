-- Add system settings table for executor preference
CREATE TABLE IF NOT EXISTS system_settings (
  key text PRIMARY KEY,
  value text NOT NULL,
  description text,
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- Set default executor to ansible
INSERT INTO system_settings (key, value, description)
VALUES ('deployment_executor', 'ansible', 'Deployment executor type: ansible or ssh')
ON CONFLICT (key) DO NOTHING;


