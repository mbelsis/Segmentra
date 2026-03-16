-- Add visual topology views for drag-and-drop policy design

CREATE TABLE IF NOT EXISTS topology_views (
  id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  name text NOT NULL,
  description text,
  layout_data jsonb NOT NULL DEFAULT '{"nodes": [], "edges": []}',
  created_by uuid REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS topology_flows (
  id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  topology_view_id uuid NOT NULL REFERENCES topology_views(id) ON DELETE CASCADE,
  source_type text NOT NULL,
  source_value text NOT NULL,
  target_type text NOT NULL,
  target_value text NOT NULL,
  direction text NOT NULL DEFAULT 'BOTH',
  action text NOT NULL DEFAULT 'ALLOW',
  protocol text NOT NULL DEFAULT 'tcp',
  ports text,
  comment text,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_topology_flows_view_id ON topology_flows(topology_view_id);
