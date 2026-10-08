-- Up Migration
-- Code review fixes. Every statement is idempotent so the file can be re-run safely.

-- 1. Live hash reported by the host after apply (drift detection vs. applied_hash).
ALTER TABLE deployment_hosts ADD COLUMN IF NOT EXISTS applied_live_hash text;

-- 2. Track who submitted a version (separation of duties: submitter/editors cannot approve).
ALTER TABLE policy_versions ADD COLUMN IF NOT EXISTS submitted_by uuid REFERENCES users(id) ON DELETE SET NULL;

-- 3. Everyone who edited a draft version.
CREATE TABLE IF NOT EXISTS policy_version_editors (
  policy_version_id uuid NOT NULL REFERENCES policy_versions(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (policy_version_id, user_id)
);

-- 4. Unique (policy_set_id, version_number).
-- Renumber existing duplicates first: within each duplicate group the earliest
-- version (created_at, then id) keeps its number; later ones get max+1, max+2, ...
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_class WHERE relkind = 'i' AND relname = 'uq_policy_versions_set_version'
  ) THEN
    WITH ranked AS (
      SELECT id, policy_set_id, version_number, created_at,
             ROW_NUMBER() OVER (PARTITION BY policy_set_id, version_number ORDER BY created_at, id) AS rn
      FROM policy_versions
    ),
    dups AS (
      SELECT id, policy_set_id,
             ROW_NUMBER() OVER (PARTITION BY policy_set_id ORDER BY version_number, created_at, id) AS n
      FROM ranked
      WHERE rn > 1
    ),
    mx AS (
      SELECT policy_set_id, MAX(version_number) AS m FROM policy_versions GROUP BY policy_set_id
    )
    UPDATE policy_versions pv
       SET version_number = mx.m + dups.n
      FROM dups JOIN mx USING (policy_set_id)
     WHERE pv.id = dups.id;

    CREATE UNIQUE INDEX uq_policy_versions_set_version ON policy_versions (policy_set_id, version_number);
  END IF;
END $$;

-- 5. Policy version status CHECK constraint (if one exists) must allow the full lifecycle.
-- Earlier migrations do not define one; this only repairs a restrictive constraint
-- that may have been added manually.
DO $$
DECLARE
  c RECORD;
BEGIN
  FOR c IN
    SELECT conname, pg_get_constraintdef(oid) AS def
    FROM pg_constraint
    WHERE conrelid = 'policy_versions'::regclass AND contype = 'c'
  LOOP
    IF c.def ILIKE '%status%' AND (c.def NOT LIKE '%DEPLOYED%' OR c.def NOT LIKE '%ARCHIVED%') THEN
      EXECUTE format('ALTER TABLE policy_versions DROP CONSTRAINT %I', c.conname);
      EXECUTE format(
        'ALTER TABLE policy_versions ADD CONSTRAINT %I CHECK (status IN '
        '(''DRAFT'', ''PENDING_APPROVAL'', ''APPROVED'', ''REJECTED'', ''DEPLOYED'', ''ARCHIVED''))',
        c.conname
      );
    END IF;
  END LOOP;
END $$;

-- 6. Foreign key ON DELETE behaviour. Constraint names are looked up from pg_constraint.
--    a) user references (created_by, approved_by, actor_user_id, ...) -> nullable + ON DELETE SET NULL
--       (user_roles and policy_version_editors are membership rows and keep CASCADE)
--    b) vlan references -> ON DELETE SET NULL
--    c) child-of-host attribute tables -> ON DELETE CASCADE,
--       except deployment_hosts.host_id which stays RESTRICT to preserve deployment history.
DO $$
DECLARE
  fk RECORD;
  target_action text;
BEGIN
  FOR fk IN
    SELECT con.conname,
           con.conrelid,
           con.conrelid::regclass AS tbl,
           con.confrelid::regclass AS ref_tbl,
           con.confdeltype,
           att.attname AS col,
           refatt.attname AS ref_col
    FROM pg_constraint con
    JOIN pg_attribute att ON att.attrelid = con.conrelid AND att.attnum = con.conkey[1]
    JOIN pg_attribute refatt ON refatt.attrelid = con.confrelid AND refatt.attnum = con.confkey[1]
    WHERE con.contype = 'f'
      AND array_length(con.conkey, 1) = 1
      AND con.confrelid IN ('users'::regclass, 'vlans'::regclass, 'hosts'::regclass)
  LOOP
    target_action := NULL;

    IF fk.ref_tbl = 'users'::regclass
       AND fk.tbl NOT IN ('user_roles'::regclass, 'policy_version_editors'::regclass) THEN
      IF fk.confdeltype <> 'n' THEN
        target_action := 'SET NULL';
      END IF;
    ELSIF fk.ref_tbl = 'vlans'::regclass THEN
      IF fk.confdeltype <> 'n' THEN
        target_action := 'SET NULL';
      END IF;
    ELSIF fk.ref_tbl = 'hosts'::regclass AND fk.tbl <> 'deployment_hosts'::regclass THEN
      IF fk.confdeltype <> 'c' THEN
        target_action := 'CASCADE';
      END IF;
    END IF;

    IF target_action IS NOT NULL THEN
      IF target_action = 'SET NULL' THEN
        EXECUTE format('ALTER TABLE %s ALTER COLUMN %I DROP NOT NULL', fk.tbl, fk.col);
      END IF;
      EXECUTE format('ALTER TABLE %s DROP CONSTRAINT %I', fk.tbl, fk.conname);
      EXECUTE format(
        'ALTER TABLE %s ADD CONSTRAINT %I FOREIGN KEY (%I) REFERENCES %s(%I) ON DELETE %s',
        fk.tbl, fk.conname, fk.col, fk.ref_tbl, fk.ref_col, target_action
      );
    END IF;
  END LOOP;
END $$;

-- Supporting index for the RESTRICT check / host deployment history lookups.
CREATE INDEX IF NOT EXISTS idx_deployment_hosts_host_id ON deployment_hosts (host_id);
