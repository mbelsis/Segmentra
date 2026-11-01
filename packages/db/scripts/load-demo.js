// Loads the demo dataset (packages/db/demo/demo-data.sql) into the database at DATABASE_URL.
//
//   npm run db:demo              load
//   npm run db:demo -- --remove  remove it again (packages/db/demo/demo-remove.sql)
//
// The dataset is idempotent (fixed ids, ON CONFLICT DO NOTHING) and only for evaluating the UI:
// it contains well-known demo user passwords. Loading therefore refuses (unless `--force`, or
// SEGMENTRA_DEMO_FORCE=1, is given) when
//   - NODE_ENV=production,
//   - DATABASE_URL points to anything but a local database (localhost / 127.0.0.1 / ::1 / socket),
//   - or the database already holds users or hosts that are not part of the demo dataset
//     (anything but the seeded "admin"), i.e. it looks like a real installation.
// Migrations and `npm run db:seed` must have run first (roles, admin user, system tags).
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import pg from 'pg';

// Outside production the local development database (start.sh / run.sh) is the default.
const DEV_DATABASE_URL = 'postgres://segmentra:segmentra@127.0.0.1:15432/segmentra';
let databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl) {
  if (process.env.NODE_ENV === 'production') {
    console.error('DATABASE_URL is required');
    process.exit(1);
  }
  databaseUrl = DEV_DATABASE_URL;
  console.log(`DATABASE_URL not set; using the local development database ${DEV_DATABASE_URL}`);
}

const remove = process.argv.includes('--remove');
const force = process.argv.includes('--force') || process.env.SEGMENTRA_DEMO_FORCE === '1';
const FORCE_HINT = 'Pass --force (npm run db:demo -- --force) if this really is a throw-away evaluation instance.';

if (!remove && !force && process.env.NODE_ENV === 'production') {
  console.error(
    'Refusing to load demo data with NODE_ENV=production: the dataset contains demo users with a well-known password.\n' +
      FORCE_HINT
  );
  process.exit(1);
}

/** True when the connection string targets a database on this machine. */
function isLocalDatabaseUrl(url) {
  let host;
  try {
    const u = new URL(url);
    host = decodeURIComponent(u.hostname || '');
    // postgres:///db?host=/var/run/postgresql (unix socket)
    if (!host) host = u.searchParams.get('host') || '';
  } catch {
    return false;
  }
  host = host.replace(/^\[|\]$/g, '').toLowerCase();
  if (!host || host.startsWith('/')) return true;
  return host === 'localhost' || host === '::1' || /^127\.\d+\.\d+\.\d+$/.test(host);
}

if (!remove && !force && !isLocalDatabaseUrl(databaseUrl)) {
  console.error(
    'Refusing to load demo data into a non-local database (DATABASE_URL host is not localhost / 127.0.0.1 / ::1): ' +
      'the dataset contains demo users with a well-known password.\n' + FORCE_HINT
  );
  process.exit(1);
}
const here = path.dirname(fileURLToPath(import.meta.url));
const sqlPath = path.resolve(here, '..', 'demo', remove ? 'demo-remove.sql' : 'demo-data.sql');
const sql = fs.readFileSync(sqlPath, 'utf8');

const client = new pg.Client({ connectionString: databaseUrl });
await client.connect();
try {
  const before = await counts(client);
  const seeded = await client.query(`SELECT 1 FROM roles WHERE name='admin'`);
  if (seeded.rowCount === 0) {
    console.error('Roles are missing: run "npm run db:migrate" and "npm run db:seed" before loading the demo data.');
    process.exit(1);
  }
  if (!remove && !force) {
    // Demo rows have fixed ids (users aaaaaaaa-0000-4000-8000-*, hosts 11111111-0000-4000-8000-*).
    const { rows } = await client.query(
      `SELECT
         (SELECT COUNT(*)::int FROM users
           WHERE username <> 'admin' AND id::text NOT LIKE 'aaaaaaaa-0000-4000-8000-%') AS users,
         (SELECT COUNT(*)::int FROM hosts WHERE id::text NOT LIKE '11111111-0000-4000-8000-%') AS hosts`
    );
    const foreign = rows[0];
    if (foreign.users > 0 || foreign.hosts > 0) {
      console.error(
        `Refusing to load demo data: the database already has ${foreign.users} user(s) and ${foreign.hosts} host(s) ` +
          'that are not part of the demo dataset, so it looks like a real installation.\n' + FORCE_HINT
      );
      await client.end();
      process.exit(1);
    }
  }
  // The file is a single transaction (BEGIN ... COMMIT); any failure rolls everything back.
  await client.query(sql);
  const after = await counts(client);
  const delta = Object.fromEntries(Object.keys(after).map((k) => [k, after[k] - before[k]]));
  const unchanged = Object.values(delta).every((n) => n === 0);
  if (remove) console.log(unchanged ? 'No demo data found; nothing changed.' : 'Demo data removed:');
  else console.log(unchanged ? 'Demo data was already present; nothing changed.' : 'Demo data loaded:');
  for (const [table, n] of Object.entries(after)) {
    const d = delta[table];
    console.log(`  ${table.padEnd(18)} ${String(n).padStart(4)} total${d ? `  (${d > 0 ? '+' : ''}${d})` : ''}`);
  }
  if (!remove) console.log('\nDemo users (password: SegmentraDemo2026!): maria.p (operator), nikos.k (approver), ana.v (viewer)');
} catch (error) {
  console.error(`${remove ? 'Removing' : 'Loading'} the demo data failed; the transaction was rolled back.`);
  console.error(error?.message ?? error);
  process.exitCode = 1;
} finally {
  await client.end();
}

async function counts(c) {
  const tables = ['users', 'vlans', 'tags', 'hosts', 'iot_assets', 'policy_sets', 'policy_versions', 'policy_rules', 'deployments', 'audit_events'];
  const out = {};
  for (const t of tables) {
    const { rows } = await c.query(`SELECT COUNT(*)::int AS n FROM ${t}`);
    out[t] = rows[0].n;
  }
  return out;
}
