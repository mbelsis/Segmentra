import pg from 'pg';
import bcrypt from 'bcrypt';

const { Client } = pg;

const databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl) {
  // eslint-disable-next-line no-console
  console.error('DATABASE_URL is required');
  process.exit(1);
}

const roles = [
  { name: 'viewer', description: 'read-only' },
  { name: 'operator', description: 'manage inventory, drafts, simulations, deployments' },
  { name: 'approver', description: 'approve/reject policy versions and risky deployments' },
  { name: 'admin', description: 'system settings, ldap mappings, secrets' }
];

const client = new Client({ connectionString: databaseUrl });
await client.connect();

// Seed roles
for (const r of roles) {
  await client.query(
    `INSERT INTO roles (name, description)
     VALUES ($1, $2)
     ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description`,
    [r.name, r.description]
  );
}

// Initial "admin" user: a true first-run bootstrap only.
// This script runs on EVERY API container start (docker-entrypoint.sh), so it must never
// re-create "admin" after an operator deleted or renamed it (hardening): the admin is only
// created while the users table is completely empty. On any later run it is skipped, even if
// no user called "admin" exists any more; recover a lost admin with SEGMENTRA_BOOTSTRAP_TOKEN
// (POST /api/admin/bootstrap) instead.
// The password comes from SEGMENTRA_ADMIN_PASSWORD. Without it, development
// falls back to the well-known default "admin123" (with a loud warning), while
// production (NODE_ENV=production) refuses to create a user with a default password.
const DEFAULT_ADMIN_PASSWORD = 'admin123';
const isProduction = process.env.NODE_ENV === 'production';
const providedPassword = process.env.SEGMENTRA_ADMIN_PASSWORD || '';

function banner(lines) {
  const bar = '='.repeat(72);
  // eslint-disable-next-line no-console
  console.warn(['', bar, ...lines.map((l) => `  ${l}`), bar, ''].join('\n'));
}

// Serialize concurrent seeds (several API replicas starting at once) so only one of them
// can see the empty users table and create the admin.
await client.query('BEGIN');
try {
  await client.query(`SELECT pg_advisory_xact_lock(hashtext('segmentra:seed-initial-admin'))`);
  const userCount = await client.query('SELECT COUNT(*)::int AS n FROM users');
  const existingUsers = userCount.rows[0].n;

  if (existingUsers > 0) {
    // eslint-disable-next-line no-console
    console.log(
      `Initial admin bootstrap skipped: the users table already has ${existingUsers} user(s). ` +
        'The seed creates "admin" only on a fresh database (it is never re-created after it was ' +
        'deleted or renamed); SEGMENTRA_ADMIN_PASSWORD is ignored.'
    );
  } else {
    let adminPassword = providedPassword;

    if (adminPassword && isProduction && adminPassword.length < 12) {
      banner([
        'ERROR: SEGMENTRA_ADMIN_PASSWORD must be at least 12 characters in production.',
        'The default admin user was NOT created.'
      ]);
      adminPassword = '';
    } else if (!adminPassword && isProduction) {
      banner([
        'NOTICE: NODE_ENV=production and SEGMENTRA_ADMIN_PASSWORD is not set.',
        'Refusing to create the default admin user with the well-known password.',
        'Set SEGMENTRA_ADMIN_PASSWORD and re-run "npm run db:seed" (or restart the',
        'container), or use SEGMENTRA_BOOTSTRAP_TOKEN with POST /api/admin/bootstrap.'
      ]);
    } else if (!adminPassword) {
      adminPassword = DEFAULT_ADMIN_PASSWORD;
      banner([
        'WARNING: creating default admin user with the well-known password "admin123".',
        'This is acceptable for local development ONLY. Change it after first login,',
        'or set SEGMENTRA_ADMIN_PASSWORD before seeding.'
      ]);
    }

    const adminRole = await client.query('SELECT id FROM roles WHERE name=$1', ['admin']);

    if (adminPassword && adminRole.rows.length > 0) {
      const passwordHash = await bcrypt.hash(adminPassword, 12);
      const userRes = await client.query(
        `INSERT INTO users (username, display_name, password_hash, is_active)
         VALUES ($1, $2, $3, true)
         RETURNING id`,
        ['admin', 'Default Admin', passwordHash]
      );

      await client.query(
        `INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)
         ON CONFLICT DO NOTHING`,
        [userRes.rows[0].id, adminRole.rows[0].id]
      );

      // eslint-disable-next-line no-console
      console.log(
        adminPassword === DEFAULT_ADMIN_PASSWORD
          ? 'Created default admin user (username: admin, password: admin123)'
          : 'Created admin user (username: admin, password from SEGMENTRA_ADMIN_PASSWORD)'
      );
    }
  }
  await client.query('COMMIT');
} catch (err) {
  await client.query('ROLLBACK').catch(() => {});
  throw err;
}

// Seed system tags (protected from deletion)
const systemTags = [
  { name: 'iot-gateway', description: 'IoT/OT gateway firewall hosts' },
  { name: 'bastion', description: 'SSH jump hosts for secure access' },
];

for (const t of systemTags) {
  await client.query(
    `INSERT INTO tags (name, description, is_system)
     VALUES ($1, $2, true)
     ON CONFLICT (name) DO UPDATE SET is_system = true, description = EXCLUDED.description`,
    [t.name, t.description]
  );
}
// eslint-disable-next-line no-console
console.log('Seeded system tags: ' + systemTags.map(t => t.name).join(', '));

await client.end();



