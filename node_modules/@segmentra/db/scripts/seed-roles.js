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

// Create default admin/admin user if it doesn't exist
const adminCheck = await client.query('SELECT id FROM users WHERE username=$1', ['admin']);
if (adminCheck.rows.length === 0) {
  const passwordHash = await bcrypt.hash('admin', 10);
  const adminRole = await client.query('SELECT id FROM roles WHERE name=$1', ['admin']);
  
  if (adminRole.rows.length > 0) {
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
    console.log('Created default admin user (username: admin, password: admin)');
  }
}

await client.end();



