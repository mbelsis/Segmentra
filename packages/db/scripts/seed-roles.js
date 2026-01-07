import pg from 'pg';

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

for (const r of roles) {
  await client.query(
    `INSERT INTO roles (name, description)
     VALUES ($1, $2)
     ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description`,
    [r.name, r.description]
  );
}

await client.end();


