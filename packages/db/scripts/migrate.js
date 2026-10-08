// Runs node-pg-migrate against ./migrations (plain .sql files only).
//
// Before running, removes duplicate rows from the "pgmigrations" table. Older
// releases shipped both NNN_x.js and NNN_x.sql for the same migration, so
// node-pg-migrate recorded (and ran) those migrations twice. With only the
// .sql files left, the duplicated history rows would trip node-pg-migrate's
// order check ("Not run migration X is preceding already run migration Y").
// Keeping the first row of each name makes the history match the files again.
import { spawn } from 'node:child_process';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';

const require = createRequire(import.meta.url);
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const migrationsDir = path.resolve(__dirname, '..', 'migrations');

async function dedupeMigrationHistory() {
  const client = new pg.Client({ connectionString: process.env.DATABASE_URL || undefined });
  try {
    await client.connect();
  } catch (err) {
    // Let node-pg-migrate report connection problems with its own messages.
    console.warn(`[migrate] Could not connect to clean migration history: ${err.message}`);
    return;
  }
  try {
    const exists = await client.query(`SELECT to_regclass('public.pgmigrations') AS t`);
    if (!exists.rows[0]?.t) return;
    const res = await client.query(
      `DELETE FROM public.pgmigrations a
        USING public.pgmigrations b
        WHERE a.name = b.name AND a.id > b.id`
    );
    if (res.rowCount > 0) {
      console.log(`[migrate] Removed ${res.rowCount} duplicate pgmigrations row(s) left by the old .js wrappers.`);
    }
  } finally {
    await client.end();
  }
}

await dedupeMigrationHistory();

const direction = process.argv[2] === 'down' ? 'down' : 'up';
const extraArgs = process.argv.slice(direction === process.argv[2] ? 3 : 2);
const bin = require.resolve('node-pg-migrate/bin/node-pg-migrate');
const child = spawn(process.execPath, [bin, direction, '-m', migrationsDir, ...extraArgs], {
  stdio: 'inherit',
  env: process.env
});
child.on('exit', (code, signal) => {
  if (signal) process.kill(process.pid, signal);
  process.exit(code ?? 1);
});
