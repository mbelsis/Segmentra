// Development-mode settings for the install/run/start scripts, in one place so the shell,
// PowerShell and batch scripts agree. The database container takes its password from .env
// (docker-compose.yml), so a hard-coded URL breaks as soon as a production install has
// written one. Values resolve in the same order as docker compose: environment, then .env.
//
//   node packages/db/scripts/dev-env.js database-url   print the URL of the local database
//   node packages/db/scripts/dev-env.js get KEY        print a value (empty when unset)
//   node packages/db/scripts/dev-env.js check-db       exit 1 with an explanation if the
//                                                      database rejects that password
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const ROOT = path.resolve(path.dirname(__filename), '..', '..', '..');

export function parseDotEnv(text) {
  const values = {};
  for (const raw of text.replace(/^﻿/, '').split(/\r?\n/)) {
    const m = raw.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)=(.*)$/);
    if (!m) continue;
    let value = m[2].trim();
    if (value.length >= 2 && /^(["']).*\1$/.test(value)) value = value.slice(1, -1);
    values[m[1]] = value;
  }
  return values;
}

// encodeURIComponent leaves !'()* alone; "!" would also be eaten by start.bat's delayed expansion.
const encode = (s) => encodeURIComponent(s).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);

export function devDatabaseUrl(env, dotenv) {
  if (env.SEGMENTRA_DATABASE_URL) return env.SEGMENTRA_DATABASE_URL;
  const get = (key) => env[key] || dotenv[key] || '';
  const user = get('DB_USER') || 'segmentra';
  const password = get('POSTGRES_PASSWORD') || get('DB_PASSWORD') || 'segmentra';
  const port = get('DB_PORT') || '15432';
  const name = get('DB_NAME') || 'segmentra';
  return `postgres://${encode(user)}:${encode(password)}@127.0.0.1:${port}/${encode(name)}`;
}

export function loadDotEnv() {
  try {
    return parseDotEnv(fs.readFileSync(path.join(ROOT, '.env'), 'utf8'));
  } catch {
    return {};
  }
}

async function checkDb() {
  const { default: pg } = await import('pg');
  const client = new pg.Client({ connectionString: devDatabaseUrl(process.env, loadDotEnv()) });
  try {
    await client.connect();
    await client.end();
  } catch (err) {
    if (err.code === '28P01' || err.code === '28000') {
      console.error(`ERROR: PostgreSQL rejected the password: ${err.message}`);
      console.error('  This database volume was created with a different password, probably by an earlier install.');
      console.error('  Keep the data: copy the .env from that install into this folder, then run this again.');
      console.error('  Start over (DELETES all Segmentra data in it): docker compose down -v');
    } else {
      console.error(`ERROR: could not connect to PostgreSQL: ${err.message}`);
    }
    process.exit(1);
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === __filename) {
  const [command, key] = process.argv.slice(2);
  if (command === 'database-url') {
    process.stdout.write(devDatabaseUrl(process.env, loadDotEnv()));
  } else if (command === 'get' && key) {
    process.stdout.write(process.env[key] || loadDotEnv()[key] || '');
  } else if (command === 'check-db') {
    await checkDb();
  } else {
    console.error('Usage: dev-env.js database-url | get KEY | check-db');
    process.exit(2);
  }
}
