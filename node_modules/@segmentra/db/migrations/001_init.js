/* eslint-disable */
// node-pg-migrate wrapper to apply 001_init.sql

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export async function up(pgm) {
  const sql = fs.readFileSync(path.join(__dirname, '001_init.sql'), 'utf8');
  pgm.sql(sql);
}

export async function down(pgm) {
  // destructive down omitted for safety
  pgm.sql('-- down migration not implemented');
}



