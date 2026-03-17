import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export async function up(pgm) {
  const sql = fs.readFileSync(path.join(__dirname, '020_add_system_tags.sql'), 'utf8');
  pgm.sql(sql);
}

export async function down(pgm) {
  pgm.sql('-- down migration not implemented');
}
