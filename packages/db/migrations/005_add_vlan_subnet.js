import fs from 'node:fs';
import path from 'path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export async function up(pgm) {
  const sql = fs.readFileSync(path.join(__dirname, '005_add_vlan_subnet.sql'), 'utf8');
  pgm.sql(sql);
}

export async function down(pgm) {
  pgm.sql('ALTER TABLE vlans DROP COLUMN IF EXISTS subnet;');
}

