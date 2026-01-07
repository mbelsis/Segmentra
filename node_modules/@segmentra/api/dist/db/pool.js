import pg from 'pg';
import { env } from '../lib/env.js';
const { Pool } = pg;
export const pool = new Pool({
    connectionString: env.DATABASE_URL
});
