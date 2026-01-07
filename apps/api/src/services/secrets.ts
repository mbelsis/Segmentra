import { pool } from '../db/pool.js';
import { decryptBlob, encryptBlob } from './crypto.js';

export type SecretType = 'SSH_KEY' | 'LDAP_BIND' | 'TLS_CA_CERT';

export async function createSecret(params: {
  name: string;
  type: SecretType;
  plaintext: Buffer;
}): Promise<{ id: string }> {
  const encrypted = encryptBlob(params.plaintext);
  const { rows } = await pool.query(
    `INSERT INTO secret_store (name, type, encrypted_blob)
     VALUES ($1, $2, $3)
     RETURNING id`,
    [params.name, params.type, encrypted]
  );
  return { id: rows[0].id };
}

export async function readSecretPlaintext(secretId: string): Promise<Buffer> {
  const { rows } = await pool.query(
    `SELECT encrypted_blob FROM secret_store WHERE id=$1 AND is_active=true`,
    [secretId]
  );
  if (!rows[0]) throw new Error('secret_not_found');
  return decryptBlob(rows[0].encrypted_blob as Buffer);
}


