import crypto from 'node:crypto';

import { env } from '../lib/env.js';

let warnedAboutDerivedKek = false;

/**
 * Emit a loud warning when secrets are protected by a key derived from JWT_SECRET.
 * Called once at startup (and lazily on first use as a fallback).
 */
export function warnIfKekDerivedFromJwtSecret(): void {
  if (env.SEGMENTRA_KEK_B64 || warnedAboutDerivedKek) return;
  warnedAboutDerivedKek = true;
  // eslint-disable-next-line no-console
  console.warn(
    '[SECURITY WARNING] SEGMENTRA_KEK_B64 is not set. Stored secrets (SSH keys/passwords, LDAP bind passwords) ' +
      'are encrypted with a key derived from JWT_SECRET. Rotating JWT_SECRET will make them undecryptable. ' +
      'Set SEGMENTRA_KEK_B64 (32 random bytes, base64) for production deployments; note that changing it later ' +
      'also requires re-entering existing secrets.'
  );
}

function getKek(): Buffer {
  if (env.SEGMENTRA_KEK_B64) {
    const buf = Buffer.from(env.SEGMENTRA_KEK_B64, 'base64');
    if (buf.length !== 32) throw new Error('SEGMENTRA_KEK_B64 must be 32 bytes (base64)');
    return buf;
  }

  // Dev fallback: derive from JWT secret (still deterministic, but not a real KEK).
  // Do NOT change this derivation: existing encrypted data depends on it.
  warnIfKekDerivedFromJwtSecret();
  return crypto.createHash('sha256').update(env.JWT_SECRET, 'utf8').digest();
}

// Format: [1-byte version][12-byte iv][16-byte tag][ciphertext...]
const VERSION = 1;

export function encryptBlob(plaintext: Buffer): Buffer {
  const iv = crypto.randomBytes(12);
  const key = getKek();
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([Buffer.from([VERSION]), iv, tag, ciphertext]);
}

export function decryptBlob(blob: Buffer): Buffer {
  if (blob.length < 1 + 12 + 16) throw new Error('invalid blob');
  const version = blob.readUInt8(0);
  if (version !== VERSION) throw new Error('unsupported blob version');
  const iv = blob.subarray(1, 13);
  const tag = blob.subarray(13, 29);
  const ciphertext = blob.subarray(29);
  const key = getKek();
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}



