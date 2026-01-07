import crypto from 'node:crypto';
import { env } from '../lib/env.js';
function getKek() {
    if (env.SEGMENTRA_KEK_B64) {
        const buf = Buffer.from(env.SEGMENTRA_KEK_B64, 'base64');
        if (buf.length !== 32)
            throw new Error('SEGMENTRA_KEK_B64 must be 32 bytes (base64)');
        return buf;
    }
    // Dev fallback: derive from JWT secret (still deterministic, but not a real KEK)
    return crypto.createHash('sha256').update(env.JWT_SECRET, 'utf8').digest();
}
// Format: [1-byte version][12-byte iv][16-byte tag][ciphertext...]
const VERSION = 1;
export function encryptBlob(plaintext) {
    const iv = crypto.randomBytes(12);
    const key = getKek();
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([Buffer.from([VERSION]), iv, tag, ciphertext]);
}
export function decryptBlob(blob) {
    if (blob.length < 1 + 12 + 16)
        throw new Error('invalid blob');
    const version = blob.readUInt8(0);
    if (version !== VERSION)
        throw new Error('unsupported blob version');
    const iv = blob.subarray(1, 13);
    const tag = blob.subarray(13, 29);
    const ciphertext = blob.subarray(29);
    const key = getKek();
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}
