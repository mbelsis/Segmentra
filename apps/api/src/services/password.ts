import bcrypt from 'bcrypt';
import { randomBytes } from 'node:crypto';

export const SALT_ROUNDS = 10;

export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, SALT_ROUNDS);
}

export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  return bcrypt.compare(password, hash);
}

// Hash of a random secret at the configured cost, computed once on first use. Comparing against it
// costs the same as checking a real password and can never succeed.
let dummyHash: Promise<string> | null = null;
function getDummyHash(): Promise<string> {
  dummyHash ??= bcrypt.hash(randomBytes(32).toString('hex'), SALT_ROUNDS).catch((e) => {
    dummyHash = null;
    throw e;
  });
  return dummyHash;
}

/**
 * Spend one bcrypt comparison without a real hash (unknown user, or a user without a local password), so
 * that login response times do not reveal which usernames exist. Always resolves to false.
 */
export async function burnPasswordCheck(password: string): Promise<false> {
  try {
    await bcrypt.compare(password, await getDummyHash());
  } catch {
    // timing equalisation only; never fail the request because of it
  }
  return false;
}
