/**
 * Password Hashing & Verification Service
 * Uses bcrypt with standard salt rounds for zero-plain-text storage.
 */

import bcrypt from 'bcryptjs';

const SALT_ROUNDS = 10;

export async function hashPassword(plaintext: string): Promise<string> {
  if (!plaintext || typeof plaintext !== 'string') {
    throw new Error('Password must be a non-empty string');
  }
  return bcrypt.hash(plaintext, SALT_ROUNDS);
}

export function hashPasswordSync(plaintext: string): string {
  if (!plaintext || typeof plaintext !== 'string') {
    throw new Error('Password must be a non-empty string');
  }
  return bcrypt.hashSync(plaintext, SALT_ROUNDS);
}

export async function verifyPassword(plaintext: string, hash: string): Promise<boolean> {
  if (!plaintext || !hash) {
    return false;
  }
  try {
    return await bcrypt.compare(plaintext, hash);
  } catch {
    return false;
  }
}

export function verifyPasswordSync(plaintext: string, hash: string): boolean {
  if (!plaintext || !hash) {
    return false;
  }
  try {
    return bcrypt.compareSync(plaintext, hash);
  } catch {
    return false;
  }
}
