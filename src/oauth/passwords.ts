// Password hashing for the built-in login page.
//
// scrypt in PHC string format, so the parameters travel with the hash and can
// be raised later without invalidating what is already stored.
//
// The optional pepper is an HMAC applied before the KDF, keyed by an
// environment variable rather than anything in the database. It means a stolen
// credentials table on its own is not crackable: the attacker needs the service
// environment too, which lives on a different part of the box.

import { createHmac, randomBytes, scrypt, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';

const scryptAsync = promisify(scrypt) as (
  password: Buffer | string,
  salt: Buffer,
  keylen: number,
  options: { N: number; r: number; p: number; maxmem: number },
) => Promise<Buffer>;

const LOG_N = 15; // N = 32768
const R = 8;
const P = 1;
const KEYLEN = 32;
// Node's default maxmem (32 MiB) is below what N=2^15, r=8 needs.
const MAXMEM = 256 * 1024 * 1024;

function pepper(password: string, secret: string | null): Buffer {
  if (!secret) return Buffer.from(password, 'utf8');
  return createHmac('sha256', secret).update(password, 'utf8').digest();
}

export async function hashPassword(password: string, secret: string | null): Promise<string> {
  const salt = randomBytes(16);
  const key = await scryptAsync(pepper(password, secret), salt, KEYLEN, {
    N: 1 << LOG_N,
    r: R,
    p: P,
    maxmem: MAXMEM,
  });
  return `$scrypt$ln=${LOG_N},r=${R},p=${P}$${salt.toString('base64url')}$${key.toString('base64url')}`;
}

export async function verifyPassword(
  password: string,
  phc: string,
  secret: string | null,
): Promise<boolean> {
  const m = /^\$scrypt\$ln=(\d+),r=(\d+),p=(\d+)\$([A-Za-z0-9_-]+)\$([A-Za-z0-9_-]+)$/.exec(phc);
  if (!m) return false;
  const logN = Number(m[1]);
  const r = Number(m[2]);
  const p = Number(m[3]);
  // A stored hash claiming absurd parameters would be a memory-exhaustion
  // request dressed up as a login.
  if (logN < 10 || logN > 20 || r < 1 || r > 32 || p < 1 || p > 16) return false;

  const salt = Buffer.from(m[4]!, 'base64url');
  const expected = Buffer.from(m[5]!, 'base64url');
  let actual: Buffer;
  try {
    actual = await scryptAsync(pepper(password, secret), salt, expected.length, {
      N: 1 << logN,
      r,
      p,
      maxmem: MAXMEM,
    });
  } catch {
    return false;
  }
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}
