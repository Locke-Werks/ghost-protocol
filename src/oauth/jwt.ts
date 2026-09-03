// Access tokens: signing, verifying, and the JWKS a client checks them against.
//
// Tokens are self-contained and short-lived because there is no revocation
// store. Longevity lives in the refresh token, which is a database row and can
// be killed; an access token is good until it expires and no sooner, which is
// why the default TTL is fifteen minutes rather than a day.

import { readFileSync } from 'node:fs';
import {
  SignJWT,
  createLocalJWKSet,
  exportJWK,
  generateKeyPair,
  importPKCS8,
  jwtVerify,
  calculateJwkThumbprint,
  type CryptoKey,
  type JWK,
  type JWTPayload,
} from 'jose';

export interface SigningKey {
  kid: string;
  alg: 'ES256' | 'RS256';
  privateKey: CryptoKey;
  publicJwk: JWK;
}

export interface AccessClaims extends JWTPayload {
  sub: string;
  client_id: string;
  scope?: string;
}

/**
 * Load a PEM private key and derive its key id from the public thumbprint.
 *
 * A thumbprint kid rather than a name means a rotated key gets a new id for
 * free, and a client that cached the old JWKS entry keeps matching the old
 * token to the old key instead of guessing.
 */
export async function loadSigningKey(path: string): Promise<SigningKey> {
  const pem = readFileSync(path, 'utf8');
  const alg: 'ES256' | 'RS256' = /BEGIN RSA|BEGIN PRIVATE KEY/.test(pem) && isRsa(pem) ? 'RS256' : 'ES256';
  const privateKey = await importPKCS8(pem, alg, { extractable: true });
  const jwk = await exportJWK(privateKey);
  const publicJwk = publicPart(jwk, alg);
  const kid = await calculateJwkThumbprint(publicJwk, 'sha256');
  publicJwk.kid = kid;
  return { kid, alg, privateKey, publicJwk };
}

// A PKCS#8 header does not name the algorithm in the label, so the DER OID is
// what distinguishes them. RSA keys are also simply much longer.
function isRsa(pem: string): boolean {
  const body = pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  const der = Buffer.from(body, 'base64');
  // 1.2.840.113549.1.1.1 rsaEncryption
  return der.includes(Buffer.from([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]));
}

function publicPart(jwk: JWK, alg: string): JWK {
  const out: JWK = { kty: jwk.kty, alg, use: 'sig' };
  if (jwk.kty === 'EC') {
    out.crv = jwk.crv;
    out.x = jwk.x;
    out.y = jwk.y;
  } else {
    out.n = jwk.n;
    out.e = jwk.e;
  }
  return out;
}

export async function generateSigningKeyPem(): Promise<string> {
  const { privateKey } = await generateKeyPair('ES256', { extractable: true });
  const { exportPKCS8 } = await import('jose');
  return await exportPKCS8(privateKey);
}

export class TokenMinter {
  constructor(
    private readonly keys: SigningKey[],
    private readonly issuer: string,
    private readonly resource: string,
  ) {
    if (keys.length === 0) throw new Error('no signing keys loaded');
  }

  private get active(): SigningKey {
    return this.keys[0]!;
  }

  /**
   * The JWKS document.
   *
   * Rotated-out keys stay listed until every token they signed has expired.
   * Removing one the moment it stops signing invalidates tokens that are still
   * inside their lifetime, which reads to a client as an outage.
   */
  jwks(): { keys: JWK[] } {
    return { keys: this.keys.map((k) => k.publicJwk) };
  }

  async sign(claims: {
    principal: string;
    clientId: string;
    scope: string;
    ttlSeconds: number;
    audience: string;
  }): Promise<{ token: string; expiresIn: number }> {
    const key = this.active;
    const now = Math.floor(Date.now() / 1000);
    const token = await new SignJWT({ client_id: claims.clientId, scope: claims.scope })
      .setProtectedHeader({ alg: key.alg, kid: key.kid, typ: 'at+jwt' })
      .setIssuer(this.issuer)
      .setSubject(claims.principal)
      // RFC 8707: the audience is the resource the token is good for. A token
      // minted for this server must not be replayable at another one that
      // happens to trust the same issuer.
      .setAudience(claims.audience || this.resource)
      .setIssuedAt(now)
      .setExpirationTime(now + claims.ttlSeconds)
      .setJti(cryptoRandomId())
      .sign(key.privateKey);
    return { token, expiresIn: claims.ttlSeconds };
  }

  async verify(token: string): Promise<AccessClaims> {
    const jwks = createLocalJWKSet(this.jwks());
    const { payload } = await jwtVerify(token, jwks, {
      issuer: this.issuer,
      audience: this.resource,
      algorithms: ['ES256', 'RS256'],
    });
    if (typeof payload.sub !== 'string' || payload.sub.length === 0) {
      throw new Error('token has no subject');
    }
    return payload as AccessClaims;
  }
}

function cryptoRandomId(): string {
  return Buffer.from(crypto.getRandomValues(new Uint8Array(12))).toString('base64url');
}
