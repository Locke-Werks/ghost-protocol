// The embedded OAuth 2.1 authorization server.
//
// This is what lets claude.ai and ChatGPT add Ghost Protocol as a remote
// connector without anyone hand-registering anything: RFC 8414 and 9728
// discovery, RFC 7591 dynamic client registration, a PKCE authorization-code
// flow with a login page, and rotating refresh tokens with reuse detection.
//
// One status rule runs through all of it, and it is not cosmetic. Bad login
// credentials answer 401, because the fail2ban jail counts those lines. Grant
// failures at the token endpoint — an expired code, a stale refresh token —
// answer 400 and never 401, because a connector backend retrying a dead token
// would otherwise accumulate toward an IP ban and lock out the legitimate user.

import { createHash, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import type { Db } from '../db.js';
import type { OAuthConfig } from '../config.js';
import { TokenMinter } from './jwt.js';
import { SlidingWindow } from './ratelimit.js';
import { verifyPassword } from './passwords.js';
import { log, errFields } from '../util/log.js';

export interface OAuthError {
  httpStatus: number;
  error: string;
  description: string;
}

export interface AuthorizeRequest {
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  state: string;
  resource: string;
  scope: string;
}

export interface AuthorizeValidation {
  ok: boolean;
  req: AuthorizeRequest;
  error?: OAuthError;
  /** True when the client was verified, so the error may ride a redirect. */
  redirectError?: boolean;
}

interface ClientRow {
  client_id: string;
  client_secret_hash: string | null;
  token_endpoint_auth: string;
  redirect_uris: string[];
}

const SCOPES = ['relay:read'];

function sha256Hex(s: string): string {
  return createHash('sha256').update(s).digest('hex');
}

/** RFC 7636 §4.1: 43 to 128 characters of the unreserved set. */
export function validPkceString(s: string): boolean {
  return /^[A-Za-z0-9\-._~]{43,128}$/.test(s);
}

export function s256Challenge(verifier: string): string {
  return createHash('sha256').update(verifier).digest('base64url');
}

/** Host of an https URI, lowercased, port and userinfo rejected. */
export function httpsHostOf(uri: string): string {
  try {
    const u = new URL(uri);
    if (u.protocol !== 'https:') return '';
    if (u.username || u.password) return '';
    return u.hostname.toLowerCase();
  } catch {
    return '';
  }
}

export function hostAllowed(host: string, allow: string[]): boolean {
  if (allow.length === 0) return true;
  return allow.some((a) => host === a || host.endsWith('.' + a));
}

const LOOPBACK_HOSTS = new Set(['127.0.0.1', '[::1]', 'localhost']);

/**
 * Split an RFC 8252 loopback redirect into host and path-plus-query, or null.
 *
 * Parsed by hand rather than with URL, because URL normalises: it turns
 * `127.1` and `0x7f.1` into `127.0.0.1` and drops a default port, and the rule
 * here is about the string the client registered, not what it resolves to.
 */
function parseLoopback(uri: string): { host: string; rest: string } | null {
  const scheme = 'http://';
  if (!uri.startsWith(scheme) || uri.includes('#')) return null;
  const tail = uri.slice(scheme.length);
  const cut = tail.search(/[/?]/);
  const authority = cut === -1 ? tail : tail.slice(0, cut);
  const m = /^(\[[^\]]*\]|[^:@[\]]*)(?::(\d{1,5}))?$/.exec(authority);
  if (!m) return null;
  if (m[2] !== undefined && Number(m[2]) > 65535) return null;
  const host = (m[1] ?? '').toLowerCase();
  if (!LOOPBACK_HOSTS.has(host)) return null;
  return { host, rest: cut === -1 ? '' : tail.slice(cut) };
}

/**
 * http to 127.0.0.1, [::1] or localhost, any port, no credentials or fragment.
 * Accepted at registration regardless of the redirect-host allowlist.
 */
export function isLoopbackRedirect(uri: string): boolean {
  return parseLoopback(uri) !== null;
}

/**
 * Whether a redirect_uri presented at authorize matches a registered one.
 * Exact, except that two loopback URIs match when host, path and query agree
 * and only the port differs: RFC 8252 §7.3 has the native app bind whatever
 * port is free at sign-in time.
 */
export function redirectMatches(registered: string, presented: string): boolean {
  if (registered === presented) return true;
  const r = parseLoopback(registered);
  const p = parseLoopback(presented);
  return r !== null && p !== null && r.host === p.host && r.rest === p.rest;
}

export class OAuthService {
  // Keyed by principal: slows a guess against one account.
  private readonly loginFails = new SlidingWindow(8, 15 * 60_000);
  // Keyed by address: slows a spray across many accounts from one place.
  private readonly loginByIp = new SlidingWindow(20, 15 * 60_000);
  // Unkeyed. Checked before the KDF runs, so aggregate password-hashing CPU is
  // capped no matter how many principals or addresses an attacker spreads over.
  private readonly loginGlobal = new SlidingWindow(60, 60_000);
  private readonly registerByIp = new SlidingWindow(10, 60 * 60_000);

  constructor(
    private readonly cfg: OAuthConfig,
    private readonly db: Db,
    private readonly minter: TokenMinter,
    private readonly pepper: string | null,
  ) {}

  // ------------------------------------------------------------- discovery

  metadataProtectedResource(): Record<string, unknown> {
    return {
      resource: this.cfg.resource,
      authorization_servers: [this.cfg.issuer],
      scopes_supported: SCOPES,
      bearer_methods_supported: ['header'],
      resource_documentation: `${this.cfg.issuer}/`,
    };
  }

  metadataAuthorizationServer(): Record<string, unknown> {
    return {
      issuer: this.cfg.issuer,
      authorization_endpoint: `${this.cfg.issuer}/oauth/authorize`,
      token_endpoint: `${this.cfg.issuer}/oauth/token`,
      registration_endpoint: `${this.cfg.issuer}/oauth/register`,
      jwks_uri: `${this.cfg.issuer}/.well-known/jwks.json`,
      scopes_supported: SCOPES,
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      // S256 only. "plain" is in the RFC and is worthless against the attack
      // PKCE exists to stop.
      code_challenge_methods_supported: ['S256'],
      token_endpoint_auth_methods_supported: ['none', 'client_secret_post', 'client_secret_basic'],
      resource_indicators_supported: true,
      authorization_response_iss_parameter_supported: true,
    };
  }

  jwks(): Record<string, unknown> {
    return this.minter.jwks();
  }

  // ------------------------------------------------ dynamic registration

  async registerClient(
    body: Record<string, unknown>,
    ip: string,
  ): Promise<Record<string, unknown> | OAuthError> {
    if (this.registerByIp.over(ip)) {
      return { httpStatus: 429, error: 'temporarily_unavailable', description: 'too many registrations' };
    }

    const uris = Array.isArray(body.redirect_uris) ? body.redirect_uris : [];
    if (uris.length === 0 || uris.length > 8) {
      return {
        httpStatus: 400,
        error: 'invalid_redirect_uri',
        description: 'redirect_uris must hold between one and eight entries',
      };
    }

    const clean: string[] = [];
    for (const raw of uris) {
      if (typeof raw !== 'string' || raw.length > 2048) {
        return { httpStatus: 400, error: 'invalid_redirect_uri', description: 'redirect_uris must be strings' };
      }
      // A native app can only receive the code on a local listener, and a code
      // sent there reaches nothing but a process on the signing-in user's own
      // machine. The allowlist exists to keep codes off third-party web
      // servers, so it does not apply.
      if (isLoopbackRedirect(raw)) {
        clean.push(raw);
        continue;
      }
      const host = httpsHostOf(raw);
      if (!host) {
        return {
          httpStatus: 400,
          error: 'invalid_redirect_uri',
          description:
            'every redirect_uri must be an https URL, or an http loopback URL, without embedded credentials',
        };
      }
      if (!hostAllowed(host, this.cfg.redirectHosts)) {
        return {
          httpStatus: 400,
          error: 'invalid_redirect_uri',
          description: `redirect host ${host} is not permitted by this server`,
        };
      }
      clean.push(raw);
    }

    const count = await this.db<{ n: number }[]>`SELECT count(*)::int AS n FROM ghost.oauth_clients`;
    if ((count[0]?.n ?? 0) >= this.cfg.maxClients) {
      return {
        httpStatus: 400,
        error: 'invalid_client_metadata',
        description: 'this server is not accepting further client registrations',
      };
    }

    const requested = typeof body.token_endpoint_auth_method === 'string' ? body.token_endpoint_auth_method : 'none';
    const authMethod = ['none', 'client_secret_post', 'client_secret_basic'].includes(requested)
      ? requested
      : 'none';

    const clientId = 'gp_' + randomBytes(16).toString('base64url');
    const secret = authMethod === 'none' ? null : randomBytes(32).toString('base64url');
    const name = typeof body.client_name === 'string' ? body.client_name.slice(0, 200) : null;

    await this.db`
      INSERT INTO ghost.oauth_clients
        (client_id, client_secret_hash, token_endpoint_auth, client_name, redirect_uris, scope)
      VALUES (${clientId}, ${secret ? sha256Hex(secret) : null}, ${authMethod}, ${name},
              ${this.db.json(clean)}, ${SCOPES.join(' ')})`;

    await this.audit('client_registered', null, { client_id: clientId, client_name: name, ip });

    const response: Record<string, unknown> = {
      client_id: clientId,
      client_id_issued_at: Math.floor(Date.now() / 1000),
      redirect_uris: clean,
      token_endpoint_auth_method: authMethod,
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      scope: SCOPES.join(' '),
    };
    if (name) response.client_name = name;
    if (secret) {
      response.client_secret = secret;
      response.client_secret_expires_at = 0;
    }
    return response;
  }

  // ------------------------------------------------------------- authorize

  async validateAuthorize(params: URLSearchParams): Promise<AuthorizeValidation> {
    const req: AuthorizeRequest = {
      clientId: params.get('client_id') ?? '',
      redirectUri: params.get('redirect_uri') ?? '',
      codeChallenge: params.get('code_challenge') ?? '',
      state: params.get('state') ?? '',
      resource: params.get('resource') ?? '',
      scope: params.get('scope') ?? '',
    };

    const fail = (error: string, description: string, redirectError = false): AuthorizeValidation => ({
      ok: false,
      req,
      error: { httpStatus: 400, error, description },
      redirectError,
    });

    if (!req.clientId) return fail('invalid_request', 'client_id is required');

    const client = await this.loadClient(req.clientId);
    // Identity unverified: rendering a page is the only safe answer, because
    // redirecting to an unvalidated URI is how an open redirector is built
    // (RFC 6749 §4.1.2.1).
    if (!client) return fail('invalid_client', 'unknown client_id');
    if (!req.redirectUri) return fail('invalid_request', 'redirect_uri is required');
    if (!client.redirect_uris.some((registered) => redirectMatches(registered, req.redirectUri))) {
      return fail('invalid_request', 'redirect_uri does not match this client registration');
    }

    // Past this line the redirect_uri is proven to belong to the client, so
    // errors may be delivered the way the spec wants them.
    if (params.get('response_type') !== 'code') {
      return fail('unsupported_response_type', 'only response_type=code is supported', true);
    }
    if (params.get('code_challenge_method') !== 'S256') {
      return fail('invalid_request', 'code_challenge_method must be S256', true);
    }
    if (!validPkceString(req.codeChallenge)) {
      return fail('invalid_request', 'code_challenge is missing or malformed', true);
    }
    if (req.state.length > 2048 || req.resource.length > 2048 || req.scope.length > 512) {
      return fail('invalid_request', 'a parameter is too long', true);
    }
    if (req.resource && !this.resourceMatches(req.resource)) {
      return fail('invalid_target', 'resource does not name this server', true);
    }

    return { ok: true, req };
  }

  /**
   * Check the submitted credentials and mint an authorization code.
   *
   * Returns the full redirect URL on success. On failure: 401 means bad
   * credentials and the form should be re-rendered, 429 means throttled.
   */
  async handleLogin(
    req: AuthorizeRequest,
    principal: string,
    password: string,
    ip: string,
  ): Promise<string | OAuthError> {
    const throttled: OAuthError = {
      httpStatus: 429,
      error: 'temporarily_unavailable',
      description: 'too many attempts; wait a few minutes and try again',
    };

    // The global gate is checked first and deliberately: it bounds total scrypt
    // CPU before a single hash runs, so a distributed guess cannot turn the
    // login page into a way to pin the box's cores.
    if (this.loginGlobal.over('')) return throttled;
    if (!principal || !password) {
      return { httpStatus: 401, error: 'access_denied', description: 'enter a principal and password' };
    }
    if (this.loginFails.over(principal) || this.loginByIp.over(ip)) return throttled;

    const rows = await this.db<{ password_phc: string }[]>`
      SELECT password_phc FROM ghost.principal_credentials WHERE principal = ${principal}`;

    // Unknown principals still pay for a hash, so response time does not say
    // which names exist.
    const phc = rows[0]?.password_phc ?? DUMMY_PHC;
    const ok = (await verifyPassword(password, phc, this.pepper)) && rows.length > 0;

    if (!ok) {
      await this.audit('login_failed', principal, { ip });
      log.warn('oauth login failed', { principal, ip });
      return { httpStatus: 401, error: 'access_denied', description: 'that principal and password do not match' };
    }

    this.loginFails.reset(principal);

    const code = randomBytes(32).toString('base64url');
    const expires = new Date(Date.now() + this.cfg.authCodeTtlS * 1000);
    await this.db`
      INSERT INTO ghost.oauth_codes
        (code_hash, client_id, principal, redirect_uri, code_challenge, resource, scope, expires_at)
      VALUES (${sha256Hex(code)}, ${req.clientId}, ${principal}, ${req.redirectUri},
              ${req.codeChallenge}, ${req.resource || null}, ${req.scope || SCOPES.join(' ')}, ${expires})`;
    await this.audit('login', principal, { ip, client_id: req.clientId });

    const url = new URL(req.redirectUri);
    url.searchParams.set('code', code);
    if (req.state) url.searchParams.set('state', req.state);
    // RFC 9207: naming the issuer in the response lets the client detect a
    // code injected from a different authorization server.
    url.searchParams.set('iss', this.cfg.issuer);
    return url.toString();
  }

  // ----------------------------------------------------------------- token

  async token(
    form: URLSearchParams,
    authorizationHeader: string,
  ): Promise<Record<string, unknown> | OAuthError> {
    const client = await this.authenticateClient(form, authorizationHeader);
    if ('httpStatus' in client) return client;

    const grant = form.get('grant_type');
    if (grant === 'authorization_code') return await this.grantAuthorizationCode(client, form);
    if (grant === 'refresh_token') return await this.grantRefreshToken(client, form);
    return {
      httpStatus: 400,
      error: 'unsupported_grant_type',
      description: 'grant_type must be authorization_code or refresh_token',
    };
  }

  private async authenticateClient(
    form: URLSearchParams,
    authorizationHeader: string,
  ): Promise<ClientRow | OAuthError> {
    let clientId = form.get('client_id') ?? '';
    let presented: string | null = form.get('client_secret');

    if (authorizationHeader.startsWith('Basic ')) {
      const decoded = Buffer.from(authorizationHeader.slice(6), 'base64').toString('utf8');
      const sep = decoded.indexOf(':');
      if (sep > 0) {
        clientId = decodeURIComponent(decoded.slice(0, sep));
        presented = decodeURIComponent(decoded.slice(sep + 1));
      }
    }

    if (!clientId) {
      return { httpStatus: 400, error: 'invalid_client', description: 'client_id is required' };
    }
    const client = await this.loadClient(clientId);
    if (!client) {
      return { httpStatus: 400, error: 'invalid_client', description: 'unknown client' };
    }

    if (client.client_secret_hash) {
      if (!presented) {
        return { httpStatus: 400, error: 'invalid_client', description: 'client authentication required' };
      }
      const a = Buffer.from(sha256Hex(presented));
      const b = Buffer.from(client.client_secret_hash);
      if (a.length !== b.length || !timingSafeEqual(a, b)) {
        return { httpStatus: 400, error: 'invalid_client', description: 'client authentication failed' };
      }
    }
    return client;
  }

  private async grantAuthorizationCode(
    client: ClientRow,
    form: URLSearchParams,
  ): Promise<Record<string, unknown> | OAuthError> {
    const code = form.get('code') ?? '';
    const verifier = form.get('code_verifier') ?? '';
    const redirectUri = form.get('redirect_uri') ?? '';
    const invalid: OAuthError = {
      httpStatus: 400,
      error: 'invalid_grant',
      description: 'the authorization code is invalid, expired, or already used',
    };

    if (!code || !validPkceString(verifier)) return invalid;

    const hash = sha256Hex(code);
    const challenge = s256Challenge(verifier);

    // Claim and validate in one statement. Every condition the exchange has to
    // satisfy is in the WHERE clause, so a row coming back means the code was
    // unclaimed, unexpired, and matched this client, this redirect_uri and this
    // PKCE verifier — and that this call is the one that claimed it. Two
    // concurrent exchanges cannot both match `used_at IS NULL`.
    //
    // Putting the PKCE check inside the claim rather than after it is the point.
    // Claiming first and validating after means a wrong code_verifier burns the
    // code, so anyone who intercepts one can lock the real client out by
    // spending it wrongly, and an ordinary retry after a transient failure dies
    // too. Here a failed verifier leaves the code untouched and retryable.
    //
    // Comparing the challenge in SQL rather than with timingSafeEqual is fine:
    // the challenge is public by construction, since the client sends it in the
    // authorize request. The verifier is the secret, and it is never stored.
    //
    // The redirect_uri comparison stays exact for loopback clients too: the
    // stored value is the URI this flow's authorize request used, port and all,
    // which already passed the port-flexible check against the registration.
    const claimed = await this.db<
      Array<{
        principal: string;
        resource: string | null;
        scope: string | null;
      }>
    >`
      UPDATE ghost.oauth_codes
         SET used_at = now()
       WHERE code_hash      = ${hash}
         AND used_at        IS NULL
         AND expires_at     > now()
         AND client_id      = ${client.client_id}
         AND code_challenge = ${challenge}
         AND (${redirectUri || null}::text IS NULL OR redirect_uri = ${redirectUri || null})
      RETURNING principal, resource, scope`;

    const row = claimed[0];
    if (row) {
      return await this.issueTokens(
        row.principal,
        client.client_id,
        row.scope ?? SCOPES.join(' '),
        row.resource ?? this.cfg.resource,
        null,
      );
    }

    // Nothing matched. Only one of the reasons is an incident: a code that was
    // already spent successfully means one of the two presenters stole it, and
    // there is no way to tell which, so every family that pairing minted dies.
    // A wrong verifier or an expired code is just a failed exchange.
    const spent = await this.db<Array<{ principal: string; client_id: string }>>`
      SELECT principal, client_id FROM ghost.oauth_codes
       WHERE code_hash = ${hash} AND used_at IS NOT NULL`;
    const prior = spent[0];
    if (prior) {
      await this.db`
        UPDATE ghost.oauth_refresh_tokens
           SET revoked_at = now()
         WHERE principal = ${prior.principal} AND client_id = ${prior.client_id}
           AND revoked_at IS NULL`;
      await this.audit('code_replay', prior.principal, { client_id: prior.client_id });
      log.warn('oauth authorization code replayed; revoked token families', {
        principal: prior.principal,
        client_id: prior.client_id,
      });
    }
    return invalid;
  }

  private async grantRefreshToken(
    client: ClientRow,
    form: URLSearchParams,
  ): Promise<Record<string, unknown> | OAuthError> {
    const presented = form.get('refresh_token') ?? '';
    const invalid: OAuthError = {
      httpStatus: 400,
      error: 'invalid_grant',
      description: 'the refresh token is invalid, expired, or has been revoked',
    };
    if (!presented) return invalid;

    const hash = sha256Hex(presented);

    // Rotate and read in one statement, matching only tokens that are still
    // live. Two concurrent refreshes with the same token cannot both succeed,
    // so the loser is indistinguishable from a thief and is treated as one.
    const rotated = await this.db<
      Array<{
        family_id: string;
        client_id: string;
        principal: string;
        scope: string | null;
        resource: string | null;
      }>
    >`
      UPDATE ghost.oauth_refresh_tokens
         SET rotated_at = now()
       WHERE token_hash = ${hash}
         AND rotated_at IS NULL AND revoked_at IS NULL AND expires_at > now()
      RETURNING family_id, client_id, principal, scope, resource`;

    const row = rotated[0];
    if (!row) {
      const rows = await this.db<
        Array<{ family_id: string; client_id: string; principal: string; rotated: boolean }>
      >`
        SELECT family_id, client_id, principal, (rotated_at IS NOT NULL) AS rotated
          FROM ghost.oauth_refresh_tokens
         WHERE token_hash = ${hash}`;
      const known = rows[0];
      if (known?.rotated) {
        // RFC 9700: a rotated token presented again means a copy is loose. The
        // whole family dies, including whichever successor the legitimate
        // client is holding, because there is no way to tell them apart.
        await this.db`
          UPDATE ghost.oauth_refresh_tokens
             SET revoked_at = now()
           WHERE family_id = ${known.family_id}::uuid AND revoked_at IS NULL`;
        await this.audit('refresh_reuse', known.principal, {
          client_id: known.client_id,
          family: known.family_id,
        });
        log.warn('oauth refresh token reuse; family revoked', {
          principal: known.principal,
          client_id: known.client_id,
        });
      }
      return invalid;
    }

    if (row.client_id !== client.client_id) return invalid;

    return await this.issueTokens(
      row.principal,
      client.client_id,
      row.scope ?? SCOPES.join(' '),
      row.resource ?? this.cfg.resource,
      row.family_id,
    );
  }

  private async issueTokens(
    principal: string,
    clientId: string,
    scope: string,
    resource: string,
    family: string | null,
  ): Promise<Record<string, unknown>> {
    const familyId = family ?? randomUUID();
    const refresh = randomBytes(32).toString('base64url');
    const refreshExpires = new Date(Date.now() + this.cfg.refreshTokenTtlS * 1000);

    await this.db`
      INSERT INTO ghost.oauth_refresh_tokens
        (token_hash, family_id, client_id, principal, scope, resource, expires_at)
      VALUES (${sha256Hex(refresh)}, ${familyId}::uuid, ${clientId}, ${principal},
              ${scope}, ${resource}, ${refreshExpires})`;

    const { token, expiresIn } = await this.minter.sign({
      principal,
      clientId,
      scope,
      ttlSeconds: this.cfg.accessTokenTtlS,
      audience: resource || this.cfg.resource,
    });

    await this.db`
      UPDATE ghost.oauth_clients SET last_used_at = now() WHERE client_id = ${clientId}`;

    return {
      access_token: token,
      token_type: 'Bearer',
      expires_in: expiresIn,
      refresh_token: refresh,
      scope,
    };
  }

  // ----------------------------------------------------------------- misc

  private async loadClient(clientId: string): Promise<ClientRow | null> {
    if (clientId.length > 200) return null;
    const rows = await this.db<ClientRow[]>`
      SELECT client_id, client_secret_hash, token_endpoint_auth, redirect_uris
        FROM ghost.oauth_clients
       WHERE client_id = ${clientId}`;
    return rows[0] ?? null;
  }

  /** RFC 8707 allows a trailing path; the origin has to be ours either way. */
  private resourceMatches(resource: string): boolean {
    try {
      const a = new URL(resource);
      const b = new URL(this.cfg.resource);
      return a.origin === b.origin;
    } catch {
      return false;
    }
  }

  private async audit(action: string, principal: string | null, details: unknown): Promise<void> {
    try {
      await this.db`
        INSERT INTO ghost.audit (action, principal, details)
        VALUES (${action}, ${principal}, ${this.db.json(details as never)})`;
    } catch (e) {
      // An audit row failing must never take down a login.
      log.warn('audit insert failed', { action, ...errFields(e) });
    }
  }
}

// A well-formed hash of a value nothing will match, so an unknown principal
// costs the same wall-clock as a known one.
const DUMMY_PHC =
  '$scrypt$ln=15,r=8,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
