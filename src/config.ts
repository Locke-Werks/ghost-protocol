// Configuration: a TOML file for shape, environment variables for secrets.
// Nothing that would hurt to read over someone's shoulder goes in the file.

import { readFileSync } from 'node:fs';
import { parse as parseToml } from 'smol-toml';
import { addDeniedAddress } from './net/guard.js';

export interface PrincipalConfig {
  name: string;
  /** Empty = every tool. Named tools restrict what this login may call. */
  tools: string[];
}

export interface OAuthConfig {
  enabled: boolean;
  issuer: string;
  resource: string;
  signingKeyPath: string;
  previousKeyPaths: string[];
  accessTokenTtlS: number;
  authCodeTtlS: number;
  refreshTokenTtlS: number;
  redirectHosts: string[];
  maxClients: number;
}

export interface Config {
  server: { bindHost: string; bindPort: number; maxBodyBytes: number };
  browser: {
    wsEndpoint: string;
    locale: string;
    timezone: string;
    viewportWidth: number;
    viewportHeight: number;
    userAgent: string | null;
    navigationTimeoutMs: number;
  };
  egress: {
    proxyHost: string;
    proxyPort: number;
    allowHosts: Set<string>;
    denyAddresses: string[];
  };
  sessions: {
    maxTotal: number;
    maxPerPrincipal: number;
    idleTimeoutS: number;
    maxLifetimeS: number;
  };
  capture: {
    width: number;
    tileHeight: number;
    maxTiles: number;
    webpQuality: number;
    maxTextBytes: number;
  };
  auth: { enabled: boolean; oauth: OAuthConfig | null; principals: PrincipalConfig[] };
  logging: { level: string };
  databaseUrl: string;
  passwordPepper: string | null;
}

function splitBind(value: string, what: string): { host: string; port: number } {
  const idx = value.lastIndexOf(':');
  if (idx <= 0) throw new Error(`${what} must be host:port, got "${value}"`);
  const host = value.slice(0, idx);
  const port = Number(value.slice(idx + 1));
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`${what} has an invalid port: "${value}"`);
  }
  return { host, port };
}

function num(v: unknown, fallback: number): number {
  return typeof v === 'number' && Number.isFinite(v) ? v : fallback;
}
function str(v: unknown, fallback: string): string {
  return typeof v === 'string' && v.length > 0 ? v : fallback;
}
function strList(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [];
}

export function loadConfig(path: string): Config {
  const raw = parseToml(readFileSync(path, 'utf8')) as Record<string, any>;

  const server = raw.server ?? {};
  const bind = splitBind(str(server.http_bind, '127.0.0.1:17719'), 'server.http_bind');

  const egressRaw = raw.egress ?? {};
  const proxyBind = splitBind(str(egressRaw.proxy_bind, '127.0.0.1:17715'), 'egress.proxy_bind');
  const denyAddresses = strList(egressRaw.deny_addresses);
  for (const a of denyAddresses) addDeniedAddress(a);

  const browserRaw = raw.browser ?? {};
  const wsPath = process.env.GHOST_BROWSER_WS_PATH ?? '';
  // Left empty when unset rather than thrown on here. The CLI loads the same
  // config to set a password or mint a key and has no business needing the
  // browser's websocket path to do it; the server checks it at startup instead.
  const wsEndpoint = str(browserRaw.ws_endpoint, '')
    || (wsPath ? `ws://${str(browserRaw.ws_host, '127.0.0.1:17716')}/${wsPath}` : '');

  const authRaw = raw.auth ?? {};
  const oauthRaw = authRaw.oauth ?? null;
  const oauth: OAuthConfig | null =
    oauthRaw && oauthRaw.enabled
      ? {
          enabled: true,
          issuer: str(oauthRaw.issuer, '').replace(/\/+$/, ''),
          resource: str(oauthRaw.resource, ''),
          signingKeyPath: str(oauthRaw.signing_key_path, ''),
          previousKeyPaths: strList(oauthRaw.previous_key_paths),
          accessTokenTtlS: num(oauthRaw.access_token_ttl_s, 900),
          authCodeTtlS: num(oauthRaw.auth_code_ttl_s, 600),
          refreshTokenTtlS: num(oauthRaw.refresh_token_ttl_s, 2_592_000),
          redirectHosts: strList(oauthRaw.redirect_hosts),
          maxClients: num(oauthRaw.max_clients, 50),
        }
      : null;
  if (oauth) {
    if (!oauth.issuer.startsWith('https://')) throw new Error('auth.oauth.issuer must be an https URL');
    if (!oauth.resource.startsWith('https://')) throw new Error('auth.oauth.resource must be an https URL');
    if (!oauth.signingKeyPath) throw new Error('auth.oauth.signing_key_path is required');
  }

  const principals: PrincipalConfig[] = (Array.isArray(authRaw.principals) ? authRaw.principals : []).map(
    (p: any) => ({ name: String(p.name), tools: strList(p.tools) }),
  );

  const databaseUrl = process.env.DATABASE_URL ?? '';
  if (!databaseUrl) throw new Error('DATABASE_URL is not set');

  const captureRaw = raw.capture ?? {};
  const sessionsRaw = raw.sessions ?? {};
  const loggingRaw = raw.logging ?? {};

  return {
    server: {
      bindHost: bind.host,
      bindPort: bind.port,
      maxBodyBytes: num(server.max_body_bytes, 1_048_576),
    },
    browser: {
      wsEndpoint,
      locale: str(browserRaw.locale, 'en-US'),
      timezone: str(browserRaw.timezone, 'America/Chicago'),
      viewportWidth: num(browserRaw.viewport_width, 1280),
      viewportHeight: num(browserRaw.viewport_height, 800),
      userAgent: typeof browserRaw.user_agent === 'string' ? browserRaw.user_agent : null,
      navigationTimeoutMs: num(browserRaw.navigation_timeout_ms, 45_000),
    },
    egress: {
      proxyHost: proxyBind.host,
      proxyPort: proxyBind.port,
      allowHosts: new Set(strList(egressRaw.allow_hosts).map((h) => h.toLowerCase())),
      denyAddresses,
    },
    sessions: {
      maxTotal: num(sessionsRaw.max_total, 8),
      maxPerPrincipal: num(sessionsRaw.max_per_principal, 3),
      idleTimeoutS: num(sessionsRaw.idle_timeout_s, 600),
      maxLifetimeS: num(sessionsRaw.max_lifetime_s, 3600),
    },
    capture: {
      width: num(captureRaw.width, 1280),
      tileHeight: num(captureRaw.tile_height, 1600),
      maxTiles: num(captureRaw.max_tiles, 4),
      webpQuality: num(captureRaw.webp_quality, 78),
      maxTextBytes: num(captureRaw.max_text_bytes, 262_144),
    },
    auth: {
      enabled: authRaw.enabled !== false,
      oauth,
      principals,
    },
    logging: { level: str(loggingRaw.level, 'info') },
    databaseUrl,
    passwordPepper: process.env.GHOST_PASSWORD_PEPPER || null,
  };
}
