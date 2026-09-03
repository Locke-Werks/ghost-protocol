// Entry point for the MCP service.
//
// Starts, in order: the database and its migrations, the egress guard proxy, the
// browser connection, and finally the HTTP listener. The proxy comes up before
// anything can navigate, deliberately — a window in which the browser is
// reachable but unguarded would be a window in which a fetch could reach
// loopback.

import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import express from 'express';
import { loadConfig } from './config.js';
import { connect, migrate, prune } from './db.js';
import { GuardedProxy } from './net/proxy.js';
import { BrowserRuntime } from './browser/sessions.js';
import { loadSigningKey, TokenMinter, type SigningKey } from './oauth/jwt.js';
import { OAuthService } from './oauth/service.js';
import { registerOAuthRoutes } from './oauth/routes.js';
import { registerMcpRoutes, SERVER_INFO } from './mcp/transport.js';
import type { RequestRecord } from './mcp/tools.js';
import { log, setLevel, errFields } from './util/log.js';

const HERE = dirname(fileURLToPath(import.meta.url));

async function main(): Promise<void> {
  const configPath = process.env.GHOST_CONFIG ?? join(HERE, '..', 'config', 'ghost-protocol.toml');
  const cfg = loadConfig(configPath);
  setLevel(cfg.logging.level);

  log.info('starting', { ...SERVER_INFO, config: configPath });

  if (!cfg.browser.wsEndpoint) {
    throw new Error(
      'browser endpoint unset: set GHOST_BROWSER_WS_PATH in the service environment, ' +
        'or [browser].ws_endpoint in the config',
    );
  }

  const db = connect(cfg.databaseUrl);
  await migrate(db, join(HERE, '..', 'sql', 'migrations'));

  // Signing keys: the first is the active one, the rest stay in the JWKS so
  // tokens minted before a rotation keep verifying until they expire.
  let minter: TokenMinter | null = null;
  let oauth: OAuthService | null = null;
  if (cfg.auth.oauth) {
    const keys: SigningKey[] = [await loadSigningKey(cfg.auth.oauth.signingKeyPath)];
    for (const path of cfg.auth.oauth.previousKeyPaths) {
      keys.push(await loadSigningKey(path));
    }
    minter = new TokenMinter(keys, cfg.auth.oauth.issuer, cfg.auth.oauth.resource);
    oauth = new OAuthService(cfg.auth.oauth, db, minter, cfg.passwordPepper);
    log.info('oauth enabled', {
      issuer: cfg.auth.oauth.issuer,
      kid: keys[0]!.kid,
      alg: keys[0]!.alg,
      keys_in_jwks: keys.length,
    });
  } else if (cfg.auth.enabled) {
    throw new Error('auth.enabled is true but [auth.oauth] is not configured; refusing to listen unauthenticated');
  } else {
    log.warn('authentication is DISABLED; this is only safe on a loopback-only bind');
  }

  // The proxy mints its own credentials at construction and the runtime needs
  // them, so the proxy is built first. The dependency in the other direction —
  // the proxy attributing an egress event to a session — is late-bound through
  // this holder rather than by handing either object a half-built copy of the
  // other.
  let runtimeRef: BrowserRuntime | null = null;

  const proxy = new GuardedProxy({
    host: cfg.egress.proxyHost,
    port: cfg.egress.proxyPort,
    allowHosts: cfg.egress.allowHosts,
    onEgress: (host, port, allowed, reason) =>
      runtimeRef?.recordEgress({ host, port, allowed, reason, at: Date.now() }),
  });
  await proxy.listen();

  const runtime = new BrowserRuntime(cfg, {
    server: proxy.url,
    username: proxy.username,
    password: proxy.password,
  });
  runtimeRef = runtime;
  runtime.start();

  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', true);
  app.use(express.json({ limit: cfg.server.maxBodyBytes }));
  app.use(express.urlencoded({ extended: false, limit: cfg.server.maxBodyBytes }));

  app.get('/healthz', (_req, res) => {
    const stats = runtime.stats();
    res.json({ ok: true, ...SERVER_INFO, browser_connected: stats.connected, sessions: stats.sessions });
  });

  if (oauth && cfg.auth.oauth) registerOAuthRoutes(app, oauth, cfg.auth.oauth);

  const chromeVersionRef = { value: '141.0.0.0' };
  const userAgentRef = {
    value:
      cfg.browser.userAgent ??
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36',
  };

  // The request trail. Deliberately fire-and-forget: a database hiccup must not
  // turn a working fetch into a failed tool call.
  const recordRequest = (r: RequestRecord): void => {
    void db`
      INSERT INTO ghost.request_log
        (principal, tool, url, final_url, status, ok, injection_findings, hidden_elements, bytes, detail)
      VALUES (${r.principal}, ${r.tool}, ${r.url.slice(0, 2048)},
              ${r.finalUrl && r.finalUrl !== r.url ? r.finalUrl.slice(0, 2048) : null},
              ${r.status ?? null}, ${r.ok}, ${r.injectionFindings ?? 0},
              ${r.hiddenElements ?? 0}, ${r.bytes ?? null}, ${r.detail ?? null})
    `.catch((e) => log.warn('request_log insert failed', errFields(e)));
  };

  registerMcpRoutes(app, { cfg, runtime, minter, chromeVersionRef, userAgentRef, recordRequest });

  // Anything not explicitly routed is not part of this server's surface. Caddy
  // narrows it further; this is the second lock.
  app.use((_req, res) => res.status(404).json({ error: 'not_found' }));

  const server = app.listen(cfg.server.bindPort, cfg.server.bindHost, () => {
    log.info('listening', { bind: `${cfg.server.bindHost}:${cfg.server.bindPort}` });
  });

  // Learn the real Chrome version once so ghost_curl's headers name the same
  // build the browser path sends. A mismatch there is exactly the kind of
  // internal disagreement the fingerprint work exists to avoid.
  //
  // Not fatal if the browser unit is still coming up: the refs keep their
  // defaults and the next successful connection refreshes them.
  const refreshIdentity = () => {
    const id = runtime.identity();
    if (!id) return false;
    chromeVersionRef.value = id.version;
    if (!cfg.browser.userAgent) userAgentRef.value = id.userAgent;
    return true;
  };

  void (async () => {
    try {
      const session = await runtime.open('startup-probe');
      await runtime.close(session.id);
      if (refreshIdentity()) {
        log.info('browser identity settled', {
          chrome: chromeVersionRef.value,
          user_agent: userAgentRef.value,
        });
      }
    } catch (e) {
      log.warn('browser probe failed at startup; it will be retried on first use', errFields(e));
    }
  })();

  // Cheap, and it catches the case where the browser unit restarts onto a
  // different Chrome after an unattended upgrade.
  const identityTimer = setInterval(() => void refreshIdentity(), 10 * 60_000);
  identityTimer.unref();

  const pruner = setInterval(() => {
    void prune(db, 90).catch((e) => log.warn('prune failed', errFields(e)));
  }, 6 * 60 * 60_000);
  pruner.unref();

  const shutdown = async (signal: string) => {
    log.info('shutting down', { signal });
    server.close();
    await runtime.stop();
    await proxy.close();
    await db.end({ timeout: 5 }).catch(() => {});
    process.exit(0);
  };
  process.on('SIGTERM', () => void shutdown('SIGTERM'));
  process.on('SIGINT', () => void shutdown('SIGINT'));
}

main().catch((e) => {
  log.error('failed to start', errFields(e));
  process.exit(1);
});
