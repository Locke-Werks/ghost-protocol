// The browser half, run by its own systemd unit under its own account.
//
// This process owns nothing. It has no database credential, no signing key and
// no read access to the MCP service's secrets. All it does is hold a Chrome and
// answer a websocket on loopback. That is the point of splitting it out: the
// component that renders attacker-controlled pages is the component with
// nothing worth taking.
//
// Chrome's own sandbox stays enabled. --no-sandbox is the usual shortcut when
// Chrome will not start under a hardened unit, and it removes the one boundary
// between a compromised renderer and everything else this account can see. The
// unit file is adjusted to permit the namespace calls Chrome needs instead.

import { chromium } from 'playwright-core';
import { launchArgs } from './browser/fingerprint.js';
import { log, setLevel, errFields } from './util/log.js';

async function main(): Promise<void> {
  setLevel(process.env.GHOST_LOG_LEVEL ?? 'info');

  const port = Number(process.env.GHOST_BROWSER_PORT ?? 17716);
  const wsPath = process.env.GHOST_BROWSER_WS_PATH ?? '';
  const proxyServer = process.env.GHOST_EGRESS_PROXY ?? 'http://127.0.0.1:17715';

  if (!wsPath || wsPath.length < 24) {
    // The path is the only thing standing between another local account and
    // control of this browser, so a short or absent one is a configuration
    // error rather than something to paper over with a default.
    throw new Error('GHOST_BROWSER_WS_PATH must be set to at least 24 random characters');
  }

  const server = await chromium.launchServer({
    channel: 'chrome',
    headless: true,
    args: launchArgs(proxyServer),
    // Bound to loopback. Caddy never sees this and it is not in any allowlist.
    host: '127.0.0.1',
    port,
    wsPath: '/' + wsPath.replace(/^\/+/, ''),
    timeout: 60_000,
    handleSIGINT: false,
    handleSIGTERM: false,
    handleSIGHUP: false,
  });

  log.info('browser server listening', {
    port,
    proxy: proxyServer,
    // The path is a secret; the fact that one is set is not.
    ws_path_len: wsPath.length,
  });

  const stop = async (signal: string) => {
    log.info('browser server stopping', { signal });
    await server.close().catch(() => {});
    process.exit(0);
  };
  process.on('SIGTERM', () => void stop('SIGTERM'));
  process.on('SIGINT', () => void stop('SIGINT'));

  // If Chrome dies on its own, exiting lets systemd restart the unit rather
  // than leaving a listener up with no browser behind it.
  server.on('close', () => {
    log.error('browser exited; leaving so systemd can restart');
    process.exit(1);
  });
}

main().catch((e) => {
  log.error('browser server failed to start', errFields(e));
  process.exit(1);
});
