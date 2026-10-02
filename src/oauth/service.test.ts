// Redirect URI policy: which URIs registration accepts, and which presented
// redirect_uri values authorize treats as matching a registration.
//
// The loopback cases are RFC 8252 §7.3 and §8.3. A native app registers an
// http://127.0.0.1 style redirect and binds whatever port is free at each
// sign-in, so the port may differ at authorize while nothing else may.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import type { Db } from '../db.js';
import type { OAuthConfig } from '../config.js';
import type { TokenMinter } from './jwt.js';
import { OAuthService, hostAllowed, httpsHostOf, isLoopbackRedirect, redirectMatches } from './service.js';

test('loopback redirects: http to 127.0.0.1, [::1], localhost, with and without a port', () => {
  for (const uri of [
    'http://127.0.0.1:25179/callback',
    'http://127.0.0.1/callback',
    'http://[::1]:25179/callback',
    'http://[::1]/callback',
    'http://localhost:8080/callback',
    'http://localhost/callback',
    'http://LocalHost:8080/cb',
    'http://127.0.0.1:1',
  ]) {
    assert.equal(isLoopbackRedirect(uri), true, uri);
  }
});

test('http to a non-loopback host, other schemes, credentials and bad ports are refused', () => {
  for (const uri of [
    'http://claude.ai/callback',
    'http://evil.com:25179/callback',
    'http://127.0.0.2/callback',
    'http://127.1/callback',
    'http://localhost.evil.com/callback',
    'http://127.0.0.1.evil.com/callback',
    'http://[::2]/callback',
    'http://user@127.0.0.1/callback',
    'http://evil.com@127.0.0.1/callback',
    'http://127.0.0.1:/callback',
    'http://127.0.0.1:99999/callback',
    'http://127.0.0.1:80a/callback',
    'http://[::1]x/callback',
    'http://127.0.0.1:25179/callback#frag',
    'https://127.0.0.1/callback',
    'ftp://127.0.0.1/callback',
    'com.example.app:/callback',
    '',
  ]) {
    assert.equal(isLoopbackRedirect(uri), false, uri);
  }
});

test('https to a host off the allowlist is still refused', () => {
  const allow = ['claude.ai', 'chatgpt.com'];
  assert.equal(hostAllowed(httpsHostOf('https://evil.com/callback'), allow), false);
  assert.equal(hostAllowed(httpsHostOf('https://api.claude.ai/callback'), allow), true);
});

test('a loopback registration matches at authorize with a different port only', () => {
  const reg = 'http://127.0.0.1:25179/callback';
  assert.equal(redirectMatches(reg, reg), true);
  assert.equal(redirectMatches(reg, 'http://127.0.0.1:61000/callback'), true);
  assert.equal(redirectMatches(reg, 'http://127.0.0.1/callback'), true);
  assert.equal(redirectMatches('http://[::1]:1/cb', 'http://[::1]:2/cb'), true);
  assert.equal(redirectMatches('http://localhost:1/cb?x=1', 'http://localhost:2/cb?x=1'), true);

  assert.equal(redirectMatches(reg, 'http://127.0.0.1:61000/other'), false);
  assert.equal(redirectMatches(reg, 'http://127.0.0.1:61000/callback/'), false);
  assert.equal(redirectMatches(reg, 'http://127.0.0.1:61000/callback?x=1'), false);
  assert.equal(redirectMatches(reg, 'http://127.0.0.1:61000/callback#x'), false);
  assert.equal(redirectMatches(reg, 'http://localhost:25179/callback'), false);
  assert.equal(redirectMatches(reg, 'http://[::1]:25179/callback'), false);
  assert.equal(redirectMatches(reg, 'http://evil.com:25179/callback'), false);
  assert.equal(redirectMatches(reg, 'https://127.0.0.1:25179/callback'), false);
});

test('a non-loopback registration keeps exact matching, port included', () => {
  const web = 'https://claude.ai/api/mcp/auth_callback';
  assert.equal(redirectMatches(web, web), true);
  assert.equal(redirectMatches(web, 'https://claude.ai:8443/api/mcp/auth_callback'), false);
  assert.equal(redirectMatches(web, 'https://claude.ai/api/mcp/auth_callback/'), false);
  assert.equal(redirectMatches(web, 'https://api.claude.ai/api/mcp/auth_callback'), false);
  assert.equal(redirectMatches('https://claude.ai:443/cb', 'https://claude.ai/cb'), false);
});

test('registration refuses non-loopback http and off-allowlist https before touching the database', async () => {
  // Every refusal below returns before the first query, so a database that
  // throws on use proves none was attempted.
  const db = new Proxy(() => {}, {
    apply: () => {
      throw new Error('database touched');
    },
    get: () => {
      throw new Error('database touched');
    },
  }) as unknown as Db;
  const cfg = { redirectHosts: ['claude.ai', 'claude.com', 'chatgpt.com', 'openai.com'], maxClients: 50 };
  const svc = new OAuthService(cfg as OAuthConfig, db, {} as TokenMinter, null);

  let n = 0;
  for (const uri of [
    'http://evil.com/callback',
    'http://claude.ai/callback',
    'https://evil.com/callback',
    'ftp://127.0.0.1/callback',
    'http://user:pw@127.0.0.1/callback',
    'http://127.0.0.1:25179/callback#frag',
  ]) {
    // A fresh address each time keeps the per-IP registration limit out of it.
    const out = await svc.registerClient({ redirect_uris: [uri] }, `203.0.113.${++n}`);
    assert.equal((out as { error?: string }).error, 'invalid_redirect_uri', uri);
  }
});
