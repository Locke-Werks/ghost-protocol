// HTTP surface of the authorization server. Handlers stay thin; every decision
// lives in OAuthService.
//
// CORS is a deliberate wildcard. Authentication here is always an explicit
// bearer token or a submitted password, never a cookie, so a cross-origin
// request has no ambient credential to ride on. Caddy host-matches the public
// name before proxying, which covers the DNS-rebinding case the MCP spec's
// Origin guidance is aimed at.

import type { Express, Request, Response } from 'express';
import type { OAuthConfig } from '../config.js';
import { renderError, renderLogin } from './pages.js';
import type { AuthorizeRequest, OAuthError, OAuthService } from './service.js';
import { log, errFields } from '../util/log.js';

function cors(res: Response): void {
  res.setHeader('Access-Control-Allow-Origin', '*');
}

function sendError(res: Response, e: OAuthError): void {
  cors(res);
  res.status(e.httpStatus).setHeader('Cache-Control', 'no-store');
  res.json({ error: e.error, error_description: e.description });
}

/**
 * The address Caddy actually saw.
 *
 * Caddy appends the real peer to whatever X-Forwarded-For the client sent, so
 * the leftmost hop is attacker-controlled and the rightmost is not. With exactly
 * one trusted proxy in front, the rightmost hop is the client, and that holds
 * whether Caddy overwrites the header or merely appends to it.
 */
export function clientIp(req: Request): string {
  const xff = req.headers['x-forwarded-for'];
  const value = Array.isArray(xff) ? xff[xff.length - 1] : xff;
  if (value) {
    const hops = value.split(',');
    const last = hops[hops.length - 1]?.trim();
    if (last) return last;
  }
  return req.socket.remoteAddress ?? 'unknown';
}

function paramsOf(req: Request): URLSearchParams {
  const out = new URLSearchParams();
  for (const [k, v] of Object.entries(req.query)) {
    if (typeof v === 'string') out.set(k, v);
  }
  const body = req.body as Record<string, unknown> | undefined;
  if (body && typeof body === 'object') {
    for (const [k, v] of Object.entries(body)) {
      if (typeof v === 'string') out.set(k, v);
    }
  }
  return out;
}

function deliverAuthorizeError(
  res: Response,
  req: AuthorizeRequest,
  error: OAuthError,
  redirectError: boolean,
): void {
  // Redirect only when the client's redirect_uri was verified. Bouncing an
  // error to an unverified URI is how an open redirector gets built.
  if (redirectError && req.redirectUri) {
    const url = new URL(req.redirectUri);
    url.searchParams.set('error', error.error);
    if (error.description) url.searchParams.set('error_description', error.description);
    if (req.state) url.searchParams.set('state', req.state);
    res.redirect(302, url.toString());
    return;
  }
  res.status(error.httpStatus).type('html').send(renderError('Cannot continue', error.description));
}

export function registerOAuthRoutes(app: Express, oauth: OAuthService, cfg: OAuthConfig): void {
  const serveDoc = (res: Response, doc: unknown) => {
    cors(res);
    res.setHeader('Cache-Control', 'public, max-age=3600');
    res.json(doc);
  };

  // ------------------------------------------------------------- discovery

  app.get('/.well-known/oauth-protected-resource', (_req, res) =>
    serveDoc(res, oauth.metadataProtectedResource()),
  );
  // Some clients append the resource path to the well-known name.
  app.get('/.well-known/oauth-protected-resource/mcp', (_req, res) =>
    serveDoc(res, oauth.metadataProtectedResource()),
  );
  app.get('/.well-known/oauth-authorization-server', (_req, res) =>
    serveDoc(res, oauth.metadataAuthorizationServer()),
  );
  app.get('/.well-known/oauth-authorization-server/mcp', (_req, res) =>
    serveDoc(res, oauth.metadataAuthorizationServer()),
  );
  // ChatGPT probes the OIDC document first. Same content: nothing here claims
  // anything beyond what RFC 8414 already shares with OIDC discovery.
  app.get('/.well-known/openid-configuration', (_req, res) =>
    serveDoc(res, oauth.metadataAuthorizationServer()),
  );
  app.get('/.well-known/jwks.json', (_req, res) => serveDoc(res, oauth.jwks()));

  // ------------------------------------------------------------- authorize

  app.get('/oauth/authorize', async (req, res) => {
    try {
      const v = await oauth.validateAuthorize(paramsOf(req));
      if (!v.ok) {
        deliverAuthorizeError(res, v.req, v.error!, v.redirectError ?? false);
        return;
      }
      res.setHeader('Cache-Control', 'no-store');
      res.type('html').send(renderLogin(v.req, ''));
    } catch (e) {
      log.error('authorize failed', errFields(e));
      res.status(500).type('html').send(renderError('Server error', 'Try again in a moment.'));
    }
  });

  app.post('/oauth/authorize', async (req, res) => {
    try {
      // The hidden fields in the posted form are client-supplied, so they are
      // revalidated exactly as if this were a fresh authorize request.
      const params = paramsOf(req);
      const v = await oauth.validateAuthorize(params);
      if (!v.ok) {
        deliverAuthorizeError(res, v.req, v.error!, v.redirectError ?? false);
        return;
      }

      const principal = params.get('principal') ?? '';
      // Bounded independently of the body cap. scrypt does not care about
      // length, so this is only about not copying an absurd input around.
      const password = (params.get('password') ?? '').slice(0, 1024);

      const outcome = await oauth.handleLogin(v.req, principal, password, clientIp(req));
      res.setHeader('Cache-Control', 'no-store');

      if (typeof outcome === 'string') {
        res.redirect(302, outcome);
        return;
      }
      if (outcome.httpStatus === 401) {
        // The 401 is load-bearing: the fail2ban jail counts these lines.
        res.status(401).type('html').send(renderLogin(v.req, outcome.description));
        return;
      }
      res.status(outcome.httpStatus).type('html').send(renderError('Cannot continue', outcome.description));
    } catch (e) {
      log.error('login failed', errFields(e));
      res.status(500).type('html').send(renderError('Server error', 'Try again in a moment.'));
    }
  });

  // ------------------------------------------------------ token + register

  app.post('/oauth/token', async (req, res) => {
    try {
      const outcome = await oauth.token(paramsOf(req), String(req.headers.authorization ?? ''));
      if ('httpStatus' in outcome) {
        sendError(res, outcome as OAuthError);
        return;
      }
      cors(res);
      res.setHeader('Cache-Control', 'no-store');
      res.setHeader('Pragma', 'no-cache');
      res.json(outcome);
    } catch (e) {
      log.error('token endpoint failed', errFields(e));
      sendError(res, { httpStatus: 500, error: 'server_error', description: 'try again in a moment' });
    }
  });

  app.post('/oauth/register', async (req, res) => {
    try {
      const body = req.body;
      if (!body || typeof body !== 'object' || Array.isArray(body)) {
        sendError(res, {
          httpStatus: 400,
          error: 'invalid_client_metadata',
          description: 'body must be a JSON object',
        });
        return;
      }
      const outcome = await oauth.registerClient(body as Record<string, unknown>, clientIp(req));
      if ('httpStatus' in outcome) {
        // Log the rejected shape so a connector whose registration we did not
        // anticipate is diagnosable without guesswork.
        log.warn('client registration rejected', {
          error: (outcome as OAuthError).error,
          description: (outcome as OAuthError).description,
          body: JSON.stringify(body).slice(0, 512),
        });
        sendError(res, outcome as OAuthError);
        return;
      }
      cors(res);
      res.status(201).setHeader('Cache-Control', 'no-store');
      res.json(outcome);
    } catch (e) {
      log.error('registration failed', errFields(e));
      sendError(res, { httpStatus: 500, error: 'server_error', description: 'try again in a moment' });
    }
  });

  // ------------------------------------------------------- CORS preflight

  const preflight = [
    '/mcp',
    '/oauth/token',
    '/oauth/register',
    '/.well-known/oauth-protected-resource',
    '/.well-known/oauth-protected-resource/mcp',
    '/.well-known/oauth-authorization-server',
    '/.well-known/oauth-authorization-server/mcp',
    '/.well-known/openid-configuration',
    '/.well-known/jwks.json',
  ];
  for (const path of preflight) {
    app.options(path, (_req, res) => {
      cors(res);
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
      res.setHeader(
        'Access-Control-Allow-Headers',
        'Authorization, Content-Type, MCP-Protocol-Version, Mcp-Session-Id, Last-Event-ID',
      );
      res.setHeader('Access-Control-Expose-Headers', 'WWW-Authenticate, Mcp-Session-Id');
      res.setHeader('Access-Control-Max-Age', '86400');
      res.status(204).end();
    });
  }

  void cfg;
}
