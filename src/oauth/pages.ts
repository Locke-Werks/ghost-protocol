// The login and error pages.
//
// Self-contained HTML with no external assets: the Caddy path allowlist in front
// of this server is deliberately narrow, and a page that reaches for a
// stylesheet would need a hole opened in it.

import type { AuthorizeRequest } from './service.js';

export function htmlEscape(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

const STYLE = `
  :root { color-scheme: light dark; --accent: #d6262a; }
  body { font: 16px/1.5 system-ui, -apple-system, Segoe UI, sans-serif;
         display: grid; place-items: center; min-height: 100vh; margin: 0;
         background: Canvas; color: CanvasText; }
  main, form { width: min(23rem, 90vw); padding: 2rem;
         border: 1px solid color-mix(in srgb, CanvasText 20%, transparent);
         border-radius: 12px; }
  h1 { font-size: 1.15rem; margin: 0 0 .25rem; letter-spacing: .01em; }
  p.sub { margin: 0 0 1.25rem; opacity: .7; font-size: .9rem; }
  label { display: block; font-size: .85rem; margin: .75rem 0 .25rem; }
  input[type=text], input[type=password] {
    width: 100%; box-sizing: border-box; padding: .55rem .7rem;
    border: 1px solid color-mix(in srgb, CanvasText 30%, transparent);
    border-radius: 8px; background: transparent; color: inherit; }
  button { width: 100%; margin-top: 1.25rem; padding: .6rem; border: 0;
           border-radius: 8px; font-weight: 600; font-size: 1rem;
           background: var(--accent); color: #fff; cursor: pointer; }
  p.err { color: var(--accent); font-size: .9rem; margin: 0 0 .5rem; }
  p.note { font-size: .8rem; opacity: .6; margin: 1.25rem 0 0; }
`;

export function renderLogin(req: AuthorizeRequest, errorMessage: string): string {
  const hidden = (
    [
      ['response_type', 'code'],
      ['client_id', req.clientId],
      ['redirect_uri', req.redirectUri],
      ['code_challenge', req.codeChallenge],
      ['code_challenge_method', 'S256'],
      ['state', req.state],
      ['resource', req.resource],
      ['scope', req.scope],
    ] as const
  )
    .filter(([, v]) => v)
    .map(([k, v]) => `<input type="hidden" name="${k}" value="${htmlEscape(v)}">`)
    .join('\n');

  const err = errorMessage ? `<p class="err">${htmlEscape(errorMessage)}</p>\n` : '';

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Ghost Protocol: sign in</title>
<style>${STYLE}</style></head><body>
<form method="post" action="/oauth/authorize" autocomplete="off">
<h1>Ghost Protocol</h1>
<p class="sub">Sign in to connect this assistant to the relay.</p>
${err}${hidden}
<label for="principal">Principal</label>
<input type="text" id="principal" name="principal" autofocus
       autocapitalize="none" autocorrect="off" spellcheck="false">
<label for="password">Password</label>
<input type="password" id="password" name="password">
<button type="submit">Sign in</button>
<p class="note">Grants read-only fetching. The relay retrieves pages on your
behalf and returns them as untrusted data.</p>
</form></body></html>
`;
}

export function renderError(title: string, detail: string): string {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Ghost Protocol: error</title>
<style>${STYLE}</style></head><body>
<main><h1>${htmlEscape(title)}</h1><p>${htmlEscape(detail)}</p></main>
</body></html>
`;
}
