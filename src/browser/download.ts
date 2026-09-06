// Getting the bytes of a file rather than the render of a page.
//
// A PDF or a spreadsheet is not something the browser can hand back as text.
// Chrome either draws it in a plugin, where the DOM holds an `<embed>` and
// nothing else, or refuses it as a download, where nothing lands at all. Either
// way the useful thing is the file itself, and there are two ways to get it.
//
// The first is free: the navigation already happened, so the response Chrome
// received is still there to be read. The second is a request made through the
// session's own context, which matters more than it sounds: it carries the
// cookies the session has collected, so a document behind a login is reachable
// on exactly the terms the pages before it were. Both leave through the same
// forward proxy as everything else, so the egress guard sees them.
//
// What this does not carry is Chrome's TLS handshake: an APIRequestContext
// request is made by the browser server process using Node's TLS stack, the
// same limitation ghost_curl has. A site fingerprinting the handshake will see
// the difference even though the cookies and the headers are right.

import type { Page, Response } from 'playwright-core';
import { log, errFields } from '../util/log.js';
import { precheckUrl } from './navigate.js';
import type { Session } from './sessions.js';

export interface FetchedBytes {
  bytes: Buffer;
  /** What the server called it. Believed for nothing but the log. */
  contentType: string;
  finalUrl: string;
  status: number;
  /** From Content-Disposition, when the server offered one. */
  filename: string | null;
}

export class DocumentTooLarge extends Error {
  constructor(
    readonly declared: number,
    readonly limit: number,
  ) {
    super(
      `the file is ${Math.round(declared / 1024 / 1024)} MB, over the ${Math.round(limit / 1024 / 1024)} MB ` +
        'this relay will pull down',
    );
    this.name = 'DocumentTooLarge';
  }
}

export interface BytesOptions {
  maxBytes: number;
  timeoutMs: number;
  maxRedirects: number;
  allowHosts: Set<string>;
}

/**
 * The body of a navigation Chrome already made.
 *
 * Free when it works, and not always available: a response whose body Chrome
 * has evicted, or that never completed, throws, so the caller falls back.
 */
export async function bytesFromResponse(response: Response, maxBytes: number): Promise<Buffer | null> {
  const declared = Number(response.headers()['content-length'] ?? NaN);
  if (Number.isFinite(declared) && declared > maxBytes) throw new DocumentTooLarge(declared, maxBytes);
  try {
    const body = await response.body();
    if (body.byteLength > maxBytes) throw new DocumentTooLarge(body.byteLength, maxBytes);
    return body.byteLength > 0 ? body : null;
  } catch (e) {
    if (e instanceof DocumentTooLarge) throw e;
    log.debug('navigation response body unavailable', errFields(e));
    return null;
  }
}

/**
 * Fetch a URL through a session's context, with its cookies.
 *
 * The size check happens twice for a reason. Content-Length is a claim by the
 * server, and refusing on it saves pulling down a file nobody can use; the
 * check after the body arrives is the one that holds, because a server that
 * wants to flood us simply omits the header.
 */
export async function fetchBytes(session: Session, url: string, opts: BytesOptions): Promise<FetchedBytes> {
  // The proxy is the control that actually holds. This is here so a private
  // address fails as "refused" rather than as a connection error from inside
  // Playwright's fetch stack, where the reason would be lost.
  await precheckUrl(url, opts.allowHosts);

  const response = await session.context.request.get(url, {
    timeout: opts.timeoutMs,
    maxRedirects: opts.maxRedirects,
    failOnStatusCode: false,
    headers: {
      // A request that claims to accept only HTML gets an HTML error page from
      // servers that content-negotiate.
      Accept: 'application/pdf,application/vnd.openxmlformats-officedocument.*,application/*,*/*;q=0.8',
      'Sec-Fetch-Dest': 'document',
      'Sec-Fetch-Mode': 'navigate',
      'Sec-Fetch-Site': 'same-origin',
    },
  });

  try {
    const headers = response.headers();
    const declared = Number(headers['content-length'] ?? NaN);
    if (Number.isFinite(declared) && declared > opts.maxBytes) {
      throw new DocumentTooLarge(declared, opts.maxBytes);
    }

    const bytes = await response.body();
    if (bytes.byteLength > opts.maxBytes) throw new DocumentTooLarge(bytes.byteLength, opts.maxBytes);

    return {
      bytes,
      contentType: headers['content-type'] ?? '',
      finalUrl: response.url(),
      status: response.status(),
      filename: filenameFrom(headers['content-disposition'] ?? '', response.url()),
    };
  } finally {
    await response.dispose().catch(() => {});
  }
}

const PATH_SEPARATORS = /[\\/]/g;
const CONTROLS = /[\x00-\x1f\x7f]/g;

/**
 * A name for the file, for labelling only.
 *
 * The server picks this, so it is treated as a label and never as a path: no
 * directory separators survive, and it is never used to open anything. Nothing
 * in this relay writes a downloaded file to disk, which is what makes that safe
 * rather than merely careful.
 */
export function filenameFrom(disposition: string, url: string): string | null {
  const star = /filename\*\s*=\s*(?:UTF-8|utf-8)''([^;]+)/i.exec(disposition);
  const plain = /filename\s*=\s*(?:"([^"]*)"|([^;]+))/i.exec(disposition);
  let name: string | null = null;
  if (star?.[1]) {
    try {
      name = decodeURIComponent(star[1]);
    } catch {
      name = star[1];
    }
  } else if (plain) {
    name = (plain[1] ?? plain[2] ?? '').trim();
  }
  if (!name) {
    try {
      name = decodeURIComponent(new URL(url).pathname.split('/').pop() ?? '');
    } catch {
      name = null;
    }
  }
  if (!name) return null;
  const clean = name.replace(PATH_SEPARATORS, '_').replace(CONTROLS, '').replace(/^\.+/, '').trim().slice(0, 200);
  return clean || null;
}

/**
 * Note the downloads a page tries to start.
 *
 * Contexts are created with downloads refused, so nothing reaches this disk;
 * the event still fires and carries the URL, which is the part worth keeping.
 * A page that answers a click with a file then gets reported as such, instead
 * of looking like a click that did nothing.
 */
export function trackDownloads(page: Page, session: Session): void {
  page.on('download', (download) => {
    const url = download.url();
    session.downloads.push({ url, filename: download.suggestedFilename() || null, at: Date.now() });
    if (session.downloads.length > 20) session.downloads.shift();
    log.info('download refused', { session: session.id, url: url.slice(0, 300) });
    void download.cancel().catch(() => {});
  });
}
