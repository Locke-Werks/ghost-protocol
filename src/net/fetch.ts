// A plain HTTP request with no browser attached: what the page's server sends
// before any JavaScript touches it.
//
// This is the cheap path and it is genuinely useful — JSON APIs, robots.txt,
// llms.txt, a raw markdown file, checking whether a block is served at the HTTP
// layer or drawn by a script. It is not a substitute for the browser path
// against anything that fingerprints the TLS handshake: these bytes come from
// Node's TLS stack, not Chrome's, and no header will make the ClientHello agree
// with the User-Agent above it.

import { request as httpRequest, type IncomingMessage } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { brotliDecompress, gunzip, inflate } from 'node:zlib';
import { promisify } from 'node:util';
import { EgressDenied, resolveGuarded } from './guard.js';

const gunzipAsync = promisify(gunzip);
const inflateAsync = promisify(inflate);
const brotliAsync = promisify(brotliDecompress);

export interface FetchOptions {
  method: 'GET' | 'HEAD';
  userAgent: string;
  chromeMajor: string;
  allowHosts: Set<string>;
  maxBytes: number;
  timeoutMs: number;
  maxRedirects: number;
  extraHeaders?: Record<string, string>;
  /**
   * A larger cap for a body that is not text.
   *
   * A PDF has no business being measured against the same limit as a page of
   * markdown, and the two cannot be told apart before the request is made — the
   * Content-Type arrives with the headers, ahead of the body, which is late
   * enough to choose a cap and early enough to still enforce one.
   */
  maxBinaryBytes?: number;
}

export interface HopRecord {
  url: string;
  status: number;
  location?: string;
}

export interface FetchResult {
  finalUrl: string;
  status: number;
  statusText: string;
  headers: Record<string, string>;
  /** The body as text, bounded by `maxBytes` whatever `bytes` holds. */
  body: string;
  /** The body before any decoding, for a caller that wants the file itself. */
  bytes: Buffer;
  bodyBytes: number;
  /** Whether `bytes` was cut short. */
  truncated: boolean;
  /** Every redirect followed, each of which was guarded in its own right. */
  hops: HopRecord[];
  contentType: string;
}

/** Content types whose bodies are text and are capped as text. */
const TEXTUAL = /^(text\/|application\/(json|xml|javascript|x-ndjson|xhtml\+xml)|[^/]+\/[^;]*\+(json|xml))/i;

function chromeHeaders(o: FetchOptions, url: URL): Record<string, string> {
  const brand = `"Not=A?Brand";v="24", "Chromium";v="${o.chromeMajor}", "Google Chrome";v="${o.chromeMajor}"`;
  return {
    Host: url.host,
    'User-Agent': o.userAgent,
    Accept:
      'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'Accept-Language': 'en-US,en;q=0.9',
    'Accept-Encoding': 'gzip, deflate, br',
    'sec-ch-ua': brand,
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'Sec-Fetch-Site': 'none',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-User': '?1',
    'Sec-Fetch-Dest': 'document',
    'Upgrade-Insecure-Requests': '1',
    Connection: 'close',
    ...(o.extraHeaders ?? {}),
  };
}

export async function guardedFetch(rawUrl: string, o: FetchOptions): Promise<FetchResult> {
  let url = new URL(rawUrl);
  const hops: HopRecord[] = [];

  for (let hop = 0; hop <= o.maxRedirects; hop++) {
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      throw new EgressDenied(url.hostname, `only http and https are relayed, not ${url.protocol.replace(':', '')}`);
    }
    if (url.username || url.password) {
      throw new EgressDenied(url.hostname, 'credentials embedded in a URL are not relayed');
    }

    // Every hop is resolved and checked on its own. A redirect is the classic
    // way past a check performed only on the URL the caller typed: the first
    // host is public and answers 302 to something on 169.254.169.254.
    const target = await resolveGuarded(url.hostname, o.allowHosts);
    const res = await once(url, target.pinned, target.family, o);

    const status = res.statusCode ?? 0;
    const location = firstHeader(res.headers['location']);

    if (status >= 300 && status < 400 && location) {
      res.resume(); // drain, we are not reading this body
      hops.push({ url: url.toString(), status, location });
      if (hop === o.maxRedirects) {
        throw new Error(`too many redirects (stopped after ${o.maxRedirects})`);
      }
      url = new URL(location, url);
      continue;
    }

    const contentType = firstHeader(res.headers['content-type']) ?? '';
    const cap =
      o.maxBinaryBytes && contentType && !TEXTUAL.test(contentType.trim())
        ? Math.max(o.maxBytes, o.maxBinaryBytes)
        : o.maxBytes;

    const { buffer, bytes, truncated } = await readBody(res, cap, o.method === 'HEAD');
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries(res.headers)) {
      headers[k] = Array.isArray(v) ? v.join(', ') : String(v ?? '');
    }

    return {
      finalUrl: url.toString(),
      status,
      statusText: res.statusMessage ?? '',
      headers,
      // The text view stays under the text cap even when the buffer was allowed
      // past it, so a 25 MB PDF fetched for the document reader is not also
      // decoded into a 25 MB string nobody is going to read. That only clips on
      // the binary path, where this field goes unused.
      body: (buffer.length > o.maxBytes ? buffer.subarray(0, o.maxBytes) : buffer).toString('utf8'),
      bytes: buffer,
      bodyBytes: bytes,
      truncated,
      hops,
      contentType,
    };
  }
  throw new Error('redirect loop');
}

function firstHeader(v: string | string[] | undefined): string | undefined {
  return Array.isArray(v) ? v[0] : v;
}

function once(url: URL, pinned: string, family: 4 | 6, o: FetchOptions): Promise<IncomingMessage> {
  const isHttps = url.protocol === 'https:';
  const send = isHttps ? httpsRequest : httpRequest;

  return new Promise((resolve, reject) => {
    const req = send(
      {
        // Connect to the address that was checked, and tell TLS the name it
        // should be validating against. Without servername a pinned-IP request
        // over https fails certificate verification on every virtual host.
        host: pinned,
        family,
        port: url.port ? Number(url.port) : isHttps ? 443 : 80,
        path: url.pathname + url.search,
        method: o.method,
        headers: chromeHeaders(o, url),
        servername: isHttps ? url.hostname : undefined,
        // A redirect is followed by this function, not by the agent, so each
        // hop passes the guard.
        setHost: false,
        timeout: o.timeoutMs,
      },
      resolve,
    );
    req.on('timeout', () => req.destroy(new Error(`timed out after ${o.timeoutMs}ms`)));
    req.on('error', reject);
    req.end();
  });
}

async function readBody(
  res: IncomingMessage,
  maxBytes: number,
  skip: boolean,
): Promise<{ buffer: Buffer; bytes: number; truncated: boolean }> {
  if (skip) {
    res.resume();
    return { buffer: Buffer.alloc(0), bytes: 0, truncated: false };
  }

  const chunks: Buffer[] = [];
  let bytes = 0;
  let truncated = false;

  await new Promise<void>((resolve, reject) => {
    res.on('data', (c: Buffer) => {
      bytes += c.length;
      // Compressed bodies expand, so the cap is applied again after decoding.
      if (bytes > maxBytes * 8) {
        truncated = true;
        res.destroy();
        resolve();
        return;
      }
      chunks.push(c);
    });
    res.on('end', () => resolve());
    res.on('error', reject);
    res.on('aborted', () => resolve());
  });

  let raw = Buffer.concat(chunks);
  const encoding = (firstHeader(res.headers['content-encoding']) ?? '').toLowerCase();
  try {
    if (encoding.includes('br')) raw = await brotliAsync(raw);
    else if (encoding.includes('gzip')) raw = await gunzipAsync(raw);
    else if (encoding.includes('deflate')) raw = await inflateAsync(raw);
  } catch {
    // A body that will not decode is returned as-is; the caller sees the
    // Content-Encoding header and can draw its own conclusion.
  }

  if (raw.length > maxBytes) {
    raw = raw.subarray(0, maxBytes);
    truncated = true;
  }
  return { buffer: raw, bytes, truncated };
}
