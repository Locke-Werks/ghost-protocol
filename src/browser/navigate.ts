// Driving a page: navigation, the small set of interactions a session supports,
// and the read that follows.

import type { Page, Response } from 'playwright-core';
import type { Config } from '../config.js';
import { EgressDenied, resolveGuarded } from '../net/guard.js';
import { capturePage, primeLazyContent, type CaptureResult, type ScreenshotMode } from './capture.js';
import { extractPage, type PageExtract } from './extract.js';
import { log, errFields } from '../util/log.js';
import type { Session } from './sessions.js';

export type WaitUntil = 'load' | 'domcontentloaded' | 'networkidle';

export type Action =
  | { type: 'wait_ms'; ms: number }
  | { type: 'wait_for'; selector: string; timeout_ms?: number }
  | { type: 'click'; selector: string }
  | { type: 'click_text'; text: string }
  | { type: 'fill'; selector: string; text: string }
  | { type: 'press'; key: string; selector?: string }
  | { type: 'scroll'; to: 'top' | 'bottom' | number }
  | { type: 'navigate'; url: string }
  | { type: 'back' }
  | { type: 'forward' };

export interface ActionOutcome {
  action: string;
  ok: boolean;
  detail: string;
}

export interface ReadResult {
  extract: PageExtract;
  capture: CaptureResult;
  finalUrl: string;
  status: number | null;
  actions: ActionOutcome[];
}

/**
 * Reject a URL before the browser sees it.
 *
 * The proxy is the control that actually holds; this is here so a caller gets
 * "that host resolves to a private address" instead of a generic navigation
 * failure thirty seconds later.
 */
export async function precheckUrl(raw: string, allowHosts: Set<string>): Promise<URL> {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error(`not a URL: ${JSON.stringify(raw.slice(0, 200))}`);
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error(`only http and https are relayed, not ${url.protocol.replace(':', '')}`);
  }
  if (url.username || url.password) {
    throw new Error('credentials embedded in a URL are not relayed');
  }
  await resolveGuarded(url.hostname, allowHosts);
  return url;
}

/**
 * Chrome answered the navigation with a file instead of a page.
 *
 * Downloads are refused, so the navigation aborts and nothing lands. The URL is
 * carried here because the bytes are still fetchable, and for the formats this
 * relay reads that is the difference between a dead end and a document.
 */
export class NavigationBecameDownload extends Error {
  constructor(readonly url: string) {
    super(`navigation to ${url} was answered with a download rather than a page`);
    this.name = 'NavigationBecameDownload';
  }
}

export async function navigate(
  session: Session,
  url: string,
  waitUntil: WaitUntil,
  cfg: Config,
): Promise<Response | null> {
  await precheckUrl(url, cfg.egress.allowHosts);
  session.navigations++;
  const downloadsBefore = session.downloads.length;
  try {
    const response = await session.page.goto(url, {
      waitUntil,
      timeout: cfg.browser.navigationTimeoutMs,
    });
    session.currentUrl = session.page.url();
    return response;
  } catch (e) {
    if (e instanceof EgressDenied) throw e;
    const msg = e instanceof Error ? e.message : String(e);
    // A refusal from the guard surfaces as a Chrome network error, which on its
    // own reads like an outage. Say which it was.
    if (/ERR_TUNNEL_CONNECTION_FAILED|ERR_PROXY_CONNECTION_FAILED|ERR_EMPTY_RESPONSE/.test(msg)) {
      throw new Error(
        `navigation to ${url} was refused at the egress guard, or the host closed the connection. ` +
          'Private and reserved addresses are never relayed.',
      );
    }
    // ERR_ABORTED is what a refused download looks like from goto's side, and
    // it is also what a page that cancels its own navigation looks like. The
    // download event is what tells them apart, so it is checked rather than
    // assumed: guessing wrong here would turn an ordinary navigation failure
    // into a confusing "this is not a readable document".
    if (/ERR_ABORTED/.test(msg)) {
      const attempt = await waitForDownload(session, downloadsBefore, 1000);
      if (attempt) throw new NavigationBecameDownload(attempt.url);
    }
    throw new Error(`navigation to ${url} failed: ${msg}`);
  }
}

/**
 * Wait a moment for a download the navigation may have started.
 *
 * The failed navigation and the download notice are two protocol messages with
 * no ordering between them, so the event has often not been dispatched yet when
 * goto rejects. Polling briefly costs a second on the one path where a
 * navigation genuinely aborted for some other reason, and is the difference
 * between reading the file and reporting a dead end on the path that matters.
 */
async function waitForDownload(
  session: Session,
  since: number,
  timeoutMs: number,
): Promise<{ url: string } | null> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (session.downloads.length > since) return session.downloads[session.downloads.length - 1]!;
    if (Date.now() >= deadline) return null;
    await new Promise((r) => setTimeout(r, 50));
  }
}

export async function runActions(
  session: Session,
  actions: Action[],
  cfg: Config,
): Promise<ActionOutcome[]> {
  const page = session.page;
  const out: ActionOutcome[] = [];

  for (const a of actions) {
    const label = describe(a);
    try {
      switch (a.type) {
        case 'wait_ms':
          await page.waitForTimeout(Math.min(Math.max(a.ms, 0), 15_000));
          break;
        case 'wait_for':
          await page.waitForSelector(a.selector, {
            timeout: Math.min(a.timeout_ms ?? 10_000, 30_000),
            state: 'visible',
          });
          break;
        case 'click':
          await page.click(a.selector, { timeout: 10_000 });
          await settle(page);
          break;
        case 'click_text':
          // getByText matches what a reader sees, which is how a caller working
          // from a screenshot or the extracted markdown will describe a target.
          await page.getByText(a.text, { exact: false }).first().click({ timeout: 10_000 });
          await settle(page);
          break;
        case 'fill':
          await page.fill(a.selector, a.text.slice(0, 2000), { timeout: 10_000 });
          break;
        case 'press':
          if (a.selector) await page.press(a.selector, a.key, { timeout: 10_000 });
          else await page.keyboard.press(a.key);
          await settle(page);
          break;
        case 'scroll': {
          const to = a.to;
          await page.evaluate((target) => {
            if (target === 'top') window.scrollTo(0, 0);
            else if (target === 'bottom') window.scrollTo(0, document.documentElement.scrollHeight);
            else window.scrollTo(0, Number(target));
          }, to);
          await page.waitForTimeout(200);
          break;
        }
        case 'navigate':
          await navigate(session, a.url, 'domcontentloaded', cfg);
          break;
        case 'back':
          await page.goBack({ timeout: cfg.browser.navigationTimeoutMs });
          break;
        case 'forward':
          await page.goForward({ timeout: cfg.browser.navigationTimeoutMs });
          break;
      }
      session.currentUrl = page.url();
      out.push({ action: label, ok: true, detail: 'ok' });
    } catch (e) {
      const msg = e instanceof Error ? e.message.split('\n')[0]! : String(e);
      log.debug('action failed', { action: label, ...errFields(e) });
      out.push({ action: label, ok: false, detail: msg.slice(0, 300) });
      // Later actions usually assume the earlier ones landed, so stop rather
      // than running the rest against a page that is not where it should be.
      break;
    }
  }
  return out;
}

function describe(a: Action): string {
  switch (a.type) {
    case 'wait_ms':
      return `wait_ms ${a.ms}`;
    case 'wait_for':
      return `wait_for ${a.selector}`;
    case 'click':
      return `click ${a.selector}`;
    case 'click_text':
      return `click_text ${JSON.stringify(a.text.slice(0, 60))}`;
    case 'fill':
      return `fill ${a.selector}`;
    case 'press':
      return `press ${a.key}`;
    case 'scroll':
      return `scroll ${a.to}`;
    case 'navigate':
      return `navigate ${a.url}`;
    default:
      return a.type;
  }
}

/** Give a click that started a navigation or an XHR a moment to land. */
async function settle(page: Page): Promise<void> {
  await page.waitForLoadState('domcontentloaded', { timeout: 15_000 }).catch(() => {});
  await page.waitForTimeout(350);
}

export interface ReadOptions {
  screenshot: ScreenshotMode;
  maxTiles: number;
  maxLinks: number;
}

export async function readPage(
  session: Session,
  status: number | null,
  actions: ActionOutcome[],
  opts: ReadOptions,
  cfg: Config,
): Promise<ReadResult> {
  const page = session.page;

  if (opts.screenshot === 'full') await primeLazyContent(page);

  // Screenshot first, and the order is load-bearing. Extraction strips the live
  // DOM, every <style> and stylesheet <link> among them, so a capture taken
  // afterwards would be a picture of unstyled HTML rather than of the page.
  //
  // The two halves therefore describe the page at the same moment but not the
  // same way, which is the useful arrangement: the screenshot is what a person
  // at a browser would see, the text is everything the DOM carried, and
  // `hidden` below is the gap between them.
  const capture = await capturePage(page, {
    mode: opts.screenshot,
    width: cfg.capture.width,
    tileHeight: cfg.capture.tileHeight,
    maxTiles: Math.min(opts.maxTiles, cfg.capture.maxTiles),
    webpQuality: cfg.capture.webpQuality,
  }).catch((e) => {
    log.warn('capture failed', errFields(e));
    return {
      tiles: [],
      pageHeight: 0,
      capturedHeight: 0,
      omittedTiles: 0,
      width: 0,
      bytes: 0,
    } satisfies CaptureResult;
  });

  const extract = await extractPage(page, opts.maxLinks).catch((e) => {
    log.warn('extraction failed', errFields(e));
    return {
      title: '',
      byline: null,
      excerpt: null,
      siteName: null,
      lang: null,
      markdown: '',
      text: '',
      html: '',
      links: [],
      hidden: [],
      metrics: { scrollHeight: 0, scrollWidth: 0 },
    } satisfies PageExtract;
  });

  session.title = extract.title;
  session.currentUrl = page.url();

  return { extract, capture, finalUrl: page.url(), status, actions };
}
