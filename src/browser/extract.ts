// Turning a rendered page into something an agent can read.
//
// The split between what runs in the page and what runs here is a security
// boundary, not a convenience. In-page code needs the live DOM for two things
// only: computed styles (deciding what a human can actually see) and the
// Readability/Turndown conversion. Everything a hostile page would want to
// suppress — the control-character strip, the injection scan, the size cap, the
// envelope that labels the result as untrusted — runs here in Node, afterwards,
// on the returned string. A page can choose what text it hands us. It cannot
// reach the code that decides how that text is labelled.

import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import type { Page } from 'playwright-core';

const require_ = createRequire(import.meta.url);

// Read once at startup. Injected with addInitScript, which runs through CDP
// before the document exists and so is not subject to the page's CSP.
export const READABILITY_SRC = readFileSync(
  require_.resolve('@mozilla/readability/Readability.js'),
  'utf8',
);
export const TURNDOWN_SRC = readFileSync(
  require_.resolve('turndown/lib/turndown.browser.umd.js'),
  'utf8',
);

export interface HiddenRemoval {
  tag: string;
  reason: string;
  /** Enough of the hidden text to scan and to show. */
  sample: string;
  /**
   * Whether the way it was hidden is a concealment technique or ordinary web
   * design. A collapsed nav menu and a paragraph of white-on-white text are
   * both invisible; only one of them is interesting.
   */
  concealment: boolean;
}

export interface PageExtract {
  title: string;
  byline: string | null;
  excerpt: string | null;
  siteName: string | null;
  lang: string | null;
  markdown: string;
  text: string;
  /** Structurally cleaned HTML: no scripts, styles, comments, or hidden nodes. */
  html: string;
  links: Array<{ text: string; href: string }>;
  /** Text a human would never see, pulled out before extraction. */
  hidden: HiddenRemoval[];
  metrics: { scrollHeight: number; scrollWidth: number };
}

/**
 * The in-page half. Stringified and shipped to the browser, so it may not
 * reference anything in this module's scope.
 */
function inPage(options: { maxLinks: number }): unknown {
  const HIDDEN: Array<{ tag: string; reason: string; sample: string; concealment: boolean }> = [];

  const STRIP_TAGS = [
    'script', 'style', 'noscript', 'template', 'iframe', 'object', 'embed',
    'applet', 'link', 'meta', 'svg', 'canvas', 'audio', 'video',
    'form', 'input', 'button', 'select', 'textarea',
  ];

  // Long enough to scan for an injected instruction, short enough to print.
  const sample = (el: Element) => (el.textContent || '').replace(/\s+/g, ' ').trim().slice(0, 600);

  // Techniques with no purpose but to keep text away from a human reader while
  // leaving it in the DOM. `display:none` is not on this list: it is how every
  // collapsed menu and inactive tab panel on the web is built.
  const CONCEALMENT = /^(positioned off-canvas|text colour matches background|font-size|opacity:0|zero-size box)/;

  // A subtree with controls in it is interface, not prose. A hidden nav has
  // links and buttons; a smuggled paragraph does not.
  const INTERACTIVE = 'a,button,input,select,textarea,summary,[role=menu],[role=menuitem],[role=dialog],[role=tab],[role=tabpanel],[role=listbox],[role=option]';

  function isConcealment(el: Element, reason: string): boolean {
    const words = (el.textContent || '').trim().split(/\s+/).length;
    if (CONCEALMENT.test(reason)) {
      // A colour match on two words of link text is a theme artefact, not a
      // smuggled instruction: there is no room in it for one.
      if (reason.startsWith('text colour') && words < 8) return false;
      return true;
    }
    // Otherwise it was hidden the ordinary way. That is only interesting when
    // what is hidden reads like prose rather than like a control.
    if (el.querySelector(INTERACTIVE) || el.matches(INTERACTIVE)) return false;
    return words >= 15;
  }

  // Elements a person looking at this page in a browser would not read.
  // Invisible text is the most common way an instruction gets smuggled into a
  // page: white-on-white, a zero-height div, an element parked at -9999px. A
  // reader never sees it and an extractor that walks the DOM naively picks it
  // up as ordinary prose.
  function whyHidden(el: Element): string | null {
    const st = getComputedStyle(el);
    if (st.display === 'none') return 'display:none';
    if (st.visibility === 'hidden' || st.visibility === 'collapse') return 'visibility:' + st.visibility;
    if (parseFloat(st.opacity) === 0) return 'opacity:0';
    const fs = parseFloat(st.fontSize);
    if (fs > 0 && fs < 4) return 'font-size:' + st.fontSize;
    if (st.clipPath === 'inset(100%)') return 'clipped';
    if (el.hasAttribute('hidden')) return 'hidden attribute';
    if (el.getAttribute('aria-hidden') === 'true') return 'aria-hidden';

    const r = (el as HTMLElement).getBoundingClientRect();
    const docW = Math.max(document.documentElement.scrollWidth, 1);
    if (r.width === 0 || r.height === 0) {
      return (el.textContent || '').trim().length > 0 ? 'zero-size box' : null;
    }
    // Parked outside the document: the -9999px trick and its cousins.
    if (r.right < -200 || r.bottom < -2000 || r.left > docW + 2000) return 'positioned off-canvas';

    // Text the same colour as what is behind it. Walks up for the background
    // because the element itself is usually transparent.
    const fg = st.color;
    let bgEl: Element | null = el;
    let bg = '';
    while (bgEl) {
      const c = getComputedStyle(bgEl).backgroundColor;
      if (c && c !== 'rgba(0, 0, 0, 0)' && c !== 'transparent') { bg = c; break; }
      bgEl = bgEl.parentElement;
    }
    if (!bg) bg = 'rgb(255, 255, 255)';
    if (fg && fg.replace(/\s/g, '') === bg.replace(/\s/g, '')) return 'text colour matches background';
    return null;
  }

  // Visibility has to be judged on the live document, because a detached clone
  // has no layout and getComputedStyle returns nothing useful. But the live
  // document has to survive: this page may be a session the caller is still
  // clicking through, and an extractor that strips its stylesheets leaves them
  // driving a wreck.
  //
  // So the live DOM is only ever marked, never cut. The marks name what to drop
  // from the clone, and come off again before this function returns.
  const doc = document;
  const MARK = 'data-ghost-hidden';

  // Everything in STRIP_TAGS is dropped from the clone regardless, and a <script>
  // is display:none by definition. Walking them here reports every inline script
  // on the page as concealed text, which is noise that buries the real finding.
  const SKIP_WALK = new Set(STRIP_TAGS.map((t) => t.toUpperCase()));

  const marked: Element[] = [];
  for (const el of Array.from(doc.body ? doc.body.querySelectorAll('*') : [])) {
    if (SKIP_WALK.has(el.tagName)) continue;
    if ((el.textContent || '').trim().length === 0) continue;
    // Only the outermost hidden element is reported. querySelectorAll walks in
    // document order, so an ancestor is always seen first; without this a single
    // hidden panel arrives as one finding per node inside it and a page shows
    // forty "concealed elements" that are one collapsed menu.
    // No mark needed on the descendant itself: removing the marked ancestor
    // from the clone takes the whole subtree with it, and the link filter
    // below asks the same question with closest().
    if (el.closest('[' + MARK + ']')) continue;
    const reason = whyHidden(el);
    if (reason) {
      HIDDEN.push({
        tag: el.tagName.toLowerCase(),
        reason,
        sample: sample(el),
        concealment: isConcealment(el, reason),
      });
      el.setAttribute(MARK, reason);
      marked.push(el);
      if (HIDDEN.length >= 200) break;
    }
  }

  const links: Array<{ text: string; href: string }> = [];
  const seen = new Set<string>();
  for (const a of Array.from(doc.querySelectorAll('a[href]')).slice(0, 4000)) {
    if (a.closest('[' + MARK + ']')) continue;
    const href = (a as HTMLAnchorElement).href;
    if (!href || !/^https?:/i.test(href) || seen.has(href)) continue;
    seen.add(href);
    links.push({ text: (a.textContent || '').replace(/\s+/g, ' ').trim().slice(0, 200), href });
    if (links.length >= options.maxLinks) break;
  }

  // Everything from here works on the copy.
  const clone = doc.cloneNode(true) as Document;
  for (const el of Array.from(clone.querySelectorAll('[' + MARK + ']'))) el.remove();
  for (const tag of STRIP_TAGS) {
    for (const el of Array.from(clone.getElementsByTagName(tag))) el.remove();
  }

  // HTML comments render as nothing and survive most text extraction, which
  // makes them a comfortable place to park a paragraph aimed at a machine.
  if (clone.documentElement) {
    const walker = clone.createTreeWalker(clone.documentElement, NodeFilter.SHOW_COMMENT);
    const comments: Comment[] = [];
    while (walker.nextNode()) comments.push(walker.currentNode as Comment);
    for (const c of comments) {
      const t = (c.nodeValue || '').replace(/\s+/g, ' ').trim();
      // A comment long enough to be prose rather than a build artefact.
      if (t.length > 80) {
        HIDDEN.push({ tag: '#comment', reason: 'html comment', sample: t.slice(0, 600), concealment: true });
      }
      c.remove();
    }
  }

  const cleanedHtml = clone.documentElement ? clone.documentElement.outerHTML : '';
  const plainText = clone.body ? clone.body.textContent || '' : '';

  let title = doc.title || '';
  let byline: string | null = null;
  let excerpt: string | null = null;
  let siteName: string | null = null;
  let articleHtml = '';

  try {
    const R = (self as unknown as { Readability?: new (d: Document, o: unknown) => { parse(): Record<string, string> | null } }).Readability;
    if (R) {
      // Readability rewrites the document it is handed, so it gets its own copy
      // rather than the one cleanedHtml was taken from.
      const article = new R(clone.cloneNode(true) as Document, { charThreshold: 200 }).parse();
      if (article) {
        title = article.title || title;
        byline = article.byline || null;
        excerpt = article.excerpt || null;
        siteName = article.siteName || null;
        articleHtml = article.content || '';
      }
    }
  } catch {
    // A page Readability cannot make sense of still has cleanedHtml.
  }

  let markdown = '';
  try {
    const TD = (self as unknown as { TurndownService?: new (o: unknown) => { turndown(h: string): string; addRule(n: string, r: unknown): void } }).TurndownService;
    if (TD) {
      const td = new TD({
        headingStyle: 'atx',
        codeBlockStyle: 'fenced',
        bulletListMarker: '-',
        emDelimiter: '*',
      });
      // Images become their alt text. A src is a URL the agent did not ask for,
      // and alt text is exactly where a caption-shaped instruction would live,
      // so it is kept but marked rather than emitted as markdown image syntax.
      td.addRule('imageAsAlt', {
        filter: 'img',
        replacement: (_c: string, node: Element) => {
          const alt = (node.getAttribute('alt') || '').replace(/\s+/g, ' ').trim();
          return alt ? '[image: ' + alt + ']' : '';
        },
      });
      markdown = td.turndown(articleHtml || (clone.body ? clone.body.innerHTML : ''));
    }
  } catch {
    // Fall through to plain text.
  }

  // Hand the page back the way it was found.
  for (const el of marked) el.removeAttribute(MARK);

  return {
    title,
    byline,
    excerpt,
    siteName,
    lang: doc.documentElement ? doc.documentElement.lang || null : null,
    markdown,
    text: plainText,
    html: articleHtml || cleanedHtml,
    links,
    hidden: HIDDEN.slice(0, 40),
    metrics: {
      scrollHeight: doc.documentElement ? doc.documentElement.scrollHeight : 0,
      scrollWidth: doc.documentElement ? doc.documentElement.scrollWidth : 0,
    },
  };
}

export async function extractPage(page: Page, maxLinks = 200): Promise<PageExtract> {
  return (await page.evaluate(inPage as never, { maxLinks })) as PageExtract;
}
