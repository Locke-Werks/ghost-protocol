// Browser lifecycle: the connection to the browser process, and the sessions
// layered on top of it.
//
// The browser itself runs under a different account, in its own systemd unit,
// and is reached over a loopback websocket. That separation is the point: the
// process that renders hostile pages holds no database credential, no OAuth
// signing key, and no read access to /etc/ghost-protocol. A renderer compromise
// that escaped Chrome's own sandbox would land on an account that owns nothing.
//
// Every session gets its own BrowserContext, which is Chromium's isolation
// boundary for cookies, storage and permissions. Contexts are never reused
// across sessions and never outlive one, so nothing a page leaves behind is
// visible to the next fetch, and two principals cannot see each other's state.

import { chromium, type Browser, type BrowserContext, type Page } from 'playwright-core';
import { randomUUID } from 'node:crypto';
import type { Config } from '../config.js';
import { log, errFields } from '../util/log.js';
import { applyIdentity, buildIdentity, INIT_SCRIPT, type Identity } from './fingerprint.js';
import { READABILITY_SRC, TURNDOWN_SRC } from './extract.js';

export interface EgressEvent {
  host: string;
  port: number;
  allowed: boolean;
  reason?: string;
  at: number;
}

export interface Session {
  id: string;
  principal: string;
  context: BrowserContext;
  page: Page;
  createdAt: number;
  lastUsedAt: number;
  /** Where the page currently is, for `ghost_sessions`. */
  currentUrl: string;
  title: string;
  /** Hosts this session reached, allowed or refused. */
  egress: EgressEvent[];
  navigations: number;
  /** What the last navigation has to say about how far the page got. */
  navNotes: string[];
}

export class SessionLimit extends Error {}

export interface ProxyCredentials {
  server: string;
  username: string;
  password: string;
}

export class BrowserRuntime {
  private browser: Browser | null = null;
  private identityValue: Identity | null = null;
  private connecting: Promise<Browser> | null = null;
  private readonly sessions = new Map<string, Session>();
  private sweeper: NodeJS.Timeout | null = null;

  constructor(
    private readonly cfg: Config,
    private readonly proxy: ProxyCredentials,
  ) {}

  start(): void {
    // One sweep a minute is enough for timeouts measured in minutes, and it
    // keeps a stuck session from holding a browser context indefinitely.
    this.sweeper = setInterval(() => void this.sweep(), 30_000);
    this.sweeper.unref();
  }

  async stop(): Promise<void> {
    if (this.sweeper) clearInterval(this.sweeper);
    this.sweeper = null;
    for (const id of [...this.sessions.keys()]) await this.close(id).catch(() => {});
    await this.browser?.close().catch(() => {});
    this.browser = null;
  }

  /**
   * Connect on demand and hold the connection.
   *
   * A dropped websocket means the browser unit restarted; the next call
   * reconnects rather than failing for the rest of the process's life.
   */
  private async connect(): Promise<Browser> {
    if (this.browser?.isConnected()) return this.browser;
    if (this.connecting) return this.connecting;

    this.connecting = (async () => {
      log.info('connecting to browser', { endpoint: redactWs(this.cfg.browser.wsEndpoint) });
      const browser = await chromium.connect(this.cfg.browser.wsEndpoint, { timeout: 20_000 });
      browser.on('disconnected', () => {
        log.warn('browser disconnected');
        this.browser = null;
        this.identityValue = null;
        // Contexts died with it; drop the bookkeeping so the limits are honest.
        this.sessions.clear();
      });
      this.browser = browser;
      this.identityValue = buildIdentity(browser.version(), this.cfg.browser.userAgent);
      log.info('browser connected', {
        version: browser.version(),
        user_agent: this.identityValue.userAgent,
      });
      return browser;
    })();

    try {
      return await this.connecting;
    } finally {
      this.connecting = null;
    }
  }

  async open(principal: string): Promise<Session> {
    const browser = await this.connect();
    this.enforceLimits(principal);

    const context = await browser.newContext({
      viewport: { width: this.cfg.browser.viewportWidth, height: this.cfg.browser.viewportHeight },
      deviceScaleFactor: 1,
      locale: this.cfg.browser.locale,
      timezoneId: this.cfg.browser.timezone,
      userAgent: this.identityValue!.userAgent,
      colorScheme: 'light',
      // Init scripts and page.evaluate have to work on sites that forbid inline
      // script. Nothing here carries a credential or a session worth defending
      // with the page's own CSP, and every request still leaves through the
      // egress guard regardless of what the page is allowed to load.
      bypassCSP: true,
      // A page must not be able to put a file on this disk.
      acceptDownloads: false,
      // Service workers outlive the navigation that registered them and keep
      // making requests afterwards. A session's network activity should end
      // when the session does.
      serviceWorkers: 'block',
      // Certificate errors are a reason to stop, not a warning to skip past.
      ignoreHTTPSErrors: false,
      permissions: [],
      extraHTTPHeaders: {
        'Accept-Language': 'en-US,en;q=0.9',
        'Upgrade-Insecure-Requests': '1',
      },
      proxy: {
        server: this.proxy.server,
        username: this.proxy.username,
        password: this.proxy.password,
      },
    });

    context.setDefaultNavigationTimeout(this.cfg.browser.navigationTimeoutMs);
    context.setDefaultTimeout(Math.min(this.cfg.browser.navigationTimeoutMs, 20_000));

    // Injected before any page script so the extractor's tools are present even
    // on a page that would refuse a script tag.
    await context.addInitScript({ content: INIT_SCRIPT });
    await context.addInitScript({ content: READABILITY_SRC });
    await context.addInitScript({ content: TURNDOWN_SRC });

    const page = await context.newPage();
    await applyIdentity(context, page, this.identityValue!);

    // A page cannot be allowed to stop a capture by opening a modal.
    page.on('dialog', (d) => void d.dismiss().catch(() => {}));
    // Popups become ordinary pages we never look at; closing them keeps the
    // context from accumulating renderers.
    page.on('popup', (p) => void p.close().catch(() => {}));

    const now = Date.now();
    const session: Session = {
      id: randomUUID(),
      principal,
      context,
      page,
      createdAt: now,
      lastUsedAt: now,
      currentUrl: 'about:blank',
      title: '',
      egress: [],
      navigations: 0,
      navNotes: [],
    };
    this.sessions.set(session.id, session);
    log.info('session opened', { session: session.id, principal, total: this.sessions.size });
    return session;
  }

  private enforceLimits(principal: string): void {
    if (this.sessions.size >= this.cfg.sessions.maxTotal) {
      // Evict the least recently used before refusing: a caller that forgot to
      // close should degrade the service, not stop it.
      const lru = [...this.sessions.values()].sort((a, b) => a.lastUsedAt - b.lastUsedAt)[0];
      if (lru && Date.now() - lru.lastUsedAt > 60_000) {
        log.info('evicting idle session to make room', { session: lru.id });
        void this.close(lru.id);
      } else {
        throw new SessionLimit(
          `the relay is holding its maximum of ${this.cfg.sessions.maxTotal} browser sessions; ` +
            'close one with ghost_close and retry',
        );
      }
    }
    const mine = [...this.sessions.values()].filter((s) => s.principal === principal).length;
    if (mine >= this.cfg.sessions.maxPerPrincipal) {
      throw new SessionLimit(
        `you already hold ${mine} browser sessions (limit ${this.cfg.sessions.maxPerPrincipal}); ` +
          'close one with ghost_close and retry',
      );
    }
  }

  get(id: string, principal: string): Session {
    const s = this.sessions.get(id);
    if (!s) throw new Error(`no session ${id}; it may have expired. Open a new one with ghost_open.`);
    // A session id is a capability. Scoping the lookup to the principal means
    // one leaking into a log or a transcript is not usable by anyone else.
    if (s.principal !== principal) {
      throw new Error(`no session ${id}; it may have expired. Open a new one with ghost_open.`);
    }
    s.lastUsedAt = Date.now();
    return s;
  }

  list(principal: string): Session[] {
    return [...this.sessions.values()].filter((s) => s.principal === principal);
  }

  async close(id: string): Promise<void> {
    const s = this.sessions.get(id);
    if (!s) return;
    this.sessions.delete(id);
    await s.context.close().catch(() => {});
    log.info('session closed', { session: id, remaining: this.sessions.size });
  }

  /** Attribute an egress event to whichever session is currently working. */
  recordEgress(event: EgressEvent): void {
    let newest: Session | null = null;
    for (const s of this.sessions.values()) {
      if (!newest || s.lastUsedAt > newest.lastUsedAt) newest = s;
    }
    if (!newest) return;
    newest.egress.push(event);
    if (newest.egress.length > 500) newest.egress.splice(0, newest.egress.length - 500);
  }

  private async sweep(): Promise<void> {
    const now = Date.now();
    for (const s of [...this.sessions.values()]) {
      const idle = (now - s.lastUsedAt) / 1000;
      const age = (now - s.createdAt) / 1000;
      if (idle > this.cfg.sessions.idleTimeoutS) {
        log.info('session expired (idle)', { session: s.id, idle_s: Math.round(idle) });
        await this.close(s.id);
      } else if (age > this.cfg.sessions.maxLifetimeS) {
        log.info('session expired (lifetime)', { session: s.id, age_s: Math.round(age) });
        await this.close(s.id);
      }
    }
  }

  stats(): { sessions: number; connected: boolean } {
    return { sessions: this.sessions.size, connected: this.browser?.isConnected() ?? false };
  }

  /**
   * The Chrome version and UA in use, once a connection has been made.
   *
   * ghost_curl reads this so its headers name the same Chrome build the browser
   * path sends. Null until the first connect, which is why the server probes at
   * startup rather than waiting for the first fetch to disagree with itself.
   */
  identity(): { version: string; userAgent: string } | null {
    if (!this.browser?.isConnected() || !this.identityValue) return null;
    return { version: this.browser.version(), userAgent: this.identityValue.userAgent };
  }
}

/** The ws path is a shared secret; it does not belong in a log line. */
function redactWs(endpoint: string): string {
  try {
    const u = new URL(endpoint);
    return `${u.protocol}//${u.host}/...`;
  } catch {
    return 'ws://...';
  }
}
