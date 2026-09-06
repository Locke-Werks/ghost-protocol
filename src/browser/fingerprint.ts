// Presenting as an ordinary Chrome on Windows 11.
//
// The header alone is not enough. A UA string claiming Windows on a box whose
// navigator.platform says Linux, whose WebGL renderer says SwiftShader and
// whose navigator.webdriver is true describes an automated Linux browser
// wearing a Windows label, and that mismatch is easier to spot than the plain
// truth would have been. So the identity is applied in one consistent pass:
// CDP for the parts Chrome generates itself (the UA header and the whole
// client-hints family), init scripts for the handful of JS surfaces CDP does
// not cover.
//
// The version is read from the running Chrome rather than pinned, so an
// unattended Chrome upgrade cannot leave a stale version in the UA while the
// TLS and HTTP/2 fingerprints move on without it.

import type { BrowserContext, Page } from 'playwright-core';

export interface Identity {
  userAgent: string;
  metadata: Record<string, unknown>;
}

/** Windows 11 reports platformVersion 13.0.0 or higher; 24H2 reports 15.0.0. */
const WINDOWS_PLATFORM_VERSION = '15.0.0';

export function buildIdentity(chromeVersion: string, override: string | null): Identity {
  const major = chromeVersion.split('.')[0] ?? '141';
  const userAgent =
    override ??
    `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) ` +
      `Chrome/${major}.0.0.0 Safari/537.36`;

  // The GREASE entry is Chrome's own deliberate junk brand; its exact spelling
  // rotates between releases. Any of the accepted forms reads as normal.
  const brands = [
    { brand: 'Not=A?Brand', version: '24' },
    { brand: 'Chromium', version: major },
    { brand: 'Google Chrome', version: major },
  ];
  const fullVersionList = [
    { brand: 'Not=A?Brand', version: '24.0.0.0' },
    { brand: 'Chromium', version: chromeVersion },
    { brand: 'Google Chrome', version: chromeVersion },
  ];

  return {
    userAgent,
    metadata: {
      brands,
      fullVersionList,
      fullVersion: chromeVersion,
      platform: 'Windows',
      platformVersion: WINDOWS_PLATFORM_VERSION,
      architecture: 'x86',
      model: '',
      mobile: false,
      bitness: '64',
      wow64: false,
    },
  };
}

/**
 * Launch flags for the browser process.
 *
 * Chrome's own sandbox is left ON. Reaching for --no-sandbox is the usual
 * shortcut and it removes the single thing standing between a renderer
 * compromise and the rest of the box, which is the opposite of what a service
 * that renders hostile pages for a living wants.
 */
export function launchArgs(proxyServer: string): string[] {
  return [
    // The automation tell Chrome sets on itself.
    '--disable-blink-features=AutomationControlled',

    // Everything egress goes through the guard. Without the bypass override
    // Chrome would still reach loopback and the private ranges directly.
    `--proxy-server=${proxyServer}`,
    '--proxy-bypass-list=<-loopback>',

    // Chrome's own chatter (variations, component updates, safe browsing
    // lists, sync) would otherwise hit the proxy, get refused, and fill the
    // egress log with noise that hides the real requests.
    '--disable-background-networking',
    '--disable-component-update',
    '--disable-domain-reliability',
    '--disable-sync',
    '--no-first-run',
    '--no-default-browser-check',
    '--disable-breakpad',
    '--metrics-recording-only',
    '--no-pings',

    // /dev/shm inside a systemd PrivateTmp is small; Chrome crashes on large
    // pages when it fills. Sending shared memory to /tmp is the standard fix.
    '--disable-dev-shm-usage',

    // Renderers get no reason to keep running once a capture is done.
    '--disable-backgrounding-occluded-windows',
    '--disable-renderer-backgrounding',
    '--disable-background-timer-throttling',

    // A window size that matches the viewport we emulate.
    '--window-size=1280,800',
    '--lang=en-US',
  ];
}

/**
 * Apply the identity to a page. CDP first, because Chrome then derives every
 * client hint (sec-ch-ua, -platform, -platform-version, -arch, -bitness, and
 * navigator.userAgentData) from one consistent record. Patching those by hand
 * is how they end up disagreeing with each other.
 */
export async function applyIdentity(context: BrowserContext, page: Page, identity: Identity): Promise<void> {
  const cdp = await context.newCDPSession(page);
  await cdp.send('Emulation.setUserAgentOverride', {
    userAgent: identity.userAgent,
    acceptLanguage: 'en-US,en;q=0.9',
    platform: 'Win32',
    userAgentMetadata: identity.metadata,
  } as never);
  await cdp.detach().catch(() => {});
}

/**
 * The JS-visible surfaces CDP leaves alone. Runs before any page script, in
 * every frame.
 *
 * Deliberately short. Each entry is a property whose Linux value contradicts
 * the Windows identity; this is not an attempt to defeat a dedicated
 * anti-automation vendor, and pretending otherwise in a comment would just
 * mislead whoever reads this next.
 */
export const INIT_SCRIPT = String.raw`
(() => {
  const def = (obj, prop, value) => {
    try {
      Object.defineProperty(obj, prop, { get: () => value, configurable: true });
    } catch { /* a frame that already sealed it is not worth throwing over */ }
  };

  // Set by Chrome under automation regardless of the Blink feature flag in
  // some frame types.
  try { delete Object.getPrototypeOf(navigator).webdriver; } catch { }
  def(navigator, 'webdriver', undefined);

  def(navigator, 'platform', 'Win32');
  def(navigator, 'hardwareConcurrency', 8);
  def(navigator, 'deviceMemory', 8);
  def(navigator, 'maxTouchPoints', 0);

  // A 1280x800 viewport on a screen that reports 1280x800 is a headless
  // browser; a real one has chrome around it on a larger display.
  def(screen, 'width', 1920);
  def(screen, 'height', 1080);
  def(screen, 'availWidth', 1920);
  def(screen, 'availHeight', 1040);
  def(screen, 'colorDepth', 24);
  def(screen, 'pixelDepth', 24);

  // Headless Linux renders through SwiftShader and says so by name.
  const VENDOR = 0x9245, RENDERER = 0x9246;
  for (const proto of [self.WebGLRenderingContext, self.WebGL2RenderingContext]) {
    if (!proto) continue;
    const original = proto.prototype.getParameter;
    proto.prototype.getParameter = function (p) {
      if (p === VENDOR) return 'Google Inc. (NVIDIA)';
      if (p === RENDERER) {
        return 'ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 (0x00002504) Direct3D11 vs_5_0 ps_5_0, D3D11)';
      }
      return original.apply(this, arguments);
    };
  }

  // Notification.permission reads "denied" in headless while the Permissions
  // API reports "prompt", a contradiction no real browser produces.
  if (self.Notification && Notification.permission === 'denied') {
    def(Notification, 'permission', 'default');
  }
})();
`;
