// Screenshots an agent can actually read.
//
// The obvious implementation — one full-page PNG — produces something useless
// on the far end. A documentation page is routinely 8000 pixels tall, and a
// 1280x8000 image gets downscaled to fit a vision model's input budget, at
// which point every line of body text is a grey smear. Height is the enemy, not
// file size.
//
// So a capture is sliced into tiles roughly 1280x1600, each of which survives
// downscaling with its text intact, and the number of tiles is capped so a long
// page cannot quietly spend the caller's entire context on screenshots.

import sharp from 'sharp';
import type { Page } from 'playwright-core';
import { log, errFields } from '../util/log.js';

/** Chrome cannot compose a single capture taller than this. */
const MAX_CAPTURE_PX = 15_000;

export type ScreenshotMode = 'full' | 'viewport' | 'none';

export interface CaptureOptions {
  mode: ScreenshotMode;
  width: number;
  tileHeight: number;
  maxTiles: number;
  webpQuality: number;
}

export interface Tile {
  index: number;
  /** Page y-coordinate of this tile's top edge, in CSS pixels. */
  y: number;
  height: number;
  webp: Buffer;
}

export interface CaptureResult {
  tiles: Tile[];
  /** Full document height in CSS pixels, whether or not all of it was captured. */
  pageHeight: number;
  /** Pixels actually captured, top-down. */
  capturedHeight: number;
  omittedTiles: number;
  width: number;
  bytes: number;
}

export const EMPTY_CAPTURE: CaptureResult = {
  tiles: [],
  pageHeight: 0,
  capturedHeight: 0,
  omittedTiles: 0,
  width: 0,
  bytes: 0,
};

/**
 * Walk the page top to bottom before capturing.
 *
 * Lazy-loaded images and virtualised lists only render what has been near the
 * viewport, so a full-page screenshot taken without scrolling first is a column
 * of placeholder boxes. Returning to the top afterwards matters too: a sticky
 * header drawn at whatever scroll position the page was left at ends up baked
 * into the middle of the capture.
 */
export async function primeLazyContent(page: Page, stepPx = 800, maxSteps = 40): Promise<void> {
  try {
    await page.evaluate(
      async ({ stepPx, maxSteps }) => {
        const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
        let y = 0;
        for (let i = 0; i < maxSteps; i++) {
          window.scrollTo(0, y);
          await sleep(60);
          y += stepPx;
          if (y >= document.documentElement.scrollHeight) break;
        }
        window.scrollTo(0, 0);
        await sleep(120);
      },
      { stepPx, maxSteps },
    );
  } catch (e) {
    log.debug('lazy-content priming failed', errFields(e));
  }
}

export async function capturePage(page: Page, opts: CaptureOptions): Promise<CaptureResult> {
  if (opts.mode === 'none') return EMPTY_CAPTURE;

  const pageHeight = await page
    .evaluate(() => document.documentElement.scrollHeight)
    .catch(() => 0);

  if (opts.mode === 'viewport') {
    const png = await page.screenshot({ type: 'png', scale: 'css' });
    const webp = await toWebp(png, opts.webpQuality);
    const vh = page.viewportSize()?.height ?? opts.tileHeight;
    return {
      tiles: [{ index: 0, y: 0, height: vh, webp }],
      pageHeight,
      capturedHeight: vh,
      omittedTiles: 0,
      width: opts.width,
      bytes: webp.byteLength,
    };
  }

  const budget = Math.max(1, opts.maxTiles) * opts.tileHeight;
  const capturedHeight = Math.min(pageHeight || opts.tileHeight, budget, MAX_CAPTURE_PX);
  const totalTiles = Math.max(1, Math.ceil((pageHeight || 1) / opts.tileHeight));
  const takenTiles = Math.min(totalTiles, opts.maxTiles);

  const png = await screenshotBounded(page, opts.width, capturedHeight);
  const image = sharp(png);
  const meta = await image.metadata();
  const imgW = meta.width ?? opts.width;
  const imgH = meta.height ?? capturedHeight;

  const tiles: Tile[] = [];
  let bytes = 0;
  for (let i = 0; i < takenTiles; i++) {
    const top = i * opts.tileHeight;
    if (top >= imgH) break;
    const height = Math.min(opts.tileHeight, imgH - top);
    if (height < 8) break;
    // A fresh sharp instance per tile: extract() mutates the pipeline, so
    // reusing one silently applies the previous crop to the next tile.
    const webp = await sharp(png)
      .extract({ left: 0, top, width: imgW, height })
      .webp({ quality: opts.webpQuality, effort: 4 })
      .toBuffer();
    bytes += webp.byteLength;
    tiles.push({ index: i, y: top, height, webp });
  }

  return {
    tiles,
    pageHeight,
    capturedHeight: Math.min(imgH, capturedHeight),
    omittedTiles: Math.max(0, totalTiles - tiles.length),
    width: imgW,
    bytes,
  };
}

/**
 * A full-page capture, bounded to `height`.
 *
 * `clip` alongside `fullPage` is the direct way to say this, but it has not
 * always been accepted, so an unbounded full-page capture is the fallback and
 * the trim happens in sharp instead. Either path produces the same image; only
 * the peak memory differs.
 */
async function screenshotBounded(page: Page, width: number, height: number): Promise<Buffer> {
  try {
    return await page.screenshot({
      type: 'png',
      scale: 'css',
      fullPage: true,
      clip: { x: 0, y: 0, width, height },
    });
  } catch (e) {
    log.debug('clipped full-page capture rejected, falling back', errFields(e));
    const full = await page.screenshot({ type: 'png', scale: 'css', fullPage: true });
    const meta = await sharp(full).metadata();
    const h = Math.min(height, meta.height ?? height);
    return await sharp(full)
      .extract({ left: 0, top: 0, width: meta.width ?? width, height: h })
      .png()
      .toBuffer();
  }
}

async function toWebp(png: Buffer, quality: number): Promise<Buffer> {
  return await sharp(png).webp({ quality, effort: 4 }).toBuffer();
}
