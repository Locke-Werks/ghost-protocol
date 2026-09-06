// PDF, via pdf.js.
//
// A PDF has no text in the sense the other formats do. It has instructions for
// placing glyphs, so "the text of this page" is a reconstruction, and every
// library doing it is guessing at where the lines and the paragraphs were.
// pdf.js is the same engine Firefox ships, which makes its guess the one most
// widely exercised against real files.
//
// Two things are asked of it here rather than one. The first is the text. The
// second is which of that text was drawn so it could not be read — invisible
// text rendering mode, or glyphs painted white on a page with nothing behind
// them. That is not an exotic concern for this format: hiding a paragraph of
// instructions in a PDF, aimed at whatever model would be asked to summarise
// it, is the version of this attack that has actually been found in the wild,
// in submitted academic papers.
//
// Nothing in a PDF is allowed to execute. XFA rendering stays off, fonts are
// never installed on the host, and the file's own JavaScript is reported as a
// finding rather than run.

import { createRequire } from 'node:module';
import { dirname } from 'node:path';
import { pathToFileURL } from 'node:url';
import {
  DocumentEncrypted,
  resolveRange,
  type DocHidden,
  type DocSection,
  type DocumentExtract,
  type ExtractOptions,
} from './types.js';

const require_ = createRequire(import.meta.url);

type PdfjsModule = typeof import('pdfjs-dist/legacy/build/pdf.mjs');
let pdfjsPromise: Promise<PdfjsModule> | null = null;

/**
 * Load pdf.js once per worker.
 *
 * The legacy build is the one that runs on a plain Node without a DOM. It is
 * loaded lazily because a worker parsing a .docx has no use for a megabyte of
 * PDF machinery.
 */
async function pdfjs(): Promise<PdfjsModule> {
  pdfjsPromise ??= import('pdfjs-dist/legacy/build/pdf.mjs');
  return pdfjsPromise;
}

/** pdf.js asks for its own data files by URL, including on the filesystem. */
function assetUrl(sub: string): string {
  const root = dirname(require_.resolve('pdfjs-dist/package.json'));
  return pathToFileURL(`${root}/${sub}/`).href;
}

export async function readPdf(bytes: Buffer, opts: ExtractOptions): Promise<DocumentExtract> {
  const lib = await pdfjs();
  const warnings: string[] = [];
  const hidden: DocHidden[] = [];

  const task = lib.getDocument({
    data: new Uint8Array(bytes),
    password: opts.password,
    // A PDF may not fetch anything or install a font on this host. Fonts are
    // only needed to draw glyphs, and nothing here draws.
    disableFontFace: true,
    useSystemFonts: false,
    enableXfa: false,
    // The standard fonts and CMaps decide what unicode a glyph maps back to.
    // Without them a document using a non-embedded font, or any CJK text,
    // extracts as mojibake rather than failing outright, which is worse.
    standardFontDataUrl: assetUrl('standard_fonts'),
    cMapUrl: assetUrl('cmaps'),
    cMapPacked: true,
    wasmUrl: assetUrl('wasm'),
    verbosity: 0,
  });

  let doc: PdfDocument;
  try {
    doc = await task.promise;
  } catch (e) {
    const name = (e as { name?: string })?.name ?? '';
    if (name === 'PasswordException') {
      throw new DocumentEncrypted(
        opts.password
          ? 'the password given does not open this PDF'
          : 'this PDF is encrypted and needs a password; pass one as `password`',
      );
    }
    throw e;
  }

  try {
    const info = await metadataOf(doc);
    const total = doc.numPages;
    const range = resolveRange(total, opts);
    const sections: DocSection[] = [];

    for (let n = range.from; n <= range.to; n++) {
      const page = await doc.getPage(n);
      try {
        const concealed = await pageConcealment(lib, page).catch(() => []);
        for (const c of concealed) {
          hidden.push({ where: `page ${n}`, reason: c.reason, sample: c.sample, concealment: true });
        }
        // getTextContent reports every glyph the page places, visible or not,
        // so text already reported as concealed has to come back out of the
        // body. Leaving it in both places would put the instruction into the
        // payload alongside the warning about it, which is the one arrangement
        // this whole mechanism exists to avoid.
        const text = withoutConcealed(await pageText(page), concealed);
        sections.push({ label: `page ${n} of ${total}`, markdown: text });
      } finally {
        page.cleanup();
      }
    }

    if (range.to < total) {
      warnings.push(
        `Read pages ${range.from} to ${range.to} of ${total}. Ask for the rest with first_page and last_page.`,
      );
    }
    const empty = sections.filter((s) => s.markdown.trim() === '').length;
    if (empty === sections.length && sections.length > 0) {
      warnings.push(
        'None of the pages read carried extractable text. This is what a scanned document looks ' +
          'like: the pages are images, and reading them would need OCR, which this relay does not do.',
      );
    } else if (empty > 0) {
      warnings.push(`${empty} of the ${sections.length} pages read carried no extractable text.`);
    }

    if (await hasJavaScript(doc)) {
      warnings.push(
        'This PDF carries embedded JavaScript. None of it has been run, and none of it appears ' +
          'below. Its presence is worth knowing about: it is uncommon outside forms.',
      );
    }
    const attachments = await attachmentNames(doc);
    if (attachments.length > 0) {
      warnings.push(
        `This PDF has ${attachments.length} embedded file(s) attached to it (${attachments.join(', ')}). ` +
          'They have not been opened or extracted.',
      );
    }

    const markdown = sections
      .map((s) => (sections.length > 1 ? `## ${s.label}\n\n${s.markdown}` : s.markdown))
      .join('\n\n')
      .trim();

    return {
      kind: 'pdf',
      ...info,
      sections,
      totalSections: total,
      selected: { from: range.from, to: range.to },
      markdown,
      hidden,
      warnings,
    };
  } finally {
    await task.destroy().catch(() => {});
  }
}

type LoadingTask = ReturnType<PdfjsModule['getDocument']>;
type PdfDocument = Awaited<LoadingTask['promise']>;
type PdfPage = Awaited<ReturnType<PdfDocument['getPage']>>;

async function metadataOf(doc: PdfDocument): Promise<{
  title: string | null;
  author: string | null;
  created: string | null;
  modified: string | null;
  producer: string | null;
}> {
  try {
    const meta = await doc.getMetadata();
    const info = (meta.info ?? {}) as Record<string, unknown>;
    const text = (v: unknown): string | null =>
      typeof v === 'string' && v.trim() ? v.trim().slice(0, 300) : null;
    return {
      title: text(info['Title']),
      author: text(info['Author']),
      created: pdfDate(text(info['CreationDate'])),
      modified: pdfDate(text(info['ModDate'])),
      producer: text(info['Producer']) ?? text(info['Creator']),
    };
  } catch {
    return { title: null, author: null, created: null, modified: null, producer: null };
  }
}

/** `D:20240117093000-06'00'` to something a reader can parse. */
function pdfDate(raw: string | null): string | null {
  if (!raw) return null;
  const m = /^D?:?(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?/.exec(raw);
  if (!m) return raw;
  const [, y, mo = '01', d = '01', h, mi, s] = m;
  const date = `${y}-${mo}-${d}`;
  return h ? `${date} ${h}:${mi ?? '00'}:${s ?? '00'}` : date;
}

/**
 * A page's text, put back into lines.
 *
 * The items arrive in the order the content stream draws them, which is
 * normally reading order, and pdf.js marks the ones that ended a line. Sorting
 * by position instead would fix the documents that draw out of order and break
 * every multi-column layout, which is the more common shape by far.
 */
async function pageText(page: PdfPage): Promise<string> {
  const content = await page.getTextContent();
  const lines: string[] = [];
  let line = '';
  let lastY: number | null = null;

  for (const raw of content.items) {
    const item = raw as { str?: string; hasEOL?: boolean; transform?: number[] };
    if (typeof item.str !== 'string') continue;
    const y = item.transform?.[5] ?? null;

    // A jump in the baseline that no EOL was reported for is still a new line:
    // some producers never set hasEOL at all.
    if (lastY !== null && y !== null && Math.abs(y - lastY) > 3 && line !== '') {
      lines.push(line);
      line = '';
    }
    line += item.str;
    lastY = y;

    if (item.hasEOL) {
      lines.push(line);
      line = '';
    }
  }
  if (line) lines.push(line);

  // Blank lines between paragraphs, single lines joined as the document wrote
  // them. Hyphen joining is left alone deliberately: a wrong join corrupts a
  // word silently, and a stray hyphen does not.
  const out: string[] = [];
  for (const l of lines) {
    const t = l.replace(/\s+$/g, '');
    if (t.trim() === '') {
      if (out.length && out[out.length - 1] !== '') out.push('');
    } else {
      out.push(t);
    }
  }
  return out.join('\n').trim();
}

interface Concealed {
  reason: string;
  sample: string;
}

/**
 * Drop the lines that were drawn invisibly.
 *
 * The operator list and the text content are two views of the same page and
 * pdf.js does not hand back a mapping between them, so the join is made on the
 * text itself: a line is removed when its collapsed form appears inside a run
 * that was already reported as concealed. Short lines are left alone, because a
 * page number matching by accident is a real possibility and losing one costs
 * more than the duplicate would.
 */
function withoutConcealed(text: string, concealed: Concealed[]): string {
  if (concealed.length === 0 || !text) return text;
  const runs = concealed.map((c) => c.sample.replace(/\s+/g, ' ').trim()).filter((s) => s.length >= 12);
  if (runs.length === 0) return text;

  const kept = text.split('\n').filter((line) => {
    const norm = line.replace(/\s+/g, ' ').trim();
    if (norm.length < 12) return true;
    return !runs.some((run) => run.includes(norm));
  });
  return kept.join('\n').replace(/\n{3,}/g, '\n\n').trim();
}

/**
 * Text on this page that was drawn so it could not be read.
 *
 * Two shapes count. Rendering mode 3 paints no glyphs at all — the text is in
 * the file and on no screen. A near-white fill is the same trick done in
 * colour. Both are ordinary on a scanned page, where an OCR layer sits
 * invisibly under the image of the paper, so a page carrying any image is left
 * alone: reporting every scanned PDF as an attack would make this warning
 * useless within a week.
 *
 * The operator list is a lower-level view than getTextContent and pdf.js does
 * not promise its shape. A change there costs the concealment check, not the
 * extraction, which is why the caller treats a throw as "found nothing".
 */
async function pageConcealment(lib: PdfjsModule, page: PdfPage): Promise<Concealed[]> {
  const ops = await page.getOperatorList();
  const OPS = lib.OPS as unknown as Record<string, number>;

  const IMAGE_OPS = new Set(
    ['paintImageXObject', 'paintImageXObjectRepeat', 'paintInlineImageXObject', 'paintJpegXObject', 'paintImageMaskXObject']
      .map((k) => OPS[k])
      .filter((v): v is number => typeof v === 'number'),
  );
  for (const fn of ops.fnArray) {
    if (IMAGE_OPS.has(fn)) return [];
  }

  const found: Concealed[] = [];
  let invisibleMode = false;
  let whiteFill = false;
  let current: { reason: string; parts: string[] } | null = null;

  const flush = () => {
    if (!current) return;
    const sample = current.parts.join('').replace(/\s+/g, ' ').trim();
    if (sample.length >= 12) found.push({ reason: current.reason, sample: sample.slice(0, 600) });
    current = null;
  };

  for (let i = 0; i < ops.fnArray.length; i++) {
    const fn = ops.fnArray[i]!;
    const args = ops.argsArray[i] as unknown[];

    if (fn === OPS['setTextRenderingMode']) {
      const mode = Number(args[0]);
      invisibleMode = mode === 3 || mode === 7;
      if (!invisibleMode && !whiteFill) flush();
      continue;
    }
    // Grey and CMYK fills are converted to RGB before they reach the operator
    // list, so this one operator covers every way of asking for white.
    if (fn === OPS['setFillRGBColor']) {
      whiteFill = isWhite(args);
      if (!invisibleMode && !whiteFill) flush();
      continue;
    }
    if (fn === OPS['showText'] || fn === OPS['showSpacedText']) {
      if (!invisibleMode && !whiteFill) {
        flush();
        continue;
      }
      const reason = invisibleMode ? 'invisible text (rendering mode 3)' : 'white text on a page with no images';
      if (!current || current.reason !== reason) {
        flush();
        current = { reason, parts: [] };
      }
      current.parts.push(glyphText(args[0]));
      if (found.length >= 10) break;
    }
  }
  flush();
  return found;
}

/** pdf.js hands glyphs as objects; the kerning numbers between them are not text. */
function glyphText(arg: unknown): string {
  if (!Array.isArray(arg)) return '';
  let out = '';
  for (const g of arg) {
    if (typeof g === 'number') {
      // A large negative adjustment is how a space gets drawn without one.
      if (g < -100) out += ' ';
    } else if (g && typeof g === 'object' && typeof (g as { unicode?: unknown }).unicode === 'string') {
      out += (g as { unicode: string }).unicode;
    }
  }
  return out;
}

/**
 * A fill colour close enough to white to be unreadable on a white page.
 *
 * pdf.js hands this operator a CSS hex string, having already converted from
 * whatever colour space the document used. The component form is accepted too,
 * on both the 0-1 and 0-255 scales, because that is what older builds emitted
 * and a version bump should not silently switch this check off.
 */
function isWhite(args: unknown[]): boolean {
  const first = args[0];
  if (typeof first === 'string') {
    const m = /^#?([0-9a-f]{6})$/i.exec(first.trim());
    if (!m) return false;
    const v = parseInt(m[1]!, 16);
    return ((v >> 16) & 0xff) >= 242 && ((v >> 8) & 0xff) >= 242 && (v & 0xff) >= 242;
  }
  const [r, g, b] = [Number(args[0]), Number(args[1]), Number(args[2])];
  if (![r, g, b].every(Number.isFinite)) return false;
  const scale = r <= 1 && g <= 1 && b <= 1 ? 255 : 1;
  return r * scale >= 242 && g * scale >= 242 && b * scale >= 242;
}

async function hasJavaScript(doc: PdfDocument): Promise<boolean> {
  try {
    if (await doc.hasJSActions()) return true;
    const open = await doc.getOpenAction();
    return Boolean(open && (open as { action?: unknown }).action === 'JavaScript');
  } catch {
    return false;
  }
}

async function attachmentNames(doc: PdfDocument): Promise<string[]> {
  try {
    const files = await doc.getAttachments();
    if (!files) return [];
    // pdf.js has returned this as both a plain object and a Map depending on
    // the version, and the names are the only part used either way.
    const names = files instanceof Map ? [...files.keys()] : Object.keys(files as Record<string, unknown>);
    return names.slice(0, 20).map((n) => String(n).slice(0, 120));
  } catch {
    return [];
  }
}

/** Exported for the tests. */
export const __test = { pdfDate, glyphText, isWhite, withoutConcealed };
