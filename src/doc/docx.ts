// WordprocessingML.
//
// A .docx is one long `word/document.xml` describing paragraphs of runs of
// text, which reads as a stream: paragraph properties arrive before the runs
// they govern, run properties before the text they govern, so a state machine
// with two small property records is enough and nothing has to be held.
//
// Word can hide text in the file format itself, not only by drawing it in a
// colour nobody can see. `w:vanish` is a run property that means "do not
// display or print this", which is a better hiding place than any CSS trick
// because the text stays perfectly ordinary to anything reading the XML. Runs
// hidden that way come out of the body and into the hidden list, the same as an
// off-canvas div does on the HTML path.

import { Zip } from './zip.js';
import { localName, scanXml } from './xml.js';
import { pushHidden, readCoreProps, readRels, sampleOf, toMarkdownTable, isNearWhite, type Rels } from './ooxml.js';
import type { DocHidden, DocSection, DocumentExtract, ExtractOptions } from './types.js';

interface RunProps {
  vanish: boolean;
  webHidden: boolean;
  white: boolean;
  /** Half-points, so 4 is 2pt. */
  size: number | null;
  bold: boolean;
  italic: boolean;
}

const PLAIN: RunProps = { vanish: false, webHidden: false, white: false, size: null, bold: false, italic: false };

interface ParaProps {
  /** 1-6 for a heading, 0 otherwise. */
  heading: number;
  listLevel: number | null;
  quote: boolean;
}

export function readDocx(zip: Zip, opts: ExtractOptions): DocumentExtract {
  const props = readCoreProps(zip);
  const warnings: string[] = [];
  const hidden: DocHidden[] = [];

  const rels = readRels(zip, 'word/document.xml');
  const body = renderPart(zip.readText('word/document.xml'), rels, hidden, 'body', opts);

  const sections: DocSection[] = [];
  if (body.trim()) sections.push({ label: 'document', markdown: body });

  // Notes and comments carry real content and are the first thing a reader
  // misses when a converter drops them. They come out as their own sections so
  // it is obvious they were not part of the running text.
  for (const [part, label] of [
    ['word/footnotes.xml', 'footnotes'],
    ['word/endnotes.xml', 'endnotes'],
    ['word/comments.xml', 'comments'],
  ] as const) {
    const xml = zip.readTextIfPresent(part);
    if (!xml) continue;
    const text = renderPart(xml, readRels(zip, part), hidden, label, opts);
    // Word writes a separator and a continuation note into every file whether
    // or not anything references them, so an empty part is the normal case.
    if (text.replace(/\s/g, '').length > 0) sections.push({ label, markdown: text });
  }

  if (sections.length === 0) {
    warnings.push('The document parsed but carried no text. It may be a scan, or entirely images.');
  }

  const markdown = sections
    .map((s) => (s.label === 'document' ? s.markdown : `\n\n## ${s.label}\n\n${s.markdown}`))
    .join('\n\n')
    .trim();

  return {
    kind: 'docx',
    ...props,
    sections,
    totalSections: sections.length,
    selected: null,
    markdown,
    hidden,
    warnings,
  };
}

/**
 * One WordprocessingML part to markdown.
 *
 * `where` names the part for anything hidden, so a finding says "footnotes"
 * rather than pointing at a paragraph number in a file the reader never sees.
 */
function renderPart(
  xml: string,
  rels: Rels,
  hidden: DocHidden[],
  where: string,
  opts: ExtractOptions,
): string {
  const out: string[] = [];

  // Paragraph state.
  let para: string[] = [];
  let paraProps: ParaProps = { heading: 0, listLevel: null, quote: false };
  let inParaProps = false;

  // Run state. `depth` tracks nesting so a `w:rPr` inside a `w:pPr` (which is
  // the paragraph mark's formatting, not a run's) does not leak into the runs.
  let runProps: RunProps = { ...PLAIN };
  let inRunProps = false;
  let hiddenRun: string[] = [];

  // Table state. Nested tables are rare enough that the inner one is flattened
  // into a cell rather than given its own grid.
  let tableRows: string[][] = [];
  let row: string[] = [];
  let cell: string[] = [];
  let tableDepth = 0;

  // Hyperlink state.
  let linkTarget: string | null = null;
  let linkText: string[] = [];

  let textSink: string[] | null = null;

  const flushHiddenRun = (reason: string) => {
    const text = hiddenRun.join('');
    hiddenRun = [];
    if (!text.trim()) return;
    pushHidden(hidden, { where, reason, sample: sampleOf(text), concealment: true });
  };

  const endParagraph = () => {
    const text = para.join('').replace(/[ \t]+$/g, '');
    para = [];
    const p = paraProps;
    paraProps = { heading: 0, listLevel: null, quote: false };
    if (tableDepth > 0) {
      if (text.trim()) cell.push(text);
      return;
    }
    if (!text.trim()) {
      // Keep one blank line between blocks, not the dozens Word writes.
      if (out.length > 0 && out[out.length - 1] !== '') out.push('');
      return;
    }
    if (p.heading > 0) out.push('#'.repeat(Math.min(p.heading, 6)) + ' ' + text.trim(), '');
    else if (p.listLevel !== null) out.push('  '.repeat(Math.min(p.listLevel, 6)) + '- ' + text.trim());
    else if (p.quote) out.push('> ' + text.trim(), '');
    else out.push(text.trim(), '');
  };

  for (const ev of scanXml(xml)) {
    if (ev.type === 'text') {
      if (textSink) textSink.push(ev.text);
      continue;
    }

    const name = ev.type === 'open' || ev.type === 'close' ? localName(ev.name) : '';

    if (ev.type === 'open') {
      switch (name) {
        case 'p':
          para = [];
          paraProps = { heading: 0, listLevel: null, quote: false };
          break;
        case 'pPr':
          inParaProps = true;
          break;
        case 'pStyle': {
          if (!inParaProps) break;
          const style = ev.attrs['w:val'] ?? ev.attrs['val'] ?? '';
          const h = /^Heading(\d)$/i.exec(style);
          if (h) paraProps.heading = Number(h[1]);
          else if (/^Title$/i.test(style)) paraProps.heading = 1;
          else if (/^Subtitle$/i.test(style)) paraProps.heading = 2;
          else if (/Quote$/i.test(style)) paraProps.quote = true;
          else if (/^List(Paragraph|Bullet|Number)/i.test(style) && paraProps.listLevel === null) {
            paraProps.listLevel = 0;
          }
          break;
        }
        case 'numPr':
          if (inParaProps && paraProps.listLevel === null) paraProps.listLevel = 0;
          break;
        case 'ilvl':
          if (inParaProps) {
            const lvl = Number(ev.attrs['w:val'] ?? ev.attrs['val'] ?? 0);
            if (Number.isFinite(lvl)) paraProps.listLevel = lvl;
          }
          break;

        case 'r':
          runProps = { ...PLAIN };
          break;
        case 'rPr':
          // Inside pPr this is the paragraph mark's own run properties, which
          // govern nothing a reader sees.
          if (!inParaProps) inRunProps = true;
          break;
        case 'vanish':
          if (inRunProps) runProps.vanish = ev.attrs['w:val'] !== '0' && ev.attrs['val'] !== '0';
          break;
        case 'webHidden':
          if (inRunProps) runProps.webHidden = ev.attrs['w:val'] !== '0' && ev.attrs['val'] !== '0';
          break;
        case 'color':
          if (inRunProps) runProps.white = isNearWhite(ev.attrs['w:val'] ?? ev.attrs['val']);
          break;
        case 'sz':
          if (inRunProps) {
            const half = Number(ev.attrs['w:val'] ?? ev.attrs['val']);
            if (Number.isFinite(half)) runProps.size = half;
          }
          break;
        case 'b':
          if (inRunProps) runProps.bold = ev.attrs['w:val'] !== '0' && ev.attrs['val'] !== '0';
          break;
        case 'i':
          if (inRunProps) runProps.italic = ev.attrs['w:val'] !== '0' && ev.attrs['val'] !== '0';
          break;

        case 't':
        case 'delText':
          // A run's text goes to the hidden list or to the paragraph, never
          // both. `delText` is tracked-change deletion: not shown, and not
          // interesting enough to report as concealment.
          if (name === 'delText') textSink = null;
          else if (concealReason(runProps)) textSink = hiddenRun;
          else if (linkTarget !== null) textSink = linkText;
          else textSink = para;
          break;
        case 'tab':
          if (!concealReason(runProps)) (linkTarget !== null ? linkText : para).push('\t');
          break;
        case 'br':
        case 'cr':
          if (!concealReason(runProps)) (linkTarget !== null ? linkText : para).push('\n');
          break;

        case 'hyperlink': {
          const id = ev.attrs['r:id'] ?? ev.attrs['id'];
          const rel = id ? rels.get(id) : undefined;
          linkTarget = rel ? rel.target : '';
          linkText = [];
          break;
        }

        case 'tbl':
          if (tableDepth === 0) tableRows = [];
          tableDepth++;
          break;
        case 'tr':
          if (tableDepth === 1) row = [];
          break;
        case 'tc':
          if (tableDepth === 1) cell = [];
          break;
      }
      if (!ev.selfClosing) continue;
    }

    if (ev.type === 'close' || (ev.type === 'open' && ev.selfClosing)) {
      switch (name) {
        case 't':
        case 'delText':
          if (textSink === hiddenRun) flushHiddenRun(concealReason(runProps) ?? 'hidden');
          textSink = null;
          break;
        case 'pPr':
          inParaProps = false;
          break;
        case 'rPr':
          inRunProps = false;
          break;
        case 'r':
          if (hiddenRun.length) flushHiddenRun(concealReason(runProps) ?? 'hidden');
          runProps = { ...PLAIN };
          break;
        case 'hyperlink': {
          const text = linkText.join('').trim();
          const target = linkTarget;
          linkTarget = null;
          linkText = [];
          if (!text) break;
          // The URL is written out beside the text rather than as a markdown
          // link, so a reader sees where it actually points instead of only
          // the words the document chose to show.
          para.push(target && /^https?:/i.test(target) ? `${text} <${target}>` : text);
          break;
        }
        case 'p':
          endParagraph();
          break;
        case 'tc':
          if (tableDepth === 1) row.push(cell.join(' ').trim());
          cell = [];
          break;
        case 'tr':
          if (tableDepth === 1 && row.length) tableRows.push(row);
          row = [];
          break;
        case 'tbl':
          tableDepth = Math.max(0, tableDepth - 1);
          if (tableDepth === 0 && tableRows.length) {
            const capped = tableRows.slice(0, opts.maxRows).map((r) => r.slice(0, opts.maxCols));
            out.push(toMarkdownTable(capped), '');
            if (tableRows.length > capped.length) {
              out.push(`_(table truncated at ${capped.length} of ${tableRows.length} rows)_`, '');
            }
            tableRows = [];
          }
          break;
      }
    }
  }

  return collapse(out);
}

/** Why this run would not be read, or null if it is ordinary text. */
function concealReason(p: RunProps): string | null {
  if (p.vanish) return 'hidden text (w:vanish)';
  if (p.webHidden) return 'hidden from web view (w:webHidden)';
  if (p.white) return 'white text';
  if (p.size !== null && p.size > 0 && p.size < 8) return `${p.size / 2}pt type`;
  return null;
}

function collapse(lines: string[]): string {
  const out: string[] = [];
  for (const line of lines) {
    if (line === '' && (out.length === 0 || out[out.length - 1] === '')) continue;
    out.push(line);
  }
  return out.join('\n').trim();
}

/** Exported for the tests, which drive the state machine directly. */
export const __test = { renderPart, concealReason };
