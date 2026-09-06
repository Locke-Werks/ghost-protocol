// OpenDocument: .odt, .ods, .odp.
//
// The whole document is one `content.xml`, which makes this the simplest of the
// three families: no shared string table, no relationship indirection, and text
// stored as text. The three types differ only in what the body element is and
// how the content inside it is grouped, so they share one walk.
//
// There is no hidden-text detection here. ODF can hide text — a paragraph style
// with `fo:color` set to white, `text:display="none"` on a section — but the
// styles live in a separate part and resolving them means implementing style
// inheritance, which is a lot of machinery for a format that is not where this
// attack shows up in practice. The injection scan still runs over everything
// extracted, so instruction-shaped text is caught either way; what would be
// missed is the finding that it was concealed. Said here so the gap is not
// mistaken for a guarantee.

import { Zip } from './zip.js';
import { localName, scanXml } from './xml.js';
import { toMarkdownTable } from './ooxml.js';
import { resolveRange, type DocSection, type DocumentExtract, type ExtractOptions, type DocKind } from './types.js';

export function readOdf(zip: Zip, kind: 'odt' | 'ods' | 'odp', opts: ExtractOptions): DocumentExtract {
  const meta = readMeta(zip);
  const content = zip.readTextIfPresent('content.xml');
  if (content === null) {
    return {
      kind,
      ...meta,
      sections: [],
      totalSections: 0,
      selected: null,
      markdown: '',
      hidden: [],
      warnings: ['The archive is an OpenDocument file with no content.xml.'],
    };
  }

  const units = walk(content, kind, opts);
  const warnings: string[] = [];

  if (units.length === 0) {
    return {
      kind,
      ...meta,
      sections: [],
      totalSections: 0,
      selected: null,
      markdown: '',
      hidden: [],
      warnings: ['The document parsed but carried no text.'],
    };
  }

  // A text document is one continuous flow, so it has nothing to page through;
  // sheets and slides do.
  const range = kind === 'odt' ? { from: 1, to: units.length, clamped: false } : resolveRange(units.length, opts);
  const sections: DocSection[] = units.slice(range.from - 1, range.to);
  if (range.to < units.length) {
    warnings.push(
      `Read ${range.from} to ${range.to} of ${units.length}. Ask for a different range with first_page and last_page.`,
    );
  }

  const markdown = (
    kind === 'odt'
      ? sections.map((s) => s.markdown)
      : sections.map((s) => `## ${s.label}\n\n${s.markdown}`)
  )
    .join('\n\n')
    .trim();

  return {
    kind,
    ...meta,
    sections,
    totalSections: units.length,
    selected: kind === 'odt' ? null : { from: range.from, to: range.to },
    markdown,
    hidden: [],
    warnings,
  };
}

function readMeta(zip: Zip): {
  title: string | null;
  author: string | null;
  created: string | null;
  modified: string | null;
  producer: string | null;
} {
  const out = { title: null, author: null, created: null, modified: null, producer: null } as {
    title: string | null;
    author: string | null;
    created: string | null;
    modified: string | null;
    producer: string | null;
  };
  const xml = zip.readTextIfPresent('meta.xml');
  if (!xml) return out;

  const want: Record<string, keyof typeof out> = {
    title: 'title',
    creator: 'author',
    'creation-date': 'created',
    date: 'modified',
    generator: 'producer',
  };
  let field: keyof typeof out | null = null;
  for (const ev of scanXml(xml)) {
    if (ev.type === 'open') field = want[localName(ev.name)] ?? null;
    else if (ev.type === 'close') field = null;
    else if (field && ev.text.trim()) {
      out[field] = ev.text.trim().slice(0, 300);
      field = null;
    }
  }
  return out;
}

/**
 * One pass over content.xml, producing whatever the format's unit is.
 *
 * For a text document that is the single flow; for a spreadsheet, one section
 * per `table:table`; for a presentation, one per `draw:page`.
 */
function walk(xml: string, kind: DocKind, opts: ExtractOptions): DocSection[] {
  const sections: DocSection[] = [];
  const flow: string[] = [];

  let unitLabel: string | null = null;
  let unitLines: string[] = [];

  // Paragraph state.
  let para: string[] = [];
  let heading = 0;
  let listDepth = 0;
  let capture = false;

  // Table state, used by every format: .ods tables are the sheets, and .odt and
  // .odp can carry tables of their own.
  let inTable = false;
  let rows: string[][] = [];
  let row: string[] = [];
  let cell: string[] = [];
  let cellRepeat = 1;

  const lines = () => (unitLabel === null ? flow : unitLines);

  const endParagraph = () => {
    const text = para.join('').replace(/\s+$/g, '');
    para = [];
    const h = heading;
    heading = 0;
    if (!text.trim()) return;
    if (inTable) {
      cell.push(text.trim());
      return;
    }
    if (h > 0) lines().push('#'.repeat(Math.min(h, 6)) + ' ' + text.trim(), '');
    else if (listDepth > 0) lines().push('  '.repeat(listDepth - 1) + '- ' + text.trim());
    else lines().push(text.trim(), '');
  };

  const endUnit = () => {
    if (unitLabel === null) return;
    sections.push({ label: unitLabel, markdown: collapse(unitLines) });
    unitLabel = null;
    unitLines = [];
  };

  const flushTable = () => {
    const capped = rows.slice(0, opts.maxRows).map((r) => r.slice(0, opts.maxCols));
    if (capped.length) {
      lines().push(toMarkdownTable(capped), '');
      if (rows.length > capped.length) {
        lines().push(`_(table truncated at ${capped.length} of ${rows.length} rows)_`, '');
      }
    }
    rows = [];
    inTable = false;
  };

  for (const ev of scanXml(xml)) {
    if (ev.type === 'text') {
      if (capture) para.push(ev.text);
      continue;
    }
    const n = localName(ev.name);

    if (ev.type === 'open') {
      switch (n) {
        case 'h':
          heading = Number(ev.attrs['text:outline-level'] ?? ev.attrs['outline-level'] ?? 1) || 1;
          capture = true;
          para = [];
          break;
        case 'p':
          capture = true;
          para = [];
          break;
        case 'list':
          listDepth++;
          break;
        case 's': {
          // `text:s` is a run of spaces the format collapses out of the text.
          const count = Number(ev.attrs['text:c'] ?? ev.attrs['c'] ?? 1) || 1;
          if (capture) para.push(' '.repeat(Math.min(count, 200)));
          break;
        }
        case 'tab':
          if (capture) para.push('\t');
          break;
        case 'line-break':
          if (capture) para.push('\n');
          break;

        case 'table':
          // In a spreadsheet the table is the unit; elsewhere it is a block
          // inside whatever unit is already open.
          if (kind === 'ods') {
            endUnit();
            unitLabel = `sheet ${sections.length + 1}: ${ev.attrs['table:name'] ?? ev.attrs['name'] ?? ''}`.trim();
            unitLines = [];
          }
          inTable = true;
          rows = [];
          break;
        case 'table-row':
          row = [];
          break;
        case 'table-cell':
        case 'covered-table-cell':
          cell = [];
          cellRepeat = Math.min(Number(ev.attrs['table:number-columns-repeated'] ?? 1) || 1, opts.maxCols);
          break;

        case 'page':
          endUnit();
          unitLabel = `slide ${sections.length + 1}: ${ev.attrs['draw:name'] ?? ev.attrs['name'] ?? ''}`.trim();
          unitLines = [];
          break;
      }
      if (!ev.selfClosing) continue;
    }

    switch (n) {
      case 'h':
      case 'p':
        capture = false;
        endParagraph();
        break;
      case 'list':
        listDepth = Math.max(0, listDepth - 1);
        break;
      case 'table-cell':
      case 'covered-table-cell': {
        const text = cell.join(' ').trim();
        for (let i = 0; i < cellRepeat; i++) row.push(text);
        cell = [];
        cellRepeat = 1;
        break;
      }
      case 'table-row':
        // A run of empty repeated cells is padding, not data.
        while (row.length && row[row.length - 1] === '') row.pop();
        if (row.length) rows.push(row);
        row = [];
        break;
      case 'table':
        flushTable();
        break;
      case 'page':
        endUnit();
        break;
    }
  }

  endParagraph();
  if (inTable) flushTable();
  endUnit();

  if (sections.length === 0) {
    const text = collapse(flow);
    return text ? [{ label: 'document', markdown: text }] : [];
  }
  // A presentation or spreadsheet can still have loose content before the first
  // page or table; it goes in front rather than being dropped.
  const preamble = collapse(flow);
  if (preamble) sections.unshift({ label: 'document', markdown: preamble });
  return sections;
}

function collapse(lines: string[]): string {
  const out: string[] = [];
  for (const line of lines) {
    if (line === '' && (out.length === 0 || out[out.length - 1] === '')) continue;
    out.push(line);
  }
  return out.join('\n').trim();
}
