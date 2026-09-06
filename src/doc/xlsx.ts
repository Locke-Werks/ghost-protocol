// SpreadsheetML.
//
// A workbook is the one office format where a naive text dump is actively
// misleading. Cell text lives in a shared string table rather than in the cell,
// so the sheet XML on its own is a list of integers; and every date is a
// floating-point day count, so a converter that skips the style table reports
// an invoice dated 45231. Both are worth the extra parts.
//
// What comes back is a markdown table per sheet, bounded in both directions,
// because a sheet is not a document and an agent asked to read one wants the
// shape of the data far more than it wants row 40,000.

import { Zip } from './zip.js';
import { localName, scanXml } from './xml.js';
import { isNearWhite, pushHidden, readCoreProps, readRels, sampleOf, toMarkdownTable } from './ooxml.js';
import { resolveRange, type DocHidden, type DocSection, type DocumentExtract, type ExtractOptions } from './types.js';

interface SheetRef {
  name: string;
  part: string;
  hidden: boolean;
}

interface Styles {
  /** cellXfs index -> whether that style formats its number as a date. */
  isDate: boolean[];
  /** cellXfs index -> whether the font is white. */
  isWhiteFont: boolean[];
}

export function readXlsx(zip: Zip, opts: ExtractOptions): DocumentExtract {
  const props = readCoreProps(zip);
  const warnings: string[] = [];
  const hidden: DocHidden[] = [];

  const workbookXml = zip.readText('xl/workbook.xml');
  const rels = readRels(zip, 'xl/workbook.xml');
  const sheets = readSheetList(workbookXml, rels);
  const date1904 = /date1904\s*=\s*"(1|true)"/i.test(workbookXml);
  const shared = readSharedStrings(zip);
  const styles = readStyles(zip);

  if (sheets.length === 0) {
    return {
      kind: 'xlsx',
      ...props,
      sections: [],
      totalSections: 0,
      selected: null,
      markdown: '',
      hidden,
      warnings: ['The workbook declares no worksheets.'],
    };
  }

  const range = resolveRange(sheets.length, opts);
  const sections: DocSection[] = [];

  for (let i = range.from - 1; i <= range.to - 1; i++) {
    const sheet = sheets[i]!;
    const label = `sheet ${i + 1} of ${sheets.length}: ${sheet.name}${sheet.hidden ? ' (hidden)' : ''}`;
    const xml = zip.readTextIfPresent(sheet.part);
    if (xml === null) {
      sections.push({ label, markdown: `_(the workbook points at ${sheet.part}, which is not in the file)_` });
      continue;
    }
    sections.push({
      label,
      markdown: renderSheet(xml, sheet, { shared, styles, date1904 }, hidden, opts),
    });
  }

  const hiddenSheets = sheets.filter((s) => s.hidden).length;
  if (hiddenSheets > 0) {
    warnings.push(
      `${hiddenSheets} of ${sheets.length} worksheet(s) are marked hidden. They are read like any other; ` +
        'a hidden sheet is ordinary workbook bookkeeping, not concealment on its own.',
    );
  }
  if (range.clamped || range.to < sheets.length) {
    warnings.push(
      `Read sheets ${range.from} to ${range.to} of ${sheets.length}. Ask for a different range with first_page and last_page.`,
    );
  }

  const markdown = sections.map((s) => `## ${s.label}\n\n${s.markdown}`).join('\n\n').trim();

  return {
    kind: 'xlsx',
    ...props,
    sections,
    totalSections: sheets.length,
    selected: { from: range.from, to: range.to },
    markdown,
    hidden,
    warnings,
  };
}

function readSheetList(xml: string, rels: ReturnType<typeof readRels>): SheetRef[] {
  const sheets: SheetRef[] = [];
  let inSheets = false;
  for (const ev of scanXml(xml)) {
    if (ev.type === 'open' && localName(ev.name) === 'sheets') inSheets = true;
    else if (ev.type === 'close' && localName(ev.name) === 'sheets') inSheets = false;
    else if (inSheets && ev.type === 'open' && localName(ev.name) === 'sheet') {
      const id = ev.attrs['r:id'] ?? ev.attrs['id'];
      const rel = id ? rels.get(id) : undefined;
      const state = (ev.attrs['state'] ?? '').toLowerCase();
      sheets.push({
        name: ev.attrs['name'] ?? `sheet${sheets.length + 1}`,
        part: rel?.target ?? `xl/worksheets/sheet${sheets.length + 1}.xml`,
        hidden: state === 'hidden' || state === 'veryhidden',
      });
    }
  }
  return sheets;
}

function readSharedStrings(zip: Zip): string[] {
  const xml = zip.readTextIfPresent('xl/sharedStrings.xml');
  if (!xml) return [];
  const out: string[] = [];
  let current: string[] | null = null;
  let capture = false;
  for (const ev of scanXml(xml)) {
    if (ev.type === 'open') {
      const n = localName(ev.name);
      if (n === 'si') current = [];
      // A string with mixed formatting is split into `r` runs, each with its
      // own `t`. Concatenating them is the whole of putting it back together.
      else if (n === 't') capture = current !== null;
      // `rPh` is furigana and `phoneticPr` its settings: pronunciation
      // guides for the same text, which would arrive as a duplicate.
      else if (n === 'rPh') capture = false;
    } else if (ev.type === 'close') {
      const n = localName(ev.name);
      if (n === 'si' && current) {
        out.push(current.join(''));
        current = null;
      } else if (n === 't') capture = false;
    } else if (capture && current) {
      current.push(ev.text);
    }
  }
  return out;
}

/**
 * Just enough of `xl/styles.xml` to know a date from a number.
 *
 * Only two questions get asked of it: does this cell's format make its number a
 * date, and is its font white. Everything else in the part — borders, fills,
 * alignment — is presentation this reader has no use for.
 */
function readStyles(zip: Zip): Styles {
  const xml = zip.readTextIfPresent('xl/styles.xml');
  const styles: Styles = { isDate: [], isWhiteFont: [] };
  if (!xml) return styles;

  const customDateFormats = new Set<number>();
  const whiteFonts = new Set<number>();
  let fontIndex = -1;
  let inFonts = false;
  let inCellXfs = false;

  for (const ev of scanXml(xml)) {
    if (ev.type === 'close') {
      const n = localName(ev.name);
      if (n === 'fonts') inFonts = false;
      else if (n === 'cellXfs') inCellXfs = false;
      continue;
    }
    if (ev.type !== 'open') continue;
    const n = localName(ev.name);

    if (n === 'numFmt') {
      const id = Number(ev.attrs['numFmtId']);
      if (Number.isFinite(id) && isDateFormatCode(ev.attrs['formatCode'] ?? '')) customDateFormats.add(id);
    } else if (n === 'fonts') {
      inFonts = true;
      fontIndex = -1;
    } else if (n === 'font' && inFonts) {
      fontIndex++;
    } else if (n === 'color' && inFonts && fontIndex >= 0) {
      if (isNearWhite(ev.attrs['rgb'])) whiteFonts.add(fontIndex);
    } else if (n === 'cellXfs') {
      inCellXfs = true;
    } else if (n === 'xf' && inCellXfs) {
      const numFmtId = Number(ev.attrs['numFmtId'] ?? 0);
      styles.isDate.push(isBuiltinDateFormat(numFmtId) || customDateFormats.has(numFmtId));
      styles.isWhiteFont.push(whiteFonts.has(Number(ev.attrs['fontId'] ?? -1)));
    }
  }
  return styles;
}

/** The built-in numbering formats that are dates or times. */
function isBuiltinDateFormat(id: number): boolean {
  return (id >= 14 && id <= 22) || (id >= 45 && id <= 47);
}

/**
 * A custom format code that renders a date.
 *
 * The date letters have to be found outside quoted literals and outside the
 * bracketed sections that carry colours and conditions. `m` is deliberately not
 * one of them: on its own it is minutes as often as months, and getting this
 * wrong in the permissive direction turns a currency column into 1970.
 */
function isDateFormatCode(code: string): boolean {
  let inQuote = false;
  let inBracket = false;
  for (let i = 0; i < code.length; i++) {
    const c = code[i]!;
    if (inQuote) {
      if (c === '"') inQuote = false;
      continue;
    }
    if (inBracket) {
      if (c === ']') inBracket = false;
      continue;
    }
    if (c === '"') inQuote = true;
    else if (c === '[') inBracket = true;
    else if (c === '\\') i++;
    else if ('yYdD'.includes(c)) return true;
    else if ('hHsS'.includes(c)) return true;
  }
  return false;
}

interface SheetContext {
  shared: string[];
  styles: Styles;
  date1904: boolean;
}

function renderSheet(
  xml: string,
  sheet: SheetRef,
  ctx: SheetContext,
  hidden: DocHidden[],
  opts: ExtractOptions,
): string {
  const hiddenCols = new Set<number>();
  const rows: Array<{ index: number; cells: Map<number, string> }> = [];
  let totalRows = 0;
  let hiddenRowCount = 0;
  let maxCol = 0;

  let rowIndex = 0;
  let rowHidden = false;
  let cells = new Map<number, string>();

  let cellRef = '';
  let cellCol = 0;
  let cellType = '';
  let cellStyle = -1;
  let value: string[] | null = null;
  let inInlineString = false;

  const noteHidden = (where: string, reason: string, text: string, concealment: boolean) => {
    if (!text.trim()) return;
    pushHidden(hidden, { where, reason, sample: sampleOf(text), concealment });
  };

  for (const ev of scanXml(xml)) {
    if (ev.type === 'text') {
      if (value) value.push(ev.text);
      continue;
    }
    const n = localName(ev.name);

    if (ev.type === 'open') {
      switch (n) {
        case 'col': {
          if (ev.attrs['hidden'] !== '1' && ev.attrs['hidden'] !== 'true') break;
          const min = Number(ev.attrs['min'] ?? 0);
          const max = Number(ev.attrs['max'] ?? min);
          // A hidden column can span the whole sheet width, so the range is
          // clamped rather than expanded into 16,384 entries.
          for (let c = min; c <= Math.min(max, min + 4096); c++) hiddenCols.add(c);
          break;
        }
        case 'row':
          rowIndex = Number(ev.attrs['r'] ?? rowIndex + 1) || rowIndex + 1;
          rowHidden = ev.attrs['hidden'] === '1' || ev.attrs['hidden'] === 'true';
          cells = new Map();
          totalRows++;
          if (rowHidden) hiddenRowCount++;
          break;
        case 'c':
          cellRef = ev.attrs['r'] ?? '';
          cellCol = columnOf(cellRef);
          cellType = ev.attrs['t'] ?? 'n';
          cellStyle = Number(ev.attrs['s'] ?? -1);
          inInlineString = false;
          break;
        case 'is':
          inInlineString = true;
          break;
        case 'v':
        case 't':
          if (cellRef) value = [];
          break;
      }
      if (!ev.selfClosing) continue;
    }

    switch (n) {
      case 'v':
      case 't': {
        if (!value) break;
        const raw = value.join('');
        value = null;
        // `t` appears both as an inline string's text and, in `is`, nested
        // inside `r` runs; either way it belongs to the open cell.
        const text = renderCell(raw, cellType, cellStyle, ctx, inInlineString || n === 't');
        if (!text) break;
        const where = `${sheet.name}!${cellRef || '?'}`;
        if (ctx.styles.isWhiteFont[cellStyle] === true) {
          noteHidden(where, 'white text', text, true);
        } else if (rowHidden) {
          noteHidden(where, 'hidden row', text, false);
        } else if (hiddenCols.has(cellCol)) {
          noteHidden(where, 'hidden column', text, false);
        } else {
          const existing = cells.get(cellCol);
          cells.set(cellCol, existing ? existing + text : text);
          if (cellCol > maxCol) maxCol = cellCol;
        }
        break;
      }
      case 'c':
        cellRef = '';
        cellCol = 0;
        break;
      case 'is':
        inInlineString = false;
        break;
      case 'row':
        if (!rowHidden && cells.size > 0 && rows.length < opts.maxRows) {
          rows.push({ index: rowIndex, cells });
        }
        cells = new Map();
        break;
    }
  }

  if (rows.length === 0) {
    return hiddenRowCount > 0
      ? `_(no visible cells; ${hiddenRowCount} hidden row(s) are listed with the concealed text below)_`
      : '_(empty sheet)_';
  }

  const cols = Math.min(maxCol, opts.maxCols);
  const grid = rows.map((r) => {
    const line: string[] = [];
    for (let c = 1; c <= cols; c++) line.push(r.cells.get(c) ?? '');
    return line;
  });

  const notes: string[] = [];
  if (totalRows > rows.length + hiddenRowCount) {
    notes.push(`showing ${rows.length} of ${totalRows} rows`);
  }
  if (maxCol > cols) notes.push(`showing ${cols} of ${maxCol} columns`);
  if (hiddenRowCount > 0) notes.push(`${hiddenRowCount} hidden row(s) held back`);

  const table = toMarkdownTable(grid);
  return notes.length ? `${table}\n\n_(${notes.join('; ')})_` : table;
}

/**
 * One cell's stored value as the text a person would see in Excel.
 *
 * Numbers are left exactly as stored rather than rounded to a display width:
 * this is data an agent may go on to compute with, and a plausible-looking
 * wrong number is worse than an ugly right one.
 */
function renderCell(raw: string, type: string, styleIndex: number, ctx: SheetContext, isText: boolean): string {
  const v = raw.trim();
  if (!v) return '';
  switch (type) {
    case 's': {
      const idx = Number(v);
      return Number.isInteger(idx) ? (ctx.shared[idx] ?? '') : '';
    }
    case 'str':
    case 'inlineStr':
      return raw;
    case 'b':
      return v === '1' ? 'TRUE' : 'FALSE';
    case 'e':
      return v; // #REF!, #DIV/0! and friends, which are the useful answer here
    case 'd':
      return v; // already an ISO date
    default: {
      if (isText && !/^-?\d/.test(v)) return raw;
      const num = Number(v);
      if (!Number.isFinite(num)) return raw;
      if (ctx.styles.isDate[styleIndex] === true) return serialToIso(num, ctx.date1904) ?? v;
      return v;
    }
  }
}

/**
 * Excel's day count to an ISO timestamp.
 *
 * The 1900 system's epoch is 1899-12-30 rather than 12-31 because Lotus 1-2-3
 * believed 1900 was a leap year and Excel kept the bug for compatibility, so
 * every date after February 1900 is one day out unless the epoch absorbs it.
 */
function serialToIso(serial: number, date1904: boolean): string | null {
  if (!Number.isFinite(serial) || serial < 0 || serial > 3_000_000) return null;
  const epoch = date1904 ? Date.UTC(1904, 0, 1) : Date.UTC(1899, 11, 30);
  const ms = epoch + Math.round(serial * 86_400_000);
  const d = new Date(ms);
  if (Number.isNaN(d.getTime())) return null;
  const iso = d.toISOString();
  // A whole number is a date with no time on it, and printing midnight for
  // every row buries the ones that genuinely carry a time.
  return Number.isInteger(serial) ? iso.slice(0, 10) : iso.slice(0, 19).replace('T', ' ');
}

/** "BC12" -> 55. */
export function columnOf(ref: string): number {
  let n = 0;
  for (let i = 0; i < ref.length; i++) {
    const c = ref.charCodeAt(i);
    if (c >= 65 && c <= 90) n = n * 26 + (c - 64);
    else if (c >= 97 && c <= 122) n = n * 26 + (c - 96);
    else break;
  }
  return n;
}

/** Exported for the tests. */
export const __test = { isDateFormatCode, serialToIso, columnOf, readSharedStrings };
