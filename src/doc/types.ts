// What a parsed document looks like by the time it leaves this module.
//
// The shape deliberately mirrors PageExtract: text plus a separate list of
// things the document kept away from a reader. A PDF with white-on-white
// paragraphs and a web page with an off-canvas div are the same attack, and
// they get reported through the same path.

export type DocKind =
  | 'pdf'
  | 'docx'
  | 'xlsx'
  | 'pptx'
  | 'odt'
  | 'ods'
  | 'odp'
  | 'text';

/** Formats recognised well enough to say what they are, but not to read. */
export type UnreadableKind = 'ole2' | 'rtf' | 'zip' | 'binary';

export const KIND_LABELS: Record<DocKind, string> = {
  pdf: 'PDF',
  docx: 'Word document (OOXML)',
  xlsx: 'Excel workbook (OOXML)',
  pptx: 'PowerPoint deck (OOXML)',
  odt: 'OpenDocument text',
  ods: 'OpenDocument spreadsheet',
  odp: 'OpenDocument presentation',
  text: 'plain text',
};

/** Text the document carried but did not show. */
export interface DocHidden {
  /** Where it was: "page 4", "Sheet1!B7", "slide 2". */
  where: string;
  /** How it was hidden, in the document's own terms. */
  reason: string;
  sample: string;
  /**
   * Whether the concealment has a purpose beyond ordinary document structure.
   * A hidden worksheet is bookkeeping; a paragraph in white 1pt type is not.
   */
  concealment: boolean;
}

/** One page, sheet or slide. */
export interface DocSection {
  /** "page 3 of 40", "Sheet: Q3 actuals", "slide 7". */
  label: string;
  markdown: string;
}

export interface DocumentExtract {
  kind: DocKind;
  title: string | null;
  author: string | null;
  created: string | null;
  modified: string | null;
  producer: string | null;
  /** Pages, sheets or slides, in document order, after any range selection. */
  sections: DocSection[];
  /** Total units in the file, before selection. */
  totalSections: number;
  /** Which ones are in `sections`, 1-based, for the header line. */
  selected: { from: number; to: number } | null;
  /** Everything, in order, ready to hand to the untrusted envelope. */
  markdown: string;
  hidden: DocHidden[];
  /** Truncation, encryption, embedded JavaScript, anything else notable. */
  warnings: string[];
}

/** Thrown for a file we can identify but cannot read. */
export class UnreadableDocument extends Error {
  constructor(
    readonly kind: UnreadableKind,
    message: string,
  ) {
    super(message);
    this.name = 'UnreadableDocument';
  }
}

/** Thrown when the file needs a password we were not given. */
export class DocumentEncrypted extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'DocumentEncrypted';
  }
}

export interface ExtractOptions {
  /** 1-based, inclusive. Absent means from the start. */
  firstSection?: number;
  /** 1-based, inclusive. Absent means to the end, subject to maxSections. */
  lastSection?: number;
  /** Hard cap on how many pages/sheets/slides are parsed in one call. */
  maxSections: number;
  /** Rows and columns per spreadsheet sheet. */
  maxRows: number;
  maxCols: number;
  /** For an encrypted PDF. */
  password?: string;
}

export const DEFAULT_EXTRACT_OPTIONS: ExtractOptions = {
  maxSections: 50,
  maxRows: 200,
  maxCols: 40,
};

/** Resolve a requested range against what the document actually holds. */
export function resolveRange(
  total: number,
  opts: ExtractOptions,
): { from: number; to: number; clamped: boolean } {
  const from = Math.min(Math.max(opts.firstSection ?? 1, 1), Math.max(total, 1));
  const wanted = Math.min(opts.lastSection ?? total, total);
  const to = Math.max(from, Math.min(wanted, from + opts.maxSections - 1));
  return { from, to, clamped: to < wanted };
}
