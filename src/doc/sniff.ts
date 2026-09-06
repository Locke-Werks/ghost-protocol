// What kind of file is this, actually.
//
// The Content-Type header and the URL's extension are hints from the same
// untrusted server that sent the bytes. They are worth reading, and they are
// not worth believing: a page that wants to be treated as HTML while shipping
// something else only has to say so. So the leading bytes decide, and the
// headers are consulted only where the bytes are genuinely ambiguous, which in
// practice means telling plain text apart from binary.

import { Zip } from './zip.js';
import type { DocKind, UnreadableKind } from './types.js';

export type Container = 'pdf' | 'zip' | 'ole2' | 'rtf' | 'text' | 'binary';

const OLE2 = Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]);

export function sniffContainer(bytes: Buffer): Container {
  if (bytes.length === 0) return 'text';
  // A PDF is allowed a little junk before its header, and plenty of real files
  // have some, so the marker is looked for rather than required at offset 0.
  const head = bytes.subarray(0, 1024);
  if (head.includes('%PDF-')) return 'pdf';
  if (bytes.length >= 4 && bytes.readUInt32LE(0) === 0x04034b50) return 'zip';
  if (bytes.length >= 8 && bytes.subarray(0, 8).equals(OLE2)) return 'ole2';
  if (head.subarray(0, 5).toString('latin1') === '{\\rtf') return 'rtf';
  return looksTextual(bytes) ? 'text' : 'binary';
}

/**
 * Valid UTF-8 with no NULs and few controls.
 *
 * The cheap version of this test is "does it decode", which passes for almost
 * any byte sequence because Buffer#toString substitutes rather than throws.
 * TextDecoder in fatal mode actually answers the question.
 */
function looksTextual(bytes: Buffer): boolean {
  const sample = bytes.subarray(0, 8192);
  if (sample.includes(0)) return false;
  try {
    new TextDecoder('utf8', { fatal: true }).decode(sample);
  } catch {
    return false;
  }
  let controls = 0;
  for (const b of sample) {
    if (b < 0x09 || (b > 0x0d && b < 0x20)) controls++;
  }
  return controls / Math.max(sample.length, 1) < 0.01;
}

export interface Identified {
  kind: DocKind | null;
  /** Set when the file is recognised but cannot be read. */
  unreadable: UnreadableKind | null;
  detail: string;
}

/**
 * Name the format of an archive.
 *
 * A ZIP has to be opened to be identified: an OOXML file, an OpenDocument file
 * and a plain archive of holiday photos all start with the same four bytes, and
 * only the entry names tell them apart.
 */
export function fromEntries(zip: Zip): Identified {
  // OpenDocument puts an uncompressed `mimetype` entry first and the format is
  // written out in full inside it.
  if (zip.has('mimetype')) {
    const mime = zip.readText('mimetype').trim();
    if (mime.startsWith('application/vnd.oasis.opendocument.text')) {
      return { kind: 'odt', unreadable: null, detail: mime };
    }
    if (mime.startsWith('application/vnd.oasis.opendocument.spreadsheet')) {
      return { kind: 'ods', unreadable: null, detail: mime };
    }
    if (mime.startsWith('application/vnd.oasis.opendocument.presentation')) {
      return { kind: 'odp', unreadable: null, detail: mime };
    }
  }

  // OOXML has no such marker, so the part names are the tell. Checking for the
  // main part rather than the directory avoids calling a stripped-down archive
  // a Word document because something left a `word/` folder in it.
  if (zip.has('word/document.xml')) return { kind: 'docx', unreadable: null, detail: 'OOXML WordprocessingML' };
  if (zip.has('xl/workbook.xml')) return { kind: 'xlsx', unreadable: null, detail: 'OOXML SpreadsheetML' };
  if (zip.has('ppt/presentation.xml')) return { kind: 'pptx', unreadable: null, detail: 'OOXML PresentationML' };

  // A macro-enabled or template variant keeps the same parts under the same
  // names, so anything that got here is genuinely something else.
  const sample = zip.names().slice(0, 8).join(', ');
  return {
    kind: null,
    unreadable: 'zip',
    detail: `a ZIP archive that is not an Office or OpenDocument file (entries: ${sample})`,
  };
}

/**
 * A media type for a kind, for labelling an attachment.
 *
 * The server's own Content-Type is not reused for this: it is the untrusted
 * half of the exchange, and a mislabelled attachment is how a reader ends up
 * opening something with the wrong application.
 */
export function mediaTypeFor(kind: DocKind): string {
  switch (kind) {
    case 'pdf':
      return 'application/pdf';
    case 'docx':
      return 'application/vnd.openxmlformats-officedocument.wordprocessingml.document';
    case 'xlsx':
      return 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';
    case 'pptx':
      return 'application/vnd.openxmlformats-officedocument.presentationml.presentation';
    case 'odt':
      return 'application/vnd.oasis.opendocument.text';
    case 'ods':
      return 'application/vnd.oasis.opendocument.spreadsheet';
    case 'odp':
      return 'application/vnd.oasis.opendocument.presentation';
    case 'text':
      return 'text/plain';
  }
}

/**
 * Whether a Content-Type is worth routing to the document reader.
 *
 * This runs before the bytes are in hand, since it decides whether to go and
 * get them, so it is the one place a header does get believed. Being wrong here
 * costs a wasted fetch, and the bytes still have the last word.
 */
export function looksLikeDocument(contentType: string, url: string): boolean {
  const type = contentType.split(';')[0]!.trim().toLowerCase();
  if (DOCUMENT_TYPES.has(type)) return true;
  if (/^application\/vnd\.(openxmlformats-officedocument|oasis\.opendocument|ms-(word|excel|powerpoint))/.test(type)) {
    return true;
  }
  // `application/octet-stream` is what a server says when it has not been
  // configured, and an empty Content-Type is what it says when it has not been
  // set at all. Both are common on the file drops that serve exactly the
  // documents this is for, so they fall back to the extension rather than being
  // taken at their word in either direction.
  if (type && type !== 'application/octet-stream' && type !== 'binary/octet-stream') return false;
  return hasDocumentExtension(url);
}

function hasDocumentExtension(url: string): boolean {
  try {
    return /\.(pdf|docx?|xlsx?|pptx?|odt|ods|odp)$/i.test(new URL(url).pathname);
  } catch {
    return false;
  }
}

const DOCUMENT_TYPES = new Set([
  'application/pdf',
  'application/x-pdf',
  'application/msword',
  'application/vnd.ms-excel',
  'application/vnd.ms-powerpoint',
]);
