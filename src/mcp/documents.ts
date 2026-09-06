// The path a document takes from bytes to a tool result.
//
// Four tools can end up here — a fetch that landed on a PDF, a navigation
// Chrome answered with a download, ghost_document asked directly, and
// ghost_curl handed something that is not text — so the parse, the size rules
// and the wording all live in one place rather than being written four times
// and drifting apart.

import type { Config } from '../config.js';
import {
  DocumentEncrypted,
  UnreadableDocument,
  extractDocument,
  mediaTypeFor,
  type DocumentExtract,
} from '../doc/index.js';
import { buildDocumentResult, buildUnreadableResult, type ContentBlock } from './results.js';
import type { Finding } from '../util/untrusted.js';
import { log } from '../util/log.js';

export interface DocumentArgs {
  first_page?: number;
  last_page?: number;
  max_rows?: number;
  max_cols?: number;
  password?: string;
  include_file?: boolean;
  max_text_bytes?: number;
}

export interface DocumentSource {
  bytes: Buffer;
  /** What the server called it. Kept for the log, believed for nothing. */
  contentType: string;
  requestedUrl: string;
  finalUrl: string;
  status: number | null;
  filename: string | null;
}

export interface DocumentOutcome {
  content: ContentBlock[];
  findings: Finding[];
  /** Absent when the file arrived but could not be read. */
  extract: DocumentExtract | null;
  /** Size of the file that was read, for the request log. */
  bytes: number;
}

export async function readDocument(
  source: DocumentSource,
  cfg: Config,
  args: DocumentArgs,
  notes: string[],
  sessionId?: string,
): Promise<DocumentOutcome> {
  // A format this cannot read is not the end of the exchange when the caller
  // asked for the file rather than for its text. The fetch worked; handing over
  // what arrived is a better answer than an error.
  if (args.include_file) {
    try {
      return await parseAndBuild(source, cfg, args, notes, sessionId);
    } catch (e) {
      if (!(e instanceof UnreadableDocument)) throw e;
      const notes2 = [...notes];
      const attachment = fitsAsAttachment(source, cfg, notes2);
      log.info('document not readable; returning the file', {
        url: source.finalUrl,
        bytes: source.bytes.byteLength,
        attached: attachment !== null,
      });
      return {
        content: buildUnreadableResult([...notes2, e.message].join(' '), {
          url: source.requestedUrl,
          finalUrl: source.finalUrl,
          filename: source.filename,
          attachment,
        }),
        findings: [],
        extract: null,
        bytes: source.bytes.byteLength,
      };
    }
  }
  return await parseAndBuild(source, cfg, args, notes, sessionId);
}

async function parseAndBuild(
  source: DocumentSource,
  cfg: Config,
  args: DocumentArgs,
  notes: string[],
  sessionId?: string,
): Promise<DocumentOutcome> {
  const extract = await extractDocument(
    source.bytes,
    {
      firstSection: args.first_page,
      lastSection: args.last_page,
      maxSections: cfg.documents.maxSections,
      maxRows: Math.min(args.max_rows ?? cfg.documents.maxRows, cfg.documents.maxRows),
      maxCols: Math.min(args.max_cols ?? cfg.documents.maxCols, cfg.documents.maxCols),
      password: args.password,
    },
    {
      timeoutMs: cfg.documents.parseTimeoutMs,
      memoryMb: cfg.documents.parseMemoryMb,
      concurrency: cfg.documents.parseConcurrency,
    },
  );

  log.info('document read', {
    kind: extract.kind,
    url: source.finalUrl,
    bytes: source.bytes.byteLength,
    sections: extract.totalSections,
    hidden: extract.hidden.length,
  });

  const all = [...notes];
  const attachment = attachmentFor(source, extract, args, cfg, all);

  const { content, findings } = buildDocumentResult(extract, {
    url: source.requestedUrl,
    finalUrl: source.finalUrl,
    status: source.status,
    maxTextBytes: Math.min(args.max_text_bytes ?? cfg.capture.maxTextBytes, cfg.capture.maxTextBytes),
    notes: all,
    filename: source.filename,
    sessionId,
    attachment,
  });

  return { content, findings, extract, bytes: source.bytes.byteLength };
}

/**
 * Whether to hand the file back as well as the text.
 *
 * Off unless asked for. Base64 inflates a file by a third and an MCP result is
 * not a download manager: a 10 MB PDF returned this way is 13 MB of context
 * spent on bytes the reader cannot read. It exists for the case where the
 * caller genuinely needs the file rather than what it says.
 */
function attachmentFor(
  source: DocumentSource,
  extract: DocumentExtract,
  args: DocumentArgs,
  cfg: Config,
  notes: string[],
): { bytes: Buffer; mediaType: string } | null {
  if (!args.include_file) return null;
  const fits = fitsAsAttachment(source, cfg, notes);
  return fits ? { bytes: fits.bytes, mediaType: mediaTypeFor(extract.kind) } : null;
}

function fitsAsAttachment(
  source: DocumentSource,
  cfg: Config,
  notes: string[],
): { bytes: Buffer } | null {
  if (source.bytes.byteLength <= cfg.documents.maxAttachmentBytes) return { bytes: source.bytes };
  notes.push(
    `The file itself was not attached: it is ${Math.round(source.bytes.byteLength / 1024)} KB, over the ` +
      `${Math.round(cfg.documents.maxAttachmentBytes / 1024)} KB limit for returning raw bytes.`,
  );
  return null;
}

/**
 * Turn a parse failure into something the caller can act on.
 *
 * "Unreadable" is not an error in the sense the other failures are: the fetch
 * worked, the file arrived, and it is simply not a format this reads. Saying
 * which format it is, and what would be readable, is more use than a stack.
 */
export function documentFailureText(e: unknown, url: string): string | null {
  if (e instanceof UnreadableDocument) {
    return `Fetched ${url}, but ${e.message}`;
  }
  if (e instanceof DocumentEncrypted) {
    return `Fetched ${url}, but ${e.message}`;
  }
  return null;
}
