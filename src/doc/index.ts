// The host side of document extraction: hand it bytes, get a DocumentExtract,
// and never wait forever for one.

import { Worker } from 'node:worker_threads';
import { log, errFields } from '../util/log.js';
import type { WorkerInput, WorkerOutput } from './worker.js';
import {
  DEFAULT_EXTRACT_OPTIONS,
  DocumentEncrypted,
  UnreadableDocument,
  type DocumentExtract,
  type ExtractOptions,
} from './types.js';
import type { ZipLimits } from './zip.js';

export { KIND_LABELS, DocumentEncrypted, UnreadableDocument } from './types.js';
export type { DocumentExtract, DocHidden, DocKind, DocSection, ExtractOptions } from './types.js';
export { looksLikeDocument, mediaTypeFor, sniffContainer } from './sniff.js';

export interface ExtractLimits {
  /** Wall clock for one document, after which the worker is killed. */
  timeoutMs: number;
  /** Heap ceiling for the worker, in MiB. */
  memoryMb: number;
  /** Parses allowed to run at once. */
  concurrency?: number;
  zipLimits?: ZipLimits;
}

export const DEFAULT_LIMITS: ExtractLimits = { timeoutMs: 30_000, memoryMb: 384, concurrency: 2 };

const WORKER_URL = new URL('./worker.js', import.meta.url);

/**
 * How many documents may be in flight at once.
 *
 * Each parse is a worker with a heap ceiling of its own, and the service runs
 * under a cgroup memory limit that several of them together would walk
 * straight through. The transport is stateless, so nothing else bounds how many
 * calls arrive at the same moment; this does.
 */
let running = 0;
const waiting: Array<() => void> = [];

async function acquire(limit: number): Promise<void> {
  if (running < limit) {
    running++;
    return;
  }
  // The slot is handed over by release() rather than taken here. Decrementing
  // and letting the woken caller increment would leave the count one low for a
  // microtask, which is long enough for a third caller to walk through.
  await new Promise<void>((resolve) => waiting.push(resolve));
}

function release(): void {
  const next = waiting.shift();
  if (next) next();
  else running--;
}

export async function extractDocument(
  bytes: Buffer,
  options: Partial<ExtractOptions> = {},
  limits: ExtractLimits = DEFAULT_LIMITS,
): Promise<DocumentExtract> {
  await acquire(limits.concurrency ?? DEFAULT_LIMITS.concurrency ?? 2);
  try {
    return await parse(bytes, options, limits);
  } finally {
    release();
  }
}

async function parse(
  bytes: Buffer,
  options: Partial<ExtractOptions>,
  limits: ExtractLimits,
): Promise<DocumentExtract> {
  const opts: ExtractOptions = { ...DEFAULT_EXTRACT_OPTIONS, ...options };

  // Node allocates small Buffers out of a shared pool, so `bytes.buffer` is
  // routinely a slab that other live Buffers also point into. Transferring that
  // would detach memory this process is still using, so the payload is copied
  // out first and the copy is what moves.
  const payload = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;

  const workerData: WorkerInput = {
    ...opts,
    zipLimits: limits.zipLimits,
    bytes: payload,
  };

  const started = Date.now();
  const worker = new Worker(WORKER_URL, {
    workerData,
    transferList: [payload],
    resourceLimits: {
      maxOldGenerationSizeMb: limits.memoryMb,
      maxYoungGenerationSizeMb: Math.min(64, limits.memoryMb),
    },
    // Nothing in the parser reads argv or the environment, and a worker that
    // cannot see them cannot leak them into a parse error either.
    env: {},
    argv: [],
  });

  let settled = false;
  const timer = setTimeout(() => {
    if (settled) return;
    log.warn('document parse timed out', { timeout_ms: limits.timeoutMs, bytes: bytes.length });
    void worker.terminate();
  }, limits.timeoutMs);
  timer.unref();

  try {
    const result = await new Promise<WorkerOutput>((resolve, reject) => {
      worker.once('message', (m: WorkerOutput) => {
        settled = true;
        resolve(m);
      });
      worker.once('error', (e) => {
        settled = true;
        reject(e);
      });
      worker.once('exit', (code) => {
        if (settled) return;
        settled = true;
        // Terminate() exits with 1, and so does running out of heap. Both look
        // the same from here, and both mean the same thing to the caller.
        reject(
          new Error(
            Date.now() - started >= limits.timeoutMs
              ? `the document did not finish parsing within ${Math.max(1, Math.round(limits.timeoutMs / 1000))}s and was abandoned`
              : `the document parser exited unexpectedly (code ${code}); the file may be far larger or more deeply nested than it declares`,
          ),
        );
      });
    });

    if (result.ok) return result.extract;
    if (result.kind === 'unreadable') throw new UnreadableDocument(result.unreadable, result.message);
    if (result.kind === 'encrypted') throw new DocumentEncrypted(result.message);
    throw new Error(result.message);
  } catch (e) {
    if (!(e instanceof UnreadableDocument) && !(e instanceof DocumentEncrypted)) {
      log.debug('document parse failed', errFields(e));
    }
    throw e;
  } finally {
    clearTimeout(timer);
    await worker.terminate().catch(() => {});
  }
}
