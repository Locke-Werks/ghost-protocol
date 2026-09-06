// The worker thread a document is parsed in.
//
// Everywhere else in this server, the process that handles attacker-controlled
// input is separated from the process that holds anything worth taking: Chrome
// renders pages under its own account, in its own unit. A document parser is
// the same kind of code — thousands of lines of format handling, driven
// entirely by bytes a stranger chose — but it runs in the MCP process, next to
// the database credential and the OAuth signing key.
//
// A thread is not the boundary a separate account is, and it is not claimed to
// be: JavaScript running here could still reach what the process can reach. It
// closes the failure that is actually likely, which is not code execution but a
// parse that never finishes or never stops allocating. A worker can be given a
// heap ceiling and can be terminated from outside while it is spinning, neither
// of which is true of a synchronous parse on the main thread — there, one
// crafted file stops the whole server answering.

import { parentPort, workerData } from 'node:worker_threads';
import { extractBytes, type ExtractRequest } from './extract.js';
import {
  DocumentEncrypted,
  UnreadableDocument,
  type DocumentExtract,
  type UnreadableKind,
} from './types.js';

export interface WorkerInput extends ExtractRequest {
  bytes: ArrayBuffer;
}

export type WorkerOutput =
  | { ok: true; extract: DocumentExtract }
  | { ok: false; kind: 'unreadable'; unreadable: UnreadableKind; message: string }
  | { ok: false; kind: 'encrypted' | 'error'; message: string };

async function main(): Promise<void> {
  const port = parentPort;
  if (!port) throw new Error('doc worker started outside a worker thread');

  const input = workerData as WorkerInput;
  const { bytes, ...opts } = input;

  try {
    const extract = await extractBytes(Buffer.from(bytes), opts);
    port.postMessage({ ok: true, extract } satisfies WorkerOutput);
  } catch (e) {
    port.postMessage(failure(e));
  }
}

function failure(e: unknown): WorkerOutput {
  if (e instanceof UnreadableDocument) {
    return { ok: false, kind: 'unreadable', unreadable: e.kind, message: e.message };
  }
  if (e instanceof DocumentEncrypted) return { ok: false, kind: 'encrypted', message: e.message };
  const message = e instanceof Error ? e.message : String(e);
  return { ok: false, kind: 'error', message: message.slice(0, 1000) };
}

void main().catch((e) => {
  parentPort?.postMessage(failure(e));
});
