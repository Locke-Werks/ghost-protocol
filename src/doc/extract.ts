// Bytes in, DocumentExtract out.
//
// This is the half that runs inside the worker. It does the identification and
// dispatch and nothing else, so that the decision about what a file is and the
// decision about how much of the host it may touch stay in different places.

import { Zip, type ZipLimits } from './zip.js';
import { fromEntries, sniffContainer } from './sniff.js';
import { readDocx } from './docx.js';
import { readXlsx } from './xlsx.js';
import { readPptx } from './pptx.js';
import { readOdf } from './odf.js';
import { readPdf } from './pdf.js';
import { UnreadableDocument, type DocumentExtract, type ExtractOptions } from './types.js';

export interface ExtractRequest extends ExtractOptions {
  zipLimits?: ZipLimits;
}

export async function extractBytes(bytes: Buffer, opts: ExtractRequest): Promise<DocumentExtract> {
  const container = sniffContainer(bytes);

  if (container === 'pdf') return await readPdf(bytes, opts);

  if (container === 'text') {
    const text = bytes.toString('utf8');
    return {
      kind: 'text',
      title: null,
      author: null,
      created: null,
      modified: null,
      producer: null,
      sections: [{ label: 'document', markdown: text }],
      totalSections: 1,
      selected: null,
      markdown: text,
      hidden: [],
      warnings: [],
    };
  }

  if (container === 'ole2') {
    throw new UnreadableDocument(
      'ole2',
      'this is a pre-2007 Office file (.doc, .xls or .ppt). Those are OLE compound documents rather ' +
        'than zipped XML and are not read here. Re-saved as .docx, .xlsx or .pptx it would be.',
    );
  }
  if (container === 'rtf') {
    throw new UnreadableDocument('rtf', 'this is a Rich Text Format file, which is not read here.');
  }
  if (container === 'binary') {
    throw new UnreadableDocument(
      'binary',
      'these bytes are in no format this relay reads. Readable: PDF, .docx, .xlsx, .pptx, the ' +
        'OpenDocument equivalents, and plain text.',
    );
  }

  const zip = Zip.open(bytes, opts.zipLimits);
  const id = fromEntries(zip);
  switch (id.kind) {
    case 'docx':
      return readDocx(zip, opts);
    case 'xlsx':
      return readXlsx(zip, opts);
    case 'pptx':
      return readPptx(zip, opts);
    case 'odt':
    case 'ods':
    case 'odp':
      return readOdf(zip, id.kind, opts);
    default:
      throw new UnreadableDocument('zip', id.detail);
  }
}
