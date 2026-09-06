// A ZIP reader with a budget.
//
// Every modern office format is a ZIP of XML, so reading one is the price of
// admission for .docx, .xlsx, .pptx and the OpenDocument family. This is a
// reader rather than a dependency because the job is small and the interesting
// part is the refusals: a document arriving here is attacker-controlled, and a
// ZIP is the classic way to turn a 40 KB download into a 5 GB heap.
//
// So nothing is inflated speculatively. Entries are located from the central
// directory, decompressed one at a time, and every one of them is bounded
// twice: once against the size the header claims, and once against the bytes
// zlib actually produces, because the header is written by the same person as
// the payload.

import { inflateRawSync } from 'node:zlib';

const LOCAL_SIG = 0x04034b50;
const CENTRAL_SIG = 0x02014b50;
const EOCD_SIG = 0x06054b50;
const ZIP64_EOCD_SIG = 0x06064b50;
const ZIP64_LOCATOR_SIG = 0x07064b50;

const METHOD_STORE = 0;
const METHOD_DEFLATE = 8;

export interface ZipLimits {
  /** Entries in the central directory. */
  maxEntries: number;
  /** Uncompressed bytes for any single entry. */
  maxEntryBytes: number;
  /** Uncompressed bytes across everything actually read. */
  maxTotalBytes: number;
}

export const DEFAULT_ZIP_LIMITS: ZipLimits = {
  maxEntries: 4096,
  maxEntryBytes: 64 * 1024 * 1024,
  maxTotalBytes: 192 * 1024 * 1024,
};

export interface ZipEntry {
  name: string;
  method: number;
  compressedSize: number;
  uncompressedSize: number;
  localOffset: number;
  encrypted: boolean;
}

export class ZipError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ZipError';
  }
}

export class Zip {
  private readonly entries = new Map<string, ZipEntry>();
  private readonly order: string[] = [];
  private spent = 0;

  private constructor(
    private readonly buf: Buffer,
    private readonly limits: ZipLimits,
  ) {}

  static open(buf: Buffer, limits: ZipLimits = DEFAULT_ZIP_LIMITS): Zip {
    const zip = new Zip(buf, limits);
    zip.readCentralDirectory();
    return zip;
  }

  names(): string[] {
    return [...this.order];
  }

  has(name: string): boolean {
    return this.entries.has(name);
  }

  entry(name: string): ZipEntry | undefined {
    return this.entries.get(name);
  }

  /** Entry names under a prefix, in central-directory order. */
  under(prefix: string): string[] {
    return this.order.filter((n) => n.startsWith(prefix));
  }

  read(name: string): Buffer {
    const entry = this.entries.get(name);
    if (!entry) throw new ZipError(`no entry "${name}" in the archive`);
    if (entry.encrypted) throw new ZipError(`entry "${name}" is encrypted`);
    if (entry.uncompressedSize > this.limits.maxEntryBytes) {
      throw new ZipError(
        `entry "${name}" declares ${entry.uncompressedSize} bytes, over the ${this.limits.maxEntryBytes} limit`,
      );
    }

    // The local header repeats the name and carries its own extra field, whose
    // length routinely differs from the central directory's. The data starts
    // after this copy, so it has to be read rather than assumed.
    const off = entry.localOffset;
    this.need(off + 30, name);
    if (this.buf.readUInt32LE(off) !== LOCAL_SIG) {
      throw new ZipError(`entry "${name}" does not start with a local file header`);
    }
    const nameLen = this.buf.readUInt16LE(off + 26);
    const extraLen = this.buf.readUInt16LE(off + 28);
    const start = off + 30 + nameLen + extraLen;
    const end = start + entry.compressedSize;
    this.need(end, name);

    const raw = this.buf.subarray(start, end);
    let out: Buffer;
    if (entry.method === METHOD_STORE) {
      out = Buffer.from(raw);
    } else if (entry.method === METHOD_DEFLATE) {
      // maxOutputLength is the check that matters: it holds even when the
      // header understates the entry, which is exactly what a bomb does.
      try {
        out = inflateRawSync(raw, { maxOutputLength: this.limits.maxEntryBytes });
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        throw new ZipError(`entry "${name}" would not inflate: ${msg}`);
      }
    } else {
      throw new ZipError(`entry "${name}" uses compression method ${entry.method}, which is not supported`);
    }

    this.spent += out.length;
    if (this.spent > this.limits.maxTotalBytes) {
      throw new ZipError(
        `the archive has expanded past ${this.limits.maxTotalBytes} bytes; refusing to read further`,
      );
    }
    return out;
  }

  /** An entry as text, or null if it is not there. Most callers want this. */
  readTextIfPresent(name: string): string | null {
    if (!this.entries.has(name)) return null;
    return stripBom(this.read(name).toString('utf8'));
  }

  readText(name: string): string {
    return stripBom(this.read(name).toString('utf8'));
  }

  private need(offset: number, what: string): void {
    if (offset > this.buf.length || offset < 0) {
      throw new ZipError(`the archive is truncated before "${what}"`);
    }
  }

  private readCentralDirectory(): void {
    const eocd = this.findEocd();
    let entryCount = this.buf.readUInt16LE(eocd + 10);
    let cdSize = this.buf.readUInt32LE(eocd + 12);
    let cdOffset = this.buf.readUInt32LE(eocd + 16);

    // Zip64 is signalled by every affected field being saturated. Office
    // applications write it for large workbooks, so it is not exotic.
    if (entryCount === 0xffff || cdSize === 0xffffffff || cdOffset === 0xffffffff) {
      const z64 = this.findZip64Eocd(eocd);
      if (z64 === null) throw new ZipError('the archive claims zip64 but carries no zip64 record');
      entryCount = Number(this.buf.readBigUInt64LE(z64 + 32));
      cdSize = Number(this.buf.readBigUInt64LE(z64 + 40));
      cdOffset = Number(this.buf.readBigUInt64LE(z64 + 48));
    }

    if (entryCount > this.limits.maxEntries) {
      throw new ZipError(`the archive holds ${entryCount} entries, over the ${this.limits.maxEntries} limit`);
    }
    this.need(cdOffset + cdSize, 'central directory');

    let p = cdOffset;
    for (let i = 0; i < entryCount; i++) {
      this.need(p + 46, 'central directory entry');
      if (this.buf.readUInt32LE(p) !== CENTRAL_SIG) break;

      const flags = this.buf.readUInt16LE(p + 8);
      const method = this.buf.readUInt16LE(p + 10);
      let compressedSize = this.buf.readUInt32LE(p + 20);
      let uncompressedSize = this.buf.readUInt32LE(p + 24);
      const nameLen = this.buf.readUInt16LE(p + 28);
      const extraLen = this.buf.readUInt16LE(p + 30);
      const commentLen = this.buf.readUInt16LE(p + 32);
      let localOffset = this.buf.readUInt32LE(p + 42);

      this.need(p + 46 + nameLen + extraLen + commentLen, 'central directory entry');
      // Bit 11 says the name is UTF-8. Without it the name is CP437, but every
      // producer we care about sets it, and CP437 and UTF-8 agree on ASCII.
      const name = this.buf.subarray(p + 46, p + 46 + nameLen).toString('utf8');

      if (compressedSize === 0xffffffff || uncompressedSize === 0xffffffff || localOffset === 0xffffffff) {
        const z64 = this.readZip64Extra(
          this.buf.subarray(p + 46 + nameLen, p + 46 + nameLen + extraLen),
          { uncompressedSize, compressedSize, localOffset },
        );
        uncompressedSize = z64.uncompressedSize;
        compressedSize = z64.compressedSize;
        localOffset = z64.localOffset;
      }

      p += 46 + nameLen + extraLen + commentLen;

      // Directory markers carry no data and a name we would never ask for.
      if (name.endsWith('/')) continue;
      // We only ever look entries up by a name we already know, so traversal is
      // not reachable. Refusing anyway costs nothing and keeps that true if a
      // future caller starts iterating.
      if (name.startsWith('/') || name.includes('..')) continue;

      const entry: ZipEntry = {
        name,
        method,
        compressedSize,
        uncompressedSize,
        localOffset,
        encrypted: (flags & 0x0001) !== 0,
      };
      if (!this.entries.has(name)) this.order.push(name);
      this.entries.set(name, entry);
    }

    if (this.entries.size === 0) throw new ZipError('the archive has no readable entries');
  }

  private findEocd(): number {
    // The record is 22 bytes plus a comment of up to 65535, so it lives in the
    // last 64 KB and is found by scanning backwards for its signature.
    const min = Math.max(0, this.buf.length - 22 - 0xffff);
    for (let i = this.buf.length - 22; i >= min; i--) {
      if (this.buf.readUInt32LE(i) === EOCD_SIG) return i;
    }
    throw new ZipError('not a ZIP archive: no end-of-central-directory record');
  }

  private findZip64Eocd(eocd: number): number | null {
    const loc = eocd - 20;
    if (loc < 0 || this.buf.readUInt32LE(loc) !== ZIP64_LOCATOR_SIG) return null;
    const off = Number(this.buf.readBigUInt64LE(loc + 8));
    if (off < 0 || off + 56 > this.buf.length) return null;
    if (this.buf.readUInt32LE(off) !== ZIP64_EOCD_SIG) return null;
    return off;
  }

  /**
   * The zip64 extended information extra field (header id 0x0001).
   *
   * Its fields are present only for the ones that were saturated in the fixed
   * record, in a fixed order, so the caller's current values decide what to
   * read.
   */
  private readZip64Extra(
    extra: Buffer,
    current: { uncompressedSize: number; compressedSize: number; localOffset: number },
  ): { uncompressedSize: number; compressedSize: number; localOffset: number } {
    const out = { ...current };
    let p = 0;
    while (p + 4 <= extra.length) {
      const id = extra.readUInt16LE(p);
      const size = extra.readUInt16LE(p + 2);
      const body = extra.subarray(p + 4, p + 4 + size);
      p += 4 + size;
      if (id !== 0x0001) continue;
      let q = 0;
      const next = (): number | null => {
        if (q + 8 > body.length) return null;
        const v = Number(body.readBigUInt64LE(q));
        q += 8;
        return v;
      };
      if (current.uncompressedSize === 0xffffffff) out.uncompressedSize = next() ?? out.uncompressedSize;
      if (current.compressedSize === 0xffffffff) out.compressedSize = next() ?? out.compressedSize;
      if (current.localOffset === 0xffffffff) out.localOffset = next() ?? out.localOffset;
      break;
    }
    return out;
  }
}

function stripBom(s: string): string {
  return s.charCodeAt(0) === 0xfeff ? s.slice(1) : s;
}
