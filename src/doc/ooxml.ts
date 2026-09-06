// Pieces every OOXML part needs: relationships, core properties, and the
// handful of colour and text helpers the three format readers share.

import { Zip } from './zip.js';
import { localName, scanXml } from './xml.js';
import type { DocHidden } from './types.js';

/** id -> target, from a `_rels/*.rels` part. */
export type Rels = Map<string, { target: string; external: boolean }>;

export function readRels(zip: Zip, partPath: string): Rels {
  const rels: Rels = new Map();
  const slash = partPath.lastIndexOf('/');
  const dir = slash < 0 ? '' : partPath.slice(0, slash + 1);
  const file = slash < 0 ? partPath : partPath.slice(slash + 1);
  const xml = zip.readTextIfPresent(`${dir}_rels/${file}.rels`);
  if (!xml) return rels;

  for (const ev of scanXml(xml)) {
    if (ev.type !== 'open' || localName(ev.name) !== 'Relationship') continue;
    const id = ev.attrs['Id'];
    const target = ev.attrs['Target'];
    if (!id || !target) continue;
    rels.set(id, {
      target: ev.attrs['TargetMode'] === 'External' ? target : resolvePart(dir, target),
      external: ev.attrs['TargetMode'] === 'External',
    });
  }
  return rels;
}

/** Resolve a relationship target against the part that declared it. */
export function resolvePart(dir: string, target: string): string {
  if (target.startsWith('/')) return target.slice(1);
  const parts = (dir + target).split('/');
  const out: string[] = [];
  for (const p of parts) {
    if (p === '.' || p === '') continue;
    if (p === '..') out.pop();
    else out.push(p);
  }
  return out.join('/');
}

export interface CoreProps {
  title: string | null;
  author: string | null;
  created: string | null;
  modified: string | null;
  producer: string | null;
}

export const NO_PROPS: CoreProps = {
  title: null,
  author: null,
  created: null,
  modified: null,
  producer: null,
};

/** `docProps/core.xml` and `docProps/app.xml`, both optional. */
export function readCoreProps(zip: Zip): CoreProps {
  const out: CoreProps = { ...NO_PROPS };
  const core = zip.readTextIfPresent('docProps/core.xml');
  if (core) {
    const want: Record<string, keyof CoreProps> = {
      title: 'title',
      creator: 'author',
      created: 'created',
      modified: 'modified',
    };
    let field: keyof CoreProps | null = null;
    for (const ev of scanXml(core)) {
      if (ev.type === 'open') field = want[localName(ev.name)] ?? null;
      else if (ev.type === 'close') field = null;
      else if (field && ev.text.trim()) {
        out[field] = ev.text.trim().slice(0, 300);
        field = null;
      }
    }
  }
  const app = zip.readTextIfPresent('docProps/app.xml');
  if (app) {
    let inApplication = false;
    for (const ev of scanXml(app)) {
      if (ev.type === 'open') inApplication = localName(ev.name) === 'Application';
      else if (ev.type === 'close') inApplication = false;
      else if (inApplication && ev.text.trim()) {
        out.producer = ev.text.trim().slice(0, 200);
        inApplication = false;
      }
    }
  }
  return out;
}

/**
 * Is this colour effectively invisible against a white page?
 *
 * Only near-white counts. A document is overwhelmingly likely to be on a white
 * background, and this is the shape the trick actually takes: white text in a
 * white margin, sized down to nothing. Guessing at arbitrary backgrounds would
 * mean resolving themes, styles and shape fills, and would still be a guess.
 */
export function isNearWhite(hex: string | undefined): boolean {
  if (!hex) return false;
  const v = hex.replace(/^#/, '').toUpperCase();
  const rgb = v.length === 8 ? v.slice(2) : v; // ARGB, as xlsx writes it
  if (!/^[0-9A-F]{6}$/.test(rgb)) return false;
  const r = parseInt(rgb.slice(0, 2), 16);
  const g = parseInt(rgb.slice(2, 4), 16);
  const b = parseInt(rgb.slice(4, 6), 16);
  return r >= 0xf2 && g >= 0xf2 && b >= 0xf2;
}

/** Collapse runs of whitespace and clip, for a hidden-text sample. */
export function sampleOf(text: string, max = 600): string {
  return text.replace(/\s+/g, ' ').trim().slice(0, max);
}

/**
 * Record concealed text, merging adjacent finds in the same place.
 *
 * A hidden paragraph arrives one run at a time, and forty findings that are one
 * sentence is the noise this whole mechanism exists to avoid.
 */
export function pushHidden(list: DocHidden[], found: DocHidden, limit = 40): void {
  const last = list[list.length - 1];
  if (last && last.where === found.where && last.reason === found.reason) {
    last.sample = sampleOf(last.sample + ' ' + found.sample);
    return;
  }
  if (list.length >= limit) return;
  list.push(found);
}

/** Markdown pipe tables from rows of cells, with the escaping they need. */
export function toMarkdownTable(rows: string[][]): string {
  if (rows.length === 0) return '';
  const width = Math.max(...rows.map((r) => r.length));
  const cell = (s: string) => s.replace(/\s*\n\s*/g, ' ').replace(/\|/g, '\\|').trim() || ' ';
  const line = (r: string[]) => {
    const padded = [...r];
    while (padded.length < width) padded.push('');
    return '| ' + padded.map(cell).join(' | ') + ' |';
  };
  const head = rows[0]!;
  const body = rows.slice(1);
  return [line(head), '| ' + Array(width).fill('---').join(' | ') + ' |', ...body.map(line)].join('\n');
}
