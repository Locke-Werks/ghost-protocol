// PresentationML.
//
// A deck is one XML part per slide, and the reading order that matters is the
// one the presentation declares, not the numeric order of the files: reordering
// slides in PowerPoint shuffles the relationship list and leaves slide12.xml
// sitting third. So the order comes from `ppt/presentation.xml`, with the
// filenames as a fallback for a deck that has lost its relationships.
//
// Speaker notes come along, labelled. They are not concealment, since an
// audience was never meant to read them, but they are exactly where the
// substance of a deck often lives, and dropping them silently is how a summary
// ends up being six words per slide.

import { Zip } from './zip.js';
import { localName, scanXml } from './xml.js';
import { isNearWhite, pushHidden, readCoreProps, readRels, sampleOf } from './ooxml.js';
import { resolveRange, type DocHidden, type DocSection, type DocumentExtract, type ExtractOptions } from './types.js';

interface SlideRef {
  part: string;
  /** PowerPoint's own number for it, which is its position in the deck. */
  number: number;
  skipped: boolean;
}

export function readPptx(zip: Zip, opts: ExtractOptions): DocumentExtract {
  const props = readCoreProps(zip);
  const warnings: string[] = [];
  const hidden: DocHidden[] = [];

  const slides = listSlides(zip);
  if (slides.length === 0) {
    return {
      kind: 'pptx',
      ...props,
      sections: [],
      totalSections: 0,
      selected: null,
      markdown: '',
      hidden,
      warnings: ['The deck declares no slides.'],
    };
  }

  const range = resolveRange(slides.length, opts);
  const sections: DocSection[] = [];

  for (let i = range.from - 1; i <= range.to - 1; i++) {
    const slide = slides[i]!;
    const label = `slide ${slide.number} of ${slides.length}${slide.skipped ? ' (hidden in the deck)' : ''}`;
    const xml = zip.readTextIfPresent(slide.part);
    if (xml === null) {
      sections.push({ label, markdown: `_(the deck points at ${slide.part}, which is not in the file)_` });
      continue;
    }
    const body = renderSlide(xml, label, hidden);
    const notes = readNotes(zip, slide.part, label, hidden);
    sections.push({
      label,
      markdown: [body || '_(no text on this slide)_', notes ? `**Speaker notes:**\n\n${notes}` : '']
        .filter(Boolean)
        .join('\n\n'),
    });
  }

  const skipped = slides.filter((s) => s.skipped).length;
  if (skipped > 0) {
    warnings.push(`${skipped} slide(s) are marked to be skipped during a presentation. They are read like any other.`);
  }
  if (range.clamped || range.to < slides.length) {
    warnings.push(
      `Read slides ${range.from} to ${range.to} of ${slides.length}. Ask for a different range with first_page and last_page.`,
    );
  }

  const markdown = sections.map((s) => `## ${s.label}\n\n${s.markdown}`).join('\n\n').trim();

  return {
    kind: 'pptx',
    ...props,
    sections,
    totalSections: slides.length,
    selected: { from: range.from, to: range.to },
    markdown,
    hidden,
    warnings,
  };
}

function listSlides(zip: Zip): SlideRef[] {
  const rels = readRels(zip, 'ppt/presentation.xml');
  const xml = zip.readTextIfPresent('ppt/presentation.xml');
  const slides: SlideRef[] = [];

  if (xml) {
    let inList = false;
    for (const ev of scanXml(xml)) {
      const n = ev.type === 'text' ? '' : localName(ev.name);
      if (ev.type === 'open' && n === 'sldIdLst') inList = true;
      else if (ev.type === 'close' && n === 'sldIdLst') inList = false;
      else if (inList && ev.type === 'open' && n === 'sldId') {
        const id = ev.attrs['r:id'] ?? ev.attrs['id'];
        const target = id ? rels.get(id)?.target : undefined;
        if (target && zip.has(target)) {
          slides.push({ part: target, number: slides.length + 1, skipped: ev.attrs['show'] === '0' });
        }
      }
    }
  }
  if (slides.length > 0) return slides;

  // No usable relationship list: fall back to the parts themselves, in the
  // numeric order of their filenames rather than the archive's.
  return zip
    .under('ppt/slides/slide')
    .filter((n) => n.endsWith('.xml'))
    .sort((a, b) => slideNumber(a) - slideNumber(b))
    .map((part, i) => ({ part, number: i + 1, skipped: false }));
}

function slideNumber(part: string): number {
  const m = /slide(\d+)\.xml$/.exec(part);
  return m ? Number(m[1]) : Number.MAX_SAFE_INTEGER;
}

/**
 * One slide's shapes to markdown.
 *
 * DrawingML nests text three deep: a shape holds a text body, which holds
 * paragraphs, which hold runs. The only things worth keeping from that are
 * where a paragraph ends, whether the shape is the title placeholder, and
 * whether a run was drawn in a colour nobody could read.
 */
function renderSlide(xml: string, where: string, hidden: DocHidden[]): string {
  const blocks: string[] = [];

  let shapeIsTitle = false;
  let shapeLines: string[] = [];
  let para: string[] = [];
  let hiddenPara: string[] = [];

  let inRunProps = false;
  let runIsWhite = false;
  let capture = false;
  let listLevel = 0;

  const endParagraph = () => {
    const text = para.join('').trim();
    para = [];
    const concealed = hiddenPara.join('').trim();
    hiddenPara = [];
    if (concealed) {
      pushHidden(hidden, { where, reason: 'white text', sample: sampleOf(concealed), concealment: true });
    }
    if (text) shapeLines.push(listLevel > 0 ? '  '.repeat(listLevel) + '- ' + text : text);
    listLevel = 0;
  };

  const endShape = () => {
    const text = shapeLines.filter(Boolean);
    shapeLines = [];
    if (text.length === 0) return;
    if (shapeIsTitle) blocks.push('### ' + text.join(' / '));
    else blocks.push(text.join('\n'));
    shapeIsTitle = false;
  };

  for (const ev of scanXml(xml)) {
    if (ev.type === 'text') {
      if (capture) (runIsWhite ? hiddenPara : para).push(ev.text);
      continue;
    }
    const n = localName(ev.name);

    if (ev.type === 'open') {
      switch (n) {
        case 'sp':
        case 'pic':
        case 'graphicFrame':
          shapeIsTitle = false;
          shapeLines = [];
          break;
        case 'ph':
          // The title placeholder is the only one worth promoting; `body` and
          // the rest are ordinary content.
          shapeIsTitle = /^(title|ctrTitle)$/.test(ev.attrs['type'] ?? '');
          break;
        case 'pPr': {
          const lvl = Number(ev.attrs['lvl'] ?? 0);
          if (Number.isFinite(lvl) && lvl > 0) listLevel = lvl;
          break;
        }
        case 'rPr':
          inRunProps = true;
          runIsWhite = false;
          break;
        case 'srgbClr':
          if (inRunProps) runIsWhite = isNearWhite(ev.attrs['val']);
          break;
        case 't':
          capture = true;
          break;
        case 'br':
          if (!runIsWhite) para.push('\n');
          break;
        case 'tab':
          if (!runIsWhite) para.push('\t');
          break;
      }
      if (!ev.selfClosing) continue;
    }

    switch (n) {
      case 't':
        capture = false;
        break;
      case 'rPr':
        inRunProps = false;
        break;
      case 'r':
        runIsWhite = false;
        break;
      case 'p':
        endParagraph();
        break;
      case 'sp':
      case 'pic':
      case 'graphicFrame':
        endShape();
        break;
    }
  }

  endParagraph();
  endShape();
  return blocks.join('\n\n').trim();
}

/** The notes part hanging off a slide, as plain paragraphs. */
function readNotes(zip: Zip, slidePart: string, where: string, hidden: DocHidden[]): string {
  const rels = readRels(zip, slidePart);
  for (const rel of rels.values()) {
    if (rel.external || !/^ppt\/notesSlides\/.*\.xml$/.test(rel.target)) continue;
    const xml = zip.readTextIfPresent(rel.target);
    if (!xml) continue;
    const text = renderSlide(xml, `${where} notes`, hidden);
    // The notes part repeats the slide number as its own text placeholder, so a
    // notes page with nothing on it arrives as a lone digit.
    return /^\s*\d+\s*$/.test(text.replace(/^#+\s*/gm, '')) ? '' : text;
  }
  return '';
}

/** Exported for the tests. */
export const __test = { renderSlide, listSlides };
