// A scanner, not a parser.
//
// Office XML is machine-written and deeply nested, a paragraph of Word being a
// dozen elements, so what the extractors need is a stream of open, close and
// text events they can drive a small state machine from, not a tree they would
// have to walk twice and hold in memory whole.
//
// Doing it here rather than with an XML library is also a security decision.
// The two ways XML parsing goes wrong on hostile input are external entities
// (XXE: a document that reads /etc/passwd or makes the parser dial an address)
// and entity expansion (a billion laughs, ten nested entities that expand to
// gigabytes). Neither is reachable from this scanner, because it does not
// process a DTD at all: `<!` anything is skipped as markup, and the only
// entities it resolves are the five predefined ones plus numeric character
// references, which expand to exactly one code point each.

export interface XmlOpen {
  type: 'open';
  name: string;
  attrs: Record<string, string>;
  /** `<w:tab/>` arrives as an open with this set and no matching close. */
  selfClosing: boolean;
}

export interface XmlClose {
  type: 'close';
  name: string;
}

export interface XmlText {
  type: 'text';
  text: string;
}

export type XmlEvent = XmlOpen | XmlClose | XmlText;

const ATTR = /([A-Za-z_:][-A-Za-z0-9_:.]*)\s*=\s*("([^"]*)"|'([^']*)')/g;

export function* scanXml(src: string): Generator<XmlEvent> {
  let i = 0;
  const n = src.length;

  while (i < n) {
    const lt = src.indexOf('<', i);
    if (lt < 0) {
      const tail = src.slice(i);
      if (tail) yield { type: 'text', text: decodeEntities(tail) };
      return;
    }
    if (lt > i) {
      yield { type: 'text', text: decodeEntities(src.slice(i, lt)) };
    }

    const c = src.charCodeAt(lt + 1);

    // <!-- comment -->, <![CDATA[...]]>, <!DOCTYPE ...>
    if (c === 0x21 /* ! */) {
      if (src.startsWith('<!--', lt)) {
        const end = src.indexOf('-->', lt + 4);
        i = end < 0 ? n : end + 3;
        continue;
      }
      if (src.startsWith('<![CDATA[', lt)) {
        const end = src.indexOf(']]>', lt + 9);
        const text = src.slice(lt + 9, end < 0 ? n : end);
        // CDATA is literal by definition: no entity resolution here.
        if (text) yield { type: 'text', text };
        i = end < 0 ? n : end + 3;
        continue;
      }
      // A DTD's internal subset can hold '>' inside brackets, so skip the
      // bracketed part first when there is one. Its contents are never read.
      const bracket = src.indexOf('[', lt);
      const close = src.indexOf('>', lt);
      if (bracket >= 0 && close >= 0 && bracket < close) {
        const endSubset = src.indexOf(']', bracket);
        const after = endSubset < 0 ? close : src.indexOf('>', endSubset);
        i = after < 0 ? n : after + 1;
      } else {
        i = close < 0 ? n : close + 1;
      }
      continue;
    }

    // <?xml ... ?>
    if (c === 0x3f /* ? */) {
      const end = src.indexOf('?>', lt + 2);
      i = end < 0 ? n : end + 2;
      continue;
    }

    const gt = src.indexOf('>', lt + 1);
    if (gt < 0) return;
    const inner = src.slice(lt + 1, gt);
    i = gt + 1;

    if (inner.startsWith('/')) {
      yield { type: 'close', name: inner.slice(1).trim() };
      continue;
    }

    const selfClosing = inner.endsWith('/');
    const body = selfClosing ? inner.slice(0, -1) : inner;
    const space = body.search(/[\s]/);
    const name = (space < 0 ? body : body.slice(0, space)).trim();
    if (!name) continue;

    const attrs: Record<string, string> = {};
    if (space >= 0) {
      const rest = body.slice(space);
      ATTR.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = ATTR.exec(rest)) !== null) {
        attrs[m[1]!] = decodeEntities(m[3] ?? m[4] ?? '');
      }
    }

    yield { type: 'open', name, attrs, selfClosing };
  }
}

const NAMED: Record<string, string> = {
  amp: '&',
  lt: '<',
  gt: '>',
  quot: '"',
  apos: "'",
};

export function decodeEntities(s: string): string {
  if (s.indexOf('&') < 0) return s;
  return s.replace(/&(#x?[0-9a-fA-F]+|[a-zA-Z]+);/g, (whole, ref: string) => {
    if (ref.charCodeAt(0) === 0x23 /* # */) {
      const hex = ref[1] === 'x' || ref[1] === 'X';
      const code = parseInt(hex ? ref.slice(2) : ref.slice(1), hex ? 16 : 10);
      if (!Number.isFinite(code) || code < 0 || code > 0x10ffff) return whole;
      // Surrogates on their own are not text; leaving the reference intact is
      // more honest than emitting a lone half.
      if (code >= 0xd800 && code <= 0xdfff) return whole;
      try {
        return String.fromCodePoint(code);
      } catch {
        return whole;
      }
    }
    // An unknown named entity is left as written. Resolving it would mean
    // reading a DTD, which is the thing this scanner refuses to do.
    return NAMED[ref] ?? whole;
  });
}

/** The local part of a namespaced name: `w:tbl` -> `tbl`. */
export function localName(name: string): string {
  const colon = name.indexOf(':');
  return colon < 0 ? name : name.slice(colon + 1);
}
