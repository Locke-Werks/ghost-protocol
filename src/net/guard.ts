// Address classification for egress. Every outbound connection the relay makes
// — browser or plain HTTP — is checked here first.
//
// This is the control that keeps a public "fetch any URL you name" endpoint
// from becoming a way into whatever else the host can reach: databases and
// admin APIs bound to loopback, an overlay network interface, a cloud metadata
// service. A URL is not trusted because it parsed; it is trusted because every
// address it resolves to came back clean.

import { BlockList, isIPv4, isIPv6 } from 'node:net';
import { promises as dns } from 'node:dns';

// Ranges that must never be reachable from a relayed request. Special-purpose
// registries (IANA IPv4/IPv6 special-purpose address registry) plus the private
// ranges, which is where overlay and container networks normally sit.
const V4_DENY: Array<[string, number]> = [
  ['0.0.0.0', 8], // "this network"
  ['10.0.0.0', 8], // RFC 1918
  ['100.64.0.0', 10], // RFC 6598 CGNAT
  ['127.0.0.0', 8], // loopback
  ['169.254.0.0', 16], // link-local, includes 169.254.169.254 metadata
  ['172.16.0.0', 12], // RFC 1918; overlay networks commonly sit in here
  ['192.0.0.0', 24], // IETF protocol assignments
  ['192.0.2.0', 24], // TEST-NET-1
  ['192.88.99.0', 24], // 6to4 relay anycast
  ['192.168.0.0', 16], // RFC 1918
  ['198.18.0.0', 15], // benchmarking
  ['198.51.100.0', 24], // TEST-NET-2
  ['203.0.113.0', 24], // TEST-NET-3
  ['224.0.0.0', 4], // multicast
  ['240.0.0.0', 4], // reserved, includes 255.255.255.255
];

const V6_DENY: Array<[string, number]> = [
  ['::', 128], // unspecified
  ['::1', 128], // loopback
  ['64:ff9b::', 96], // NAT64
  ['64:ff9b:1::', 48], // local-use NAT64
  ['100::', 64], // discard-only
  ['2001::', 32], // Teredo
  ['2001:db8::', 32], // documentation
  ['2002::', 16], // 6to4
  ['fc00::', 7], // unique local
  ['fe80::', 10], // link-local
  ['ff00::', 8], // multicast
];

const blocked = new BlockList();
for (const [addr, prefix] of V4_DENY) blocked.addSubnet(addr, prefix, 'ipv4');
for (const [addr, prefix] of V6_DENY) blocked.addSubnet(addr, prefix, 'ipv6');

// Operator-supplied extras, applied on top of the built-ins at startup.
const extra = new BlockList();

export function addDeniedAddress(addr: string): void {
  if (isIPv4(addr)) extra.addAddress(addr, 'ipv4');
  else if (isIPv6(addr)) extra.addAddress(addr, 'ipv6');
}

// An IPv4-mapped IPv6 literal (::ffff:127.0.0.1) is an IPv4 address wearing a
// costume. BlockList's ipv6 check does not see through it, so unwrap first —
// this is the classic way a v4-only denylist gets walked past.
function unwrapMapped(addr: string): string {
  const m = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(addr);
  if (m && m[1]) return m[1];
  // The all-hex form of the same thing: ::ffff:7f00:1
  const h = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i.exec(addr);
  if (h && h[1] && h[2]) {
    const hi = parseInt(h[1], 16);
    const lo = parseInt(h[2], 16);
    return `${hi >> 8}.${hi & 0xff}.${lo >> 8}.${lo & 0xff}`;
  }
  return addr;
}

export function isDeniedAddress(raw: string): boolean {
  const addr = unwrapMapped(raw.replace(/^\[|\]$/g, '').split('%')[0] ?? raw);
  const type = isIPv4(addr) ? 'ipv4' : isIPv6(addr) ? 'ipv6' : null;
  if (!type) return true; // unparseable is not a thing we dial
  return blocked.check(addr, type) || extra.check(addr, type);
}

export class EgressDenied extends Error {
  constructor(
    readonly host: string,
    readonly reason: string,
  ) {
    super(`egress refused for ${host}: ${reason}`);
    this.name = 'EgressDenied';
  }
}

export interface ResolvedTarget {
  host: string;
  /** Every address the name resolved to. All of them passed the denylist. */
  addresses: string[];
  /** The one address to actually dial, so the name cannot be re-resolved. */
  pinned: string;
  family: 4 | 6;
}

/**
 * Resolve a hostname and refuse it unless *every* address it answers with is
 * publicly routable.
 *
 * Checking all of them rather than the first is deliberate: a name that returns
 * one public address and one private address is a rebinding attempt, and which
 * one a later connect() picks is not ours to decide. Callers dial `pinned`, so
 * the address that was checked is the address that gets connected to and a
 * second lookup never happens.
 */
export async function resolveGuarded(host: string, allowHosts: Set<string>): Promise<ResolvedTarget> {
  const name = host.replace(/^\[|\]$/g, '').toLowerCase();

  // A bare IP literal skips DNS but not the denylist.
  if (isIPv4(name) || isIPv6(name)) {
    if (isDeniedAddress(name)) throw new EgressDenied(host, 'address is in a reserved or private range');
    return { host: name, addresses: [name], pinned: name, family: isIPv4(name) ? 4 : 6 };
  }

  if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*\.?$/.test(name)) {
    throw new EgressDenied(host, 'not a valid hostname');
  }
  // ".localhost" is reserved for loopback by RFC 6761 and may never resolve.
  if (name === 'localhost' || name.endsWith('.localhost')) {
    throw new EgressDenied(host, 'loopback name');
  }
  // A single-label name resolves through the box's own search domains, which is
  // never what a relayed request meant to reach.
  if (!name.includes('.') || name.endsWith('.local') || name.endsWith('.internal')) {
    throw new EgressDenied(host, 'not a public name');
  }
  if (allowHosts.size > 0 && !hostAllowed(name, allowHosts)) {
    throw new EgressDenied(host, 'host is not on the allowlist');
  }

  let answers: Array<{ address: string; family: number }>;
  try {
    answers = await dns.lookup(name, { all: true, verbatim: true });
  } catch {
    throw new EgressDenied(host, 'name does not resolve');
  }
  if (answers.length === 0) throw new EgressDenied(host, 'name does not resolve');

  for (const a of answers) {
    if (isDeniedAddress(a.address)) {
      throw new EgressDenied(host, `resolves to a reserved or private address (${a.address})`);
    }
  }

  const first = answers[0]!;
  return {
    host: name,
    addresses: answers.map((a) => a.address),
    pinned: first.address,
    family: first.family === 6 ? 6 : 4,
  };
}

// Exact match or a subdomain of an allowlist entry.
export function hostAllowed(host: string, allow: Set<string>): boolean {
  if (allow.has(host)) return true;
  for (const entry of allow) {
    if (host.endsWith('.' + entry)) return true;
  }
  return false;
}
