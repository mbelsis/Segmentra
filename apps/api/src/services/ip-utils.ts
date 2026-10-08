import net from 'node:net';

/**
 * Small, dependency-free IPv4/IPv6 CIDR helpers used by safety checks, the
 * troubleshooting simulator, webhook URL validation and Kubernetes export.
 */

export type ParsedCidr = { family: 4 | 6; network: bigint; prefix: number; bits: number };

function ipv4ToBigInt(ip: string): bigint {
  return ip.split('.').reduce((acc, octet) => (acc << 8n) + BigInt(Number(octet)), 0n);
}

function ipv6ToBigInt(ip: string): bigint {
  let addr = ip;
  // Embedded IPv4 (e.g. ::ffff:10.0.0.1)
  const v4Match = addr.match(/(\d+\.\d+\.\d+\.\d+)$/);
  if (v4Match) {
    const v4 = ipv4ToBigInt(v4Match[1]);
    const hi = Number((v4 >> 16n) & 0xffffn).toString(16);
    const lo = Number(v4 & 0xffffn).toString(16);
    addr = addr.slice(0, addr.length - v4Match[1].length) + `${hi}:${lo}`;
  }
  const [head, tail] = addr.split('::');
  const headParts = head ? head.split(':').filter(Boolean) : [];
  const tailParts = tail !== undefined && tail ? tail.split(':').filter(Boolean) : [];
  const missing = 8 - headParts.length - tailParts.length;
  const parts = addr.includes('::')
    ? [...headParts, ...Array(Math.max(0, missing)).fill('0'), ...tailParts]
    : headParts;
  return parts.reduce((acc, p) => (acc << 16n) + BigInt(parseInt(p || '0', 16)), 0n);
}

/** Parse an IP or CIDR string. Returns null when invalid. */
export function parseCidr(value: string | null | undefined): ParsedCidr | null {
  if (!value) return null;
  const trimmed = String(value).trim();
  const [ipPart, prefixPart] = trimmed.split('/');
  const family = net.isIP(ipPart);
  if (family === 0) return null;
  const bits = family === 4 ? 32 : 128;
  let prefix = bits;
  if (prefixPart !== undefined) {
    if (!/^\d{1,3}$/.test(prefixPart)) return null;
    prefix = Number(prefixPart);
    if (prefix < 0 || prefix > bits) return null;
  }
  const raw = family === 4 ? ipv4ToBigInt(ipPart) : ipv6ToBigInt(ipPart);
  const mask = prefix === 0 ? 0n : ((1n << BigInt(prefix)) - 1n) << BigInt(bits - prefix);
  return { family: family as 4 | 6, network: raw & mask, prefix, bits };
}

export function isValidIp(value: string | null | undefined): boolean {
  return !!value && net.isIP(String(value).trim()) !== 0;
}

export function isValidCidr(value: string | null | undefined): boolean {
  return parseCidr(value) !== null;
}

function maskFor(c: ParsedCidr, prefix: number): bigint {
  return prefix === 0 ? 0n : ((1n << BigInt(prefix)) - 1n) << BigInt(c.bits - prefix);
}

/** True when `inner` (IP or CIDR) lies entirely inside `outer`. */
export function cidrContains(outer: string, inner: string): boolean {
  const o = parseCidr(outer);
  const i = parseCidr(inner);
  if (!o || !i || o.family !== i.family) return false;
  if (i.prefix < o.prefix) return false;
  return (i.network & maskFor(o, o.prefix)) === o.network;
}

/** True when the two IPs/CIDRs share at least one address. */
export function cidrsOverlap(a: string, b: string): boolean {
  const x = parseCidr(a);
  const y = parseCidr(b);
  if (!x || !y || x.family !== y.family) return false;
  const p = Math.min(x.prefix, y.prefix);
  const m = maskFor(x, p);
  return (x.network & m) === (y.network & m);
}

/** Strip a /32 or /128 suffix pg may return for inet values. */
export function hostIpOnly(value: unknown): string | null {
  if (value === null || value === undefined) return null;
  const s = String(value).trim();
  if (!s) return null;
  return s.split('/')[0];
}

export const PORT_SPEC_REGEX = /^\d{1,5}(-\d{1,5})?(\s*,\s*\d{1,5}(-\d{1,5})?)*$/;

export type PortRange = { from: number; to: number };

/** Parse a port spec like "22, 80-90". Returns null when syntactically/semantically invalid. */
export function parsePortSpec(spec: string | null | undefined): PortRange[] | null {
  if (spec === null || spec === undefined) return null;
  const s = String(spec).trim();
  if (!PORT_SPEC_REGEX.test(s)) return null;
  const ranges: PortRange[] = [];
  for (const part of s.split(',')) {
    const [a, b] = part.trim().split('-');
    const from = Number(a);
    const to = b === undefined ? from : Number(b);
    if (from < 1 || from > 65535 || to < 1 || to > 65535 || to < from) return null;
    ranges.push({ from, to });
  }
  return ranges;
}

export function isValidPortSpec(spec: string | null | undefined): boolean {
  return parsePortSpec(spec) !== null;
}

/** True when the port spec (null/empty = all ports) includes the given port. */
export function portSpecIncludes(spec: string | null | undefined, port: number): boolean {
  if (spec === null || spec === undefined || String(spec).trim() === '') return true;
  const ranges = parsePortSpec(spec);
  if (!ranges) return false;
  return ranges.some((r) => port >= r.from && port <= r.to);
}

/** True when the port spec (null/empty = all ports) fully covers [from, to]. */
export function portSpecCoversRange(spec: string | null | undefined, from: number, to: number): boolean {
  if (spec === null || spec === undefined || String(spec).trim() === '') return true;
  const ranges = parsePortSpec(spec);
  if (!ranges) return false;
  const sorted = [...ranges].sort((a, b) => a.from - b.from);
  let cursor = from;
  for (const r of sorted) {
    if (r.from > cursor) break;
    if (r.to >= cursor) cursor = r.to + 1;
    if (cursor > to) return true;
  }
  return cursor > to;
}

/** True when the port spec (null/empty = all ports) intersects [from, to]. */
export function portSpecIntersectsRange(spec: string | null | undefined, from: number, to: number): boolean {
  if (spec === null || spec === undefined || String(spec).trim() === '') return true;
  const ranges = parsePortSpec(spec);
  if (!ranges) return false;
  return ranges.some((r) => r.from <= to && r.to >= from);
}
