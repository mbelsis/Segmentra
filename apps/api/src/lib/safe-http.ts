import dns from 'node:dns';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';

import { cidrContains } from '../services/ip-utils.js';

/**
 * SSRF-safe outbound HTTP for user-configured URLs (webhooks, Slack, ...).
 *
 * The destination check and the connection use the SAME DNS answer: the request is made
 * with node:http(s) and a custom `lookup` that resolves the hostname, rejects the request
 * if ANY resolved address is blocked, and hands only validated addresses to the socket.
 * That closes the DNS-rebinding TOCTOU of "resolve + check, then fetch() resolves again".
 * TLS SNI / certificate hostname verification still use the original hostname.
 */

export const DEFAULT_OUTBOUND_TIMEOUT_MS = 10_000;
const MAX_RESPONSE_BYTES = 64 * 1024;

export const BLOCKED_HOSTNAMES = new Set([
  'localhost',
  'localhost.localdomain',
  'metadata',
  'metadata.google.internal',
  'metadata.goog',
  'metadata.azure.com',
  'instance-data',
  'instance-data.ec2.internal',
]);

// Loopback, link-local (incl. cloud metadata 169.254.169.254), unspecified and well-known
// metadata addresses. RFC1918 private ranges are intentionally allowed (on-prem product).
const BLOCKED_CIDRS = [
  '127.0.0.0/8',
  '0.0.0.0/8',
  '169.254.0.0/16',
  '100.100.100.200/32', // Alibaba Cloud metadata
  '::1/128',
  '::/128',
  'fe80::/10',
  'fd00:ec2::254/128', // AWS IPv6 metadata
];

/** True when SEGMENTRA_ALLOW_PRIVATE_WEBHOOKS=true disables destination checks. */
export function destinationChecksDisabled(): boolean {
  return process.env.SEGMENTRA_ALLOW_PRIVATE_WEBHOOKS === 'true';
}

/** Normalise a URL hostname: strip IPv6 brackets, trailing dot, lowercase. */
export function normalizeHost(hostname: string): string {
  return hostname.replace(/^\[|\]$/g, '').toLowerCase().replace(/\.$/, '');
}

export function isBlockedHostname(host: string): boolean {
  const h = normalizeHost(host);
  return BLOCKED_HOSTNAMES.has(h) || h.endsWith('.localhost');
}

/** True for loopback / link-local / unspecified / metadata addresses (incl. IPv4-mapped IPv6 forms). */
export function isBlockedAddress(ip: string): boolean {
  let addr = normalizeHost(ip);
  // Strip an IPv6 zone id (fe80::1%eth0)
  const pct = addr.indexOf('%');
  if (pct >= 0) addr = addr.slice(0, pct);
  if (!net.isIP(addr)) return true; // not an IP at all: refuse rather than guess
  // IPv4-mapped / IPv4-compatible IPv6: ::ffff:a.b.c.d, ::ffff:7f00:1, ::a.b.c.d
  const mappedDotted = addr.match(/^::(?:ffff:(?:0:)?)?(\d+\.\d+\.\d+\.\d+)$/i);
  if (mappedDotted) addr = mappedDotted[1];
  const mappedHex = addr.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i);
  if (mappedHex) {
    const hi = parseInt(mappedHex[1], 16);
    const lo = parseInt(mappedHex[2], 16);
    addr = `${hi >> 8}.${hi & 0xff}.${lo >> 8}.${lo & 0xff}`;
  }
  return BLOCKED_CIDRS.some((cidr) => cidrContains(cidr, addr));
}

export class BlockedDestinationError extends Error {
  code = 'EBLOCKEDDEST';
  constructor(message: string) {
    super(message);
    this.name = 'BlockedDestinationError';
  }
}

type LookupAddress = { address: string; family: number };
type LookupCallback = (err: NodeJS.ErrnoException | null, address: string | LookupAddress[], family?: number) => void;

/**
 * A drop-in `lookup` for net/http/https/tls. Resolves all addresses for the hostname, fails if
 * any of them is blocked (or the hostname itself is blocked), and returns only validated
 * addresses — in the single-address or `all: true` form, whichever the caller asked for.
 */
export function safeLookup(hostname: string, options: dns.LookupOptions | number | LookupCallback, callback?: LookupCallback): void {
  let opts: dns.LookupOptions = {};
  let cb: LookupCallback;
  if (typeof options === 'function') {
    cb = options;
  } else {
    cb = callback!;
    opts = typeof options === 'number' ? { family: options } : (options ?? {});
  }
  const wantAll = Boolean(opts.all);
  const checksOff = destinationChecksDisabled();

  if (!checksOff && isBlockedHostname(hostname)) {
    process.nextTick(() => cb(new BlockedDestinationError(`destination host "${normalizeHost(hostname)}" is not allowed`), wantAll ? [] : ''));
    return;
  }

  dns.lookup(hostname, { family: opts.family as any, hints: opts.hints, all: true, verbatim: true } as dns.LookupAllOptions, (err, addresses) => {
    if (err) return cb(err, wantAll ? [] : '');
    const list = (addresses ?? []) as LookupAddress[];
    if (list.length === 0) {
      const e: NodeJS.ErrnoException = new Error(`cannot resolve host "${hostname}"`);
      e.code = 'ENOTFOUND';
      return cb(e, wantAll ? [] : '');
    }
    if (!checksOff) {
      const blocked = list.find((a) => isBlockedAddress(a.address));
      if (blocked) {
        return cb(new BlockedDestinationError(`"${normalizeHost(hostname)}" resolves to disallowed address ${blocked.address}`), wantAll ? [] : '');
      }
    }
    if (wantAll) return cb(null, list);
    return cb(null, list[0].address, list[0].family);
  });
}

/** Promise wrapper around safeLookup (all addresses), handy for tests/diagnostics. */
export function safeResolve(hostname: string): Promise<LookupAddress[]> {
  return new Promise((resolve, reject) => {
    safeLookup(hostname, { all: true }, (err, addrs) => (err ? reject(err) : resolve(addrs as LookupAddress[])));
  });
}

/**
 * Static URL validation: protocol must be http/https; blocked hostnames and literal blocked
 * IPs are rejected (unless checks are disabled). DNS names are NOT resolved here — the
 * authoritative check happens at connect time in safeLookup.
 * Throws an Error whose message starts with "invalid_webhook_url:".
 */
export function validateOutboundUrl(rawUrl: unknown): URL {
  if (typeof rawUrl !== 'string' || !rawUrl.trim()) throw new Error('invalid_webhook_url: URL is required');
  let url: URL;
  try {
    url = new URL(rawUrl.trim());
  } catch {
    throw new Error('invalid_webhook_url: not a valid URL');
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error('invalid_webhook_url: only http and https are allowed');
  }
  if (destinationChecksDisabled()) return url;
  const host = normalizeHost(url.hostname);
  if (isBlockedHostname(host)) throw new Error(`invalid_webhook_url: destination host "${host}" is not allowed`);
  if (net.isIP(host) && isBlockedAddress(host)) throw new Error(`invalid_webhook_url: destination address ${host} is not allowed`);
  return url;
}

export interface SafeHttpResponse {
  ok: boolean;
  status: number;
  headers: http.IncomingHttpHeaders;
  text: string;
}

/**
 * POST a JSON body to a user-supplied URL with SSRF protection. Redirects are never followed
 * (a 3xx yields ok=false). Rejects on blocked destinations, network errors and timeout.
 */
export function postJsonSafe(
  rawUrl: string,
  headers: Record<string, string>,
  body: unknown,
  opts: { timeoutMs?: number } = {}
): Promise<SafeHttpResponse> {
  let url: URL;
  try {
    url = validateOutboundUrl(rawUrl);
  } catch (e) {
    return Promise.reject(e);
  }
  const timeoutMs = opts.timeoutMs ?? DEFAULT_OUTBOUND_TIMEOUT_MS;
  const payload = Buffer.from(JSON.stringify(body), 'utf8');
  const host = normalizeHost(url.hostname);
  const isHttps = url.protocol === 'https:';
  const mod = isHttps ? https : http;

  const reqHeaders: Record<string, string | number> = { ...headers, 'Content-Length': payload.length };
  if (url.username || url.password) {
    reqHeaders['Authorization'] ??= `Basic ${Buffer.from(`${decodeURIComponent(url.username)}:${decodeURIComponent(url.password)}`).toString('base64')}`;
  }

  return new Promise<SafeHttpResponse>((resolve, reject) => {
    let settled = false;
    const done = (fn: () => void) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      fn();
    };

    const req = mod.request({
      protocol: url.protocol,
      hostname: host,
      port: url.port ? Number(url.port) : undefined,
      path: `${url.pathname || '/'}${url.search}`,
      method: 'POST',
      headers: reqHeaders,
      // Literal IPs never hit lookup (Node connects directly); they were validated above.
      lookup: safeLookup as any,
      // Fresh agent: never reuse a pooled socket opened by code that skipped these checks.
      agent: false,
      ...(isHttps && !net.isIP(host) ? { servername: host } : {}),
    });

    const timer = setTimeout(() => {
      req.destroy(new Error(`request timed out after ${timeoutMs}ms`));
    }, timeoutMs);

    req.on('error', (err) => done(() => reject(err)));
    req.on('response', (res) => {
      const chunks: Buffer[] = [];
      let size = 0;
      res.on('data', (c: Buffer) => {
        if (size < MAX_RESPONSE_BYTES) chunks.push(c);
        size += c.length;
      });
      res.on('end', () => {
        const status = res.statusCode ?? 0;
        done(() => resolve({
          ok: status >= 200 && status < 300,
          status,
          headers: res.headers,
          text: Buffer.concat(chunks).toString('utf8').slice(0, MAX_RESPONSE_BYTES),
        }));
      });
      res.on('error', (err) => done(() => reject(err)));
    });
    req.end(payload);
  });
}
