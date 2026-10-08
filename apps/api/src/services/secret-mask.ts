/**
 * Masking helpers so secrets stored in JSON config columns (integration API keys,
 * webhook auth headers / URL tokens) are never returned verbatim by GET endpoints.
 *
 * Contract for clients: a masked value looks like "••••" + last 4 chars (or just "••••"
 * for very short values). Sending a masked value back on update — or omitting the field —
 * keeps the stored value. Sending an empty string clears it.
 */

export const MASK_PREFIX = '••••';

const SENSITIVE_KEY_RE = /(api[_-]?key|apikey|token|secret|password|passwd|auth[_-]?header|authorization|credential|private[_-]?key)/i;

export function isSensitiveKey(key: string): boolean {
  return SENSITIVE_KEY_RE.test(key);
}

export function maskSecret(value: unknown): string {
  if (value === null || value === undefined) return '';
  const s = String(value);
  if (s.length === 0) return '';
  if (s.startsWith(MASK_PREFIX)) return s; // already masked (idempotent)
  if (s.length <= 8) return MASK_PREFIX;
  return `${MASK_PREFIX}${s.slice(-4)}`;
}

export function isMaskedValue(value: unknown): boolean {
  return typeof value === 'string' && value.startsWith(MASK_PREFIX);
}

/** Return a copy of a (shallow or nested) config object with sensitive values masked. */
export function maskConfigSecrets<T>(config: T): T {
  if (Array.isArray(config)) return config.map((v) => maskConfigSecrets(v)) as unknown as T;
  if (!config || typeof config !== 'object') return config;
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(config as Record<string, unknown>)) {
    if (isSensitiveKey(k) && (typeof v === 'string' || typeof v === 'number')) {
      out[k] = maskSecret(v);
    } else if (v && typeof v === 'object') {
      out[k] = maskConfigSecrets(v);
    } else {
      out[k] = v;
    }
  }
  return out as T;
}

/**
 * Merge an incoming config onto the stored one: for sensitive keys, a masked value or an
 * omitted key keeps the stored value. Non-sensitive keys follow the incoming object exactly.
 */
export function mergeConfigSecrets(
  existing: Record<string, unknown> | null | undefined,
  incoming: Record<string, unknown>
): Record<string, unknown> {
  const prev = existing ?? {};
  const out: Record<string, unknown> = { ...incoming };
  for (const [k, v] of Object.entries(prev)) {
    if (!isSensitiveKey(k)) continue;
    if (!(k in incoming) || isMaskedValue(incoming[k])) out[k] = v;
  }
  // A masked value for a key that never existed must not be stored literally.
  for (const [k, v] of Object.entries(out)) {
    if (isMaskedValue(v) && !(k in prev)) delete out[k];
  }
  return out;
}

function isTokenLikeSegment(segment: string): boolean {
  return segment.length >= 16 && /^[A-Za-z0-9_\-.~%]+$/.test(segment) && /\d/.test(segment);
}

/** Mask credentials embedded in a URL: userinfo password and query values of token-like params. */
export function maskUrlSecrets(rawUrl: unknown): string {
  if (typeof rawUrl !== 'string' || !rawUrl) return typeof rawUrl === 'string' ? rawUrl : '';
  try {
    const u = new URL(rawUrl);
    let changed = false;
    if (u.password) {
      u.password = 'xxxx';
      changed = true;
    }
    for (const [k, v] of Array.from(u.searchParams.entries())) {
      if (isSensitiveKey(k) || /^(key|sig|signature|code)$/i.test(k)) {
        u.searchParams.set(k, maskSecret(v));
        changed = true;
      }
    }
    // Slack/Teams/Discord style webhooks carry the secret in the path; keep the host and
    // the first path segment only. Other hosts: mask any opaque, token-like path segment
    // (16+ chars of letters/digits/-/_ containing a digit), e.g. /hooks/<token>.
    const segments = u.pathname.split('/').filter(Boolean);
    if (segments.length > 1 && /hooks\.slack\.com|webhook\.office\.com|discord(app)?\.com|outlook\.office/i.test(u.host)) {
      const last = segments[segments.length - 1];
      u.pathname = `/${segments[0]}/${MASK_PREFIX}${last.slice(-4)}`;
      changed = true;
    } else if (segments.some(isTokenLikeSegment)) {
      u.pathname = '/' + segments.map((s) => (isTokenLikeSegment(s) ? `${MASK_PREFIX}${s.slice(-4)}` : s)).join('/');
      changed = true;
    }
    return changed ? decodeURI(u.toString()) : rawUrl;
  } catch {
    return rawUrl;
  }
}
