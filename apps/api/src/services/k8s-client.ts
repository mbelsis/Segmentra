import dns from 'node:dns';
import https from 'node:https';
import net from 'node:net';

import { parse as parseYaml } from 'yaml';

import { destinationChecksDisabled, normalizeHost } from '../lib/safe-http.js';
import { cidrContains } from './ip-utils.js';
import { readSecretPlaintext } from './secrets.js';

/**
 * Minimal Kubernetes API client (no kubectl, no extra dependency) used to apply, check and
 * remove the NetworkPolicies Segmentra generates.
 *
 * Credentials come from secret_store (AES-256-GCM) and are decrypted only for the duration of a
 * call. Supported: a bearer token (service account / token auth) or a kubeconfig with an inline
 * token or inline client certificate. Anything that makes the API server read files or run
 * programs (certificate paths, tokenFile, exec plugins, auth providers) is refused.
 */

const REQUEST_TIMEOUT_MS = 20_000;
const MAX_RESPONSE_BYTES = 4 * 1024 * 1024;
export const MANAGED_BY_LABEL = 'app.kubernetes.io/managed-by';
export const MANAGED_BY_VALUE = 'segmentra';

export class K8sError extends Error {
  constructor(message: string, public status?: number, public code: string = 'k8s_error') {
    super(message);
    this.name = 'K8sError';
  }
}

export type K8sConnection = {
  server: URL;
  ca?: string;
  token?: string;
  clientCert?: string;
  clientKey?: string;
  insecureSkipTlsVerify: boolean;
};

// ---- destination checks -----------------------------------------------------------------------
// Cluster API servers are usually on loopback/private networks, so only link-local, unspecified
// and cloud-metadata destinations are refused (the SSRF targets that matter).
const FORBIDDEN_CIDRS = ['169.254.0.0/16', '0.0.0.0/8', '100.100.100.200/32', 'fe80::/10', 'fd00:ec2::254/128', '::/128'];

const METADATA_HOSTNAMES = new Set(['metadata', 'metadata.google.internal', 'metadata.goog', 'metadata.azure.com', 'instance-data', 'instance-data.ec2.internal']);

function isForbiddenAddress(ip: string): boolean {
  const addr = normalizeHost(ip).replace(/^::ffff:/i, '');
  if (!net.isIP(addr)) return true;
  return FORBIDDEN_CIDRS.some((c) => cidrContains(c, addr));
}

export function validateClusterUrl(raw: string): URL {
  let url: URL;
  try {
    url = new URL(raw.trim());
  } catch {
    throw new K8sError('API server URL is not a valid URL', undefined, 'invalid_url');
  }
  if (url.protocol !== 'https:') throw new K8sError('API server URL must use https', undefined, 'invalid_url');
  if (!destinationChecksDisabled()) {
    const host = normalizeHost(url.hostname);
    if (METADATA_HOSTNAMES.has(host)) {
      throw new K8sError(`API server host "${host}" is not allowed`, undefined, 'invalid_url');
    }
    if (net.isIP(host) && isForbiddenAddress(host)) throw new K8sError(`API server address ${host} is not allowed`, undefined, 'invalid_url');
  }
  return url;
}

function k8sLookup(hostname: string, options: any, callback?: any): void {
  const cb = typeof options === 'function' ? options : callback;
  const opts = typeof options === 'function' ? {} : (options ?? {});
  dns.lookup(hostname, { ...opts, all: true, verbatim: true }, (err, addresses) => {
    if (err) return cb(err, opts.all ? [] : '');
    const list = (addresses ?? []) as unknown as Array<{ address: string; family: number }>;
    const bad = destinationChecksDisabled() ? undefined : list.find((a) => isForbiddenAddress(a.address));
    if (bad) return cb(new K8sError(`"${hostname}" resolves to disallowed address ${bad.address}`, undefined, 'blocked_destination'), opts.all ? [] : '');
    if (opts.all) return cb(null, list);
    return cb(null, list[0].address, list[0].family);
  });
}

// ---- credentials ------------------------------------------------------------------------------
function b64(s: unknown): string | undefined {
  return typeof s === 'string' && s ? Buffer.from(s, 'base64').toString('utf8') : undefined;
}

/** Parse + validate a kubeconfig (YAML or JSON) into connection settings. Throws K8sError. */
export function parseKubeconfig(text: string): Omit<K8sConnection, 'insecureSkipTlsVerify'> & { insecureSkipTlsVerify?: boolean } {
  let doc: any;
  try {
    doc = parseYaml(text);
  } catch {
    throw new K8sError('kubeconfig is not valid YAML/JSON', undefined, 'invalid_credentials');
  }
  if (!doc || typeof doc !== 'object') throw new K8sError('kubeconfig is empty', undefined, 'invalid_credentials');
  const ctxName = doc['current-context'] ?? doc.contexts?.[0]?.name;
  const ctx = (doc.contexts ?? []).find((c: any) => c.name === ctxName)?.context;
  if (!ctx) throw new K8sError('kubeconfig has no usable current-context', undefined, 'invalid_credentials');
  const cluster = (doc.clusters ?? []).find((c: any) => c.name === ctx.cluster)?.cluster;
  const user = (doc.users ?? []).find((u: any) => u.name === ctx.user)?.user ?? {};
  if (!cluster?.server) throw new K8sError('kubeconfig cluster has no server', undefined, 'invalid_credentials');

  const refusals: Array<[unknown, string]> = [
    [cluster['certificate-authority'], 'certificate-authority (file path); embed it as certificate-authority-data'],
    [user['client-certificate'], 'client-certificate (file path); embed it as client-certificate-data'],
    [user['client-key'], 'client-key (file path); embed it as client-key-data'],
    [user.tokenFile, 'tokenFile'],
    [user.exec, 'exec credential plugins'],
    [user['auth-provider'], 'auth-provider plugins'],
    [cluster['proxy-url'], 'proxy-url'],
  ];
  for (const [v, what] of refusals) {
    if (v) throw new K8sError(`kubeconfig uses ${what}, which Segmentra does not support. Use an inline token or inline client certificate data.`, undefined, 'invalid_credentials');
  }
  const token = typeof user.token === 'string' && user.token ? user.token : undefined;
  const clientCert = b64(user['client-certificate-data']);
  const clientKey = b64(user['client-key-data']);
  if (!token && !(clientCert && clientKey)) {
    throw new K8sError('kubeconfig user has neither an inline token nor client-certificate-data + client-key-data', undefined, 'invalid_credentials');
  }
  return {
    server: validateClusterUrl(String(cluster.server)),
    ca: b64(cluster['certificate-authority-data']),
    token,
    clientCert,
    clientKey,
    insecureSkipTlsVerify: cluster['insecure-skip-tls-verify'] === true,
  };
}

/** Check credentials at save time. Returns the API server URL found in a kubeconfig (if any). */
export function validateCredentials(authType: string, credentials: string): { serverUrl?: string } {
  const text = credentials.trim();
  if (!text) throw new K8sError('credentials are empty', undefined, 'invalid_credentials');
  if (authType === 'kubeconfig') return { serverUrl: parseKubeconfig(text).server.toString().replace(/\/$/, '') };
  if (/\s/.test(text)) throw new K8sError('a bearer token must not contain whitespace', undefined, 'invalid_credentials');
  return {};
}

export async function loadConnection(cluster: {
  api_server_url: string;
  auth_type: string;
  credentials_secret_id: string | null;
  ca_cert_secret_id: string | null;
  tls_skip_verify: boolean;
}): Promise<K8sConnection> {
  if (!cluster.credentials_secret_id) throw new K8sError('No credentials are stored for this cluster', 409, 'no_credentials');
  const secret = (await readSecretPlaintext(cluster.credentials_secret_id)).toString('utf8').trim();
  const caPem = cluster.ca_cert_secret_id ? (await readSecretPlaintext(cluster.ca_cert_secret_id)).toString('utf8') : undefined;
  if (cluster.auth_type === 'kubeconfig') {
    const kc = parseKubeconfig(secret);
    return {
      server: kc.server,
      ca: caPem ?? kc.ca,
      token: kc.token,
      clientCert: kc.clientCert,
      clientKey: kc.clientKey,
      insecureSkipTlsVerify: cluster.tls_skip_verify || kc.insecureSkipTlsVerify === true,
    };
  }
  return { server: validateClusterUrl(cluster.api_server_url), ca: caPem, token: secret, insecureSkipTlsVerify: cluster.tls_skip_verify };
}

// ---- requests ---------------------------------------------------------------------------------
export function k8sRequest(
  conn: K8sConnection,
  method: string,
  path: string,
  opts: { body?: unknown; contentType?: string; query?: Record<string, string> } = {}
): Promise<{ status: number; json: any }> {
  const qs = opts.query && Object.keys(opts.query).length ? `?${new URLSearchParams(opts.query).toString()}` : '';
  const payload = opts.body === undefined ? undefined : Buffer.from(JSON.stringify(opts.body), 'utf8');
  const headers: Record<string, string | number> = { Accept: 'application/json' };
  if (conn.token) headers.Authorization = `Bearer ${conn.token}`;
  if (payload) {
    headers['Content-Type'] = opts.contentType ?? 'application/json';
    headers['Content-Length'] = payload.length;
  }
  const base = conn.server.pathname.replace(/\/$/, '');
  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        host: normalizeHost(conn.server.hostname),
        port: conn.server.port || 443,
        servername: net.isIP(normalizeHost(conn.server.hostname)) ? undefined : normalizeHost(conn.server.hostname),
        path: `${base}${path}${qs}`,
        method,
        headers,
        ca: conn.ca,
        cert: conn.clientCert,
        key: conn.clientKey,
        rejectUnauthorized: !conn.insecureSkipTlsVerify,
        lookup: k8sLookup as any,
        timeout: REQUEST_TIMEOUT_MS,
      },
      (res) => {
        const chunks: Buffer[] = [];
        let size = 0;
        res.on('data', (c: Buffer) => {
          size += c.length;
          if (size > MAX_RESPONSE_BYTES) return req.destroy(new K8sError('response from the API server is too large'));
          chunks.push(c);
        });
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          let json: any = null;
          try { json = text ? JSON.parse(text) : null; } catch { json = { message: text.slice(0, 300) }; }
          resolve({ status: res.statusCode ?? 0, json });
        });
      }
    );
    req.on('timeout', () => req.destroy(new K8sError('timed out talking to the Kubernetes API server', undefined, 'timeout')));
    req.on('error', (e: any) => reject(e instanceof K8sError ? e : new K8sError(describeNetworkError(e), undefined, 'connection_failed')));
    if (payload) req.write(payload);
    req.end();
  });
}

function describeNetworkError(e: any): string {
  const code = e?.code as string | undefined;
  if (code === 'ECONNREFUSED') return 'connection refused by the API server';
  if (code === 'ENOTFOUND') return 'API server host name cannot be resolved';
  if (code && /CERT|SELF_SIGNED|UNABLE_TO_VERIFY|ERR_TLS/.test(code)) return `TLS verification failed (${code}); provide the cluster CA certificate`;
  return e?.message ? String(e.message) : 'cannot reach the API server';
}

function statusError(res: { status: number; json: any }, what: string): K8sError {
  const msg = res.json?.message ? String(res.json.message) : `HTTP ${res.status}`;
  if (res.status === 401) return new K8sError(`${what}: the credentials were rejected (401). ${msg}`, 401, 'unauthorized');
  if (res.status === 403) return new K8sError(`${what}: forbidden (403). ${msg}`, 403, 'forbidden');
  return new K8sError(`${what}: ${msg}`, res.status);
}

const npPath = (ns: string, name?: string) =>
  `/apis/networking.k8s.io/v1/namespaces/${encodeURIComponent(ns)}/networkpolicies${name ? `/${encodeURIComponent(name)}` : ''}`;

export async function getVersion(conn: K8sConnection): Promise<string> {
  const res = await k8sRequest(conn, 'GET', '/version');
  if (res.status !== 200) throw statusError(res, 'GET /version');
  return String(res.json?.gitVersion ?? 'unknown');
}

/** Can the credentials list NetworkPolicies in `namespace`? (read access needed for check/apply) */
export async function canListNetworkPolicies(conn: K8sConnection, namespace: string): Promise<{ ok: boolean; message?: string }> {
  const res = await k8sRequest(conn, 'GET', npPath(namespace), { query: { limit: '1' } });
  if (res.status === 200) return { ok: true };
  return { ok: false, message: statusError(res, `list NetworkPolicies in ${namespace}`).message };
}

export async function getNetworkPolicy(conn: K8sConnection, ns: string, name: string): Promise<any | null> {
  const res = await k8sRequest(conn, 'GET', npPath(ns, name));
  if (res.status === 404) return null;
  if (res.status !== 200) throw statusError(res, `read NetworkPolicy ${ns}/${name}`);
  return res.json;
}

export function isManagedBySegmentra(policy: any): boolean {
  return policy?.metadata?.labels?.[MANAGED_BY_LABEL] === MANAGED_BY_VALUE;
}

/** Create-or-update with server-side apply (idempotent). dryRun validates without persisting. */
export async function applyNetworkPolicy(conn: K8sConnection, manifest: any, opts: { dryRun?: boolean } = {}): Promise<any> {
  const ns = manifest?.metadata?.namespace;
  const name = manifest?.metadata?.name;
  const res = await k8sRequest(conn, 'PATCH', npPath(ns, name), {
    body: manifest,
    contentType: 'application/apply-patch+yaml',
    query: { fieldManager: 'segmentra', force: 'true', ...(opts.dryRun ? { dryRun: 'All' } : {}) },
  });
  if (res.status === 404 && res.json?.details?.kind === 'namespaces') {
    throw new K8sError(`namespace "${ns}" does not exist in the cluster`, 404, 'namespace_not_found');
  }
  if (res.status !== 200 && res.status !== 201) throw statusError(res, `apply NetworkPolicy ${ns}/${name}`);
  return res.json;
}

/** Returns false when the policy was already gone. */
export async function deleteNetworkPolicy(conn: K8sConnection, ns: string, name: string): Promise<boolean> {
  const res = await k8sRequest(conn, 'DELETE', npPath(ns, name));
  if (res.status === 404) return false;
  if (res.status !== 200 && res.status !== 202) throw statusError(res, `delete NetworkPolicy ${ns}/${name}`);
  return true;
}

/** Stable JSON for comparing a stored spec with the live one (sorted keys). */
export function canonicalJson(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(',')}]`;
  if (v && typeof v === 'object') {
    return `{${Object.keys(v as object).sort().map((k) => `${JSON.stringify(k)}:${canonicalJson((v as any)[k])}`).join(',')}}`;
  }
  return JSON.stringify(v);
}
