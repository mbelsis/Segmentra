import crypto from 'node:crypto';

/**
 * Native cloud logins for Kubernetes API servers, so managed clusters (EKS, GKE, AKS) can be used
 * without kubectl exec plugins (aws, gke-gcloud-auth-plugin, kubelogin): nothing is executed, a
 * short-lived bearer token is minted in-process from the stored (encrypted) cloud credentials.
 *
 *  - EKS: the token `aws eks get-token` would print, a SigV4-presigned STS GetCallerIdentity URL
 *         (access key, secret key and optional session token).
 *  - GKE: a Google OAuth2 access token from a service-account JSON key (JWT bearer grant).
 *  - AKS: a Microsoft Entra ID access token for the AKS server app from a service principal
 *         (client-credentials grant).
 *
 * Token endpoints are fixed (never taken from the stored credentials), so a stored credential
 * cannot redirect Segmentra to an arbitrary URL.
 */

export type CloudAuthType = 'eks' | 'gke' | 'aks';
export const CLOUD_AUTH_TYPES: readonly string[] = ['eks', 'gke', 'aks'];

export class CloudAuthError extends Error {
  constructor(message: string, public code: string = 'invalid_credentials') {
    super(message);
    this.name = 'CloudAuthError';
  }
}

type FetchLike = (url: string, init: { method: string; headers: Record<string, string>; body: string; signal?: AbortSignal }) => Promise<{
  ok: boolean;
  status: number;
  text(): Promise<string>;
}>;

export type MintOptions = { now?: Date; fetchImpl?: FetchLike; tokenUrl?: string };

// ---- credential shapes ------------------------------------------------------------------------
export type EksCredentials = { clusterName: string; region: string; accessKeyId: string; secretAccessKey: string; sessionToken?: string };
export type AksCredentials = { tenantId: string; clientId: string; clientSecret: string };
export type GkeCredentials = { client_email: string; private_key: string };

function parseJson(text: string, what: string): Record<string, any> {
  let v: unknown;
  try { v = JSON.parse(text); } catch { throw new CloudAuthError(`${what} credentials must be valid JSON`); }
  if (!v || typeof v !== 'object' || Array.isArray(v)) throw new CloudAuthError(`${what} credentials must be a JSON object`);
  return v as Record<string, any>;
}
const str = (v: unknown) => (typeof v === 'string' ? v.trim() : '');

export function parseEksCredentials(text: string): EksCredentials {
  const o = parseJson(text, 'EKS');
  const c = { clusterName: str(o.clusterName), region: str(o.region), accessKeyId: str(o.accessKeyId), secretAccessKey: str(o.secretAccessKey), sessionToken: str(o.sessionToken) || undefined };
  if (!c.clusterName) throw new CloudAuthError('EKS credentials need the cluster name (it is signed into the token)');
  if (!/^[a-z]{2}(-[a-z]+)+-\d$/.test(c.region)) throw new CloudAuthError('EKS credentials need an AWS region such as eu-west-1');
  if (!/^[A-Z0-9]{16,128}$/.test(c.accessKeyId)) throw new CloudAuthError('EKS accessKeyId does not look like an AWS access key id');
  if (!c.secretAccessKey) throw new CloudAuthError('EKS credentials need the secret access key');
  return c;
}

export function parseGkeCredentials(text: string): GkeCredentials {
  const o = parseJson(text, 'GKE');
  if (o.type && o.type !== 'service_account') throw new CloudAuthError('GKE credentials must be a service account key (type "service_account")');
  const c = { client_email: str(o.client_email), private_key: typeof o.private_key === 'string' ? o.private_key : '' };
  if (!c.client_email || !/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(c.private_key)) {
    throw new CloudAuthError('GKE credentials must be a service account JSON key with client_email and private_key');
  }
  try { crypto.createPrivateKey(c.private_key); } catch { throw new CloudAuthError('GKE private_key could not be read'); }
  return c;
}

export function parseAksCredentials(text: string): AksCredentials {
  const o = parseJson(text, 'AKS');
  const c = { tenantId: str(o.tenantId), clientId: str(o.clientId), clientSecret: str(o.clientSecret) };
  if (!/^[A-Za-z0-9][A-Za-z0-9.-]{2,}$/.test(c.tenantId)) throw new CloudAuthError('AKS credentials need the tenant id (GUID or domain)');
  if (!/^[0-9a-fA-F-]{36}$/.test(c.clientId)) throw new CloudAuthError('AKS clientId must be the service principal application (client) id GUID');
  if (!c.clientSecret) throw new CloudAuthError('AKS credentials need the client secret');
  return c;
}

/** Validate stored-credential text for a cloud auth type (throws CloudAuthError). */
export function validateCloudCredentials(authType: string, text: string): void {
  if (authType === 'eks') parseEksCredentials(text);
  else if (authType === 'gke') parseGkeCredentials(text);
  else if (authType === 'aks') parseAksCredentials(text);
}

// ---- AWS SigV4 (query-string presign) ---------------------------------------------------------
const sha256Hex = (d: string) => crypto.createHash('sha256').update(d, 'utf8').digest('hex');
const hmac = (key: crypto.BinaryLike, d: string) => crypto.createHmac('sha256', key).update(d, 'utf8').digest();
const rfc3986 = (s: string) => encodeURIComponent(s).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);

export function sigV4Presign(p: {
  method: string; host: string; path: string; query: Record<string, string>; region: string; service: string;
  accessKeyId: string; secretAccessKey: string; sessionToken?: string;
  headers: Record<string, string>; expires: number; payloadHash: string; now: Date;
}): string {
  const amzDate = p.now.toISOString().replace(/[:-]|\.\d{3}/g, '');
  const day = amzDate.slice(0, 8);
  const scope = `${day}/${p.region}/${p.service}/aws4_request`;
  const headers: Record<string, string> = { host: p.host };
  for (const [k, v] of Object.entries(p.headers)) headers[k.toLowerCase()] = v.trim();
  const signedHeaders = Object.keys(headers).sort().join(';');
  const query: Record<string, string> = {
    ...p.query,
    'X-Amz-Algorithm': 'AWS4-HMAC-SHA256',
    'X-Amz-Credential': `${p.accessKeyId}/${scope}`,
    'X-Amz-Date': amzDate,
    'X-Amz-Expires': String(p.expires),
    'X-Amz-SignedHeaders': signedHeaders,
    ...(p.sessionToken ? { 'X-Amz-Security-Token': p.sessionToken } : {}),
  };
  const canonicalQuery = Object.keys(query).sort().map((k) => `${rfc3986(k)}=${rfc3986(query[k])}`).join('&');
  const canonicalHeaders = Object.keys(headers).sort().map((k) => `${k}:${headers[k]}\n`).join('');
  const canonicalRequest = [p.method, p.path, canonicalQuery, canonicalHeaders, signedHeaders, p.payloadHash].join('\n');
  const stringToSign = ['AWS4-HMAC-SHA256', amzDate, scope, sha256Hex(canonicalRequest)].join('\n');
  const kSigning = hmac(hmac(hmac(hmac(`AWS4${p.secretAccessKey}`, day), p.region), p.service), 'aws4_request');
  const signature = crypto.createHmac('sha256', kSigning).update(stringToSign, 'utf8').digest('hex');
  return `https://${p.host}${p.path}?${canonicalQuery}&X-Amz-Signature=${signature}`;
}

/** The token `aws eks get-token` prints: "k8s-aws-v1." + base64url(presigned STS GetCallerIdentity URL). */
export function mintEksToken(c: EksCredentials, opts: MintOptions = {}): string {
  const suffix = c.region.startsWith('cn-') ? 'amazonaws.com.cn' : 'amazonaws.com';
  const url = sigV4Presign({
    method: 'GET', host: `sts.${c.region}.${suffix}`, path: '/',
    query: { Action: 'GetCallerIdentity', Version: '2011-06-15' },
    region: c.region, service: 'sts', accessKeyId: c.accessKeyId, secretAccessKey: c.secretAccessKey, sessionToken: c.sessionToken,
    headers: { 'x-k8s-aws-id': c.clusterName }, expires: 60,
    payloadHash: sha256Hex(''), now: opts.now ?? new Date(),
  });
  return `k8s-aws-v1.${Buffer.from(url, 'utf8').toString('base64url')}`;
}

// ---- OAuth token endpoints --------------------------------------------------------------------
const REQUEST_TIMEOUT_MS = 15_000;
const defaultFetch: FetchLike = (url, init) => fetch(url, { ...init, redirect: 'error' }) as any;

async function postForm(url: string, form: Record<string, string>, what: string, opts: MintOptions): Promise<any> {
  const doFetch = opts.fetchImpl ?? defaultFetch;
  let res;
  try {
    res = await doFetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
      body: new URLSearchParams(form).toString(),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
  } catch (e: any) {
    throw new CloudAuthError(`${what}: cannot reach the token endpoint (${e?.cause?.code ?? e?.code ?? e?.message ?? 'network error'})`, 'connection_failed');
  }
  const text = await res.text();
  let json: any = null;
  try { json = JSON.parse(text); } catch { /* not JSON */ }
  if (!res.ok || !json?.access_token) {
    const detail = json?.error_description ?? json?.error ?? text.slice(0, 200);
    throw new CloudAuthError(`${what}: login failed (${res.status}): ${String(detail).replace(/\s+/g, ' ').slice(0, 300)}`, 'unauthorized');
  }
  return json;
}

const b64url = (b: Buffer | string) => Buffer.from(b).toString('base64url');

export async function mintGkeToken(c: GkeCredentials, opts: MintOptions = {}): Promise<string> {
  const tokenUrl = opts.tokenUrl ?? 'https://oauth2.googleapis.com/token';
  const iat = Math.floor((opts.now ?? new Date()).getTime() / 1000);
  const header = b64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const claims = b64url(JSON.stringify({ iss: c.client_email, scope: 'https://www.googleapis.com/auth/cloud-platform', aud: tokenUrl, iat, exp: iat + 3600 }));
  const signature = crypto.sign('RSA-SHA256', Buffer.from(`${header}.${claims}`), crypto.createPrivateKey(c.private_key)).toString('base64url');
  const json = await postForm(tokenUrl, { grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion: `${header}.${claims}.${signature}` }, 'GKE', opts);
  return String(json.access_token);
}

/** Microsoft Entra ID application id of the AKS server app (used as the token audience). */
export const AKS_SERVER_APP_ID = '6dae42f8-4368-4678-94ff-3960e28e3630';

export async function mintAksToken(c: AksCredentials, opts: MintOptions = {}): Promise<string> {
  const tokenUrl = opts.tokenUrl ?? `https://login.microsoftonline.com/${encodeURIComponent(c.tenantId)}/oauth2/v2.0/token`;
  const json = await postForm(tokenUrl, {
    grant_type: 'client_credentials', client_id: c.clientId, client_secret: c.clientSecret, scope: `${AKS_SERVER_APP_ID}/.default`,
  }, 'AKS', opts);
  return String(json.access_token);
}

/** Mint a bearer token for the stored cloud credentials of the given auth type. */
export async function mintCloudToken(authType: string, credentialsText: string, opts: MintOptions = {}): Promise<string> {
  if (authType === 'eks') return mintEksToken(parseEksCredentials(credentialsText), opts);
  if (authType === 'gke') return mintGkeToken(parseGkeCredentials(credentialsText), opts);
  if (authType === 'aks') return mintAksToken(parseAksCredentials(credentialsText), opts);
  throw new CloudAuthError(`unsupported cloud auth type "${authType}"`);
}
