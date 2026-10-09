import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { test } from 'node:test';

import {
  AKS_SERVER_APP_ID, mintAksToken, mintCloudToken, mintEksToken, mintGkeToken, parseAksCredentials,
  parseEksCredentials, parseGkeCredentials, sigV4Presign, validateCloudCredentials
} from '../apps/api/dist/services/k8s-cloud-auth.js';

// k8s-client imports the API environment config; give it test-only values before loading it.
process.env.JWT_SECRET ??= 'test-only-secret-with-at-least-32-characters';
process.env.DATABASE_URL ??= 'postgres://localhost/segmentra_test';
const { validateCredentials } = await import('../apps/api/dist/services/k8s-client.js');

// AWS documentation example "Authenticating Requests: Using Query Parameters (AWS Signature Version 4)".
test('SigV4 presign reproduces the AWS documentation example signature', () => {
  const url = sigV4Presign({
    method: 'GET', host: 'examplebucket.s3.amazonaws.com', path: '/test.txt', query: {}, region: 'us-east-1', service: 's3',
    accessKeyId: 'AKIAIOSFODNN7EXAMPLE', secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    headers: {}, expires: 86400, payloadHash: 'UNSIGNED-PAYLOAD', now: new Date('2013-05-24T00:00:00Z')
  });
  assert.match(url, /X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404$/);
});

const eks = { clusterName: 'prod-eks', region: 'eu-west-1', accessKeyId: 'AKIAIOSFODNN7EXAMPLE', secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' };

test('EKS token is the presigned STS GetCallerIdentity URL signing the cluster id header', () => {
  const token = mintEksToken({ ...eks, sessionToken: 'SESSION/token+value' }, { now: new Date('2026-10-09T10:00:00Z') });
  assert.ok(token.startsWith('k8s-aws-v1.'));
  const url = new URL(Buffer.from(token.slice('k8s-aws-v1.'.length), 'base64url').toString());
  assert.equal(url.host, 'sts.eu-west-1.amazonaws.com');
  assert.equal(url.searchParams.get('Action'), 'GetCallerIdentity');
  assert.equal(url.searchParams.get('X-Amz-SignedHeaders'), 'host;x-k8s-aws-id');
  assert.equal(url.searchParams.get('X-Amz-Expires'), '60');
  assert.equal(url.searchParams.get('X-Amz-Date'), '20261009T100000Z');
  assert.equal(url.searchParams.get('X-Amz-Security-Token'), 'SESSION/token+value');
  assert.match(url.searchParams.get('X-Amz-Signature'), /^[0-9a-f]{64}$/);
  // The secret never appears in the token, and the signature depends on the cluster name.
  assert.ok(!Buffer.from(token.slice(11), 'base64url').toString().includes(eks.secretAccessKey));
  const other = mintEksToken({ ...eks, clusterName: 'other' }, { now: new Date('2026-10-09T10:00:00Z') });
  const sig = (t) => new URL(Buffer.from(t.slice(11), 'base64url').toString()).searchParams.get('X-Amz-Signature');
  assert.notEqual(sig(token), sig(other));
  assert.equal(new URL(Buffer.from(mintEksToken({ ...eks, region: 'cn-north-1' }).slice(11), 'base64url').toString()).host, 'sts.cn-north-1.amazonaws.com.cn');
});

test('GKE: signed JWT bearer assertion is exchanged for an access token', async () => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const creds = { client_email: 'segmentra@proj.iam.gserviceaccount.com', private_key: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString() };
  let seen;
  const token = await mintGkeToken(creds, {
    now: new Date('2026-10-09T10:00:00Z'),
    fetchImpl: async (url, init) => { seen = { url, init }; return { ok: true, status: 200, text: async () => JSON.stringify({ access_token: 'ya29.test', expires_in: 3599 }) }; }
  });
  assert.equal(token, 'ya29.test');
  assert.equal(seen.url, 'https://oauth2.googleapis.com/token');
  const form = new URLSearchParams(seen.init.body);
  assert.equal(form.get('grant_type'), 'urn:ietf:params:oauth:grant-type:jwt-bearer');
  const [h, c, s] = form.get('assertion').split('.');
  assert.ok(crypto.verify('RSA-SHA256', Buffer.from(`${h}.${c}`), publicKey, Buffer.from(s, 'base64url')), 'JWT signature verifies with the public key');
  const claims = JSON.parse(Buffer.from(c, 'base64url').toString());
  assert.equal(claims.iss, creds.client_email);
  assert.equal(claims.scope, 'https://www.googleapis.com/auth/cloud-platform');
  assert.equal(claims.exp - claims.iat, 3600);
});

test('AKS: client-credentials request for the AKS server app, errors are reported without the secret', async () => {
  const creds = { tenantId: '11111111-2222-3333-4444-555555555555', clientId: '66666666-7777-8888-9999-000000000000', clientSecret: 'S3cr3t-value' };
  let seen;
  const token = await mintAksToken(creds, { fetchImpl: async (url, init) => { seen = { url, init }; return { ok: true, status: 200, text: async () => JSON.stringify({ access_token: 'eyJ.aks' }) }; } });
  assert.equal(token, 'eyJ.aks');
  assert.equal(seen.url, `https://login.microsoftonline.com/${creds.tenantId}/oauth2/v2.0/token`);
  const form = new URLSearchParams(seen.init.body);
  assert.equal(form.get('scope'), `${AKS_SERVER_APP_ID}/.default`);
  assert.equal(form.get('grant_type'), 'client_credentials');

  await assert.rejects(
    mintAksToken(creds, { fetchImpl: async () => ({ ok: false, status: 401, text: async () => JSON.stringify({ error: 'invalid_client', error_description: 'AADSTS7000215: Invalid client secret provided.' }) }) }),
    (e) => /login failed \(401\).*AADSTS7000215/.test(e.message) && !e.message.includes(creds.clientSecret) && e.code === 'unauthorized'
  );
  await assert.rejects(mintAksToken(creds, { fetchImpl: async () => { throw new Error('boom'); } }), /cannot reach the token endpoint/);
});

test('cloud credentials are validated when they are stored', () => {
  assert.doesNotThrow(() => validateCredentials('eks', JSON.stringify(eks)));
  assert.throws(() => validateCredentials('eks', JSON.stringify({ ...eks, region: 'nowhere' })), /region/);
  assert.throws(() => validateCredentials('eks', JSON.stringify({ ...eks, clusterName: '' })), /cluster name/);
  assert.throws(() => validateCredentials('eks', 'not json'), /valid JSON/);
  assert.throws(() => validateCredentials('gke', JSON.stringify({ client_email: 'a@b', private_key: 'x' })), /service account JSON key/);
  assert.throws(() => validateCredentials('gke', JSON.stringify({ type: 'authorized_user' })), /service account key/);
  assert.throws(() => validateCredentials('aks', JSON.stringify({ tenantId: 't', clientId: 'x', clientSecret: 'y' })), /tenant|client/);
  assert.throws(() => parseEksCredentials('[]'), /JSON object/);
  assert.throws(() => parseAksCredentials('{}'), /tenant/);
  assert.throws(() => parseGkeCredentials('{}'), /service account JSON key/);
  assert.throws(() => validateCloudCredentials('eks', '{}'), /cluster name/);
});

test('mintCloudToken dispatches on the auth type and rejects unknown ones', async () => {
  assert.ok((await mintCloudToken('eks', JSON.stringify(eks))).startsWith('k8s-aws-v1.'));
  await assert.rejects(mintCloudToken('nope', '{}'), /unsupported cloud auth type/);
});
