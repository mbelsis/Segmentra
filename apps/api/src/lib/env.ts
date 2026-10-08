import { z } from 'zod';

const isProduction = process.env.NODE_ENV === 'production';

const envSchema = z.object({
  NODE_ENV: z.string().optional(),
  PORT: z.coerce.number().default(8080),
  DATABASE_URL: z.string().min(1),
  // Production requires a long secret; shorter secrets are tolerated for local dev only.
  JWT_SECRET: z.string().min(isProduction ? 32 : 16),
  SEGMENTRA_KEK_B64: z.string().optional().default(''),
  BUNDLES_DIR: z.string().optional().default('./data/bundles'),
  ANSIBLE_RUNNER_CONTAINER: z.string().optional().default('segmentra-ansible-runner'),
  SEGMENTRA_BOOTSTRAP_TOKEN: z.string().optional().default(''),
  // Comma-separated list of allowed CORS origins (empty = allow all; set in production).
  CORS_ORIGIN: z.string().optional().default(''),
  // Express 'trust proxy' setting. Set when running behind a reverse proxy so req.ip
  // reflects the client address (e.g. "1", "loopback", "10.0.0.0/8", "true").
  TRUST_PROXY: z.string().optional().default('')
});

export const env = envSchema.parse(process.env);

/** Convert TRUST_PROXY into a value accepted by app.set('trust proxy', ...). Returns undefined when unset. */
export function parseTrustProxy(raw: string): boolean | number | string | undefined {
  const value = raw.trim();
  if (!value) return undefined;
  if (value === 'true') return true;
  if (value === 'false') return false;
  if (/^\d+$/.test(value)) return Number(value);
  return value;
}

// Refuse (production) or warn loudly (dev) when running with a known default JWT secret
const KNOWN_UNSAFE_SECRETS = [
  'change-me-to-a-long-random-string',
  'dev-secret-change-me-in-production'
];
if (KNOWN_UNSAFE_SECRETS.includes(env.JWT_SECRET)) {
  if (env.NODE_ENV === 'production') {
    // eslint-disable-next-line no-console
    console.error('[FATAL] JWT_SECRET is set to an unsafe default. Set a strong, unique secret before running in production.');
    process.exit(1);
  } else {
    // eslint-disable-next-line no-console
    console.warn('[SECURITY WARNING] JWT_SECRET is set to an unsafe default. Tokens are forgeable. Set a strong, unique JWT_SECRET for any non-dev environment.');
  }
}
