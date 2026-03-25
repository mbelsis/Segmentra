import { z } from 'zod';
const envSchema = z.object({
    NODE_ENV: z.string().optional(),
    PORT: z.coerce.number().default(8080),
    DATABASE_URL: z.string().min(1),
    JWT_SECRET: z.string().min(16),
    SEGMENTRA_KEK_B64: z.string().optional().default(''),
    BUNDLES_DIR: z.string().optional().default('./data/bundles'),
    ANSIBLE_RUNNER_CONTAINER: z.string().optional().default('segmentra-ansible-runner'),
    SEGMENTRA_BOOTSTRAP_TOKEN: z.string().optional().default('')
});
export const env = envSchema.parse(process.env);
// Warn loudly if running with the default JWT secret
const KNOWN_UNSAFE_SECRETS = ['change-me-to-a-long-random-string'];
if (KNOWN_UNSAFE_SECRETS.includes(env.JWT_SECRET)) {
    if (env.NODE_ENV === 'production') {
        // eslint-disable-next-line no-console
        console.error('[FATAL] JWT_SECRET is set to an unsafe default. Set a strong, unique secret before running in production.');
        process.exit(1);
    }
    else {
        // eslint-disable-next-line no-console
        console.warn('[SECURITY WARNING] JWT_SECRET is set to an unsafe default. Tokens are forgeable. Set a strong, unique JWT_SECRET for any non-dev environment.');
    }
}
