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


