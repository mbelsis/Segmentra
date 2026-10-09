import type { CorsOptions } from 'cors';

export function corsOptions(nodeEnv: string | undefined, allowedOrigins: string): CorsOptions {
  if (allowedOrigins) {
    return { origin: allowedOrigins.split(',').map(origin => origin.trim()) };
  }
  return { origin: nodeEnv === 'production' ? false : '*' };
}
