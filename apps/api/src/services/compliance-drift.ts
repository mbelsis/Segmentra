import { runWithConcurrency } from './compliance-drift-util.js';
import { checkHostCompliance } from '../routes/compliance.js';

/** Live drift for a set of hosts: reads each host over SSH (a few at a time) and compares it with its last deployment. */
export async function runLiveDrift(hostIds: string[]) {
  const results = await runWithConcurrency(hostIds, 4, (id) => checkHostCompliance(id));
  const counts: Record<string, number> = {};
  for (const r of results) counts[r.status] = (counts[r.status] ?? 0) + 1;
  return {
    checked: results.length,
    counts,
    hosts: results.map((r) => ({ hostname: r.hostname, status: r.status, message: r.message ?? null, error: r.error ?? null, persistence: r.persistence?.state ?? null })),
  };
}
