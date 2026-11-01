/**
 * Pure helpers for deployment bookkeeping (no database access, so they can be unit-tested from the built dist).
 */

export type HostStatusCounts = {
  pending: number;
  running: number;
  paused: number;
  succeeded: number;
  failed: number;
  skipped: number;
  /** succeeded + failed + skipped */
  total: number;
  /** pending + running + paused */
  unfinished: number;
};

/** Counts from `SELECT status, COUNT(*) AS count FROM deployment_hosts ... GROUP BY status` rows. */
export function countHostStatuses(rows: Array<{ status: string; count: number | string }>): HostStatusCounts {
  const by: Record<string, number> = {};
  for (const r of rows) by[String(r.status)] = (by[String(r.status)] ?? 0) + (Number.parseInt(String(r.count), 10) || 0);
  const c = {
    pending: by.PENDING ?? 0,
    running: by.RUNNING ?? 0,
    paused: by.PAUSED ?? 0,
    succeeded: by.SUCCEEDED ?? 0,
    failed: by.FAILED ?? 0,
    skipped: by.SKIPPED ?? 0
  };
  return { ...c, total: c.succeeded + c.failed + c.skipped, unfinished: c.pending + c.running + c.paused };
}

export type FinalDeploymentStatus = 'SUCCEEDED' | 'PARTIAL' | 'FAILED';

/**
 * The one rule every finalization path uses (executor, stale-host timeout, restart recovery):
 *   some failed and some succeeded -> PARTIAL; any failed or nothing succeeded (e.g. all SKIPPED) -> FAILED;
 *   otherwise SUCCEEDED. Returns null while hosts are still PENDING/RUNNING/PAUSED.
 */
export function finalDeploymentStatus(c: Pick<HostStatusCounts, 'succeeded' | 'failed' | 'unfinished'>): FinalDeploymentStatus | null {
  if (c.unfinished > 0) return null;
  if (c.failed > 0 && c.succeeded > 0) return 'PARTIAL';
  if (c.failed > 0 || c.succeeded === 0) return 'FAILED';
  return 'SUCCEEDED';
}

const MIN = 60 * 1000;

/**
 * How long a deployment host may stay RUNNING (counted from when its host lock was acquired) before the stale-host job
 * fails it. Only applies to hosts NOT owned by an execution in this process (crashed/other process). Must comfortably
 * exceed one host's realistic maximum: an SSH deployment runs several commands of up to SEGMENTRA_SSH_COMMAND_TIMEOUT_MS
 * each, an Ansible run is bounded by its own timeout (default 30 min) plus the post-run checks.
 * Override with SEGMENTRA_HOST_DEPLOYMENT_TIMEOUT_MS (>= 1 minute).
 */
export function hostDeploymentTimeoutMs(
  envVars: Record<string, string | undefined> = process.env,
  ansibleTimeoutMs = 30 * MIN
): number {
  const explicit = Number(envVars.SEGMENTRA_HOST_DEPLOYMENT_TIMEOUT_MS);
  if (Number.isFinite(explicit) && explicit >= MIN) return Math.floor(explicit);
  const sshEnv = Number(envVars.SEGMENTRA_SSH_COMMAND_TIMEOUT_MS);
  const sshCmd = Number.isFinite(sshEnv) && sshEnv > 0 ? sshEnv : 5 * MIN;
  return Math.max(60 * MIN, 8 * sshCmd + 5 * MIN, ansibleTimeoutMs + 15 * MIN);
}

/** page >= 1, 1 <= limit <= max; non-numeric values fall back to the defaults. */
export function clampPagination(
  pageRaw: unknown,
  limitRaw: unknown,
  opts: { defaultLimit?: number; maxLimit?: number } = {}
): { page: number; limit: number; offset: number } {
  const maxLimit = opts.maxLimit ?? 100;
  const defaultLimit = opts.defaultLimit ?? 50;
  const p = Number.parseInt(String(pageRaw ?? ''), 10);
  const l = Number.parseInt(String(limitRaw ?? ''), 10);
  const page = Number.isFinite(p) && p >= 1 ? p : 1;
  const limit = Number.isFinite(l) && l >= 1 ? Math.min(l, maxLimit) : Math.min(defaultLimit, maxLimit);
  return { page, limit, offset: (page - 1) * limit };
}

/**
 * SSH login names accepted in the Ansible inventory. Same pattern as USER_RE in packages/executor/src/ssh-options.ts
 * (not exported there; keep the two in sync). The INI inventory value is templated by Ansible, so anything outside this
 * set (`{`, `%`, quotes, whitespace, `=` ...) could inject Jinja (e.g. {{ lookup('pipe', ...) }}) or extra variables.
 */
export const ANSIBLE_USER_RE = /^[A-Za-z0-9._][A-Za-z0-9._-]{0,63}$/;

export function isSafeAnsibleUsername(username: unknown): boolean {
  return typeof username === 'string' && ANSIBLE_USER_RE.test(username);
}
