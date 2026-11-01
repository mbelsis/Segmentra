import pg from 'pg';
import type { PoolClient } from 'pg';

import { env } from '../lib/env.js';
import { pool } from '../db/pool.js';

/**
 * Per-host mutual exclusion for operations that change a host's firewall (deployments, audit and policy-test
 * start/restore, expiry REMOVE). PostgreSQL session-level advisory locks, so it also works across API processes and is
 * released automatically if the process dies.
 *
 * The locks live on their own small pool, never on the shared query pool: they are held for as long as an SSH or Ansible
 * run takes, and an operation still needs ordinary queries while it holds them. One operation uses ONE connection for
 * all of its hosts (a session can hold any number of advisory locks), so an Ansible run over 50 hosts costs one
 * connection, not 50. The wait is bounded by `lock_timeout`, and getting a connection by `connectionTimeoutMillis`.
 */
const key = (hostId: string) => `segmentra-host:${hostId}`;

const envInt = (name: string, def: number, min: number) => {
  const n = Number(process.env[name]);
  return Number.isFinite(n) && n >= min ? Math.floor(n) : def;
};

/** Longest wait for another operation's lock on a host (default 30 min: an Ansible run can legitimately take that long). */
export const HOST_LOCK_TIMEOUT_MS = envInt('SEGMENTRA_HOST_LOCK_TIMEOUT_MS', 30 * 60 * 1000, 1000);
/** Concurrent lock-holding operations (each holds one connection of this pool). */
const HOST_LOCK_POOL_MAX = envInt('SEGMENTRA_HOST_LOCK_POOL_MAX', 20, 1);

const lockPool = new pg.Pool({
  connectionString: env.DATABASE_URL,
  max: HOST_LOCK_POOL_MAX,
  connectionTimeoutMillis: HOST_LOCK_TIMEOUT_MS,
  idleTimeoutMillis: 30_000
});
// A connection that drops while idle must not crash the process (the locks it held are gone with it anyway).
lockPool.on('error', (e) => {
  // eslint-disable-next-line no-console
  console.error('[host-lock] idle lock connection error:', e?.message ?? e);
});

export class HostLockTimeoutError extends Error {
  constructor(hostIds: string[], cause: unknown) {
    super(`timed out waiting for the firewall lock of ${hostIds.length === 1 ? 'the host' : `${hostIds.length} hosts`} (another deployment or learning/test session is still running on it): ${(cause as any)?.message ?? cause}`);
    this.name = 'HostLockTimeoutError';
  }
}

export type HostLockRelease = () => Promise<void>;

function releaser(client: PoolClient): HostLockRelease {
  let done = false;
  const onError = () => { /* reported by the query that fails; the connection is destroyed on release */ };
  client.on('error', onError);
  return async () => {
    if (done) return;
    done = true;
    let broken = false;
    try {
      await client.query('SELECT pg_advisory_unlock_all()');
    } catch {
      broken = true; // destroying the connection releases its session locks as well
    } finally {
      client.off('error', onError);
      client.release(broken);
    }
  };
}

const isLockTimeout = (e: any) => e?.code === '55P03' || /timeout exceeded when trying to connect/i.test(String(e?.message ?? ''));

/** Wait for the lock on every host (in a fixed order, so concurrent callers cannot deadlock), on one connection. */
export async function acquireHostLocks(hostIds: string[], opts: { timeoutMs?: number } = {}): Promise<HostLockRelease> {
  const ids = Array.from(new Set(hostIds)).sort();
  if (ids.length === 0) return async () => {};
  const timeoutMs = Math.max(1, Math.floor(opts.timeoutMs ?? HOST_LOCK_TIMEOUT_MS));
  let client: PoolClient;
  try {
    client = await lockPool.connect();
  } catch (e) {
    if (isLockTimeout(e)) throw new HostLockTimeoutError(ids, e);
    throw e;
  }
  const release = releaser(client);
  try {
    await client.query(`SELECT set_config('lock_timeout', $1, false)`, [`${timeoutMs}ms`]);
    for (const id of ids) await client.query('SELECT pg_advisory_lock(hashtextextended($1, 0))', [key(id)]);
  } catch (e) {
    await release();
    if (isLockTimeout(e)) throw new HostLockTimeoutError(ids, e);
    throw e;
  }
  return release;
}

export const acquireHostLock = (hostId: string, opts?: { timeoutMs?: number }) => acquireHostLocks([hostId], opts);

/** Take the lock only if it is free right now; null when another operation holds it. */
export async function tryAcquireHostLock(hostId: string): Promise<HostLockRelease | null> {
  const client = await lockPool.connect();
  const release = releaser(client);
  try {
    const { rows } = await client.query('SELECT pg_try_advisory_lock(hashtextextended($1, 0)) AS ok', [key(hostId)]);
    if (!rows[0]?.ok) {
      await release();
      return null;
    }
  } catch (e) {
    await release();
    throw e;
  }
  return release;
}

/** For tests and shutdown. */
export const endHostLockPool = () => lockPool.end();

type Queryable = { query: PoolClient['query'] };

/** Learning-session statuses that own the host's firewall (see services/audit-scheduler.ts). */
export const ACTIVE_AUDIT_SESSION_STATUSES = ['PENDING', 'RUNNING'] as const;
/** Policy-test statuses that own the host's firewall (see lib/policy-test-session.ts). */
export const ACTIVE_TEST_SESSION_STATUSES = ['PENDING', 'DEPLOYING', 'RUNNING'] as const;

export type ActiveFirewallSession = { kind: 'learning' | 'policy_test'; id: string; status: string };

/**
 * The learning or policy-test session that currently owns the host's firewall, if any. Only one may exist per host,
 * across BOTH kinds: each takes a backup of the rules it replaces, so a second session would back up the first one's
 * log-only rules and later put them back. Call it while holding the host lock, so the answer cannot change before the
 * caller has recorded its own session.
 */
export async function activeFirewallSession(hostId: string, db: Queryable = pool): Promise<ActiveFirewallSession | null> {
  const { rows } = await db.query(
    `SELECT 'learning' AS kind, id, status FROM firewall_audit_sessions WHERE host_id = $1 AND status = ANY($2::text[])
     UNION ALL
     SELECT 'policy_test' AS kind, id, status FROM policy_test_sessions WHERE host_id = $1 AND status = ANY($3::text[])
     LIMIT 1`,
    [hostId, ACTIVE_AUDIT_SESSION_STATUSES, ACTIVE_TEST_SESSION_STATUSES]
  );
  return (rows[0] as ActiveFirewallSession | undefined) ?? null;
}

export function describeActiveSession(s: ActiveFirewallSession): string {
  return s.kind === 'learning'
    ? `a firewall learning session (${s.id}, ${s.status}) is already active on this host`
    : `a policy test (${s.id}, ${s.status}) is already active on this host`;
}

/**
 * True when the host's Segmentra rules were changed by a deployment after `since`: a deployment that succeeded
 * (and was not removed again), or an expiry REMOVE that ran. A backup taken before that moment describes an older
 * policy: restoring it would silently replace the newer deployment, or bring back a policy that was removed on purpose.
 */
export async function deploymentSucceededSince(hostId: string, since: Date | string | null): Promise<boolean> {
  if (!since) return false;
  const { rows } = await pool.query(
    `SELECT 1 FROM deployment_hosts dh
       JOIN deployments d ON d.id = dh.deployment_id
      WHERE dh.host_id = $1
        AND (
          (dh.status = 'SUCCEEDED' AND COALESCE(dh.finished_at, d.finished_at, d.created_at) > $2 AND COALESCE(dh.expiry_status, '') <> 'REMOVED')
          OR (dh.expiry_status = 'REMOVED' AND dh.expiry_processed_at > $2)
        )
      LIMIT 1`,
    [hostId, since]
  );
  return rows.length > 0;
}
