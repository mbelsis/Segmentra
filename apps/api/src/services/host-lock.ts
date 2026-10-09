import type { PoolClient } from 'pg';

import { pool } from '../db/pool.js';

/**
 * Per-host mutual exclusion for operations that change a host's firewall (deployments, audit and policy-test
 * start/restore). A PostgreSQL session-level advisory lock on a dedicated connection, so it also works across
 * API processes and is released automatically if the process dies.
 */
const key = (hostId: string) => `segmentra-host:${hostId}`;

export type HostLockRelease = () => Promise<void>;

/** Wait for the lock on every host (in a fixed order, so concurrent callers cannot deadlock). */
export async function acquireHostLocks(hostIds: string[]): Promise<HostLockRelease> {
  const ids = Array.from(new Set(hostIds)).sort();
  const held: Array<{ client: PoolClient; id: string }> = [];
  const release: HostLockRelease = async () => {
    for (const h of held.splice(0).reverse()) {
      try { await h.client.query('SELECT pg_advisory_unlock(hashtextextended($1, 0))', [key(h.id)]); } finally { h.client.release(); }
    }
  };
  try {
    for (const id of ids) {
      const client = await pool.connect();
      try {
        await client.query('SELECT pg_advisory_lock(hashtextextended($1, 0))', [key(id)]);
      } catch (e) {
        client.release();
        throw e;
      }
      held.push({ client, id });
    }
  } catch (e) {
    await release();
    throw e;
  }
  return release;
}

export const acquireHostLock = (hostId: string) => acquireHostLocks([hostId]);

/** Take the lock only if it is free right now; null when another operation holds it. */
export async function tryAcquireHostLock(hostId: string): Promise<HostLockRelease | null> {
  const client = await pool.connect();
  try {
    const { rows } = await client.query('SELECT pg_try_advisory_lock(hashtextextended($1, 0)) AS ok', [key(hostId)]);
    if (!rows[0]?.ok) {
      client.release();
      return null;
    }
  } catch (e) {
    client.release();
    throw e;
  }
  return async () => {
    try { await client.query('SELECT pg_advisory_unlock(hashtextextended($1, 0))', [key(hostId)]); } finally { client.release(); }
  };
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
