/**
 * Forwards EVERY audit_events row to the enabled SIEM integrations, exactly once, however the
 * row was inserted (createAuditEvent or a direct INSERT in a route/service).
 *
 * Mechanism (migration 031):
 *  - An AFTER INSERT trigger on audit_events runs pg_notify('segmentra_audit', NEW.id). NOTIFY
 *    is delivered on commit, so rolled-back inserts are never forwarded.
 *  - Each API process keeps ONE dedicated pg connection that LISTENs on that channel and queues
 *    the ids (processed one at a time, in arrival order).
 *  - For each id the row is claimed with
 *      UPDATE audit_events SET siem_forwarded_at = now() WHERE id = $1 AND siem_forwarded_at IS NULL
 *    Only the process whose UPDATE returned the row sends it, so several API replicas (each with
 *    its own listener) never forward an event twice.
 *  - Nothing is claimed while no SIEM integration is enabled (checked through a 10s cache).
 *  - If every enabled collector rejected the message (e.g. TCP collector down) the claim is
 *    released so the sweep below retries it.
 *  - A catch-up sweep runs at startup, after every LISTEN reconnect and every minute: it forwards
 *    unclaimed rows from the last SIEM_CATCHUP_MINUTES (bounded, at most SWEEP_BATCH per run).
 *    This covers notifications lost while the LISTEN connection was down and retries failures.
 *  - The LISTEN connection is health-checked every minute and reconnected with exponential
 *    backoff (1s .. 30s) when it drops.
 *
 * Delivery is at-least-once to the collector set as a whole but not per collector: with several
 * enabled SIEM integrations, an event that reached at least one of them is not retried for the
 * others.
 */
import pg from 'pg';

import { pool } from '../db/pool.js';
import { env } from '../lib/env.js';
import { forwardAuditToSiem, getEnabledSiemConfigs } from './siem-forwarder.js';

const CHANNEL = 'segmentra_audit';
/** How far back the catch-up sweep looks for events that were never forwarded. */
export const SIEM_CATCHUP_MINUTES = 60;
const SWEEP_BATCH = 500;
const SWEEP_INTERVAL_MS = 60_000;
const MIN_BACKOFF_MS = 1_000;
const MAX_BACKOFF_MS = 30_000;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

let active: pg.Client | null = null;
let backoffMs = MIN_BACKOFF_MS;
let reconnectTimer: NodeJS.Timeout | null = null;
let sweepTimer: NodeJS.Timeout | null = null;
let started = false;
let queue: Promise<void> = Promise.resolve();
let sweeping = false;

function log(msg: string, err?: unknown): void {
  // eslint-disable-next-line no-console
  if (err) console.error(`[SIEM] ${msg}`, (err as any)?.message ?? err);
  // eslint-disable-next-line no-console
  else console.log(`[SIEM] ${msg}`);
}

function enqueue(id: string): void {
  queue = queue.then(async () => { await forwardAuditEventById(id); }).catch((e) => log(`Failed to forward audit event ${id}:`, e));
}

/** Claim one audit event and forward it. Returns true when this process sent it. */
export async function forwardAuditEventById(id: string): Promise<boolean> {
  const configs = await getEnabledSiemConfigs();
  if (configs.length === 0) return false; // nothing to send to; leave the row unclaimed

  const { rows } = await pool.query(
    `WITH claimed AS (
       UPDATE audit_events SET siem_forwarded_at = now()
        WHERE id = $1 AND siem_forwarded_at IS NULL
        RETURNING actor_user_id, action, entity_type, entity_id, metadata
     )
     SELECT c.action, c.entity_type, c.entity_id, c.metadata, u.username AS actor_username
       FROM claimed c LEFT JOIN users u ON u.id = c.actor_user_id`,
    [id]
  );
  const row = rows[0];
  if (!row) return false; // already forwarded (by another replica, or the sweep)

  const result = await forwardAuditToSiem({
    action: row.action,
    actorUsername: row.actor_username ?? undefined,
    entityType: row.entity_type,
    entityId: String(row.entity_id),
    metadata: row.metadata && typeof row.metadata === 'object' ? row.metadata : undefined,
  });
  if (result.targets > 0 && result.sent === 0) {
    // Every collector failed: release the claim so the sweep retries within the catch-up window.
    await pool.query(`UPDATE audit_events SET siem_forwarded_at = NULL WHERE id = $1`, [id]);
    return false;
  }
  return result.sent > 0;
}

/** Forward unclaimed events from the last SIEM_CATCHUP_MINUTES (bounded). */
export async function sweepPendingAuditEvents(): Promise<number> {
  if (sweeping) return 0;
  sweeping = true;
  try {
    if ((await getEnabledSiemConfigs()).length === 0) return 0;
    const { rows } = await pool.query(
      `SELECT id FROM audit_events
        WHERE siem_forwarded_at IS NULL
          AND timestamp > now() - make_interval(mins => $1)
          AND timestamp < now() - interval '5 seconds'
        ORDER BY timestamp ASC
        LIMIT $2`,
      [SIEM_CATCHUP_MINUTES, SWEEP_BATCH]
    );
    let sent = 0;
    for (const r of rows) {
      // Run through the same queue as notifications so ordering/claims stay consistent.
      await new Promise<void>((resolve) => {
        queue = queue
          .then(async () => {
            if (await forwardAuditEventById(r.id)) sent++;
          })
          .catch((e) => log(`Failed to forward audit event ${r.id}:`, e))
          .finally(resolve);
      });
    }
    if (sent > 0) log(`Catch-up forwarded ${sent} pending audit event(s)`);
    return sent;
  } finally {
    sweeping = false;
  }
}

function scheduleReconnect(client: pg.Client): void {
  if (client !== active) return; // stale client, already handled
  active = null;
  client.removeAllListeners('notification');
  client.end().catch(() => {});
  if (reconnectTimer) return;
  const delay = backoffMs;
  backoffMs = Math.min(backoffMs * 2, MAX_BACKOFF_MS);
  log(`LISTEN connection lost; reconnecting in ${Math.round(delay / 1000)}s`);
  reconnectTimer = setTimeout(() => {
    reconnectTimer = null;
    void connect();
  }, delay);
}

async function connect(): Promise<void> {
  const client = new pg.Client({ connectionString: env.DATABASE_URL, keepAlive: true });
  active = client;
  client.on('notification', (msg) => {
    if (msg.channel === CHANNEL && msg.payload && UUID_RE.test(msg.payload)) enqueue(msg.payload);
  });
  client.on('error', (err) => {
    log('LISTEN connection error:', err);
    scheduleReconnect(client);
  });
  client.on('end', () => scheduleReconnect(client));
  try {
    await client.connect();
    await client.query(`LISTEN ${CHANNEL}`);
    backoffMs = MIN_BACKOFF_MS;
    log(`Listening for audit events (channel ${CHANNEL})`);
    // Pick up anything inserted while we were not listening.
    void sweepPendingAuditEvents().catch((e) => log('Catch-up sweep failed:', e));
  } catch (e) {
    log('Cannot start LISTEN connection:', e);
    scheduleReconnect(client);
  }
}

/** Start the audit -> SIEM forwarder (idempotent). */
export function startSiemAuditListener(): void {
  if (started) return;
  started = true;
  void connect();
  sweepTimer = setInterval(() => {
    // Health-check the LISTEN connection; a silently dead socket is ended so it reconnects.
    const c = active;
    if (c) {
      c.query('SELECT 1').catch(() => {
        c.end().catch(() => {});
      });
    }
    void sweepPendingAuditEvents().catch((e) => log('Catch-up sweep failed:', e));
  }, SWEEP_INTERVAL_MS);
  sweepTimer.unref();
}
