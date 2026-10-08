import { Router } from 'express';
import { z } from 'zod';

import { pool } from '../../db/pool.js';
import { requireAuth, requireRole } from '../../middleware/auth.js';
import { createAuditEvent } from '../../services/audit.js';
import {
  DiscoveryAlreadyRunningError,
  MAX_ADDRESSES_PER_RUN,
  resolveTargets,
  startDiscoveryRun,
  type DiscoveryTargetInput
} from '../../services/discovery.js';

/**
 * Automated inventory discovery (mounted at /api/discovery).
 *   Profiles: admin only (they reference SSH credentials).
 *   Run now:  operator, admin.
 *   Read:     viewer and above.
 */
export const discoveryRouter = Router();
discoveryRouter.use(requireAuth);

const READ_ROLES = ['viewer', 'operator', 'approver', 'admin'];

const uuid = z.string().uuid();

const targetSchema = z.object({
  sshCredentialId: uuid,
  sshPort: z.number().int().min(1).max(65535).default(22),
  cidrs: z.array(z.string().trim().min(1).max(64)).max(64).default([]),
  vlanIds: z.array(uuid).max(64).default([])
});

const profileSchema = z.object({
  name: z.string().trim().min(1).max(100),
  enabled: z.boolean().default(true),
  /** null = manual only */
  scheduleIntervalMinutes: z.number().int().min(1).max(525600).nullable().default(null),
  defaultTagName: z.string().trim().min(1).max(100).default('new-server'),
  targets: z.array(targetSchema).min(1, 'add at least one target set').max(20)
});

/** Profiles with their target sets and latest run summary. */
async function loadProfiles(id?: string) {
  const { rows } = await pool.query(
    `SELECT p.*, u.username AS created_by_username,
            COALESCE((
              SELECT json_agg(json_build_object(
                       'id', t.id, 'sshCredentialId', t.ssh_credential_id, 'sshCredentialName', c.name,
                       'sshCredentialUsername', c.username, 'sshCredentialAuthMethod', c.auth_method,
                       'sshCredentialSudoMode', c.sudo_mode,
                       'sshPort', t.ssh_port, 'cidrs', t.cidrs, 'vlanIds', t.vlan_ids
                     ) ORDER BY t.position, t.created_at)
                FROM discovery_targets t JOIN ssh_credentials c ON c.id = t.ssh_credential_id
               WHERE t.profile_id = p.id), '[]'::json) AS targets,
            (SELECT row_to_json(r) FROM (
               SELECT id, trigger, status, started_at, finished_at, addresses_scanned, ssh_open, login_ok,
                      imported, already_present, login_failed, error
                 FROM discovery_runs WHERE profile_id = p.id ORDER BY started_at DESC LIMIT 1) r) AS last_run
       FROM discovery_profiles p
       LEFT JOIN users u ON u.id = p.created_by
      ${id ? 'WHERE p.id = $1' : ''}
      ORDER BY p.name`,
    id ? [id] : []
  );
  return rows;
}

discoveryRouter.get('/profiles', requireRole(...READ_ROLES), async (_req, res) => {
  res.json({ profiles: await loadProfiles(), limits: { maxAddressesPerRun: MAX_ADDRESSES_PER_RUN, minPrefix: 20 } });
});

discoveryRouter.get('/profiles/:id', requireRole(...READ_ROLES), async (req, res) => {
  if (!uuid.safeParse(req.params.id).success) return res.status(404).json({ error: 'not_found' });
  const [profile] = await loadProfiles(req.params.id);
  if (!profile) return res.status(404).json({ error: 'not_found' });
  res.json({ profile });
});

async function validateTargetsOr400(targets: DiscoveryTargetInput[], res: any): Promise<{ uniqueAddressCount: number } | null> {
  const { problems, uniqueAddressCount } = await resolveTargets(targets, { strictVlans: true });
  if (problems.length) {
    res.status(400).json({ error: 'invalid_targets', message: 'Invalid discovery targets', details: problems.map((p) => ({ message: p })) });
    return null;
  }
  return { uniqueAddressCount };
}

async function writeTargets(client: any, profileId: string, targets: DiscoveryTargetInput[]) {
  await client.query(`DELETE FROM discovery_targets WHERE profile_id = $1`, [profileId]);
  for (const [i, t] of targets.entries()) {
    await client.query(
      `INSERT INTO discovery_targets (profile_id, position, ssh_credential_id, ssh_port, cidrs, vlan_ids)
       VALUES ($1, $2, $3, $4, $5::text[], $6::uuid[])`,
      [profileId, i, t.sshCredentialId, t.sshPort, t.cidrs.map((c) => c.trim()), [...new Set(t.vlanIds)]]
    );
  }
}

discoveryRouter.post('/profiles', requireRole('admin'), async (req, res) => {
  const parsed = profileSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body', details: parsed.error.issues });
  const b = parsed.data;
  const v = await validateTargetsOr400(b.targets, res);
  if (!v) return;

  const client = await pool.connect();
  let id: string;
  try {
    await client.query('BEGIN');
    const { rows } = await client.query(
      `INSERT INTO discovery_profiles (name, enabled, schedule_interval_minutes, default_tag_name, next_run_at, created_by)
       VALUES ($1, $2, $3::int, $4,
               CASE WHEN $3::int IS NULL THEN NULL ELSE now() + make_interval(mins => $3::int) END, $5)
       RETURNING id`,
      [b.name, b.enabled, b.scheduleIntervalMinutes, b.defaultTagName, req.auth!.userId]
    );
    id = rows[0].id;
    await writeTargets(client, id, b.targets);
    await client.query('COMMIT');
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    throw e;
  } finally {
    client.release();
  }

  await createAuditEvent({
    actorUserId: req.auth!.userId,
    action: 'DISCOVERY_PROFILE_CREATE',
    entityType: 'discovery_profile',
    entityId: id,
    ipAddress: req.ip,
    metadata: { name: b.name, scheduleIntervalMinutes: b.scheduleIntervalMinutes, targetSets: b.targets.length, addresses: v.uniqueAddressCount }
  });
  const [profile] = await loadProfiles(id);
  res.status(201).json({ profile });
});

discoveryRouter.put('/profiles/:id', requireRole('admin'), async (req, res) => {
  if (!uuid.safeParse(req.params.id).success) return res.status(404).json({ error: 'not_found' });
  const parsed = profileSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body', details: parsed.error.issues });
  const b = parsed.data;
  const v = await validateTargetsOr400(b.targets, res);
  if (!v) return;

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    // Recompute next_run_at only when the schedule changes or the profile is (re-)enabled.
    const { rows } = await client.query(
      `UPDATE discovery_profiles p
          SET name = $2, enabled = $3, schedule_interval_minutes = $4::int, default_tag_name = $5, updated_at = now(),
              next_run_at = CASE
                WHEN $4::int IS NULL THEN NULL
                WHEN p.schedule_interval_minutes IS DISTINCT FROM $4::int OR p.next_run_at IS NULL OR (NOT p.enabled AND $3)
                  THEN now() + make_interval(mins => $4::int)
                ELSE p.next_run_at END
        WHERE p.id = $1
        RETURNING p.id`,
      [req.params.id, b.name, b.enabled, b.scheduleIntervalMinutes, b.defaultTagName]
    );
    if (!rows[0]) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'not_found' });
    }
    await writeTargets(client, req.params.id, b.targets);
    await client.query('COMMIT');
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    throw e;
  } finally {
    client.release();
  }

  await createAuditEvent({
    actorUserId: req.auth!.userId,
    action: 'DISCOVERY_PROFILE_UPDATE',
    entityType: 'discovery_profile',
    entityId: req.params.id,
    ipAddress: req.ip,
    metadata: { name: b.name, enabled: b.enabled, scheduleIntervalMinutes: b.scheduleIntervalMinutes, targetSets: b.targets.length, addresses: v.uniqueAddressCount }
  });
  const [profile] = await loadProfiles(req.params.id);
  res.json({ profile });
});

discoveryRouter.delete('/profiles/:id', requireRole('admin'), async (req, res) => {
  if (!uuid.safeParse(req.params.id).success) return res.status(404).json({ error: 'not_found' });
  const { rows: running } = await pool.query(
    `SELECT 1 FROM discovery_runs WHERE profile_id = $1 AND status = 'RUNNING' LIMIT 1`,
    [req.params.id]
  );
  if (running[0]) return res.status(409).json({ error: 'discovery_running', message: 'A run of this profile is in progress. Wait for it to finish before deleting.' });
  const { rows } = await pool.query(`DELETE FROM discovery_profiles WHERE id = $1 RETURNING name`, [req.params.id]);
  if (!rows[0]) return res.status(404).json({ error: 'not_found' });
  await createAuditEvent({
    actorUserId: req.auth!.userId,
    action: 'DISCOVERY_PROFILE_DELETE',
    entityType: 'discovery_profile',
    entityId: req.params.id,
    ipAddress: req.ip,
    metadata: { name: rows[0].name }
  });
  res.json({ ok: true });
});

discoveryRouter.post('/profiles/:id/run', requireRole('operator', 'admin'), async (req, res) => {
  if (!uuid.safeParse(req.params.id).success) return res.status(404).json({ error: 'not_found' });
  const { rows } = await pool.query(`SELECT id, name FROM discovery_profiles WHERE id = $1`, [req.params.id]);
  if (!rows[0]) return res.status(404).json({ error: 'not_found' });
  try {
    const { runId } = await startDiscoveryRun(req.params.id, 'manual', req.auth!.userId);
    await createAuditEvent({
      actorUserId: req.auth!.userId,
      action: 'DISCOVERY_RUN_START',
      entityType: 'discovery_run',
      entityId: runId,
      ipAddress: req.ip,
      metadata: { profileId: req.params.id, profileName: rows[0].name, trigger: 'manual' }
    });
    res.status(202).json({ runId, status: 'RUNNING' });
  } catch (e) {
    if (e instanceof DiscoveryAlreadyRunningError) {
      return res.status(409).json({ error: 'discovery_running', message: 'A run of this profile is already in progress.' });
    }
    throw e;
  }
});

const RUN_SUMMARY_COLUMNS = `r.id, r.profile_id, r.trigger, r.status, r.started_at, r.finished_at, r.addresses_scanned, r.ssh_open,
  r.login_ok, r.imported, r.already_present, r.login_failed, r.error, u.username AS created_by_username`;

discoveryRouter.get('/profiles/:id/runs', requireRole(...READ_ROLES), async (req, res) => {
  if (!uuid.safeParse(req.params.id).success) return res.status(404).json({ error: 'not_found' });
  const limit = Math.min(200, Math.max(1, parseInt(String(req.query.limit ?? '20'), 10) || 20));
  const { rows } = await pool.query(
    `SELECT ${RUN_SUMMARY_COLUMNS}
       FROM discovery_runs r LEFT JOIN users u ON u.id = r.created_by
      WHERE r.profile_id = $1
      ORDER BY r.started_at DESC
      LIMIT $2`,
    [req.params.id, limit]
  );
  res.json({ runs: rows });
});

discoveryRouter.get('/runs/:runId', requireRole(...READ_ROLES), async (req, res) => {
  if (!uuid.safeParse(req.params.runId).success) return res.status(404).json({ error: 'not_found' });
  const { rows } = await pool.query(
    `SELECT ${RUN_SUMMARY_COLUMNS}, r.results, p.name AS profile_name
       FROM discovery_runs r
       JOIN discovery_profiles p ON p.id = r.profile_id
       LEFT JOIN users u ON u.id = r.created_by
      WHERE r.id = $1`,
    [req.params.runId]
  );
  if (!rows[0]) return res.status(404).json({ error: 'not_found' });
  res.json({ run: rows[0] });
});
