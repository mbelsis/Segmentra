import { pool } from '../db/pool.js';
export async function createAuditEvent(params) {
    await pool.query(`INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, ip_address, metadata)
     VALUES ($1, $2, $3, $4, $5, $6::jsonb)`, [
        params.actorUserId,
        params.action,
        params.entityType,
        params.entityId,
        params.ipAddress || null,
        params.metadata || null
    ]);
}
