import { pool } from '../db/pool.js';

export interface AuditEventParams {
  actorUserId: string | null;
  action: string;
  entityType: string;
  entityId: string;
  ipAddress?: string;
  metadata?: Record<string, any>;
}

export async function createAuditEvent(params: AuditEventParams): Promise<void> {
  await pool.query(
    `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, ip_address, metadata)
     VALUES ($1, $2, $3, $4, $5, $6::jsonb)`,
    [
      params.actorUserId,
      params.action,
      params.entityType,
      params.entityId,
      params.ipAddress || null,
      params.metadata || null
    ]
  );
}
