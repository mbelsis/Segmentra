export interface ReadinessRefusal {
  deploymentId: string;
  code: 'readiness_blocked' | 'readiness_notes';
  hosts: Array<{ hostname: string; messages: string[] }>;
}

/** Turns a refused start into dialog state; null when the error is something else. */
export function readinessRefusal(deploymentId: string, code: string | undefined, body: unknown): ReadinessRefusal | null {
  const b = (body ?? {}) as { blocked?: ReadinessRefusal['hosts']; notes?: ReadinessRefusal['hosts'] };
  if (code === 'readiness_blocked') return { deploymentId, code, hosts: b.blocked ?? [] };
  if (code === 'readiness_notes') return { deploymentId, code, hosts: b.notes ?? [] };
  return null;
}
