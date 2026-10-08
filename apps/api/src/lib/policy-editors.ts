type Queryable = { query: (text: string, params?: any[]) => Promise<any> };

/**
 * Record that a user changed the content of a policy version (created/cloned it or edited rules).
 * Used for separation of duties: editors may not approve the version. Requires migration 025.
 */
export async function recordPolicyVersionEditor(db: Queryable, policyVersionId: string, userId: string | null | undefined) {
  if (!userId) return;
  await db.query(
    `INSERT INTO policy_version_editors (policy_version_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
    [policyVersionId, userId]
  );
}

export const EDITABLE_VERSION_STATUSES = ['DRAFT', 'REJECTED'];
