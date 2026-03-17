import type { ReactNode } from 'react';
import { useAuth, hasRole } from '../lib/auth-context';

export function RequireRole({ roles, children }: { roles: string[]; children: ReactNode }) {
  const { roles: userRoles, loading } = useAuth();

  if (loading) return <div>Loading...</div>;

  if (!hasRole(userRoles, ...roles)) {
    return (
      <div style={{ padding: 40, textAlign: 'center' }}>
        <h3 style={{ color: '#a63d2f' }}>Access Denied</h3>
        <p style={{ color: '#78644e' }}>You don't have permission to access this page. Contact your administrator if you need access.</p>
        <p style={{ color: '#97846c', fontSize: '13px' }}>Required role: {roles.join(' or ')}</p>
      </div>
    );
  }

  return <>{children}</>;
}
