import { useEffect, useState } from 'react';
import { NavLink, Outlet, useNavigate } from 'react-router-dom';

import { api } from '../lib/api';
import { clearToken } from '../lib/auth';
import { useAuth, hasRole } from '../lib/auth-context';

const sectionLabel = (text: string) => (
  <div style={{
    fontSize: '10px',
    fontWeight: 700,
    textTransform: 'uppercase',
    letterSpacing: '0.06em',
    color: '#97846c',
    padding: '12px 12px 4px',
    marginTop: 4,
    borderTop: '1px solid #e8e0d4',
  }}>
    {text}
  </div>
);

export function AppShell() {
  const navigate = useNavigate();
  const { username, roles } = useAuth();

  const isViewer = hasRole(roles, 'viewer', 'operator', 'approver', 'admin');
  const isOperator = hasRole(roles, 'operator', 'admin');
  const isApprover = hasRole(roles, 'approver', 'admin');
  const isAdmin = hasRole(roles, 'admin');

  // Counters in the menu: versions waiting for my decision (approvers) and my versions that were rejected (authors).
  const [pendingCount, setPendingCount] = useState(0);
  const [rejectedCount, setRejectedCount] = useState(0);
  useEffect(() => {
    let alive = true;
    const load = () => {
      if (isApprover) api.pendingApprovals().then((r) => { if (alive) setPendingCount(r.versions.length); }).catch(() => {});
      if (isOperator) api.myApprovalRequests().then((r) => { if (alive) setRejectedCount(r.requests.filter((x: any) => x.status === 'REJECTED').length); }).catch(() => {});
    };
    load();
    const t = setInterval(load, 30000);
    return () => { alive = false; clearInterval(t); };
  }, [isApprover, isOperator]);

  return (
    <div className="appShell">
      <nav className="nav">
        <div style={{ marginBottom: 12, textAlign: 'center' }}>
          <img src="/segmentra-mark.png" alt="Segmentra" style={{ width: 60, height: 'auto', display: 'inline-block', margin: '4px 0 6px' }} />
        </div>

        <NavLink to="/" end>Dashboard</NavLink>

        {sectionLabel('Policies')}
        <NavLink to="/policies">Policy Sets{rejectedCount > 0 && <span className="nav-badge nav-badge-warn" title="Policy versions of yours that were rejected">{rejectedCount}</span>}</NavLink>
        <NavLink to="/policy-templates">Templates</NavLink>
        {isApprover && <NavLink to="/approvals">Approvals{pendingCount > 0 && <span className="nav-badge" title="Versions waiting for review">{pendingCount}</span>}</NavLink>}
        {isViewer && <NavLink to="/deployments">Deployments</NavLink>}

        {sectionLabel('Infrastructure')}
        <NavLink to="/inventory">Inventory</NavLink>
        {isOperator && <NavLink to="/topology">Topology</NavLink>}

        {sectionLabel('Analysis')}
        <NavLink to="/troubleshoot">Troubleshoot</NavLink>
        {(isOperator || isApprover) && <NavLink to="/policy-testing">Policy Impact Analysis</NavLink>}

        {sectionLabel('Extended')}
        <NavLink to="/kubernetes">Kubernetes</NavLink>
        <NavLink to="/iot">OT/IoT</NavLink>

        <NavLink to="/security-audit">Security Audit</NavLink>
        <NavLink to="/compliance-report">Compliance Report</NavLink>
        <NavLink to="/audit">Audit Log</NavLink>

        {isAdmin && (
          <>
            {sectionLabel('Settings')}
            <NavLink to="/integrations">Integrations</NavLink>
            <NavLink to="/notifications">Notifications</NavLink>
            <NavLink to="/admin">Admin</NavLink>
          </>
        )}

        <div style={{
          marginTop: 'auto',
          paddingTop: 16,
          borderTop: '1px solid #e8e0d4'
        }}>
          {username && (
            <div style={{ textAlign: 'center', fontSize: '12px', color: '#5c4633', marginBottom: 8 }}>
              <strong>{username}</strong>
              <div style={{ fontSize: '11px', color: '#97846c' }}>
                {roles.join(', ')}
              </div>
            </div>
          )}
          <div style={{ marginBottom: 12 }}>
            <button
              onClick={() => {
                clearToken();
                navigate('/login');
              }}
            >
              Logout
            </button>
          </div>
          <div style={{
            textAlign: 'center',
            fontSize: '0.85em',
            color: '#97846c'
          }}>
            © Belsis Meletis
          </div>
        </div>
      </nav>
      <main className="card">
        <Outlet />
      </main>
    </div>
  );
}
