import { NavLink, Outlet, useNavigate } from 'react-router-dom';

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

  return (
    <div className="appShell">
      <nav className="nav">
        <div style={{ marginBottom: 12, textAlign: 'center' }}>
          <img src="/segmentra.png" alt="Segmentra" style={{ maxWidth: '115%', height: 'auto', marginBottom: 4, marginLeft: '-7.5%' }} />
        </div>

        <NavLink to="/" end>Dashboard</NavLink>

        {sectionLabel('Policies')}
        <NavLink to="/policies">Policy Sets</NavLink>
        <NavLink to="/policy-templates">Templates</NavLink>
        {isApprover && <NavLink to="/approvals">Approvals</NavLink>}
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
