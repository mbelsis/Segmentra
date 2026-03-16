import { NavLink, Outlet, useNavigate } from 'react-router-dom';

import { clearToken } from '../lib/auth';

export function AppShell() {
  const navigate = useNavigate();
  return (
    <div className="appShell">
      <nav className="nav">
        <div style={{ marginBottom: 16, textAlign: 'center' }}>
          <img src="/segmentra.png" alt="Segmentra" style={{ maxWidth: '115%', height: 'auto', marginBottom: 8, marginLeft: '-7.5%' }} />
        </div>
        <NavLink to="/" end>
          Dashboard
        </NavLink>
        <NavLink to="/inventory">Inventory</NavLink>
        <NavLink to="/policies">Policy Sets</NavLink>
        <NavLink to="/policy-templates">Templates</NavLink>
        <NavLink to="/topology">Topology</NavLink>
        <NavLink to="/approvals">Approvals</NavLink>
        <NavLink to="/deployments">Deployments</NavLink>
        <NavLink to="/policy-testing">Policy Testing</NavLink>
        <NavLink to="/troubleshoot">Troubleshoot</NavLink>
        <NavLink to="/integrations">Integrations</NavLink>
        <NavLink to="/kubernetes">Kubernetes</NavLink>
        <NavLink to="/iot">OT/IoT</NavLink>
        <NavLink to="/audit">Audit</NavLink>
        <NavLink to="/admin">Admin</NavLink>
        <div style={{ 
          marginTop: 'auto', 
          paddingTop: 16, 
          borderTop: '1px solid #e0e0e0'
        }}>
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
            fontSize: '0.75em', 
            color: '#666'
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



