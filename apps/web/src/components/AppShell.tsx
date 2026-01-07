import { NavLink, Outlet, useNavigate } from 'react-router-dom';

import { clearToken } from '../lib/auth';

export function AppShell() {
  const navigate = useNavigate();
  return (
    <div className="appShell">
      <nav className="nav">
        <div style={{ fontWeight: 700, marginBottom: 8 }}>Segmentra</div>
        <NavLink to="/" end>
          Dashboard
        </NavLink>
        <NavLink to="/inventory">Inventory</NavLink>
        <NavLink to="/policies">Policy Sets</NavLink>
        <NavLink to="/approvals">Approvals</NavLink>
        <NavLink to="/deployments">Deployments</NavLink>
        <NavLink to="/audit">Audit</NavLink>
        <NavLink to="/admin">Admin</NavLink>
        <div style={{ marginTop: 12 }}>
          <button
            onClick={() => {
              clearToken();
              navigate('/login');
            }}
          >
            Logout
          </button>
        </div>
      </nav>
      <main className="card">
        <Outlet />
      </main>
    </div>
  );
}


