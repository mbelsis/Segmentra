import { useEffect, useState } from 'react';

import { api } from '../lib/api';

export function DashboardPage() {
  const [deployments, setDeployments] = useState<any[]>([]);
  const [me, setMe] = useState<any>(null);

  useEffect(() => {
    api.me().then(setMe).catch(() => undefined);
    api.deployments().then((r) => setDeployments(r.deployments.slice(0, 10))).catch(() => undefined);
  }, []);

  return (
    <div style={{ display: 'grid', gap: 12 }}>
      <div>
        <h2>Dashboard</h2>
        <div style={{ opacity: 0.8, fontSize: 13 }}>
          Logged in as: <code>{me?.user?.username ?? 'unknown'}</code>
        </div>
      </div>
      <div>
        <h3>Recent deployments</h3>
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Status</th>
              <th>Mode</th>
              <th>Targets</th>
            </tr>
          </thead>
          <tbody>
            {deployments.map((d) => (
              <tr key={d.id}>
                <td>
                  <code>{String(d.id).slice(0, 8)}</code>
                </td>
                <td>{d.status}</td>
                <td>{d.mode}</td>
                <td>{d.target_count}</td>
              </tr>
            ))}
            {deployments.length === 0 ? (
              <tr>
                <td colSpan={4} style={{ opacity: 0.7 }}>
                  No deployments yet.
                </td>
              </tr>
            ) : null}
          </tbody>
        </table>
      </div>
    </div>
  );
}


