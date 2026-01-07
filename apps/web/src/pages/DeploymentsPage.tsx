import { useEffect, useState } from 'react';

import { api } from '../lib/api';

export function DeploymentsPage() {
  const [deployments, setDeployments] = useState<any[]>([]);
  const [policyVersionId, setPolicyVersionId] = useState('');
  const [hostId, setHostId] = useState('');
  const [createdId, setCreatedId] = useState<string>('');
  const [hosts, setHosts] = useState<any[]>([]);

  useEffect(() => {
    api.deployments().then((r) => setDeployments(r.deployments)).catch(() => undefined);
  }, []);

  return (
    <div style={{ display: 'grid', gap: 12 }}>
      <h2>Deployments</h2>

      <div style={{ display: 'grid', gap: 8 }}>
        <div style={{ fontWeight: 600 }}>Create deployment (v1: HOST target)</div>
        <label>
          Policy version ID
          <input value={policyVersionId} onChange={(e) => setPolicyVersionId(e.target.value)} />
        </label>
        <label>
          Host ID
          <input value={hostId} onChange={(e) => setHostId(e.target.value)} />
        </label>
        <button
          disabled={!policyVersionId || !hostId}
          onClick={async () => {
            const d = await api.createDeployment({
              policyVersionId,
              mode: 'FULL',
              targetQuery: { hosts: [hostId], tags: [], vlans: [] }
            });
            setCreatedId(d.deployment.id);
            setDeployments((prev) => [d.deployment, ...prev]);
          }}
        >
          Create
        </button>

        {createdId ? (
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <div>
              Created: <code>{createdId}</code>
            </div>
            <button
              onClick={async () => {
                await api.startDeployment(createdId);
                const r = await api.deploymentHosts(createdId);
                setHosts(r.hosts);
              }}
            >
              Start
            </button>
          </div>
        ) : null}
      </div>

      {hosts.length ? (
        <div>
          <h3>Deployment hosts</h3>
          <table>
            <thead>
              <tr>
                <th>Host</th>
                <th>Status</th>
                <th>Message</th>
              </tr>
            </thead>
            <tbody>
              {hosts.map((h) => (
                <tr key={h.host_id}>
                  <td>{h.hostname}</td>
                  <td>{h.status}</td>
                  <td>{h.message}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}

      <div>
        <h3>All deployments</h3>
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


