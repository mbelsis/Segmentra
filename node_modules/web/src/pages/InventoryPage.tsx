import { useEffect, useState } from 'react';

import { api } from '../lib/api';

export function InventoryPage() {
  const [hosts, setHosts] = useState<any[]>([]);
  const [hostname, setHostname] = useState('');
  const [mgmtIp, setMgmtIp] = useState('');

  useEffect(() => {
    api.hosts().then((r) => setHosts(r.hosts)).catch(() => undefined);
  }, []);

  return (
    <div style={{ display: 'grid', gap: 12 }}>
      <h2>Inventory</h2>

      <div style={{ display: 'flex', gap: 8, alignItems: 'flex-end' }}>
        <label>
          Hostname
          <input value={hostname} onChange={(e) => setHostname(e.target.value)} />
        </label>
        <label>
          Mgmt IP
          <input value={mgmtIp} onChange={(e) => setMgmtIp(e.target.value)} />
        </label>
        <button
          onClick={async () => {
            const r = await api.createHost({ hostname, mgmtIp });
            setHosts((prev) => [...prev, r.host]);
            setHostname('');
            setMgmtIp('');
          }}
        >
          Add host
        </button>
      </div>

      <table>
        <thead>
          <tr>
            <th>Hostname</th>
            <th>Mgmt IP</th>
            <th>Backend</th>
            <th>Enabled</th>
          </tr>
        </thead>
        <tbody>
          {hosts.map((h) => (
            <tr key={h.id}>
              <td>{h.hostname}</td>
              <td>{h.mgmt_ip}</td>
              <td>{h.firewall_backend}</td>
              <td>{String(h.enabled)}</td>
            </tr>
          ))}
          {hosts.length === 0 ? (
            <tr>
              <td colSpan={4} style={{ opacity: 0.7 }}>
                No hosts found.
              </td>
            </tr>
          ) : null}
        </tbody>
      </table>
    </div>
  );
}


