import { useEffect, useState } from 'react';

import { api } from '../lib/api';

export function AuditPage() {
  const [events, setEvents] = useState<any[]>([]);

  useEffect(() => {
    api.audit().then((r) => setEvents(r.events)).catch(() => undefined);
  }, []);

  return (
    <div style={{ display: 'grid', gap: 12 }}>
      <h2>Audit</h2>
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Actor</th>
            <th>Action</th>
            <th>Entity</th>
          </tr>
        </thead>
        <tbody>
          {events.map((e) => (
            <tr key={e.id}>
              <td>{e.timestamp}</td>
              <td>{e.actor_username ?? ''}</td>
              <td>{e.action}</td>
              <td>
                {e.entity_type}:{String(e.entity_id).slice(0, 8)}
              </td>
            </tr>
          ))}
          {events.length === 0 ? (
            <tr>
              <td colSpan={4} style={{ opacity: 0.7 }}>
                No audit events yet.
              </td>
            </tr>
          ) : null}
        </tbody>
      </table>
    </div>
  );
}


