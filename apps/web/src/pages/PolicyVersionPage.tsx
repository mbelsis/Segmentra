import { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';

import { api } from '../lib/api';

export function PolicyVersionPage() {
  const { versionId } = useParams();
  const [rules, setRules] = useState<any[]>([]);
  const [orderIndex, setOrderIndex] = useState(0);
  const [cidr, setCidr] = useState('10.0.0.0/24');
  const [action, setAction] = useState<'ALLOW' | 'DENY'>('ALLOW');
  const [direction, setDirection] = useState<'IN' | 'OUT' | 'BOTH'>('IN');
  const [hostId, setHostId] = useState('');
  const [rendered, setRendered] = useState<string>('');

  useEffect(() => {
    if (!versionId) return;
    api.rules(versionId).then((r) => setRules(r.rules)).catch(() => undefined);
  }, [versionId]);

  if (!versionId) return <div>Missing versionId</div>;

  return (
    <div style={{ display: 'grid', gap: 12 }}>
      <h2>Policy Version</h2>
      <div style={{ display: 'flex', gap: 8, alignItems: 'flex-end', flexWrap: 'wrap' }}>
        <label>
          Order
          <input type="number" value={orderIndex} onChange={(e) => setOrderIndex(Number(e.target.value))} />
        </label>
        <label>
          Direction
          <select value={direction} onChange={(e) => setDirection(e.target.value as any)}>
            <option value="IN">IN</option>
            <option value="OUT">OUT</option>
            <option value="BOTH">BOTH</option>
          </select>
        </label>
        <label>
          Action
          <select value={action} onChange={(e) => setAction(e.target.value as any)}>
            <option value="ALLOW">ALLOW</option>
            <option value="DENY">DENY</option>
          </select>
        </label>
        <label>
          CIDR
          <input value={cidr} onChange={(e) => setCidr(e.target.value)} />
        </label>
        <button
          onClick={async () => {
            const r = await api.addRule(versionId, {
              orderIndex,
              direction,
              action,
              protocol: 'tcp',
              ports: '22',
              sourceType: 'CIDR',
              sourceValue: cidr,
              logMode: 'NONE',
              usePolicyInterfaceScope: true
            });
            setRules((prev) => [...prev, r.rule]);
          }}
        >
          Add rule
        </button>
        <button onClick={() => api.submitApproval(versionId)}>Submit for approval</button>
      </div>

      <div>
        <h3>Rules</h3>
        <table>
          <thead>
            <tr>
              <th>#</th>
              <th>Dir</th>
              <th>Action</th>
              <th>Proto</th>
              <th>Ports</th>
              <th>Source</th>
            </tr>
          </thead>
          <tbody>
            {rules.map((r) => (
              <tr key={r.id}>
                <td>{r.order_index}</td>
                <td>{r.direction}</td>
                <td>{r.action}</td>
                <td>{r.protocol}</td>
                <td>{r.ports}</td>
                <td>
                  {r.source_type}:{r.source_value}
                </td>
              </tr>
            ))}
            {rules.length === 0 ? (
              <tr>
                <td colSpan={6} style={{ opacity: 0.7 }}>
                  No rules yet.
                </td>
              </tr>
            ) : null}
          </tbody>
        </table>
      </div>

      <div style={{ display: 'grid', gap: 8 }}>
        <h3>Render preview (host)</h3>
        <label>
          Host ID
          <input value={hostId} onChange={(e) => setHostId(e.target.value)} placeholder="paste host UUID" />
        </label>
        <button
          onClick={async () => {
            const r = await api.render(versionId, hostId);
            setRendered(r.text);
          }}
          disabled={!hostId}
        >
          Render
        </button>
        <textarea value={rendered} readOnly rows={12} />
      </div>
    </div>
  );
}


