import { useEffect, useState } from 'react';

import { api, errorMessage } from '../lib/api';

const STATE: Record<string, { label: string; color: string; bg: string; help: string }> = {
  PROTECTED: { label: 'Protected', color: '#3f5a26', bg: '#eef4e8', help: 'Every assigned gateway was deployed after the assignment: forwarded traffic to the asset is default-denied there.' },
  PENDING_DEPLOY: { label: 'Deploy pending', color: '#8b6914', bg: '#fdf6ec', help: 'A gateway was assigned or the asset changed after the gateway\'s last deployment. Deploy the gateway.' },
  GATEWAY_NOT_DEPLOYED: { label: 'Gateway not deployed', color: '#a63d2f', bg: '#faf0ee', help: 'No assigned gateway has a policy deployed yet.' },
  NO_IP: { label: 'No IP address', color: '#a63d2f', bg: '#faf0ee', help: 'Without an IP address nothing can be enforced for the asset. Add it to the asset.' },
  NO_GATEWAY: { label: 'No gateway', color: '#a63d2f', bg: '#faf0ee', help: 'No gateway is assigned: nothing protects this asset.' },
};
const ORDER = ['NO_GATEWAY', 'NO_IP', 'GATEWAY_NOT_DEPLOYED', 'PENDING_DEPLOY', 'PROTECTED'];
const CRIT_COLOR: Record<string, string> = { critical: '#a63d2f', high: '#c47a1a', medium: '#8b6914', low: '#5a7a3a' };

export function StateBadge({ state }: { state: string }) {
  const s = STATE[state] ?? STATE.NO_GATEWAY;
  return <span title={s.help} style={{ display: 'inline-block', padding: '0 7px', borderRadius: 4, fontSize: '12px', color: s.color, background: s.bg, border: `1px solid ${s.color}33` }}>{s.label}</span>;
}

/** Protection coverage of the IoT/OT assets: state per asset, per zone, and what is allowed to reach each asset. */
export function IotCoverageTab() {
  const [data, setData] = useState<any>(null);
  const [error, setError] = useState('');
  const [filter, setFilter] = useState('');
  const [open, setOpen] = useState<string | null>(null);

  const load = async () => { try { setData(await api.iot.coverage()); } catch (e: any) { setError(errorMessage(e)); } };
  useEffect(() => { load(); }, []);
  if (error) return <div className="error-banner">{error}</div>;
  if (!data) return <div>Loading...</div>;

  const total = data.assets.length;
  const shown = data.assets.filter((a: any) => !filter || a.state === filter);
  const th = { textAlign: 'left' as const, padding: '6px 8px', background: '#f7f4ef', borderBottom: '1px solid #e0d6c6', fontSize: '12.5px' };
  const td = { padding: '6px 8px', borderBottom: '1px solid #eee7da', verticalAlign: 'top' as const, fontSize: '13px' };

  return (
    <>
      <p style={{ color: '#78644e', fontSize: '13px', lineHeight: 1.6, marginTop: 0 }}>
        Is something protecting each enabled asset, and what is allowed to reach it? This is derived from what Segmentra recorded (gateway assignments, the last successful
        deployment of each gateway and its FORWARD rules), not from a live check of the gateways.
      </p>
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', marginBottom: 14 }}>
        {ORDER.map((st) => (
          <button key={st} onClick={() => setFilter(filter === st ? '' : st)} title={STATE[st].help}
            style={{ textAlign: 'left', cursor: 'pointer', background: data.summary[st] > 0 && st !== 'PROTECTED' ? STATE[st].bg : '#f7f4ef', border: `1px solid ${filter === st ? STATE[st].color : '#e8e0d4'}`, borderRadius: 8, padding: '8px 12px', minWidth: 150 }}>
            <div style={{ fontSize: '20px', fontWeight: 600, color: data.summary[st] > 0 && st !== 'PROTECTED' ? STATE[st].color : '#3d2e1e' }}>{data.summary[st]}<span style={{ fontSize: '12px', color: '#97846c' }}> / {total}</span></div>
            <div style={{ fontSize: '12px', color: '#78644e' }}>{STATE[st].label}</div>
          </button>
        ))}
      </div>

      <div className="card">
        <h4 style={{ marginTop: 0 }}>Zones</h4>
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead><tr><th style={th}>Zone</th><th style={th}>Assets</th>{ORDER.map((s) => <th key={s} style={th}>{STATE[s].label}</th>)}</tr></thead>
          <tbody>
            {data.zones.map((z: any) => (
              <tr key={z.zone}>
                <td style={td}><strong>{z.zone}</strong></td><td style={td}>{z.assets}</td>
                {ORDER.map((s) => <td key={s} style={{ ...td, color: z[s] > 0 && s !== 'PROTECTED' ? '#a63d2f' : undefined, fontWeight: z[s] > 0 && s !== 'PROTECTED' ? 600 : undefined }}>{z[s] || ''}</td>)}
              </tr>
            ))}
            {data.zones.length === 0 && <tr><td style={td} colSpan={7}>No enabled IoT/OT assets.</td></tr>}
          </tbody>
        </table>
      </div>

      <div className="card">
        <h4 style={{ marginTop: 0 }}>Assets{filter ? ` (${STATE[filter].label})` : ''}</h4>
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead><tr><th style={th}>Asset</th><th style={th}>Criticality</th><th style={th}>Zone</th><th style={th}>IP</th><th style={th}>Status</th><th style={th}>Gateways</th><th style={th}>Allowed to reach it</th></tr></thead>
          <tbody>
            {shown.map((a: any) => (
              <tr key={a.id}>
                <td style={td}><strong>{a.name}</strong><div style={{ color: '#97846c', fontSize: '11.5px' }}>{a.assetType}{a.vendor ? ` · ${a.vendor}` : ''}</div></td>
                <td style={{ ...td, color: CRIT_COLOR[a.criticality], fontWeight: 600 }}>{a.criticality}</td>
                <td style={td}>{a.zone || '-'}</td>
                <td style={td}><code>{a.ip || '-'}</code></td>
                <td style={td}><StateBadge state={a.state} /></td>
                <td style={td}>{a.gateways.length ? a.gateways.map((g: any) => <div key={g.id} style={{ fontSize: '12px' }}>{g.hostname} <span style={{ color: g.status === 'deployed' ? '#3f5a26' : g.status === 'pending' ? '#8b6914' : '#a63d2f' }}>({g.status.replace('_', ' ')})</span></div>) : '-'}</td>
                <td style={td}>
                  {a.rules.length === 0 ? <span style={{ color: '#97846c' }}>{a.state === 'PROTECTED' ? 'nothing (default deny)' : '-'}</span> : (
                    <>
                      <button className="btn-small btn-secondary" onClick={() => setOpen(open === a.id ? null : a.id)}>{a.rules.length} rule{a.rules.length > 1 ? 's' : ''}{open === a.id ? ' ▲' : ' ▼'}</button>
                      {a.cleartextAllowed.length > 0 && <div style={{ color: '#8b5a14', fontSize: '11.5px', marginTop: 2 }}>cleartext: {a.cleartextAllowed.join(', ')}</div>}
                      {open === a.id && (
                        <ul style={{ margin: '6px 0 0 16px', padding: 0, fontSize: '12px' }}>
                          {a.rules.map((r: any, i: number) => (
                            <li key={i}><strong style={{ color: r.action === 'ALLOW' ? '#3f5a26' : '#a63d2f' }}>{r.action}</strong> {r.protocol}{r.ports ? `/${r.ports}` : ''}{r.services.length ? ` (${r.services.join(', ')})` : ''} from <code>{r.from}</code> <span style={{ color: '#97846c' }}>via {r.gateway}, {r.policySet} v{r.version}</span></li>
                          ))}
                        </ul>
                      )}
                    </>
                  )}
                </td>
              </tr>
            ))}
            {shown.length === 0 && <tr><td style={td} colSpan={7}>No assets{filter ? ' in this state' : ''}.</td></tr>}
          </tbody>
        </table>
      </div>
    </>
  );
}
