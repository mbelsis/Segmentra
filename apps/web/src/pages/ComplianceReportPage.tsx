import { useEffect, useState } from 'react';

import { api, errorMessage } from '../lib/api';
import { useAuth, hasRole } from '../lib/auth-context';

const FRAMEWORKS = [
  { id: 'pci-dss-4', label: 'PCI DSS v4.0' },
  { id: 'iso-27001-2022', label: 'ISO/IEC 27001:2022' },
  { id: 'soc2', label: 'SOC 2' },
  { id: 'hipaa', label: 'HIPAA Security Rule' },
];
const STATUS_STYLE: Record<string, { color: string; bg: string; label: string }> = {
  evidence: { color: '#3f5a26', bg: '#eef4e8', label: 'Evidence' },
  attention: { color: '#a63d2f', bg: '#faf0ee', label: 'Attention' },
  gap: { color: '#6b5a45', bg: '#f0ebe2', label: 'Not covered' },
  ok: { color: '#3f5a26', bg: '#eef4e8', label: 'OK' },
  info: { color: '#5c4633', bg: '#f7f4ef', label: 'Info' },
};
const CSV_LABELS: Record<string, string> = {
  controls: 'Controls', metrics: 'Measurements', hosts: 'Hosts', changes: 'Changes', deployment_failures: 'Deployment failures',
  users_inactive: 'Inactive users', credentials: 'SSH credentials', iot_assets: 'IoT assets', audit_events: 'Audit events (full list)',
};

const isoDay = (d: Date) => d.toISOString().slice(0, 10);

function Badge({ status }: { status: string }) {
  const s = STATUS_STYLE[status] ?? STATUS_STYLE.info;
  return <span style={{ display: 'inline-block', padding: '0 7px', borderRadius: 4, fontSize: '12px', color: s.color, background: s.bg, border: `1px solid ${s.color}33` }}>{s.label}</span>;
}

function save(text: string, filename: string, type: string) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export function ComplianceReportPage() {
  const { roles } = useAuth();
  const canGenerate = hasRole(roles, 'operator', 'approver', 'admin');
  const canLiveDrift = hasRole(roles, 'operator', 'admin');
  const [reports, setReports] = useState<any[]>([]);
  const [current, setCurrent] = useState<any>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [form, setForm] = useState({
    title: '', frameworks: FRAMEWORKS.map((f) => f.id), from: isoDay(new Date(Date.now() - 90 * 86400000)), to: isoDay(new Date()),
    staleDays: 90, reviewDays: 180, credentialMaxAgeDays: 365, inactiveUserDays: 90, liveDrift: false,
  });

  const loadList = async () => {
    try { setReports((await api.complianceReports()).reports); } catch (e: any) { setError(errorMessage(e)); }
  };
  useEffect(() => { loadList(); }, []);

  const open = async (id: string) => {
    setError('');
    try { setCurrent(await api.complianceReport(id)); window.scrollTo({ top: 0, behavior: 'smooth' }); } catch (e: any) { setError(errorMessage(e)); }
  };

  const generate = async () => {
    setBusy(true); setError('');
    try {
      const r = await api.generateComplianceReport({
        ...(form.title.trim() ? { title: form.title.trim() } : {}),
        frameworks: form.frameworks,
        from: new Date(`${form.from}T00:00:00Z`).toISOString(),
        to: new Date(`${form.to}T23:59:59Z`).toISOString(),
        staleDays: form.staleDays, reviewDays: form.reviewDays, credentialMaxAgeDays: form.credentialMaxAgeDays,
        inactiveUserDays: form.inactiveUserDays, liveDrift: form.liveDrift && canLiveDrift,
      });
      await loadList();
      await open(r.id);
    } catch (e: any) { setError(errorMessage(e)); }
    setBusy(false);
  };

  const openPrintable = async () => {
    try {
      const f = await api.complianceReportFile(current.id, 'html');
      const url = URL.createObjectURL(new Blob([f.text], { type: 'text/html' }));
      window.open(url, '_blank', 'noopener');
      setTimeout(() => URL.revokeObjectURL(url), 60000);
    } catch (e: any) { setError(errorMessage(e)); }
  };
  const downloadCsv = async (dataset: string) => {
    try { const f = await api.complianceReportFile(current.id, 'csv', dataset); save(f.text, f.filename, 'text/csv'); } catch (e: any) { setError(errorMessage(e)); }
  };

  const c = current?.content;
  const ev = c?.evidence;
  const th = { textAlign: 'left' as const, padding: '6px 8px', background: '#f7f4ef', borderBottom: '1px solid #e0d6c6', fontSize: '12.5px' };
  const td = { padding: '6px 8px', borderBottom: '1px solid #eee7da', verticalAlign: 'top' as const, fontSize: '13px' };

  return (
    <div className="page">
      <div className="page-header"><h2>Compliance Report</h2></div>
      <p style={{ color: '#78644e', fontSize: '13.5px', marginTop: -4, lineHeight: 1.6 }}>
        Generate point-in-time <strong>evidence</strong> from what Segmentra holds (coverage, change control and approvals, deployments, drift, audit trail, access, credentials, IoT, Kubernetes, Swarm),
        mapped to controls of PCI DSS, ISO 27001, SOC 2 and HIPAA. Reports are stored unchanged with a SHA-256 hash, so they can be handed to an auditor and re-checked later.
        It supports an assessment; it is not an audit opinion or a certification.
      </p>
      {error && <div className="error-banner">{error} <button onClick={() => setError('')} className="btn-small btn-secondary" style={{ marginLeft: 8 }}>dismiss</button></div>}

      {canGenerate && (
        <div className="card">
          <h3 style={{ marginTop: 0 }}>Generate a report</h3>
          <div className="form-grid">
            <div className="form-group"><label>Title (optional)</label><input value={form.title} onChange={(e) => setForm({ ...form, title: e.target.value })} placeholder="e.g., Q3 PCI evidence" /></div>
            <div className="form-group"><label>Period from</label><input type="date" value={form.from} onChange={(e) => setForm({ ...form, from: e.target.value })} /></div>
            <div className="form-group"><label>Period to</label><input type="date" value={form.to} onChange={(e) => setForm({ ...form, to: e.target.value })} /></div>
          </div>
          <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap', margin: '6px 0 10px' }}>
            {FRAMEWORKS.map((f) => (
              <label key={f.id} style={{ display: 'flex', gap: 6, alignItems: 'center', fontSize: '13px' }}>
                <input type="checkbox" style={{ width: 'auto' }} checked={form.frameworks.includes(f.id)}
                  onChange={(e) => setForm({ ...form, frameworks: e.target.checked ? [...form.frameworks, f.id] : form.frameworks.filter((x) => x !== f.id) })} />
                {f.label}
              </label>
            ))}
          </div>
          <details style={{ marginBottom: 10 }}>
            <summary style={{ cursor: 'pointer', fontSize: '13px' }}>Thresholds and live check</summary>
            <div className="form-grid" style={{ marginTop: 8 }}>
              <div className="form-group"><label>Host stale after (days)</label><input type="number" min={1} value={form.staleDays} onChange={(e) => setForm({ ...form, staleDays: Number(e.target.value) || 1 })} /></div>
              <div className="form-group"><label>Policy review due after (days)</label><input type="number" min={1} value={form.reviewDays} onChange={(e) => setForm({ ...form, reviewDays: Number(e.target.value) || 1 })} /></div>
              <div className="form-group"><label>SSH credential rotation (days)</label><input type="number" min={1} value={form.credentialMaxAgeDays} onChange={(e) => setForm({ ...form, credentialMaxAgeDays: Number(e.target.value) || 1 })} /></div>
              <div className="form-group"><label>Inactive account after (days)</label><input type="number" min={1} value={form.inactiveUserDays} onChange={(e) => setForm({ ...form, inactiveUserDays: Number(e.target.value) || 1 })} /></div>
            </div>
            <label style={{ display: 'flex', gap: 6, alignItems: 'center', fontSize: '13px', opacity: canLiveDrift ? 1 : 0.6 }}>
              <input type="checkbox" style={{ width: 'auto' }} disabled={!canLiveDrift} checked={form.liveDrift && canLiveDrift} onChange={(e) => setForm({ ...form, liveDrift: e.target.checked })} />
              Also read every managed host over SSH and compare its live rules with the last deployment (slow; operator or admin)
            </label>
          </details>
          <button className="btn-primary" disabled={busy || form.frameworks.length === 0} onClick={generate}>{busy ? 'Generating...' : 'Generate report'}</button>
        </div>
      )}

      {current && c && (
        <div className="card" style={{ border: '1px solid #d4c9b8' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12, flexWrap: 'wrap', alignItems: 'flex-start' }}>
            <div>
              <h3 style={{ margin: 0 }}>{current.title}</h3>
              <div style={{ color: '#78644e', fontSize: '12.5px', marginTop: 2 }}>
                Period {isoDay(new Date(c.period.from))} to {isoDay(new Date(c.period.to))} · generated {new Date(c.generatedAt).toLocaleString()} by {c.generatedBy}<br />
                SHA-256 <code>{current.integrity.sha256}</code>{' '}
                {current.integrity.verified ? <Badge status="ok" /> : <span style={{ color: '#a63d2f', fontWeight: 600 }}>MISMATCH: the stored report was altered</span>}
                {current.integrity.verified && <span style={{ marginLeft: 4 }}>integrity verified</span>}
              </div>
            </div>
            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
              <button className="btn-primary" onClick={openPrintable}>Open printable report</button>
              <button className="btn-secondary" onClick={() => save(JSON.stringify(current, null, 2), `compliance-${current.id.slice(0, 8)}.json`, 'application/json')}>JSON</button>
              <select value="" onChange={(e) => e.target.value && downloadCsv(e.target.value)} style={{ width: 'auto' }}>
                <option value="">CSV dataset...</option>
                {(current.datasets as string[]).map((d) => <option key={d} value={d}>{CSV_LABELS[d] ?? d}</option>)}
              </select>
            </div>
          </div>
          <div style={{ background: '#f7f4ef', border: '1px solid #e8e0d4', borderRadius: 8, padding: '8px 12px', margin: '12px 0', fontSize: '12.5px', color: '#5c4633' }}>{c.disclaimer}</div>

          <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', marginBottom: 12 }}>
            {[
              [`${ev.inventory.managed}/${ev.inventory.hostsEnabled}`, 'hosts under a deployed policy', ev.inventory.unmanaged > 0],
              [String(ev.changes.approvedInPeriod), 'versions approved in the period', false],
              [String(ev.changes.selfApproved), 'self-approvals', ev.changes.selfApproved > 0],
              [String(ev.deployments.withFailedHosts), 'deployments with failed hosts', ev.deployments.withFailedHosts > 0],
              [`${ev.iot.unprotected.rows.length}/${ev.iot.assets}`, 'IoT assets without a gateway', ev.iot.unprotected.rows.length > 0],
              [String(ev.audit.events), 'audit events', false],
            ].map(([v, l, warn], i) => (
              <div key={i} style={{ background: warn ? '#faf0ee' : '#f7f4ef', border: `1px solid ${warn ? '#e8c4bd' : '#e8e0d4'}`, borderRadius: 8, padding: '8px 12px', minWidth: 150 }}>
                <div style={{ fontSize: '20px', fontWeight: 600, color: warn ? '#a63d2f' : '#3d2e1e' }}>{v as string}</div>
                <div style={{ fontSize: '12px', color: '#78644e' }}>{l as string}</div>
              </div>
            ))}
          </div>

          {c.frameworks.map((f: any) => (
            <div key={f.id} style={{ marginBottom: 16 }}>
              <h4 style={{ margin: '8px 0 2px' }}>{f.name} <span style={{ color: '#97846c', fontWeight: 'normal', fontSize: '0.8em' }}>{f.version}</span></h4>
              <div style={{ color: '#78644e', fontSize: '12.5px', marginBottom: 4 }}>{f.summary.evidence} with supporting evidence · {f.summary.attention} need attention · {f.summary.gap} not covered by Segmentra</div>
              <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                <thead><tr><th style={th}>Control</th><th style={th}>Requirement (summary)</th><th style={th}>Status</th><th style={th}>Segmentra evidence</th></tr></thead>
                <tbody>
                  {f.controls.map((ct: any) => (
                    <tr key={ct.id}>
                      <td style={{ ...td, whiteSpace: 'nowrap' }}>{ct.id}</td>
                      <td style={td}>{ct.title}</td>
                      <td style={td}><Badge status={ct.status} /></td>
                      <td style={td}>
                        {ct.gap ? <span style={{ color: '#6b5a45' }}>{ct.gap}</span> : (
                          <>
                            <span style={{ color: '#78644e' }}>{ct.note}</span>
                            <ul style={{ margin: '4px 0 0 16px', padding: 0 }}>
                              {ct.metrics.map((m: any) => <li key={m.id}><Badge status={m.status} /> {m.label}: <strong>{m.value ?? 'n/a'}</strong>{m.detail && <span style={{ color: '#97846c' }}> ({m.detail})</span>}</li>)}
                            </ul>
                          </>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ))}

          {ev.inventory.unmanaged > 0 && (
            <div style={{ marginBottom: 12 }}>
              <h4 style={{ margin: '8px 0 4px' }}>Hosts without a deployed policy ({ev.inventory.unmanaged})</h4>
              <div style={{ fontSize: '13px' }}>{ev.inventory.hosts.rows.filter((h: any) => h.state === 'unmanaged').slice(0, 15).map((h: any) => h.hostname).join(', ')}{ev.inventory.unmanaged > 15 ? ` and ${ev.inventory.unmanaged - 15} more (see the Hosts CSV)` : ''}</div>
            </div>
          )}
          {ev.iot.unprotected.rows.length > 0 && (
            <div style={{ marginBottom: 12 }}>
              <h4 style={{ margin: '8px 0 4px' }}>IoT / OT assets without a protecting gateway ({ev.iot.unprotected.rows.length})</h4>
              <div style={{ fontSize: '13px' }}>{ev.iot.unprotected.rows.slice(0, 15).map((a: any) => `${a.name} (${a.criticality})`).join(', ')}</div>
            </div>
          )}
        </div>
      )}

      <div className="card">
        <h3 style={{ marginTop: 0 }}>Stored reports</h3>
        {reports.length === 0 ? <p style={{ color: '#97846c' }}>No report has been generated yet.</p> : (
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead><tr><th style={th}>Title</th><th style={th}>Period</th><th style={th}>Frameworks</th><th style={th}>Generated</th><th style={th}>By</th><th style={th}></th></tr></thead>
            <tbody>
              {reports.map((r) => (
                <tr key={r.id}>
                  <td style={td}>{r.title}</td>
                  <td style={td}>{isoDay(new Date(r.period_from))} to {isoDay(new Date(r.period_to))}</td>
                  <td style={td}>{(r.frameworks as string[]).map((id) => FRAMEWORKS.find((f) => f.id === id)?.label ?? id).join(', ')}</td>
                  <td style={td}>{new Date(r.created_at).toLocaleString()}</td>
                  <td style={td}>{r.generated_by_username}</td>
                  <td style={td}><button className="btn-small btn-primary" onClick={() => open(r.id)}>Open</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
