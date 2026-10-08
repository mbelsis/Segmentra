import { useState, useEffect } from 'react';
import { api, errorMessage } from '../lib/api';

/** Parse a JSON object from a textarea. Returns an error message instead of silently falling back to {}. */
function parseConfigJson(text: string): { ok: true; value: Record<string, unknown> } | { ok: false; error: string } {
  if (!text.trim()) return { ok: false, error: 'Configuration JSON is required (use {} if none is needed).' };
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (e: any) {
    return { ok: false, error: `Configuration is not valid JSON: ${e?.message ?? e}` };
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return { ok: false, error: 'Configuration must be a JSON object, e.g. {"key": "value"}.' };
  }
  return { ok: true, value: parsed as Record<string, unknown> };
}

const INTEGRATION_TYPES = [
  { value: 'siem', label: 'SIEM (Syslog Forwarder)', active: true, hint: 'Config: {"host": "siem.company.com", "port": 514, "protocol": "udp", "facility": 13, "severity": 6}' },
  { value: 'threat_intel', label: 'Threat Intelligence (AbuseIPDB)', active: true, hint: 'Config: {"apiKey": "your-abuseipdb-key", "confidenceMinimum": 90, "maxResults": 100, "expiryDays": 7, "autoBlock": false}' },
  { value: 'soar', label: 'SOAR (planned)', active: false, hint: 'Not yet implemented — requires custom adapter' },
  { value: 'vulnerability_db', label: 'Vulnerability DB (planned)', active: false, hint: 'Not yet implemented — requires custom adapter' },
];

export function IntegrationsPage() {
  const [integrations, setIntegrations] = useState<any[]>([]);
  const [selected, setSelected] = useState<any>(null);
  const [events, setEvents] = useState<any[]>([]);
  const [threatEntries, setThreatEntries] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [showCreate, setShowCreate] = useState(false);
  const [tab, setTab] = useState<'list' | 'threat'>('list');
  const [form, setForm] = useState({ type: 'siem', provider: '', name: '', description: '', enabled: false, config: '{}' });
  const [configError, setConfigError] = useState('');

  const load = async () => {
    setLoading(true);
    try {
      const res = await api.integrations.list();
      setIntegrations(res.integrations);
    } catch (e: any) { setError(e.message); }
    setLoading(false);
  };

  useEffect(() => { load(); }, []);

  const selectIntegration = async (i: any) => {
    setSelected(i);
    try {
      const res = await api.integrations.get(i.id);
      setEvents(res.recentEvents);
    } catch (e: any) { setError(e.message); }
  };

  const loadThreatIntel = async () => {
    setTab('threat');
    try {
      const res = await api.integrations.threatIntel();
      setThreatEntries(res.entries);
    } catch (e: any) { setError(e.message); }
  };

  const createIntegration = async () => {
    try {
      const parsed = parseConfigJson(form.config);
      if (!parsed.ok) { setConfigError(parsed.error); return; }
      setConfigError('');
      await api.integrations.create({ type: form.type, provider: form.provider, name: form.name, description: form.description || undefined, enabled: form.enabled, config: parsed.value });
      setShowCreate(false);
      setForm({ type: 'siem', provider: '', name: '', description: '', enabled: false, config: '{}' });
      load();
    } catch (e: any) { setError(errorMessage(e)); }
  };

  const testIntegration = async (id: string) => {
    try {
      const res = await api.integrations.test(id);
      alert(res.message);
      load();
    } catch (e: any) { setError(e.message); }
  };

  const syncIntegration = async (id: string) => {
    try {
      const res = await api.integrations.sync(id);
      alert(res.message);
      load();
    } catch (e: any) { setError(e.message); }
  };

  const deleteIntegration = async (id: string) => {
    if (!confirm('Delete this integration?')) return;
    try {
      await api.integrations.delete(id);
      if (selected?.id === id) { setSelected(null); setEvents([]); }
      load();
    } catch (e: any) { setError(e.message); }
  };

  const toggleEnabled = async (i: any) => {
    try {
      await api.integrations.update(i.id, { enabled: !i.enabled });
      load();
    } catch (e: any) { setError(e.message); }
  };

  if (loading) return <div>Loading...</div>;

  return (
    <div>
      <h2>Integrations</h2>
      <p style={{ color: '#78644e', fontSize: '13.5px', marginTop: -4, marginBottom: 16, lineHeight: 1.6 }}>
        Connect Segmentra to external security tools. Currently supported:
        <strong> SIEM</strong> (forward audit events as syslog to Splunk, QRadar, Elastic, Graylog) and
        <strong> Threat Intelligence</strong> (sync malicious IP blocklists from AbuseIPDB with optional auto-deny rules).
        SOAR and Vulnerability DB integrations are planned for a future release.
      </p>
      {error && <div style={{ color: 'red', marginBottom: 8 }}>{error} <button onClick={() => setError('')}>dismiss</button></div>}

      <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
        <button onClick={() => { setTab('list'); setSelected(null); }} className={tab === 'list' ? 'btn-primary' : 'btn-secondary'}>Integrations</button>
        <button onClick={loadThreatIntel} className={tab === 'threat' ? 'btn-primary' : 'btn-secondary'}>Threat Intelligence</button>
        <button onClick={() => setShowCreate(true)} className="btn-primary" style={{ marginLeft: 'auto' }}>+ New Integration</button>
      </div>

      {showCreate && (
        <div className="card" style={{ border: '2px solid #8b6914' }}>
          <h3>Add Integration</h3>
          <div className="form-grid" style={{ gridTemplateColumns: '1fr 1fr' }}>
            <div className="form-group"><label>Type *</label>
              <select value={form.type} onChange={e => setForm(f => ({ ...f, type: e.target.value, config: '' }))}>
                {INTEGRATION_TYPES.filter(t => t.active).map(t => <option key={t.value} value={t.value}>{t.label}</option>)}
                <optgroup label="Planned (not yet available)">
                  {INTEGRATION_TYPES.filter(t => !t.active).map(t => <option key={t.value} value={t.value} disabled>{t.label}</option>)}
                </optgroup>
              </select>
            </div>
            <div className="form-group"><label>Provider</label>
              <input placeholder={form.type === 'siem' ? 'e.g., Splunk, QRadar, Elastic, Graylog' : form.type === 'threat_intel' ? 'AbuseIPDB' : 'Provider name'} value={form.provider} onChange={e => setForm(f => ({ ...f, provider: e.target.value }))} />
            </div>
            <div className="form-group"><label>Name *</label>
              <input placeholder="Integration name" value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} />
            </div>
            <div className="form-group"><label>Description</label>
              <input placeholder="Optional description" value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))} />
            </div>
            <div className="form-group" style={{ gridColumn: '1 / -1' }}>
              <label>Configuration (JSON) *</label>
              {(() => {
                const selectedType = INTEGRATION_TYPES.find(t => t.value === form.type);
                return selectedType?.hint ? (
                  <div style={{ padding: '8px 12px', background: '#f7f4ef', borderRadius: 6, marginBottom: 8, fontSize: '12px', color: '#5c4633', fontFamily: "'JetBrains Mono', monospace" }}>
                    {selectedType.hint}
                  </div>
                ) : null;
              })()}
              <textarea
                placeholder={INTEGRATION_TYPES.find(t => t.value === form.type)?.hint || '{"key": "value"}'}
                value={form.config}
                onChange={e => { setConfigError(''); setForm(f => ({ ...f, config: e.target.value })); }}
                rows={4}
                style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '13px' }}
              />
              {configError && <div style={{ color: '#a63d2f', fontSize: '12.5px', marginTop: 4 }}>{configError}</div>}
              {form.type === 'siem' && (
                <small>Forward all audit events as RFC 5424 syslog messages. Protocol: udp (default) or tcp. Facility: 13=audit (default). Severity: 6=info (default).</small>
              )}
              {form.type === 'threat_intel' && (
                <small>Get a free API key at <a href="https://www.abuseipdb.com" target="_blank" rel="noopener noreferrer" style={{ color: '#8b6914' }}>abuseipdb.com</a>. Set autoBlock: true and autoBlockPolicySetId to auto-create DENY rules from blocklist.</small>
              )}
            </div>
            <div className="form-group">
              <label style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <input type="checkbox" checked={form.enabled} onChange={e => setForm(f => ({ ...f, enabled: e.target.checked }))} /> Enable immediately
              </label>
            </div>
          </div>
          <div className="form-actions" style={{ marginTop: 12 }}>
            <button onClick={createIntegration} className="btn-primary" disabled={!form.name.trim() || !INTEGRATION_TYPES.find(t => t.value === form.type)?.active}>Create Integration</button>
            <button onClick={() => setShowCreate(false)} className="btn-secondary">Cancel</button>
          </div>
        </div>
      )}

      {tab === 'list' && (
        <div style={{ display: 'flex', gap: 20 }}>
          <div style={{ flex: 1 }}>
            <div className="card">
              <h4 style={{ margin: '0 0 8px', color: '#5c4633' }}>Configured Integrations</h4>
              <p style={{ fontSize: '12.5px', color: '#97846c', margin: '0 0 12px' }}>Click a row to view events and details.</p>
              <table className="data-table">
                <thead><tr><th>Name</th><th>Type</th><th>Provider</th><th>Status</th><th>Last Sync</th><th>Actions</th></tr></thead>
                <tbody>
                  {integrations.map(i => (
                    <tr key={i.id} onClick={() => selectIntegration(i)} style={{ cursor: 'pointer', background: selected?.id === i.id ? '#f0ebe2' : undefined }}>
                      <td><strong>{i.name}</strong></td>
                      <td style={{ fontSize: '12.5px' }}>{INTEGRATION_TYPES.find(t => t.value === i.type)?.label ?? i.type}</td>
                      <td style={{ fontSize: '12.5px' }}>{i.provider}</td>
                      <td>
                        <span style={{ color: i.enabled ? '#5a7a3a' : '#97846c', fontWeight: 600, fontSize: '12.5px' }}>{i.enabled ? 'Enabled' : 'Disabled'}</span>
                        {i.last_sync_status && <span style={{ marginLeft: 6, fontSize: '11px', color: '#97846c' }}>({i.last_sync_status})</span>}
                      </td>
                      <td style={{ fontSize: '12.5px', color: '#78644e' }}>{i.last_sync_at ? new Date(i.last_sync_at).toLocaleString() : 'Never'}</td>
                      <td onClick={e => e.stopPropagation()}>
                        <div style={{ display: 'flex', gap: 4 }}>
                          <button onClick={() => toggleEnabled(i)} className="btn-small btn-secondary">{i.enabled ? 'Disable' : 'Enable'}</button>
                          <button onClick={() => testIntegration(i.id)} className="btn-small btn-secondary">Test</button>
                          <button onClick={() => syncIntegration(i.id)} className="btn-small btn-secondary">Sync</button>
                          <button onClick={() => deleteIntegration(i.id)} className="btn-small btn-danger">Del</button>
                        </div>
                      </td>
                    </tr>
                  ))}
                  {integrations.length === 0 && <tr><td colSpan={6} className="empty-state">No integrations configured. Click "+ New Integration" to add one.</td></tr>}
                </tbody>
              </table>
            </div>
          </div>

          {selected && (
            <div style={{ width: 400, flexShrink: 0 }}>
              <div className="card">
                <h4 style={{ margin: '0 0 12px', color: '#5c4633' }}>{selected.name} — Events</h4>
                <div style={{ maxHeight: 400, overflow: 'auto' }}>
                  {events.map(ev => (
                    <div key={ev.id} style={{ borderBottom: '1px solid #f0ebe2', padding: '6px 0', fontSize: '12.5px' }}>
                      <span style={{ color: ev.status === 'SUCCESS' ? '#5a7a3a' : '#a63d2f', fontWeight: 600 }}>{ev.status}</span>
                      {' '}<span style={{ color: '#5c4633' }}>{ev.event_type}</span> <span style={{ color: '#97846c' }}>({ev.direction})</span>
                      <div style={{ fontSize: '11.5px', color: '#97846c' }}>{new Date(ev.created_at).toLocaleString()}</div>
                    </div>
                  ))}
                  {events.length === 0 && <p style={{ color: '#97846c', fontStyle: 'italic', fontSize: '13px' }}>No events recorded</p>}
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {tab === 'threat' && (
        <div className="card">
          <h4 style={{ margin: '0 0 12px', color: '#5c4633' }}>Active Threat Intelligence Entries</h4>
          <table className="data-table">
            <thead><tr><th>Type</th><th>Value</th><th>Threat</th><th>Confidence</th><th>Source</th><th>Expires</th></tr></thead>
            <tbody>
              {threatEntries.map(e => (
                <tr key={e.id}>
                  <td style={{ fontSize: '12.5px' }}>{e.entry_type}</td>
                  <td><code>{e.value}</code></td>
                  <td style={{ fontSize: '12.5px' }}>{e.threat_type || '-'}</td>
                  <td style={{ fontSize: '12.5px' }}>{e.confidence}%</td>
                  <td style={{ fontSize: '12.5px' }}>{e.integration_name}</td>
                  <td style={{ fontSize: '12.5px', color: '#78644e' }}>{e.expires_at ? new Date(e.expires_at).toLocaleDateString() : 'Never'}</td>
                </tr>
              ))}
              {threatEntries.length === 0 && <tr><td colSpan={6} className="empty-state">No active threat intel entries</td></tr>}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
