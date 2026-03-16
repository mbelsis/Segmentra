import { useState, useEffect } from 'react';
import { api } from '../lib/api';

const INTEGRATION_TYPES = [
  { value: 'siem', label: 'SIEM' },
  { value: 'soar', label: 'SOAR' },
  { value: 'vulnerability_db', label: 'Vulnerability DB' },
  { value: 'threat_intel', label: 'Threat Intelligence' },
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
      let config = {};
      try { config = JSON.parse(form.config); } catch { /* keep empty */ }
      await api.integrations.create({ type: form.type, provider: form.provider, name: form.name, description: form.description || undefined, enabled: form.enabled, config });
      setShowCreate(false);
      setForm({ type: 'siem', provider: '', name: '', description: '', enabled: false, config: '{}' });
      load();
    } catch (e: any) { setError(e.message); }
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
      {error && <div style={{ color: 'red', marginBottom: 8 }}>{error} <button onClick={() => setError('')}>dismiss</button></div>}

      <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
        <button onClick={() => { setTab('list'); setSelected(null); }} style={{ fontWeight: tab === 'list' ? 'bold' : 'normal' }}>Integrations</button>
        <button onClick={loadThreatIntel} style={{ fontWeight: tab === 'threat' ? 'bold' : 'normal' }}>Threat Intelligence</button>
        <button onClick={() => setShowCreate(true)}>+ New Integration</button>
      </div>

      {showCreate && (
        <div style={{ border: '1px solid #ccc', padding: 16, marginBottom: 16, borderRadius: 4 }}>
          <h3>Add Integration</h3>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
            <select value={form.type} onChange={e => setForm(f => ({ ...f, type: e.target.value }))}>
              {INTEGRATION_TYPES.map(t => <option key={t.value} value={t.value}>{t.label}</option>)}
            </select>
            <input placeholder="Provider (e.g., Splunk, QRadar)" value={form.provider} onChange={e => setForm(f => ({ ...f, provider: e.target.value }))} />
            <input placeholder="Name" value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} />
            <input placeholder="Description" value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))} />
            <textarea placeholder='Config JSON (e.g., {"url": "...", "apiKey": "..."})' value={form.config} onChange={e => setForm(f => ({ ...f, config: e.target.value }))} rows={3} />
            <label><input type="checkbox" checked={form.enabled} onChange={e => setForm(f => ({ ...f, enabled: e.target.checked }))} /> Enable immediately</label>
          </div>
          <div style={{ marginTop: 8 }}>
            <button onClick={createIntegration}>Create</button>
            <button onClick={() => setShowCreate(false)} style={{ marginLeft: 8 }}>Cancel</button>
          </div>
        </div>
      )}

      {tab === 'list' && (
        <div style={{ display: 'flex', gap: 24 }}>
          <div style={{ flex: 1 }}>
            <table style={{ width: '100%' }}>
              <thead><tr><th>Name</th><th>Type</th><th>Provider</th><th>Status</th><th>Last Sync</th><th>Actions</th></tr></thead>
              <tbody>
                {integrations.map(i => (
                  <tr key={i.id} onClick={() => selectIntegration(i)} style={{ cursor: 'pointer', background: selected?.id === i.id ? '#e8f0fe' : undefined }}>
                    <td>{i.name}</td>
                    <td>{INTEGRATION_TYPES.find(t => t.value === i.type)?.label ?? i.type}</td>
                    <td>{i.provider}</td>
                    <td>
                      <span style={{ color: i.enabled ? 'green' : '#999' }}>{i.enabled ? 'Enabled' : 'Disabled'}</span>
                      {i.last_sync_status && <span style={{ marginLeft: 8, fontSize: '0.8em' }}>({i.last_sync_status})</span>}
                    </td>
                    <td>{i.last_sync_at ? new Date(i.last_sync_at).toLocaleString() : 'Never'}</td>
                    <td>
                      <button onClick={(e) => { e.stopPropagation(); toggleEnabled(i); }}>{i.enabled ? 'Disable' : 'Enable'}</button>
                      <button onClick={(e) => { e.stopPropagation(); testIntegration(i.id); }} style={{ marginLeft: 4 }}>Test</button>
                      <button onClick={(e) => { e.stopPropagation(); syncIntegration(i.id); }} style={{ marginLeft: 4 }}>Sync</button>
                      <button onClick={(e) => { e.stopPropagation(); deleteIntegration(i.id); }} style={{ marginLeft: 4, color: 'red' }}>Del</button>
                    </td>
                  </tr>
                ))}
                {integrations.length === 0 && <tr><td colSpan={6}>No integrations configured</td></tr>}
              </tbody>
            </table>
          </div>

          {selected && (
            <div style={{ width: 400, border: '1px solid #ccc', padding: 16, borderRadius: 4 }}>
              <h3>{selected.name} — Events</h3>
              <div style={{ maxHeight: 400, overflow: 'auto' }}>
                {events.map(ev => (
                  <div key={ev.id} style={{ borderBottom: '1px solid #eee', padding: '4px 0', fontSize: '0.85em' }}>
                    <span style={{ color: ev.status === 'SUCCESS' ? 'green' : 'red' }}>{ev.status}</span>
                    {' '}{ev.event_type} ({ev.direction}) — {new Date(ev.created_at).toLocaleString()}
                  </div>
                ))}
                {events.length === 0 && <p style={{ color: '#666' }}>No events</p>}
              </div>
            </div>
          )}
        </div>
      )}

      {tab === 'threat' && (
        <div>
          <h3>Active Threat Intelligence Entries</h3>
          <table style={{ width: '100%' }}>
            <thead><tr><th>Type</th><th>Value</th><th>Threat</th><th>Confidence</th><th>Source</th><th>Expires</th></tr></thead>
            <tbody>
              {threatEntries.map(e => (
                <tr key={e.id}>
                  <td>{e.entry_type}</td>
                  <td><code>{e.value}</code></td>
                  <td>{e.threat_type || '-'}</td>
                  <td>{e.confidence}%</td>
                  <td>{e.integration_name}</td>
                  <td>{e.expires_at ? new Date(e.expires_at).toLocaleDateString() : 'Never'}</td>
                </tr>
              ))}
              {threatEntries.length === 0 && <tr><td colSpan={6}>No active threat intel entries</td></tr>}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
