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

const EVENT_TYPES = [
  'POLICY_SUBMITTED', 'POLICY_APPROVED', 'POLICY_REJECTED',
  'DEPLOYMENT_STARTED', 'DEPLOYMENT_COMPLETED', 'DEPLOYMENT_FAILED',
  'COMPLIANCE_DRIFT', 'POLICY_EXPIRING_SOON', 'POLICY_EXPIRED',
  'EXCESSIVE_RULES_DETECTED',
];

const CHANNEL_TYPES = [
  { value: 'slack', label: 'Slack', active: true, configHint: '{"webhookUrl": "https://hooks.slack.com/services/T.../B.../xxx"}', description: 'Send color-coded notifications to a Slack channel via incoming webhook' },
  { value: 'webhook', label: 'HTTP Webhook', active: true, configHint: '{"url": "https://your-endpoint.com/webhook", "authHeader": "Bearer your-token"}', description: 'POST JSON payloads to any HTTP endpoint (SIEM, PagerDuty, custom)' },
  { value: 'email', label: 'Email (planned)', active: false, configHint: '{"to": "admin@company.com"}', description: 'Not yet implemented — requires SMTP configuration' },
];

export function NotificationsPage() {
  const [channels, setChannels] = useState<any[]>([]);
  const [selectedChannel, setSelectedChannel] = useState<any>(null);
  const [rules, setRules] = useState<any[]>([]);
  const [log, setLog] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [showCreate, setShowCreate] = useState(false);
  const [showAddRule, setShowAddRule] = useState(false);
  const [tab, setTab] = useState<'channels' | 'log'>('channels');
  const [form, setForm] = useState({ name: '', type: 'slack', config: '', enabled: true });
  const [configError, setConfigError] = useState('');
  const [ruleForm, setRuleForm] = useState({ eventType: 'DEPLOYMENT_COMPLETED', enabled: true });

  const load = async () => {
    setLoading(true);
    try {
      const res = await api.notifications.channels();
      setChannels(res.channels);
    } catch (e: any) { setError(e.message); }
    setLoading(false);
  };

  useEffect(() => { load(); }, []);

  const selectChannel = async (ch: any) => {
    setSelectedChannel(ch);
    setShowAddRule(false);
    try {
      const res = await api.notifications.channel(ch.id);
      setRules(res.rules);
      setLog(res.recentLog);
    } catch (e: any) { setError(e.message); }
  };

  const createChannel = async () => {
    setError(''); // clear any stale error from an earlier action
    try {
      const parsed = parseConfigJson(form.config);
      if (!parsed.ok) { setConfigError(parsed.error); return; }
      setConfigError('');
      await api.notifications.createChannel({ name: form.name, type: form.type, config: parsed.value, enabled: form.enabled });
      setShowCreate(false);
      setForm({ name: '', type: 'slack', config: '', enabled: true });
      load();
    } catch (e: any) { setError(errorMessage(e)); }
  };

  const deleteChannel = async (id: string) => {
    if (!confirm('Delete this notification channel and all its rules?')) return;
    setError(''); // clear any stale error from an earlier action
    try {
      await api.notifications.deleteChannel(id);
      if (selectedChannel?.id === id) { setSelectedChannel(null); setRules([]); setLog([]); }
      load();
    } catch (e: any) { setError(e.message); }
  };

  const testChannel = async (id: string) => {
    setError(''); // clear any stale error from an earlier action
    try {
      const res = await api.notifications.testChannel(id);
      alert(res.message);
    } catch (e: any) { setError(e.message); }
  };

  const addRule = async () => {
    if (!selectedChannel) return;
    setError(''); // clear any stale error from an earlier action
    try {
      await api.notifications.addRule(selectedChannel.id, { eventType: ruleForm.eventType, enabled: ruleForm.enabled });
      setShowAddRule(false);
      selectChannel(selectedChannel);
    } catch (e: any) { setError(e.message); }
  };

  const deleteRule = async (ruleId: string) => {
    setError(''); // clear any stale error from an earlier action
    try {
      await api.notifications.deleteRule(ruleId);
      if (selectedChannel) selectChannel(selectedChannel);
    } catch (e: any) { setError(e.message); }
  };

  const loadLog = async () => {
    setTab('log');
    try {
      const res = await api.notifications.log();
      setLog(res.log);
    } catch (e: any) { setError(e.message); }
  };

  if (loading) return <div>Loading...</div>;

  // configHint is now inline in the form

  return (
    <div>
      <h2>Notifications</h2>
      <p style={{ color: '#78644e', fontSize: '13.5px', marginTop: -4, marginBottom: 16, lineHeight: 1.6 }}>
        Configure where and when Segmentra sends alerts. Create a <strong>Slack</strong> or <strong>HTTP Webhook</strong> channel,
        then subscribe it to specific events — policy approvals, deployment failures, compliance drift,
        policy expiry warnings, and security audit findings. Notifications are sent automatically when subscribed events occur.
      </p>

      {error && <div style={{ color: '#a63d2f', marginBottom: 12, padding: 10, background: '#faf0ee', borderRadius: 8, borderLeft: '4px solid #a63d2f' }}>{error} <button onClick={() => setError('')} className="btn-small btn-secondary" style={{ marginLeft: 8 }}>dismiss</button></div>}

      <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
        <button onClick={() => { setTab('channels'); setSelectedChannel(null); }} className={tab === 'channels' ? 'btn-primary' : 'btn-secondary'}>Channels</button>
        <button onClick={loadLog} className={tab === 'log' ? 'btn-primary' : 'btn-secondary'}>Notification Log</button>
        <button onClick={() => setShowCreate(true)} className="btn-primary" style={{ marginLeft: 'auto' }}>+ New Channel</button>
      </div>

      {showCreate && (
        <div className="card" style={{ border: '2px solid #8b6914' }}>
          <h3>Create Notification Channel</h3>
          <div className="form-grid" style={{ gridTemplateColumns: '1fr 1fr' }}>
            <div className="form-group">
              <label>Channel Name *</label>
              <input placeholder={form.type === 'slack' ? 'e.g., #ops-alerts' : 'e.g., PagerDuty Webhook'} value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} />
            </div>
            <div className="form-group">
              <label>Type *</label>
              <select value={form.type} onChange={e => setForm(f => ({ ...f, type: e.target.value, config: '' }))}>
                {CHANNEL_TYPES.filter(t => t.active).map(t => <option key={t.value} value={t.value}>{t.label}</option>)}
                <optgroup label="Planned (not yet available)">
                  {CHANNEL_TYPES.filter(t => !t.active).map(t => <option key={t.value} value={t.value} disabled>{t.label}</option>)}
                </optgroup>
              </select>
            </div>
            <div className="form-group" style={{ gridColumn: '1 / -1' }}>
              {(() => {
                const selectedType = CHANNEL_TYPES.find(t => t.value === form.type);
                return selectedType ? (
                  <div style={{ padding: '10px 14px', background: '#f7f4ef', borderRadius: 6, marginBottom: 8, fontSize: '12.5px', color: '#5c4633', border: '1px solid #e8e0d4' }}>
                    <strong>{selectedType.label}:</strong> {selectedType.description}
                  </div>
                ) : null;
              })()}
              <label>Configuration (JSON) *</label>
              <div style={{ padding: '6px 12px', background: '#292018', borderRadius: '6px 6px 0 0', fontSize: '11.5px', color: '#d4c9b8', fontFamily: "'JetBrains Mono', monospace" }}>
                Example: {CHANNEL_TYPES.find(t => t.value === form.type)?.configHint || '{}'}
              </div>
              <textarea value={form.config} onChange={e => { setConfigError(''); setForm(f => ({ ...f, config: e.target.value })); }}
                placeholder={CHANNEL_TYPES.find(t => t.value === form.type)?.configHint || '{}'}
                rows={3} style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '13px', borderRadius: '0 0 6px 6px' }} />
              {configError && <div style={{ color: '#a63d2f', fontSize: '12.5px', marginTop: 4 }}>{configError}</div>}
              {form.type === 'slack' && (
                <small>Create an incoming webhook in Slack: App Settings → Incoming Webhooks → Add New Webhook to Workspace</small>
              )}
              {form.type === 'webhook' && (
                <small>Segmentra POSTs JSON with fields: event, subject, data, timestamp, source. Optional authHeader for Bearer token auth.</small>
              )}
            </div>
            <div className="form-group">
              <label style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <input type="checkbox" checked={form.enabled} onChange={e => setForm(f => ({ ...f, enabled: e.target.checked }))} /> Enable immediately
              </label>
            </div>
          </div>
          <div className="form-actions" style={{ marginTop: 12 }}>
            <button onClick={createChannel} className="btn-primary" disabled={!form.name.trim() || !CHANNEL_TYPES.find(t => t.value === form.type)?.active}>Create Channel</button>
            <button onClick={() => setShowCreate(false)} className="btn-secondary">Cancel</button>
          </div>
        </div>
      )}

      {tab === 'channels' && (
        <div style={{ display: 'flex', gap: 20 }}>
          <div style={{ width: 280, flexShrink: 0 }}>
            {channels.map(ch => (
              <div key={ch.id} onClick={() => selectChannel(ch)}
                style={{ padding: '10px 12px', cursor: 'pointer', marginBottom: 6, borderRadius: 8,
                  background: selectedChannel?.id === ch.id ? '#f0ebe2' : '#fdfcf9',
                  border: `1px solid ${selectedChannel?.id === ch.id ? '#d4c9b8' : '#e8e0d4'}` }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <strong style={{ fontSize: '13.5px', color: '#3d2e1e' }}>{ch.name}</strong>
                  <span style={{ fontSize: '11px', padding: '1px 6px', borderRadius: 4, background: ch.enabled ? '#eef4e8' : '#f0ebe2', color: ch.enabled ? '#5a7a3a' : '#97846c' }}>
                    {ch.enabled ? 'Active' : 'Off'}
                  </span>
                </div>
                <div style={{ fontSize: '12px', color: '#97846c', marginTop: 2 }}>
                  {ch.type.toUpperCase()} | {ch.rule_count} rule(s) {ch.failed_24h > 0 && <span style={{ color: '#a63d2f' }}>| {ch.failed_24h} failed (24h)</span>}
                </div>
              </div>
            ))}
            {channels.length === 0 && <p style={{ color: '#97846c', fontSize: '13px', fontStyle: 'italic' }}>No channels configured.</p>}
          </div>

          {selectedChannel && (
            <div style={{ flex: 1 }}>
              <div className="card">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <h3 style={{ margin: 0 }}>{selectedChannel.name} <span style={{ fontSize: '12px', color: '#97846c', fontWeight: 400 }}>({selectedChannel.type})</span></h3>
                  <div style={{ display: 'flex', gap: 8 }}>
                    <button onClick={() => testChannel(selectedChannel.id)} className="btn-small btn-secondary">Send Test</button>
                    <button onClick={() => deleteChannel(selectedChannel.id)} className="btn-small btn-danger">Delete</button>
                  </div>
                </div>
              </div>

              <div className="card">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
                  <h4 style={{ margin: 0, color: '#5c4633' }}>Event Subscriptions</h4>
                  <button onClick={() => setShowAddRule(true)} className="btn-small btn-primary">+ Add Event</button>
                </div>

                {showAddRule && (
                  <div style={{ padding: 12, background: '#f7f4ef', borderRadius: 8, marginBottom: 12 }}>
                    <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                      <select value={ruleForm.eventType} onChange={e => setRuleForm(f => ({ ...f, eventType: e.target.value }))}>
                        {EVENT_TYPES.map(et => <option key={et} value={et}>{et.replace(/_/g, ' ')}</option>)}
                      </select>
                      <button onClick={addRule} className="btn-small btn-primary">Add</button>
                      <button onClick={() => setShowAddRule(false)} className="btn-small btn-secondary">Cancel</button>
                    </div>
                  </div>
                )}

                <table className="data-table">
                  <thead><tr><th>Event</th><th>Status</th><th></th></tr></thead>
                  <tbody>
                    {rules.map(r => (
                      <tr key={r.id}>
                        <td>{r.event_type.replace(/_/g, ' ')}</td>
                        <td><span style={{ color: r.enabled ? '#5a7a3a' : '#97846c' }}>{r.enabled ? 'Enabled' : 'Disabled'}</span></td>
                        <td><button onClick={() => deleteRule(r.id)} className="btn-small btn-danger" style={{ padding: '2px 8px', minHeight: 'auto' }}>x</button></td>
                      </tr>
                    ))}
                    {rules.length === 0 && <tr><td colSpan={3} className="empty-state">No event subscriptions. Add events to receive notifications on this channel.</td></tr>}
                  </tbody>
                </table>
              </div>

              {log.length > 0 && (
                <div className="card">
                  <h4 style={{ margin: '0 0 8px', color: '#5c4633' }}>Recent Activity</h4>
                  <table className="data-table">
                    <thead><tr><th>Event</th><th>Subject</th><th>Status</th><th>Sent</th></tr></thead>
                    <tbody>
                      {log.slice(0, 15).map(l => (
                        <tr key={l.id}>
                          <td style={{ fontSize: '12.5px' }}>{l.event_type.replace(/_/g, ' ')}</td>
                          <td style={{ fontSize: '12.5px' }}>{l.subject || '-'}</td>
                          <td><span style={{ color: l.status === 'SENT' ? '#5a7a3a' : l.status === 'FAILED' ? '#a63d2f' : '#97846c', fontWeight: 600, fontSize: '12.5px' }}>{l.status}</span></td>
                          <td style={{ fontSize: '12px', color: '#97846c' }}>{l.sent_at ? new Date(l.sent_at).toLocaleString() : '-'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {tab === 'log' && (
        <div className="card">
          <h3>Notification Log</h3>
          <table className="data-table">
            <thead><tr><th>Channel</th><th>Event</th><th>Subject</th><th>Status</th><th>Error</th><th>Time</th></tr></thead>
            <tbody>
              {log.map(l => (
                <tr key={l.id}>
                  <td>{l.channel_name || '-'} <span style={{ fontSize: '11px', color: '#97846c' }}>({l.channel_type})</span></td>
                  <td style={{ fontSize: '12.5px' }}>{l.event_type.replace(/_/g, ' ')}</td>
                  <td style={{ fontSize: '12.5px' }}>{l.subject || '-'}</td>
                  <td><span style={{ color: l.status === 'SENT' ? '#5a7a3a' : l.status === 'FAILED' ? '#a63d2f' : '#97846c', fontWeight: 600, fontSize: '12.5px' }}>{l.status}</span></td>
                  <td style={{ fontSize: '12px', color: '#a63d2f' }}>{l.error_message || '-'}</td>
                  <td style={{ fontSize: '12px', color: '#97846c' }}>{new Date(l.created_at).toLocaleString()}</td>
                </tr>
              ))}
              {log.length === 0 && <tr><td colSpan={6} className="empty-state">No notification history.</td></tr>}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
