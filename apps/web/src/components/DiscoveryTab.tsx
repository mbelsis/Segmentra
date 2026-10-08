import { Fragment, useEffect, useRef, useState } from 'react';

import { api, errorMessage } from '../lib/api';

type TargetForm = {
  key: number;
  sshCredentialId: string;
  sshPort: string;
  cidrsText: string;
  vlanIds: string[];
};

type NewCredForm = {
  name: string;
  username: string;
  authMethod: 'PASSWORD' | 'KEY';
  password: string;
  privateKeyPem: string;
  makeGlobal: boolean;
};

type ScheduleMode = 'manual' | '15' | '60' | '360' | '1440' | 'custom';

const SCHEDULE_PRESETS: Array<{ value: ScheduleMode; label: string }> = [
  { value: 'manual', label: 'Manual only' },
  { value: '15', label: 'Every 15 minutes' },
  { value: '60', label: 'Every hour' },
  { value: '360', label: 'Every 6 hours' },
  { value: '1440', label: 'Every 24 hours' },
  { value: 'custom', label: 'Custom (minutes)' },
];

let targetKeySeq = 1;
function emptyTarget(): TargetForm {
  return { key: targetKeySeq++, sshCredentialId: '', sshPort: '22', cidrsText: '', vlanIds: [] };
}

function emptyNewCred(): NewCredForm {
  return { name: '', username: '', authMethod: 'PASSWORD', password: '', privateKeyPem: '', makeGlobal: false };
}

function parseCidrList(text: string): string[] {
  return text.split(/[\s,;]+/).map(s => s.trim()).filter(Boolean);
}

function describeSchedule(minutes: number | null | undefined): string {
  if (!minutes) return 'Manual only';
  if (minutes % 1440 === 0) return minutes === 1440 ? 'Every 24 h' : `Every ${minutes / 1440} days`;
  if (minutes % 60 === 0) return minutes === 60 ? 'Every hour' : `Every ${minutes / 60} h`;
  return `Every ${minutes} min`;
}

function statusColor(status: string): string {
  if (status === 'SUCCEEDED') return '#4CAF50';
  if (status === 'FAILED') return '#f44336';
  if (status === 'RUNNING') return '#2196F3';
  return '#999';
}

const RESULT_LABELS: Record<string, { label: string; color: string }> = {
  imported: { label: 'Imported', color: '#4CAF50' },
  already_present: { label: 'Already in inventory', color: '#757575' },
  login_failed: { label: 'Login failed', color: '#f44336' },
  error: { label: 'Error', color: '#f44336' },
};

function fmtTime(v: string | null | undefined): string {
  return v ? new Date(v).toLocaleString() : '-';
}

function duration(run: any): string {
  if (!run?.started_at) return '-';
  const end = run.finished_at ? new Date(run.finished_at).getTime() : Date.now();
  const s = Math.max(0, Math.round((end - new Date(run.started_at).getTime()) / 1000));
  return s >= 60 ? `${Math.floor(s / 60)}m ${s % 60}s` : `${s}s`;
}

function RunCounts({ run }: { run: any }) {
  return (
    <span style={{ fontSize: '0.85em' }}>
      scanned <strong>{run.addresses_scanned}</strong> · SSH open <strong>{run.ssh_open}</strong> · login OK <strong>{run.login_ok}</strong> ·{' '}
      imported <strong style={{ color: '#4CAF50' }}>{run.imported}</strong> · present <strong>{run.already_present}</strong> ·{' '}
      login failed <strong style={{ color: run.login_failed > 0 ? '#f44336' : undefined }}>{run.login_failed}</strong>
    </span>
  );
}

export function DiscoveryTab(props: {
  vlans: any[];
  canManage: boolean; // admin: create/edit/delete profiles, manage credentials
  canRun: boolean; // operator/admin: Run Now
  onHostsImported?: () => void;
}) {
  const { vlans, canManage, canRun, onHostsImported } = props;

  const [profiles, setProfiles] = useState<any[]>([]);
  const [limits, setLimits] = useState<{ maxAddressesPerRun: number; minPrefix: number }>({ maxAddressesPerRun: 8192, minPrefix: 20 });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [credentials, setCredentials] = useState<any[]>([]);

  // Form state
  const [showForm, setShowForm] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [name, setName] = useState('');
  const [enabled, setEnabled] = useState(true);
  const [scheduleMode, setScheduleMode] = useState<ScheduleMode>('manual');
  const [customMinutes, setCustomMinutes] = useState('30');
  const [defaultTagName, setDefaultTagName] = useState('new-server');
  const [targets, setTargets] = useState<TargetForm[]>([emptyTarget()]);
  const [formError, setFormError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  // Inline "new credential" panel (per target set, by key)
  const [newCredFor, setNewCredFor] = useState<number | null>(null);
  const [newCred, setNewCred] = useState<NewCredForm>(emptyNewCred());
  const [savingCred, setSavingCred] = useState(false);
  const [credError, setCredError] = useState<string | null>(null);

  // List actions
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null);
  const [startingRunId, setStartingRunId] = useState<string | null>(null);

  // Run history
  const [historyProfileId, setHistoryProfileId] = useState<string | null>(null);
  const [runs, setRuns] = useState<any[]>([]);
  const [expandedRunId, setExpandedRunId] = useState<string | null>(null);
  const [expandedRun, setExpandedRun] = useState<any>(null);

  const prevRunning = useRef<Set<string>>(new Set());

  useEffect(() => {
    loadProfiles();
    if (canManage) loadCredentials();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function loadProfiles() {
    setLoading(prev => prev || profiles.length === 0);
    try {
      const res = await api.discovery.profiles();
      setProfiles(res.profiles || []);
      if (res.limits) setLimits(res.limits);
      // When a run that was RUNNING finishes, the hosts list may have changed.
      const nowRunning = new Set<string>((res.profiles || []).filter((p: any) => p.last_run?.status === 'RUNNING').map((p: any) => p.id));
      const finished = [...prevRunning.current].some(id => !nowRunning.has(id));
      prevRunning.current = nowRunning;
      if (finished) onHostsImported?.();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setLoading(false);
    }
  }

  async function loadCredentials() {
    try {
      const res = await api.sshCredentials();
      // Host-scoped copies created by discovery are not useful choices here.
      setCredentials((res.sshCredentials || []).filter((c: any) => c.scope_type !== 'HOST'));
    } catch {
      setCredentials([]);
    }
  }

  async function loadRuns(profileId: string) {
    try {
      const res = await api.discovery.runs(profileId);
      setRuns(res.runs || []);
    } catch (e) {
      setError(errorMessage(e));
    }
  }

  async function loadRunDetail(runId: string) {
    try {
      const res = await api.discovery.getRun(runId);
      setExpandedRun(res.run);
    } catch (e) {
      setError(errorMessage(e));
    }
  }

  // Auto-refresh while any run is RUNNING
  const anyRunning = profiles.some(p => p.last_run?.status === 'RUNNING') || runs.some(r => r.status === 'RUNNING');
  useEffect(() => {
    if (!anyRunning) return;
    const t = setInterval(() => {
      loadProfiles();
      if (historyProfileId) loadRuns(historyProfileId);
      if (expandedRunId) loadRunDetail(expandedRunId);
    }, 3000);
    return () => clearInterval(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [anyRunning, historyProfileId, expandedRunId]);

  function resetForm() {
    setShowForm(false);
    setEditingId(null);
    setName('');
    setEnabled(true);
    setScheduleMode('manual');
    setCustomMinutes('30');
    setDefaultTagName('new-server');
    setTargets([emptyTarget()]);
    setFormError(null);
    setNewCredFor(null);
    setNewCred(emptyNewCred());
    setCredError(null);
  }

  function startCreate() {
    resetForm();
    setShowForm(true);
    loadCredentials();
  }

  function startEdit(p: any) {
    resetForm();
    setEditingId(p.id);
    setName(p.name);
    setEnabled(!!p.enabled);
    const m = p.schedule_interval_minutes as number | null;
    if (!m) setScheduleMode('manual');
    else if (['15', '60', '360', '1440'].includes(String(m))) setScheduleMode(String(m) as ScheduleMode);
    else { setScheduleMode('custom'); setCustomMinutes(String(m)); }
    setDefaultTagName(p.default_tag_name || 'new-server');
    setTargets((p.targets || []).map((t: any) => ({
      key: targetKeySeq++,
      sshCredentialId: t.sshCredentialId,
      sshPort: String(t.sshPort ?? 22),
      cidrsText: (t.cidrs || []).join('\n'),
      vlanIds: t.vlanIds || [],
    })));
    setShowForm(true);
    loadCredentials();
  }

  function updateTarget(key: number, patch: Partial<TargetForm>) {
    setTargets(ts => ts.map(t => (t.key === key ? { ...t, ...patch } : t)));
  }

  function toggleTargetVlan(key: number, vlanId: string) {
    setTargets(ts => ts.map(t => {
      if (t.key !== key) return t;
      const has = t.vlanIds.includes(vlanId);
      return { ...t, vlanIds: has ? t.vlanIds.filter(v => v !== vlanId) : [...t.vlanIds, vlanId] };
    }));
  }

  function scheduleMinutes(): number | null | 'invalid' {
    if (scheduleMode === 'manual') return null;
    if (scheduleMode === 'custom') {
      const n = parseInt(customMinutes, 10);
      return Number.isFinite(n) && n >= 1 && n <= 525600 ? n : 'invalid';
    }
    return parseInt(scheduleMode, 10);
  }

  async function saveProfile() {
    setFormError(null);
    const minutes = scheduleMinutes();
    if (minutes === 'invalid') { setFormError('Custom schedule must be a whole number of minutes (1 to 525600).'); return; }
    if (!name.trim()) { setFormError('Profile name is required.'); return; }
    const body = {
      name: name.trim(),
      enabled,
      scheduleIntervalMinutes: minutes,
      defaultTagName: defaultTagName.trim() || 'new-server',
      targets: targets.map(t => ({
        sshCredentialId: t.sshCredentialId,
        sshPort: parseInt(t.sshPort, 10) || 22,
        cidrs: parseCidrList(t.cidrsText),
        vlanIds: t.vlanIds,
      })),
    };
    const missingCred = body.targets.findIndex(t => !t.sshCredentialId);
    if (missingCred >= 0) { setFormError(`Target set ${missingCred + 1}: choose an SSH credential.`); return; }
    const noNetworks = body.targets.findIndex(t => t.cidrs.length === 0 && t.vlanIds.length === 0);
    if (noNetworks >= 0) { setFormError(`Target set ${noNetworks + 1}: add at least one CIDR or VLAN.`); return; }

    setSaving(true);
    try {
      if (editingId) await api.discovery.updateProfile(editingId, body);
      else await api.discovery.createProfile(body);
      setNotice(editingId ? `Profile "${body.name}" updated.` : `Profile "${body.name}" created.`);
      resetForm();
      await loadProfiles();
    } catch (e) {
      setFormError(errorMessage(e));
    } finally {
      setSaving(false);
    }
  }

  async function saveNewCredential(targetKey: number) {
    setCredError(null);
    const c = newCred;
    if (!c.name.trim() || !c.username.trim() || (c.authMethod === 'PASSWORD' ? !c.password : !c.privateKeyPem.trim())) {
      setCredError(c.authMethod === 'PASSWORD' ? 'Name, username and password are required.' : 'Name, username and private key are required.');
      return;
    }
    setSavingCred(true);
    try {
      // Non-global credentials are only used by discovery until a host is imported; the host then
      // gets its own HOST-scoped credential so deployments use the credential that worked.
      const scopeType = c.makeGlobal ? 'GLOBAL' : 'TAG';
      const res = await api.createSshCredential(
        c.authMethod === 'PASSWORD'
          ? { name: c.name.trim(), username: c.username.trim(), authMethod: 'PASSWORD', password: c.password, scopeType }
          : { name: c.name.trim(), username: c.username.trim(), authMethod: 'KEY', privateKeyPem: c.privateKeyPem.trim(), scopeType }
      );
      await loadCredentials();
      updateTarget(targetKey, { sshCredentialId: res.sshCredential.id });
      setNewCredFor(null);
      setNewCred(emptyNewCred());
    } catch (e) {
      setCredError(errorMessage(e));
    } finally {
      setSavingCred(false);
    }
  }

  async function deleteProfile(id: string) {
    setError(null);
    try {
      await api.discovery.deleteProfile(id);
      setConfirmDeleteId(null);
      if (historyProfileId === id) { setHistoryProfileId(null); setRuns([]); }
      setNotice('Profile deleted.');
      await loadProfiles();
    } catch (e) {
      setError(errorMessage(e));
      setConfirmDeleteId(null);
    }
  }

  async function runNow(p: any) {
    setError(null);
    setStartingRunId(p.id);
    try {
      await api.discovery.run(p.id);
      setNotice(`Discovery run started for "${p.name}".`);
      setHistoryProfileId(p.id);
      await Promise.all([loadProfiles(), loadRuns(p.id)]);
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setStartingRunId(null);
    }
  }

  function showHistory(p: any) {
    if (historyProfileId === p.id) { setHistoryProfileId(null); setRuns([]); return; }
    setHistoryProfileId(p.id);
    setExpandedRunId(null);
    setExpandedRun(null);
    loadRuns(p.id);
  }

  function toggleRun(runId: string) {
    if (expandedRunId === runId) { setExpandedRunId(null); setExpandedRun(null); return; }
    setExpandedRunId(runId);
    setExpandedRun(null);
    loadRunDetail(runId);
  }

  function vlanLabel(id: string): string {
    const v = vlans.find(x => x.id === id);
    return v ? `VLAN ${v.vlan_tag}${v.subnet ? ` (${v.subnet})` : ''}` : 'deleted VLAN';
  }

  function targetSummary(t: any): string {
    const nets = [...(t.cidrs || []), ...(t.vlanIds || []).map(vlanLabel)];
    const shown = nets.slice(0, 3).join(', ') + (nets.length > 3 ? ` +${nets.length - 3} more` : '');
    return `${t.sshCredentialName} (${t.sshCredentialUsername}) → ${shown} :${t.sshPort}`;
  }

  const historyProfile = profiles.find(p => p.id === historyProfileId);

  return (
    <>
      <div className="card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 16 }}>
          <div>
            <h3 style={{ margin: 0 }}>Inventory Discovery</h3>
            <p style={{ color: '#666', fontSize: '0.9em', margin: '4px 0 0' }}>
              Scan networks for SSH servers, log in with your SSH credentials (read-only: hostname, OS, nft/iptables, sudo)
              and import new hosts with a default tag. Existing hosts (same management IP) are never modified.
              IPv4 only; each network at most /{limits.minPrefix}, at most {limits.maxAddressesPerRun} addresses per run.
            </p>
          </div>
          {canManage && !showForm && (
            <button onClick={startCreate} className="btn-primary" data-testid="discovery-new-profile">+ New Discovery Profile</button>
          )}
        </div>
      </div>

      {error && <div className="error-banner">{error}</div>}
      {notice && (
        <div style={{ padding: '8px 12px', background: '#E8F5E9', border: '1px solid #C8E6C9', borderRadius: 4, marginBottom: 16, display: 'flex', justifyContent: 'space-between' }}>
          <span>{notice}</span>
          <button className="btn-small btn-secondary" onClick={() => setNotice(null)}>Dismiss</button>
        </div>
      )}

      {canManage && showForm && (
        <div className="card" style={{ border: '2px solid #646cff' }} data-testid="discovery-form">
          <h3>{editingId ? 'Edit Discovery Profile' : 'New Discovery Profile'}</h3>
          <div className="form-grid" style={{ gridTemplateColumns: '2fr 1.5fr 1fr 1.5fr 1fr' }}>
            <div className="form-group">
              <label>Name *</label>
              <input type="text" value={name} onChange={e => setName(e.target.value)} placeholder="e.g., DC1 server subnets" />
            </div>
            <div className="form-group">
              <label>Schedule</label>
              <select value={scheduleMode} onChange={e => setScheduleMode(e.target.value as ScheduleMode)}>
                {SCHEDULE_PRESETS.map(s => <option key={s.value} value={s.value}>{s.label}</option>)}
              </select>
            </div>
            {scheduleMode === 'custom' ? (
              <div className="form-group">
                <label>Minutes</label>
                <input type="number" min={1} value={customMinutes} onChange={e => setCustomMinutes(e.target.value)} />
              </div>
            ) : <div />}
            <div className="form-group">
              <label>Tag for imported hosts</label>
              <input type="text" value={defaultTagName} onChange={e => setDefaultTagName(e.target.value)} placeholder="new-server" />
              <small>Created if it does not exist.</small>
            </div>
            <div className="form-group">
              <label>Status</label>
              <label style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 8 }}>
                <input type="checkbox" checked={enabled} onChange={e => setEnabled(e.target.checked)} />
                Enabled
              </label>
              <small>Disabled profiles are skipped by the scheduler.</small>
            </div>
          </div>

          <h4 style={{ marginBottom: 8 }}>Target sets</h4>
          <p style={{ color: '#666', fontSize: '0.85em', marginTop: 0 }}>
            Each target set pairs an SSH credential with the networks to scan. If several target sets cover the same address,
            their credentials are tried in order until one works.
          </p>
          {targets.map((t, i) => (
            <div key={t.key} style={{ padding: 12, background: '#f9f9f9', borderRadius: 4, marginBottom: 12, border: '1px solid #eee' }} data-testid={`discovery-target-${i}`}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <strong>Target set {i + 1}</strong>
                {targets.length > 1 && (
                  <button className="btn-small btn-danger" onClick={() => setTargets(ts => ts.filter(x => x.key !== t.key))}>Remove target set</button>
                )}
              </div>
              <div className="form-grid" style={{ gridTemplateColumns: '2fr 1fr', marginTop: 8 }}>
                <div className="form-group">
                  <label>SSH credential *</label>
                  <div style={{ display: 'flex', gap: 8 }}>
                    <select value={t.sshCredentialId} onChange={e => updateTarget(t.key, { sshCredentialId: e.target.value })} style={{ flex: 1 }}>
                      <option value="">Select a credential...</option>
                      {credentials.map(c => (
                        <option key={c.id} value={c.id}>
                          {c.name} ({c.username}, {c.auth_method === 'PASSWORD' ? 'password' : 'key'}{c.scope_type === 'GLOBAL' ? ', global' : ''})
                        </option>
                      ))}
                    </select>
                    {newCredFor !== t.key && (
                      <button className="btn-small btn-secondary" onClick={() => { setNewCredFor(t.key); setNewCred(emptyNewCred()); setCredError(null); }}>
                        + New credential
                      </button>
                    )}
                  </div>
                </div>
                <div className="form-group">
                  <label>SSH port</label>
                  <input type="number" min={1} max={65535} value={t.sshPort} onChange={e => updateTarget(t.key, { sshPort: e.target.value })} />
                </div>
              </div>

              {newCredFor === t.key && (
                <div style={{ padding: 12, background: 'white', border: '1px dashed #646cff', borderRadius: 4, marginBottom: 8 }}>
                  <strong>New SSH credential</strong>
                  <div className="form-grid" style={{ gridTemplateColumns: '1fr 1fr 1fr', marginTop: 8 }}>
                    <div className="form-group">
                      <label>Name *</label>
                      <input type="text" value={newCred.name} onChange={e => setNewCred(c => ({ ...c, name: e.target.value }))} placeholder="e.g., dc1-ops" />
                    </div>
                    <div className="form-group">
                      <label>Username *</label>
                      <input type="text" value={newCred.username} onChange={e => setNewCred(c => ({ ...c, username: e.target.value }))} placeholder="sudo-capable user" />
                    </div>
                    <div className="form-group">
                      <label>Authentication</label>
                      <select value={newCred.authMethod} onChange={e => setNewCred(c => ({ ...c, authMethod: e.target.value as 'PASSWORD' | 'KEY' }))}>
                        <option value="PASSWORD">Password</option>
                        <option value="KEY">Private key</option>
                      </select>
                    </div>
                  </div>
                  {newCred.authMethod === 'PASSWORD' ? (
                    <div className="form-group">
                      <label>Password *</label>
                      <input type="password" autoComplete="new-password" value={newCred.password} onChange={e => setNewCred(c => ({ ...c, password: e.target.value }))} />
                    </div>
                  ) : (
                    <div className="form-group">
                      <label>Private key (PEM) *</label>
                      <textarea rows={5} value={newCred.privateKeyPem} onChange={e => setNewCred(c => ({ ...c, privateKeyPem: e.target.value }))}
                        style={{ fontFamily: 'monospace', fontSize: '0.85em' }} placeholder="-----BEGIN OPENSSH PRIVATE KEY-----" />
                    </div>
                  )}
                  <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: '0.9em' }}>
                    <input type="checkbox" checked={newCred.makeGlobal} onChange={e => setNewCred(c => ({ ...c, makeGlobal: e.target.checked }))} />
                    Make this the global default credential (used for deployments to every host without a host-specific credential)
                  </label>
                  <small style={{ display: 'block', color: '#666', marginTop: 4 }}>
                    Stored encrypted (Admin → SSH Credentials). Hosts imported with a non-global credential get their own host-scoped copy, so deployments use the credential that worked.
                  </small>
                  {credError && <div className="error" style={{ marginTop: 8, color: '#f44336' }}>{credError}</div>}
                  <div className="form-actions" style={{ marginTop: 8 }}>
                    <button className="btn-small btn-primary" disabled={savingCred} onClick={() => saveNewCredential(t.key)}>
                      {savingCred ? 'Saving...' : 'Save credential'}
                    </button>
                    <button className="btn-small btn-secondary" onClick={() => { setNewCredFor(null); setCredError(null); }}>Cancel</button>
                  </div>
                </div>
              )}

              <div className="form-grid" style={{ gridTemplateColumns: '1fr 1fr' }}>
                <div className="form-group">
                  <label>Networks (CIDR or single IP)</label>
                  <textarea rows={4} value={t.cidrsText} onChange={e => updateTarget(t.key, { cidrsText: e.target.value })}
                    placeholder={'10.0.10.0/24\n10.0.11.5'} style={{ fontFamily: 'monospace', fontSize: '0.9em' }} />
                  <small>One per line (or comma-separated). IPv4, /{limits.minPrefix} or smaller.</small>
                </div>
                <div className="form-group">
                  <label>VLANs (their subnet is scanned)</label>
                  <div style={{ maxHeight: 120, overflowY: 'auto', border: '1px solid #ddd', borderRadius: 4, padding: 6, background: 'white' }}>
                    {vlans.length === 0 && <span style={{ color: '#999', fontSize: '0.85em' }}>No VLANs defined.</span>}
                    {vlans.map(v => (
                      <label key={v.id} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: '0.9em', color: v.subnet ? undefined : '#999' }}
                        title={v.subnet ? '' : 'This VLAN has no subnet configured'}>
                        <input type="checkbox" disabled={!v.subnet && !t.vlanIds.includes(v.id)} checked={t.vlanIds.includes(v.id)} onChange={() => toggleTargetVlan(t.key, v.id)} />
                        VLAN {v.vlan_tag} – {v.name} {v.subnet ? <code>({v.subnet})</code> : <em>(no subnet)</em>}
                      </label>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          ))}
          <button className="btn-small btn-secondary" onClick={() => setTargets(ts => [...ts, emptyTarget()])}>+ Add target set</button>

          {formError && <div className="error-banner" style={{ marginTop: 12 }}>{formError}</div>}
          <div className="form-actions" style={{ marginTop: 16 }}>
            <button className="btn-primary" disabled={saving} onClick={saveProfile}>
              {saving ? 'Saving...' : editingId ? 'Update Profile' : 'Create Profile'}
            </button>
            <button className="btn-secondary" onClick={resetForm}>Cancel</button>
          </div>
        </div>
      )}

      <div className="card">
        <h3>Discovery Profiles</h3>
        {loading && profiles.length === 0 ? <p>Loading...</p> : (
          <table className="data-table" data-testid="discovery-profiles">
            <thead>
              <tr>
                <th>Name</th>
                <th>Schedule</th>
                <th>Targets</th>
                <th>Last run</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {profiles.map(p => {
                const lr = p.last_run;
                return (
                  <tr key={p.id}>
                    <td>
                      <strong>{p.name}</strong>
                      <div style={{ fontSize: '0.8em', color: '#666' }}>tag: <code>{p.default_tag_name}</code></div>
                    </td>
                    <td style={{ fontSize: '0.9em' }}>
                      {describeSchedule(p.schedule_interval_minutes)}
                      {p.schedule_interval_minutes && p.enabled && p.next_run_at && (
                        <div style={{ fontSize: '0.8em', color: '#666' }}>next: {fmtTime(p.next_run_at)}</div>
                      )}
                    </td>
                    <td style={{ fontSize: '0.85em' }}>
                      {(p.targets || []).map((t: any) => <div key={t.id}>{targetSummary(t)}</div>)}
                    </td>
                    <td style={{ fontSize: '0.85em' }}>
                      {lr ? (
                        <>
                          <span style={{ color: statusColor(lr.status), fontWeight: 'bold' }}>{lr.status}</span>{' '}
                          <span style={{ color: '#666' }}>{fmtTime(lr.started_at)} ({lr.trigger})</span>
                          {lr.status !== 'RUNNING' && <div><RunCounts run={lr} /></div>}
                          {lr.error && <div style={{ color: '#f44336' }}>{lr.error}</div>}
                        </>
                      ) : <span style={{ color: '#999' }}>Never run</span>}
                    </td>
                    <td>
                      <span style={{ color: p.enabled ? '#4CAF50' : '#999', fontWeight: 'bold' }}>{p.enabled ? 'Enabled' : 'Disabled'}</span>
                    </td>
                    <td style={{ whiteSpace: 'nowrap' }}>
                      {canRun && (
                        <button className="btn-small btn-primary" style={{ marginRight: 4 }}
                          disabled={startingRunId === p.id || lr?.status === 'RUNNING'} onClick={() => runNow(p)}>
                          {lr?.status === 'RUNNING' ? 'Running...' : startingRunId === p.id ? 'Starting...' : 'Run Now'}
                        </button>
                      )}
                      <button className="btn-small btn-secondary" style={{ marginRight: 4 }} onClick={() => showHistory(p)}>
                        {historyProfileId === p.id ? 'Hide history' : 'History'}
                      </button>
                      {canManage && <button className="btn-small btn-secondary" style={{ marginRight: 4 }} onClick={() => startEdit(p)}>Edit</button>}
                      {canManage && (confirmDeleteId === p.id ? (
                        <span>
                          <span style={{ fontSize: '0.85em', marginRight: 4 }}>Delete profile and its run history?</span>
                          <button className="btn-small btn-danger" style={{ marginRight: 4 }} onClick={() => deleteProfile(p.id)}>Yes, delete</button>
                          <button className="btn-small btn-secondary" onClick={() => setConfirmDeleteId(null)}>No</button>
                        </span>
                      ) : (
                        <button className="btn-small btn-danger" onClick={() => setConfirmDeleteId(p.id)}>Delete</button>
                      ))}
                    </td>
                  </tr>
                );
              })}
              {profiles.length === 0 && (
                <tr>
                  <td colSpan={6} className="empty-state">
                    No discovery profiles yet.{canManage ? ' Create one to find and import servers automatically.' : ''}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        )}
      </div>

      {historyProfile && (
        <div className="card" data-testid="discovery-history">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <h3 style={{ margin: 0 }}>Run history: {historyProfile.name}</h3>
            <button className="btn-small btn-secondary" onClick={() => loadRuns(historyProfile.id)}>Refresh</button>
          </div>
          <table className="data-table" style={{ marginTop: 12 }}>
            <thead>
              <tr>
                <th>Started</th>
                <th>Trigger</th>
                <th>Status</th>
                <th>Duration</th>
                <th>Results</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {runs.map(r => (
                <Fragment key={r.id}>
                  <tr>
                    <td style={{ fontSize: '0.9em' }}>{fmtTime(r.started_at)}</td>
                    <td>{r.trigger}{r.created_by_username ? ` (${r.created_by_username})` : ''}</td>
                    <td><span style={{ color: statusColor(r.status), fontWeight: 'bold' }}>{r.status}</span></td>
                    <td>{duration(r)}</td>
                    <td>
                      {r.status === 'RUNNING' ? <span style={{ color: '#666' }}>Scanning...</span> : <RunCounts run={r} />}
                      {r.error && <div style={{ color: '#f44336', fontSize: '0.85em' }}>{r.error}</div>}
                    </td>
                    <td>
                      <button className="btn-small btn-secondary" onClick={() => toggleRun(r.id)}>
                        {expandedRunId === r.id ? 'Hide details' : 'Details'}
                      </button>
                    </td>
                  </tr>
                  {expandedRunId === r.id && (
                    <tr>
                      <td colSpan={6} style={{ background: '#fafafa' }}>
                        {!expandedRun ? <p>Loading...</p> : (expandedRun.results || []).length === 0 ? (
                          <p style={{ color: '#666', margin: 4 }}>
                            {expandedRun.status === 'RUNNING' ? 'Run in progress...' : 'No address had the SSH port open.'}
                          </p>
                        ) : (
                          <table className="data-table" style={{ fontSize: '0.85em' }}>
                            <thead>
                              <tr>
                                <th>Address</th>
                                <th>Result</th>
                                <th>Hostname</th>
                                <th>Credential</th>
                                <th>OS</th>
                                <th>Backend</th>
                                <th>Sudo</th>
                                <th>Reason / notes</th>
                              </tr>
                            </thead>
                            <tbody>
                              {(expandedRun.results || []).map((a: any) => {
                                const lbl = RESULT_LABELS[a.status] ?? { label: a.status, color: '#999' };
                                return (
                                  <tr key={a.ip}>
                                    <td><code>{a.ip}{a.port && a.port !== 22 ? `:${a.port}` : ''}</code></td>
                                    <td><span style={{ color: lbl.color, fontWeight: 'bold' }}>{lbl.label}</span></td>
                                    <td>{a.hostname ?? '-'}</td>
                                    <td>{a.credentialName ?? '-'}</td>
                                    <td>{a.osPrettyName ?? '-'}</td>
                                    <td>{a.firewallBackend ?? '-'}</td>
                                    <td>{a.sudo ?? '-'}</td>
                                    <td style={{ color: a.status === 'login_failed' || a.status === 'error' ? '#f44336' : '#666' }}>{a.reason ?? ''}</td>
                                  </tr>
                                );
                              })}
                            </tbody>
                          </table>
                        )}
                      </td>
                    </tr>
                  )}
                </Fragment>
              ))}
              {runs.length === 0 && (
                <tr><td colSpan={6} className="empty-state">No runs yet.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}
