import { useEffect, useState } from 'react';
import { api } from '../lib/api';
import { K8S_AUTH_TYPES, K8sCredentialFields } from './K8sCredentialFields';

type Form = { authType: string; apiServerUrl: string; credentials: string; caCert: string; tlsSkipVerify: boolean };

/**
 * Admin card to manage the credentials Segmentra stores (encrypted, write-only) to apply
 * NetworkPolicies to Kubernetes clusters. Clusters themselves are registered on the Kubernetes page.
 */
export function K8sCredentialsPanel() {
  const [clusters, setClusters] = useState<any[]>([]);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [editing, setEditing] = useState<any>(null);
  const [form, setForm] = useState<Form>({ authType: 'kubeconfig', apiServerUrl: '', credentials: '', caCert: '', tlsSkipVerify: false });
  const [busy, setBusy] = useState<string | null>(null);

  const load = async () => {
    try { setClusters((await api.k8s.clusters()).clusters); } catch (e: any) { setError(e.message); }
  };
  useEffect(() => { load(); }, []);

  const startEdit = (c: any) => {
    setEditing(c); setError(''); setSuccess('');
    setForm({ authType: c.auth_type, apiServerUrl: c.api_server_url, credentials: '', caCert: '', tlsSkipVerify: !!c.tls_skip_verify });
  };

  const save = async () => {
    if (!editing || !form.credentials.trim()) return;
    setBusy(editing.id); setError(''); setSuccess('');
    try {
      await api.k8s.updateCluster(editing.id, {
        authType: form.authType,
        ...(form.authType !== 'kubeconfig' ? { apiServerUrl: form.apiServerUrl.trim() } : {}),
        credentials: form.credentials.trim(),
        ...(form.caCert.trim() ? { caCert: form.caCert.trim() } : {}),
        tlsSkipVerify: form.tlsSkipVerify,
      });
      setSuccess(`Credentials saved for "${editing.name}" (encrypted)`);
      setEditing(null);
      await load();
    } catch (e: any) { setError(e.message); }
    setBusy(null);
  };

  const remove = async (c: any) => {
    if (!window.confirm(`Remove the stored credentials of cluster "${c.name}"? Segmentra will no longer be able to apply policies to it.`)) return;
    setBusy(c.id); setError(''); setSuccess('');
    try {
      await api.k8s.updateCluster(c.id, { credentials: null, caCert: null });
      setSuccess(`Credentials removed from "${c.name}"`);
      await load();
    } catch (e: any) { setError(e.message); }
    setBusy(null);
  };

  const test = async (c: any) => {
    setBusy(c.id); setError(''); setSuccess('');
    try {
      const r = await api.k8s.testConnection(c.id);
      setSuccess(`"${c.name}": connected, Kubernetes ${r.serverVersion}`);
    } catch (e: any) { setError(`"${c.name}": ${e.message}`); }
    await load();
    setBusy(null);
  };

  return (
    <div className="card">
      <h3 style={{ marginTop: 0 }}>Kubernetes Credentials</h3>
      <p style={{ marginBottom: 20, color: '#666', fontSize: '0.9em' }}>
        Credentials Segmentra uses to apply, check and remove NetworkPolicies on a Kubernetes cluster: a kubeconfig (with an inline token or
        client certificate), a service-account bearer token with the API server CA, or a cloud login for managed clusters (Amazon EKS, Google GKE, Azure AKS; not yet tested against real cloud accounts). They are encrypted like the SSH credentials above, are never
        shown again, and can only be replaced or removed. Register clusters on the <a href="/kubernetes">Kubernetes</a> page.
      </p>
      <div role="note" style={{ background: '#e3f2fd', border: '1px solid #2196F3', borderRadius: 8, padding: '10px 14px', marginBottom: 16, fontSize: '0.9em', color: '#1a4a7a' }}>
        <strong>Please add the cluster first, so you can attach credentials to it.</strong> Credentials belong to a cluster: register it on the{' '}
        <a href="/kubernetes">Kubernetes</a> page (<em>+ Add Cluster</em>), then come back here, or paste them while registering. Each cluster then appears in the table below with an <em>Add</em> button.
      </div>
      {error && <div style={{ color: '#a63d2f', marginBottom: 12 }}>{error}</div>}
      {success && <div style={{ color: '#3f5a26', marginBottom: 12 }}>{success}</div>}

      {editing && (
        <div style={{ border: '1px solid #d4c9b8', borderRadius: 8, padding: 16, marginBottom: 20 }}>
          <h4 style={{ marginTop: 0 }}>{editing.has_credentials ? 'Replace' : 'Add'} credentials for {editing.name}</h4>
          <div className="form-group">
            <label>Auth Type</label>
            <select value={form.authType} onChange={(e) => setForm((f) => ({ ...f, authType: e.target.value }))}>
              {K8S_AUTH_TYPES.map((t) => <option key={t.value} value={t.value}>{t.label}</option>)}
            </select>
          </div>
          {form.authType !== 'kubeconfig' && (
            <div className="form-group">
              <label>API Server URL *</label>
              <input value={form.apiServerUrl} onChange={(e) => setForm((f) => ({ ...f, apiServerUrl: e.target.value }))} placeholder="https://k8s-api.example.com:6443" />
            </div>
          )}
          <K8sCredentialFields authType={form.authType} resetKey={editing.id} onChange={(credentials) => setForm((f) => (f.credentials === credentials ? f : { ...f, credentials }))} />
          {form.authType !== 'kubeconfig' && (
            <div className="form-group">
              <label>API server CA certificate (PEM, leave empty to keep the stored one)</label>
              <textarea rows={4} value={form.caCert} onChange={(e) => setForm((f) => ({ ...f, caCert: e.target.value }))} spellCheck={false} style={{ fontFamily: 'monospace', fontSize: '12px' }} />
            </div>
          )}
          <label style={{ display: 'flex', gap: 6, alignItems: 'center', fontSize: '0.9em', color: '#666' }}>
            <input type="checkbox" checked={form.tlsSkipVerify} onChange={(e) => setForm((f) => ({ ...f, tlsSkipVerify: e.target.checked }))} style={{ width: 'auto' }} />
            Skip TLS certificate verification (insecure; prefer providing the CA certificate)
          </label>
          <div className="form-actions" style={{ marginTop: 12 }}>
            <button className="btn-primary" onClick={save} disabled={busy === editing.id || !form.credentials.trim() || (form.authType !== 'kubeconfig' && !form.apiServerUrl.trim())}>Save credentials</button>
            <button className="btn-secondary" onClick={() => setEditing(null)}>Cancel</button>
          </div>
        </div>
      )}

      {clusters.length > 0 ? (
        <table className="data-table">
          <thead><tr><th>Cluster</th><th>Auth</th><th>API Server</th><th>Credentials</th><th>TLS</th><th>Last test</th><th>Actions</th></tr></thead>
          <tbody>
            {clusters.map((c) => (
              <tr key={c.id}>
                <td><strong>{c.name}</strong></td>
                <td style={{ fontSize: '12.5px' }}>{c.auth_type}</td>
                <td style={{ fontSize: '12px' }}><code>{c.api_server_url}</code></td>
                <td>{c.has_credentials ? <span style={{ color: '#3f5a26' }}>Stored (encrypted){c.has_ca_cert ? ' + CA' : ''}</span> : <span style={{ color: '#97846c' }}>None</span>}</td>
                <td style={{ fontSize: '12px' }}>{c.tls_skip_verify ? <span style={{ color: '#a63d2f' }}>Not verified</span> : 'Verified'}</td>
                <td style={{ fontSize: '11.5px', color: '#97846c' }}>{c.last_sync_status ? `${c.last_sync_status}${c.last_sync_at ? ` (${new Date(c.last_sync_at).toLocaleString()})` : ''}` : '-'}</td>
                <td>
                  <div style={{ display: 'flex', gap: 4 }}>
                    {c.has_credentials && <button className="btn-small btn-secondary" disabled={busy === c.id} onClick={() => test(c)}>Test</button>}
                    <button className="btn-small btn-secondary" onClick={() => startEdit(c)}>{c.has_credentials ? 'Replace' : 'Add'}</button>
                    {c.has_credentials && <button className="btn-small btn-danger" disabled={busy === c.id} onClick={() => remove(c)}>Remove</button>}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <div style={{ padding: 40, textAlign: 'center', color: '#999' }}>
          No Kubernetes clusters registered yet, so there is nothing to attach credentials to.<br />
          <a href="/kubernetes" className="btn-primary" style={{ display: 'inline-block', marginTop: 12, textDecoration: 'none' }}>+ Add a cluster on the Kubernetes page</a>
        </div>
      )}
    </div>
  );
}
