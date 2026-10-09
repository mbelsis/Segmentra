import { useState, useEffect, useRef } from 'react';
import { api } from '../lib/api';
import { useAuth, hasRole } from '../lib/auth-context';
import { K8S_AUTH_TYPES, K8sCredentialFields } from '../components/K8sCredentialFields';

export function KubernetesPage() {
  const { roles } = useAuth();
  // Cluster create/update/delete is admin-only in the API
  const isAdmin = hasRole(roles, 'admin');
  // Generating NetworkPolicy manifests is operator/admin in the API
  const canGenerate = hasRole(roles, 'operator') || isAdmin;
  // Latest cluster selection; responses for any other cluster are stale and ignored
  const selectedClusterIdRef = useRef<string | null>(null);
  const workloadsRequestId = useRef(0);
  const [clusters, setClusters] = useState<any[]>([]);
  const [selectedCluster, setSelectedCluster] = useState<any>(null);
  const [workloads, setWorkloads] = useState<any[]>([]);
  const [networkPolicies, setNetworkPolicies] = useState<any[]>([]);
  const [namespaces, setNamespaces] = useState<any[]>([]);
  const [selectedNamespace, setSelectedNamespace] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [showCreate, setShowCreate] = useState(false);
  const [tab, setTab] = useState<'workloads' | 'policies'>('workloads');
  const [selectedManifest, setSelectedManifest] = useState<any>(null);
  const emptyForm = { name: '', description: '', apiServerUrl: '', authType: 'kubeconfig', cni: 'unknown', defaultNamespace: 'default', credentials: '', caCert: '', tlsSkipVerify: false };
  const [form, setForm] = useState(emptyForm);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{ ok: boolean; text: string } | null>(null);
  const [showCreds, setShowCreds] = useState(false);
  const [credForm, setCredForm] = useState({ credentials: '', caCert: '', tlsSkipVerify: false });
  const [busyPolicy, setBusyPolicy] = useState<string | null>(null);
  const [policyMsg, setPolicyMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [showAddWorkload, setShowAddWorkload] = useState(false);
  const [wlForm, setWlForm] = useState({ namespace: 'default', kind: 'Pod', name: '', labels: '' });
  const [allTags, setAllTags] = useState<any[]>([]);
  const [showGenerate, setShowGenerate] = useState(false);
  const [deployableVersions, setDeployableVersions] = useState<Array<{ id: string; label: string }>>([]);
  const [genForm, setGenForm] = useState({ policyVersionId: '', namespace: 'default', policyName: '' });
  const [genWarnings, setGenWarnings] = useState<string[]>([]);
  const [generating, setGenerating] = useState(false);

  // NetworkPolicies can only be generated from APPROVED or DEPLOYED versions
  const openGenerate = async () => {
    setShowGenerate(true);
    setGenWarnings([]);
    setGenForm(f => ({ ...f, namespace: selectedCluster?.default_namespace || 'default' }));
    try {
      const { policySets } = await api.policySets();
      const lists = await Promise.all(policySets.map(async (ps: any) => {
        const { versions } = await api.versions(ps.id);
        return versions
          .filter((v: any) => v.status === 'APPROVED' || v.status === 'DEPLOYED')
          .map((v: any) => ({ id: v.id, label: `${ps.name} v${v.version_number} (${v.status})` }));
      }));
      setDeployableVersions(lists.flat());
    } catch (e: any) { setError(e.message); }
  };

  const generateNetworkPolicy = async () => {
    if (!selectedCluster || !genForm.policyVersionId || !genForm.namespace.trim() || !genForm.policyName.trim()) return;
    setGenerating(true);
    setError('');
    try {
      const res: any = await api.k8s.deployPolicy(selectedCluster.id, {
        policyVersionId: genForm.policyVersionId,
        namespace: genForm.namespace.trim(),
        policyName: genForm.policyName.trim()
      });
      setGenWarnings(res.warnings || []);
      if (!res.warnings?.length) setShowGenerate(false);
      const npRes = await api.k8s.networkPolicies(selectedCluster.id);
      setNetworkPolicies(npRes.networkPolicies);
    } catch (e: any) { setError(e.message); }
    setGenerating(false);
  };

  const load = async () => {
    setLoading(true);
    try {
      const res = await api.k8s.clusters();
      setClusters(res.clusters);
    } catch (e: any) { setError(e.message); }
    setLoading(false);
  };

  useEffect(() => { load(); api.tags().then(r => setAllTags(r.tags)).catch(() => {}); }, []);

  const selectCluster = async (c: any) => {
    selectedClusterIdRef.current = c.id;
    setSelectedCluster(c);
    setTab('workloads');
    setSelectedManifest(null);
    setTestResult(null); setPolicyMsg(null); setShowCreds(false); setShowAddWorkload(false);
    // Namespaces belong to a cluster: reset filter and clear old cluster data
    setSelectedNamespace('');
    setNamespaces([]);
    setWorkloads([]);
    setNetworkPolicies([]);
    try {
      const [res, npRes] = await Promise.all([api.k8s.cluster(c.id), api.k8s.networkPolicies(c.id)]);
      if (selectedClusterIdRef.current !== c.id) return; // user switched clusters meanwhile
      setNamespaces(res.namespaces);
      setNetworkPolicies(npRes.networkPolicies);
    } catch (e: any) {
      if (selectedClusterIdRef.current === c.id) setError(e.message);
    }
  };

  // Load workloads whenever the cluster or namespace filter changes; ignore stale responses
  const selectedClusterId = selectedCluster?.id as string | undefined;
  useEffect(() => {
    if (!selectedClusterId) return;
    const requestId = ++workloadsRequestId.current;
    api.k8s.workloads(selectedClusterId, { namespace: selectedNamespace || undefined })
      .then(res => { if (requestId === workloadsRequestId.current) setWorkloads(res.workloads); })
      .catch((e: any) => { if (requestId === workloadsRequestId.current) setError(e.message); });
  }, [selectedClusterId, selectedNamespace]);

  // A kubeconfig carries the API server URL; tokens need it typed in.
  const createNeedsUrl = !(form.authType === 'kubeconfig' && form.credentials.trim());
  const createCluster = async () => {
    if (!form.name.trim() || (createNeedsUrl && !form.apiServerUrl.trim())) return;
    try {
      await api.k8s.createCluster({
        name: form.name, description: form.description || undefined, apiServerUrl: form.apiServerUrl.trim() || undefined,
        authType: form.authType, cni: form.cni, defaultNamespace: form.defaultNamespace,
        credentials: form.credentials.trim() || undefined, caCert: form.caCert.trim() || undefined, tlsSkipVerify: form.tlsSkipVerify,
      });
      setShowCreate(false);
      setForm(emptyForm);
      load();
    } catch (e: any) { setError(e.message); }
  };

  const refreshCluster = async (id: string) => {
    const res = await api.k8s.cluster(id);
    if (selectedClusterIdRef.current === id) setSelectedCluster(res.cluster);
    setClusters(cs => cs.map(c => (c.id === id ? { ...c, ...res.cluster } : c)));
  };
  const refreshPolicies = async (id: string) => {
    const npRes = await api.k8s.networkPolicies(id);
    if (selectedClusterIdRef.current === id) setNetworkPolicies(npRes.networkPolicies);
  };
  const refreshWorkloads = async () => {
    if (!selectedClusterId) return;
    const res = await api.k8s.workloads(selectedClusterId, { namespace: selectedNamespace || undefined });
    setWorkloads(res.workloads);
    const c = await api.k8s.cluster(selectedClusterId);
    setNamespaces(c.namespaces);
  };

  const testConnection = async () => {
    if (!selectedCluster) return;
    setTesting(true); setTestResult(null);
    try {
      const r = await api.k8s.testConnection(selectedCluster.id);
      setTestResult({ ok: true, text: `Connected, Kubernetes ${r.serverVersion}` });
    } catch (e: any) { setTestResult({ ok: false, text: e.message }); }
    await refreshCluster(selectedCluster.id).catch(() => {});
    setTesting(false);
  };

  const saveCredentials = async () => {
    if (!selectedCluster || !credForm.credentials.trim()) return;
    try {
      await api.k8s.updateCluster(selectedCluster.id, {
        credentials: credForm.credentials.trim(),
        ...(credForm.caCert.trim() ? { caCert: credForm.caCert.trim() } : {}),
        tlsSkipVerify: credForm.tlsSkipVerify,
      });
      setShowCreds(false); setCredForm({ credentials: '', caCert: '', tlsSkipVerify: false }); setTestResult(null);
      await refreshCluster(selectedCluster.id);
    } catch (e: any) { setError(e.message); }
  };

  const removeCredentials = async () => {
    if (!selectedCluster || !confirm('Remove the stored credentials? Segmentra will no longer be able to apply policies to this cluster.')) return;
    try {
      await api.k8s.updateCluster(selectedCluster.id, { credentials: null, caCert: null });
      setTestResult(null);
      await refreshCluster(selectedCluster.id);
    } catch (e: any) { setError(e.message); }
  };

  const npWarnings = (np: any): string[] => (Array.isArray(np.warnings) ? np.warnings : []);

  const applyPolicy = async (np: any, opts: { dryRun?: boolean; overwrite?: boolean } = {}) => {
    if (!selectedCluster) return;
    if (!opts.dryRun && !opts.overwrite) {
      const w = npWarnings(np);
      const msg = `Apply NetworkPolicy "${np.policy_name}" to namespace "${np.namespace}" on cluster "${selectedCluster.name}"?\n\n` +
        `Once applied, only the traffic allowed by this policy can reach the pods in that namespace; everything else inbound is denied.` +
        (w.length ? `\n\nWarnings:\n- ${w.join('\n- ')}` : '');
      if (!confirm(msg)) return;
    }
    setBusyPolicy(np.id); setPolicyMsg(null);
    try {
      const r = await api.k8s.applyPolicy(selectedCluster.id, np.id, opts);
      setPolicyMsg({ ok: true, text: opts.dryRun ? `Dry run OK: ${r.message}` : `Applied ${np.policy_name}${r.replaced ? ' (updated the existing policy)' : ' (created)'}` });
    } catch (e: any) {
      if (/not created by Segmentra/i.test(e.message) && !opts.overwrite && !opts.dryRun
          && confirm(`${e.message}\n\nOverwrite it with the Segmentra policy?`)) {
        setBusyPolicy(null);
        return applyPolicy(np, { ...opts, overwrite: true });
      }
      setPolicyMsg({ ok: false, text: e.message });
    }
    await refreshPolicies(selectedCluster.id).catch(() => {});
    setBusyPolicy(null);
  };

  const checkPolicy = async (np: any) => {
    if (!selectedCluster) return;
    setBusyPolicy(np.id); setPolicyMsg(null);
    try {
      const r = await api.k8s.checkPolicy(selectedCluster.id, np.id);
      setPolicyMsg({ ok: r.state === 'IN_SYNC', text: r.state === 'IN_SYNC' ? `${np.policy_name} matches the cluster` : r.state === 'DRIFTED' ? `${np.policy_name} on the cluster differs from Segmentra's manifest; apply again to repair it` : `${np.policy_name} does not exist on the cluster` });
    } catch (e: any) { setPolicyMsg({ ok: false, text: e.message }); }
    await refreshPolicies(selectedCluster.id).catch(() => {});
    setBusyPolicy(null);
  };

  const removePolicy = async (np: any) => {
    if (!selectedCluster || !confirm(`Remove NetworkPolicy "${np.policy_name}" from namespace "${np.namespace}" on cluster "${selectedCluster.name}"?\n\nInbound traffic to those pods is no longer restricted by this policy.`)) return;
    setBusyPolicy(np.id); setPolicyMsg(null);
    try {
      const r = await api.k8s.removePolicy(selectedCluster.id, np.id);
      setPolicyMsg({ ok: true, text: r.alreadyAbsent ? `${np.policy_name} was already absent from the cluster` : `Removed ${np.policy_name} from the cluster` });
    } catch (e: any) { setPolicyMsg({ ok: false, text: e.message }); }
    await refreshPolicies(selectedCluster.id).catch(() => {});
    setBusyPolicy(null);
  };

  const parseLabels = (text: string): Record<string, string> => {
    const out: Record<string, string> = {};
    for (const line of text.split(/[\n,]/)) {
      const t = line.trim();
      if (!t) continue;
      const i = t.indexOf('=');
      if (i > 0) out[t.slice(0, i).trim()] = t.slice(i + 1).trim();
    }
    return out;
  };

  const addWorkload = async () => {
    if (!selectedCluster || !wlForm.namespace.trim() || !wlForm.name.trim()) return;
    try {
      await api.k8s.createWorkload(selectedCluster.id, { namespace: wlForm.namespace.trim(), kind: wlForm.kind, name: wlForm.name.trim(), labels: parseLabels(wlForm.labels) });
      setShowAddWorkload(false); setWlForm(f => ({ ...f, name: '', labels: '' }));
      await refreshWorkloads();
    } catch (e: any) { setError(e.message); }
  };
  const mapTag = async (w: any, tagId: string) => {
    if (!tagId) return;
    try { await api.k8s.mapWorkloadTag(w.id, tagId); await refreshWorkloads(); } catch (e: any) { setError(e.message); }
  };
  const unmapTag = async (w: any, tagId: string) => {
    try { await api.k8s.unmapWorkloadTag(w.id, tagId); await refreshWorkloads(); } catch (e: any) { setError(e.message); }
  };
  const deleteWorkload = async (w: any) => {
    if (!confirm(`Remove workload "${w.name}" from Segmentra? The cluster is not touched.`)) return;
    try { await api.k8s.deleteWorkload(w.id); await refreshWorkloads(); } catch (e: any) { setError(e.message); }
  };

  const deleteCluster = async (id: string) => {
    if (!confirm('Delete this cluster and all its workloads/policies?')) return;
    try {
      await api.k8s.deleteCluster(id);
      if (selectedCluster?.id === id) { selectedClusterIdRef.current = null; setSelectedCluster(null); setWorkloads([]); setNetworkPolicies([]); setNamespaces([]); setSelectedNamespace(''); }
      load();
    } catch (e: any) { setError(e.message); }
  };

  // Generate manifest and show it for copy/download
  const generateManifest = async (np: any) => {
    const manifest = typeof np.manifest === 'string' ? JSON.parse(np.manifest) : np.manifest;
    setSelectedManifest({ ...np, manifestObj: manifest });
  };

  const copyKubectl = (manifest: any, name: string) => {
    const json = JSON.stringify(manifest, null, 2);
    const cmd = `cat <<'EOF' | kubectl apply -f -\n${json}\nEOF`;
    navigator.clipboard.writeText(cmd);
    alert(`kubectl command copied to clipboard for "${name}"`);
  };

  const downloadManifest = (manifest: any, name: string) => {
    const json = JSON.stringify(manifest, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${name}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  if (loading) return <div>Loading...</div>;

  return (
    <div>
      <h2>Kubernetes Microsegmentation</h2>
      <p style={{ color: '#78644e', fontSize: '13.5px', marginTop: -4, marginBottom: 16, lineHeight: 1.6 }}>
        Generate Kubernetes NetworkPolicy manifests from Segmentra policies and apply them to your clusters. Register a cluster with
        its credentials (stored encrypted), register the workloads you want to select by label, then generate, apply, check and remove
        NetworkPolicies from here. You can still copy the <code>kubectl</code> command or download the JSON.
      </p>

      <div style={{ padding: 12, background: '#f7f4ef', borderRadius: 8, marginBottom: 16, fontSize: '13px', color: '#5c4633', border: '1px solid #e8e0d4' }}>
        <strong>How it works:</strong> Create a policy in <a href="/policies" style={{ color: '#8b6914' }}>Policy Sets</a>,
        then use "Generate NetworkPolicy" here to translate the rules into K8s NetworkPolicy manifests.
        Use <strong>Apply</strong> to create or update it on the cluster (needs stored credentials), or copy the <code>kubectl apply</code>
        command / download the JSON to apply it yourself. <strong>Check</strong> detects drift and <strong>Remove</strong> deletes it from the cluster.
      </div>

      {error && <div style={{ color: '#a63d2f', marginBottom: 12, padding: 10, background: '#faf0ee', borderRadius: 8, borderLeft: '4px solid #a63d2f' }}>{error} <button onClick={() => setError('')} className="btn-small btn-secondary" style={{ marginLeft: 8 }}>dismiss</button></div>}

      {isAdmin && (
      <div style={{ marginBottom: 16 }}>
        <button onClick={() => setShowCreate(true)} className="btn-primary">+ Add Cluster</button>
      </div>
      )}

      {isAdmin && showCreate && (
        <div className="card" style={{ border: '2px solid #8b6914' }}>
          <h3>Register Kubernetes Cluster</h3>
          <p style={{ fontSize: '12.5px', color: '#78644e', marginBottom: 12 }}>Register a cluster to generate NetworkPolicy manifests and, with credentials, apply them to the cluster.</p>
          <div className="form-grid" style={{ gridTemplateColumns: '1fr 1fr' }}>
            <div className="form-group"><label>Cluster Name *</label><input value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} placeholder="e.g., Production EKS" /></div>
            <div className="form-group"><label>API Server URL{createNeedsUrl ? ' *' : ''}</label><input value={form.apiServerUrl} onChange={e => setForm(f => ({ ...f, apiServerUrl: e.target.value }))} placeholder={createNeedsUrl ? 'e.g., https://k8s-api.company.com:6443' : 'taken from the kubeconfig'} disabled={!createNeedsUrl} /></div>
            <div className="form-group"><label>Description</label><input value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))} placeholder="Optional description" /></div>
            <div className="form-group"><label>Auth Type</label>
              <select value={form.authType} onChange={e => setForm(f => ({ ...f, authType: e.target.value, credentials: '' }))}>
                {K8S_AUTH_TYPES.map(t => <option key={t.value} value={t.value}>{t.label}</option>)}
              </select>
            </div>
            <div className="form-group"><label>CNI Plugin</label>
              <select value={form.cni} onChange={e => setForm(f => ({ ...f, cni: e.target.value }))}>
                <option value="unknown">Unknown</option>
                <option value="calico">Calico</option>
                <option value="cilium">Cilium</option>
                <option value="kindnet">kindnet</option>
                <option value="antrea">Antrea</option>
                <option value="weave">Weave Net</option>
                <option value="kube-router">kube-router</option>
                <option value="other">Other</option>
              </select>
            </div>
            <div className="form-group"><label>Default Namespace</label><input value={form.defaultNamespace} onChange={e => setForm(f => ({ ...f, defaultNamespace: e.target.value }))} /></div>
          </div>
          <div style={{ marginTop: 8 }}>
            <K8sCredentialFields authType={form.authType} resetKey={String(showCreate)} onChange={(credentials) => setForm(f => (f.credentials === credentials ? f : { ...f, credentials }))} />
            <div style={{ fontSize: '11.5px', color: '#97846c', marginTop: 2, marginBottom: 8 }}>Optional, needed to apply from Segmentra. Stored encrypted and never shown again. The account needs get/list/create/patch/delete on <code>networkpolicies</code>; see the docs for a minimal ClusterRole.</div>
          </div>
          {form.authType !== 'kubeconfig' && (
            <div className="form-group">
              <label>API server CA certificate (PEM, optional)</label>
              <textarea rows={3} value={form.caCert} onChange={e => setForm(f => ({ ...f, caCert: e.target.value }))} spellCheck={false} style={{ fontFamily: 'monospace', fontSize: '12px' }} placeholder="-----BEGIN CERTIFICATE-----" />
            </div>
          )}
          <label style={{ display: 'flex', gap: 6, alignItems: 'center', fontSize: '12.5px', color: '#78644e' }}>
            <input type="checkbox" checked={form.tlsSkipVerify} onChange={e => setForm(f => ({ ...f, tlsSkipVerify: e.target.checked }))} style={{ width: 'auto' }} />
            Skip TLS certificate verification (insecure; prefer providing the CA certificate)
          </label>
          <div className="form-actions" style={{ marginTop: 12 }}>
            <button onClick={createCluster} className="btn-primary" disabled={!form.name.trim() || (createNeedsUrl && !form.apiServerUrl.trim())}>Register Cluster</button>
            <button onClick={() => setShowCreate(false)} className="btn-secondary">Cancel</button>
          </div>
        </div>
      )}

      <div style={{ display: 'flex', gap: 20 }}>
        {/* Cluster sidebar */}
        <div style={{ width: 270, flexShrink: 0 }}>
          <h4 style={{ color: '#5c4633', marginTop: 0, marginBottom: 12 }}>Clusters</h4>
          {clusters.map(c => (
            <div key={c.id} onClick={() => selectCluster(c)}
              style={{ padding: '10px 12px', cursor: 'pointer', marginBottom: 6, borderRadius: 8,
                background: selectedCluster?.id === c.id ? '#f0ebe2' : '#fdfcf9',
                border: `1px solid ${selectedCluster?.id === c.id ? '#d4c9b8' : '#e8e0d4'}` }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <strong style={{ fontSize: '13.5px', color: '#3d2e1e' }}>{c.name}</strong>
                <span style={{ fontSize: '11px', padding: '1px 6px', borderRadius: 4, background: c.enabled ? '#eef4e8' : '#f0ebe2', color: c.enabled ? '#5a7a3a' : '#97846c' }}>
                  {c.enabled ? 'Active' : 'Off'}
                </span>
              </div>
              <div style={{ fontSize: '11.5px', color: '#97846c', marginTop: 2 }}>{c.api_server_url}{c.cni && c.cni !== 'unknown' ? ` · ${c.cni}` : ''}{c.has_credentials ? ' · credentials stored' : ''}</div>
              <div style={{ marginTop: 6, display: 'flex', gap: 4 }}>
                {isAdmin && <button onClick={(e) => { e.stopPropagation(); deleteCluster(c.id); }} className="btn-small btn-danger" style={{ padding: '2px 8px', minHeight: 'auto', fontSize: '11px' }}>Delete</button>}
              </div>
            </div>
          ))}
          {clusters.length === 0 && <p style={{ color: '#97846c', fontSize: '13px', fontStyle: 'italic' }}>No clusters registered.</p>}
        </div>

        {/* Cluster content */}
        {selectedCluster && (
          <div style={{ flex: 1 }}>
            <div className="card" style={{ marginBottom: 12 }}>
              <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
                <strong style={{ color: '#3d2e1e' }}>{selectedCluster.name}</strong>
                <span style={{ fontSize: '12px', padding: '1px 8px', borderRadius: 4, background: selectedCluster.has_credentials ? '#eef4e8' : '#f0ebe2', color: selectedCluster.has_credentials ? '#5a7a3a' : '#97846c' }}>
                  {selectedCluster.has_credentials ? 'Credentials stored (encrypted)' : 'No credentials: manifests can only be applied manually'}
                </span>
                {selectedCluster.tls_skip_verify && <span style={{ fontSize: '12px', color: '#a63d2f' }}>TLS verification disabled</span>}
                {selectedCluster.last_sync_status && <span style={{ fontSize: '11.5px', color: '#97846c' }}>last test: {selectedCluster.last_sync_status}</span>}
                <span style={{ marginLeft: 'auto', display: 'flex', gap: 6 }}>
                  {canGenerate && selectedCluster.has_credentials && <button onClick={testConnection} disabled={testing} className="btn-small btn-secondary">{testing ? 'Testing...' : 'Test connection'}</button>}
                  {isAdmin && <button onClick={() => { setShowCreds(s => !s); setCredForm({ credentials: '', caCert: '', tlsSkipVerify: !!selectedCluster.tls_skip_verify }); }} className="btn-small btn-secondary">{selectedCluster.has_credentials ? 'Replace credentials' : 'Add credentials'}</button>}
                  {isAdmin && selectedCluster.has_credentials && <button onClick={removeCredentials} className="btn-small btn-danger">Remove credentials</button>}
                </span>
              </div>
              {testResult && <div style={{ marginTop: 8, fontSize: '12.5px', color: testResult.ok ? '#5a7a3a' : '#a63d2f' }}>{testResult.text}</div>}
              {isAdmin && showCreds && (
                <div style={{ marginTop: 12 }}>
                  <K8sCredentialFields authType={selectedCluster.auth_type} resetKey={`${selectedCluster.id}:${showCreds}`} onChange={(credentials) => setCredForm(f => (f.credentials === credentials ? f : { ...f, credentials }))} />
                  {selectedCluster.auth_type !== 'kubeconfig' && (
                    <div className="form-group">
                      <label>API server CA certificate (PEM, leave empty to keep the stored one)</label>
                      <textarea rows={3} value={credForm.caCert} onChange={e => setCredForm(f => ({ ...f, caCert: e.target.value }))} spellCheck={false} style={{ fontFamily: 'monospace', fontSize: '12px' }} />
                    </div>
                  )}
                  <label style={{ display: 'flex', gap: 6, alignItems: 'center', fontSize: '12.5px', color: '#78644e' }}>
                    <input type="checkbox" checked={credForm.tlsSkipVerify} onChange={e => setCredForm(f => ({ ...f, tlsSkipVerify: e.target.checked }))} style={{ width: 'auto' }} />
                    Skip TLS certificate verification (insecure)
                  </label>
                  <div className="form-actions" style={{ marginTop: 8 }}>
                    <button onClick={saveCredentials} className="btn-primary" disabled={!credForm.credentials.trim()}>Save credentials</button>
                    <button onClick={() => setShowCreds(false)} className="btn-secondary">Cancel</button>
                  </div>
                </div>
              )}
            </div>
            <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
              <button onClick={() => { setTab('workloads'); setSelectedManifest(null); }} className={tab === 'workloads' ? 'btn-primary' : 'btn-secondary'}>Workloads</button>
              <button onClick={() => { setTab('policies'); setSelectedManifest(null); }} className={tab === 'policies' ? 'btn-primary' : 'btn-secondary'}>Network Policies</button>
              {tab === 'workloads' && (
                <select value={selectedNamespace} onChange={e => setSelectedNamespace(e.target.value)} style={{ marginLeft: 'auto' }}>
                  <option value="">All Namespaces</option>
                  {namespaces.map(n => <option key={n.namespace} value={n.namespace}>{n.namespace} ({n.count})</option>)}
                </select>
              )}
            </div>

            {tab === 'workloads' && (
              <div className="card">
                <p style={{ fontSize: '12.5px', color: '#78644e', marginTop: 0 }}>
                  Register the workloads that should be selected by <strong>pod labels</strong> and map them to Segmentra tags. A rule whose source is such a tag then
                  allows those pods by <code>namespaceSelector</code> + <code>podSelector</code>, which works on every CNI (IP ranges do not match in-cluster pods on Cilium).
                </p>
                {canGenerate && !showAddWorkload && <div style={{ marginBottom: 10 }}><button onClick={() => { setShowAddWorkload(true); setWlForm(f => ({ ...f, namespace: selectedNamespace || selectedCluster.default_namespace || 'default' })); }} className="btn-primary">+ Add workload</button></div>}
                {showAddWorkload && (
                  <div style={{ border: '1px solid #d4c9b8', borderRadius: 8, padding: 12, marginBottom: 12 }}>
                    <div className="form-grid" style={{ gridTemplateColumns: '1fr 1fr 1fr' }}>
                      <div className="form-group"><label>Namespace *</label><input value={wlForm.namespace} onChange={e => setWlForm(f => ({ ...f, namespace: e.target.value }))} /></div>
                      <div className="form-group"><label>Kind</label>
                        <select value={wlForm.kind} onChange={e => setWlForm(f => ({ ...f, kind: e.target.value }))}>
                          {['Pod', 'Deployment', 'StatefulSet', 'DaemonSet', 'Service'].map(k => <option key={k} value={k}>{k}</option>)}
                        </select>
                      </div>
                      <div className="form-group"><label>Name *</label><input value={wlForm.name} onChange={e => setWlForm(f => ({ ...f, name: e.target.value }))} placeholder="e.g., web-frontend" /></div>
                    </div>
                    <div className="form-group">
                      <label>Pod labels (one key=value per line)</label>
                      <textarea rows={3} value={wlForm.labels} onChange={e => setWlForm(f => ({ ...f, labels: e.target.value }))} placeholder={'app=web\ntier=frontend'} style={{ fontFamily: 'monospace', fontSize: '12px' }} />
                      <div style={{ fontSize: '11.5px', color: '#97846c', marginTop: 2 }}>For a Deployment use the pod template labels. At least one label is needed: an empty selector would match every pod in the namespace.</div>
                    </div>
                    <div className="form-actions">
                      <button onClick={addWorkload} className="btn-primary" disabled={!wlForm.namespace.trim() || !wlForm.name.trim() || Object.keys(parseLabels(wlForm.labels)).length === 0}>Save workload</button>
                      <button onClick={() => setShowAddWorkload(false)} className="btn-secondary">Cancel</button>
                    </div>
                  </div>
                )}
                <table className="data-table">
                  <thead><tr><th>Namespace</th><th>Kind</th><th>Name</th><th>Labels</th><th>Tags</th><th>IPs</th>{canGenerate && <th></th>}</tr></thead>
                  <tbody>
                    {workloads.map(w => (
                      <tr key={w.id}>
                        <td>{w.namespace}</td>
                        <td style={{ fontSize: '12.5px' }}>{w.kind}</td>
                        <td><strong>{w.name}</strong></td>
                        <td style={{ fontSize: '11.5px' }}>{Object.entries(w.labels || {}).map(([k, v]) => <span key={k} style={{ display: 'inline-block', padding: '1px 6px', background: '#f0ebe2', borderRadius: 4, marginRight: 3, marginBottom: 2 }}>{k}={String(v)}</span>) || '-'}</td>
                        <td style={{ fontSize: '12px' }}>
                          {(w.tags || []).map((t: any) => (
                            <span key={t.id} style={{ display: 'inline-block', padding: '1px 6px', background: '#eef4e8', color: '#5a7a3a', borderRadius: 4, marginRight: 3 }}>
                              {t.name}{canGenerate && <button onClick={() => unmapTag(w, t.id)} title="Unmap tag" style={{ border: 0, background: 'none', cursor: 'pointer', color: '#5a7a3a', padding: '0 0 0 4px' }}>×</button>}
                            </span>
                          ))}
                          {!(w.tags || []).length && '-'}
                          {canGenerate && (
                            <select value="" onChange={e => mapTag(w, e.target.value)} style={{ marginLeft: 4, fontSize: '11.5px', width: 'auto' }}>
                              <option value="">+ tag</option>
                              {allTags.filter(t => !(w.tags || []).some((x: any) => x.id === t.id)).map(t => <option key={t.id} value={t.id}>{t.name}</option>)}
                            </select>
                          )}
                        </td>
                        <td style={{ fontSize: '11.5px' }}><code>{w.pod_ips?.join(', ') || w.service_cluster_ip || '-'}</code></td>
                        {canGenerate && <td><button onClick={() => deleteWorkload(w)} className="btn-small btn-danger" style={{ padding: '2px 8px', minHeight: 'auto', fontSize: '11px' }}>Delete</button></td>}
                      </tr>
                    ))}
                    {workloads.length === 0 && <tr><td colSpan={7} className="empty-state">No workloads registered. Workload discovery from the cluster is not implemented yet: add the workloads you want to select by label.</td></tr>}
                  </tbody>
                </table>
              </div>
            )}

            {tab === 'policies' && (
              <>
                {canGenerate && !showGenerate && (
                  <div style={{ marginBottom: 12 }}>
                    <button onClick={openGenerate} className="btn-primary">Generate NetworkPolicy</button>
                  </div>
                )}
                {showGenerate && (
                  <div className="card" style={{ border: '1px solid #d4c9b8' }}>
                    <h4 style={{ marginTop: 0 }}>Generate NetworkPolicy</h4>
                    <div className="form-grid">
                      <div className="form-group">
                        <label>Policy Version *</label>
                        <select value={genForm.policyVersionId} onChange={e => setGenForm(f => ({ ...f, policyVersionId: e.target.value }))}>
                          <option value="">Select an approved or deployed version</option>
                          {deployableVersions.map(v => <option key={v.id} value={v.id}>{v.label}</option>)}
                        </select>
                      </div>
                      <div className="form-group">
                        <label>Namespace *</label>
                        <input value={genForm.namespace} onChange={e => setGenForm(f => ({ ...f, namespace: e.target.value }))} />
                      </div>
                      <div className="form-group">
                        <label>NetworkPolicy Name *</label>
                        <input value={genForm.policyName} onChange={e => setGenForm(f => ({ ...f, policyName: e.target.value }))} placeholder="e.g., web-access" />
                      </div>
                    </div>
                    {genWarnings.length > 0 && (
                      <div role="note" style={{ background: '#fff8e6', border: '1px solid #f0d58c', color: '#6b5310', padding: '8px 12px', borderRadius: 6, fontSize: '0.88em', marginBottom: 12 }}>
                        <strong>Generated with warnings</strong> (rules NetworkPolicy can't express were skipped):
                        <ul style={{ margin: '6px 0 0 18px' }}>{genWarnings.map((w, i) => <li key={i}>{w}</li>)}</ul>
                      </div>
                    )}
                    <div className="form-actions">
                      <button onClick={generateNetworkPolicy} className="btn-primary" disabled={generating || !genForm.policyVersionId || !genForm.namespace.trim() || !genForm.policyName.trim()}>
                        {generating ? 'Generating...' : 'Generate'}
                      </button>
                      <button onClick={() => { setShowGenerate(false); setGenWarnings([]); }} className="btn-secondary">Close</button>
                    </div>
                  </div>
                )}
                {policyMsg && (
                  <div role="status" style={{ marginBottom: 12, padding: '8px 12px', borderRadius: 6, fontSize: '0.9em',
                    background: policyMsg.ok ? '#eef4e8' : '#faf0ee', border: `1px solid ${policyMsg.ok ? '#c9dcb8' : '#e8c4bd'}`, color: policyMsg.ok ? '#3f5a26' : '#a63d2f' }}>
                    {policyMsg.text} <button onClick={() => setPolicyMsg(null)} className="btn-small btn-secondary" style={{ marginLeft: 8 }}>dismiss</button>
                  </div>
                )}
                <div className="card">
                  <table className="data-table">
                    <thead><tr><th>Namespace</th><th>Policy Name</th><th>Source Policy</th><th>Status</th><th>On cluster</th><th>Generated</th><th>Actions</th></tr></thead>
                    <tbody>
                      {networkPolicies.map(np => (
                        <tr key={np.id} style={{ background: selectedManifest?.id === np.id ? '#f0ebe2' : undefined }}>
                          <td>{np.namespace}</td>
                          <td><strong>{np.policy_name}</strong></td>
                          <td style={{ fontSize: '12.5px' }}>{np.policy_set_name ? `${np.policy_set_name} v${np.version_number}` : '-'}</td>
                          <td>
                            {(() => {
                              const st = np.status as string;
                              const style: Record<string, { color: string; label: string }> = {
                                GENERATED: { color: '#8b6914', label: 'Generated' }, APPLIED: { color: '#3f5a26', label: 'Applied' },
                                FAILED: { color: '#a63d2f', label: 'Apply failed' }, REMOVED: { color: '#97846c', label: 'Removed' },
                                SUPERSEDED: { color: '#97846c', label: 'Superseded' },
                              };
                              const x = style[st] ?? { color: '#8b6914', label: st };
                              return <span title={np.last_error || undefined} style={{ color: x.color, fontWeight: 600, fontSize: '12.5px' }}>{x.label}</span>;
                            })()}
                            {np.applied_at && np.status === 'APPLIED' && <div style={{ fontSize: '11px', color: '#97846c' }}>{new Date(np.applied_at).toLocaleString()}</div>}
                            {np.status === 'FAILED' && np.last_error && <div style={{ fontSize: '11px', color: '#a63d2f', maxWidth: 220 }}>{np.last_error}</div>}
                            {npWarnings(np).length > 0 && <div title={npWarnings(np).join('\n')} style={{ fontSize: '11px', color: '#8b6914' }}>{npWarnings(np).length} warning{npWarnings(np).length > 1 ? 's' : ''}</div>}
                          </td>
                          <td style={{ fontSize: '12px' }}>
                            {np.live_state === 'IN_SYNC' && <span style={{ color: '#3f5a26' }}>In sync</span>}
                            {np.live_state === 'DRIFTED' && <span style={{ color: '#a63d2f', fontWeight: 600 }}>Drifted</span>}
                            {np.live_state === 'MISSING' && <span style={{ color: '#97846c' }}>Not present</span>}
                            {!np.live_state && '-'}
                            {np.live_checked_at && <div style={{ fontSize: '11px', color: '#97846c' }}>{new Date(np.live_checked_at).toLocaleTimeString()}</div>}
                          </td>
                          <td style={{ fontSize: '12px', color: '#97846c' }}>{np.deployed_at ? new Date(np.deployed_at).toLocaleString() : '-'}</td>
                          <td>
                            <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                              {canGenerate && selectedCluster?.has_credentials && np.status !== 'SUPERSEDED' && (
                                <>
                                  <button onClick={() => applyPolicy(np)} disabled={busyPolicy === np.id} className="btn-small btn-primary">{np.status === 'APPLIED' ? 'Re-apply' : 'Apply'}</button>
                                  <button onClick={() => applyPolicy(np, { dryRun: true })} disabled={busyPolicy === np.id} className="btn-small btn-secondary" style={{ fontSize: '11px' }}>Dry run</button>
                                  <button onClick={() => checkPolicy(np)} disabled={busyPolicy === np.id} className="btn-small btn-secondary" style={{ fontSize: '11px' }}>Check</button>
                                  {(np.status === 'APPLIED' || np.status === 'FAILED') && <button onClick={() => removePolicy(np)} disabled={busyPolicy === np.id} className="btn-small btn-danger" style={{ fontSize: '11px' }}>Remove</button>}
                                </>
                              )}
                              <button onClick={() => generateManifest(np)} className="btn-small btn-secondary">View</button>
                              <button onClick={() => copyKubectl(typeof np.manifest === 'string' ? JSON.parse(np.manifest) : np.manifest, np.policy_name)} className="btn-small btn-secondary" style={{ fontSize: '11px' }}>Copy kubectl</button>
                              <button onClick={() => downloadManifest(typeof np.manifest === 'string' ? JSON.parse(np.manifest) : np.manifest, np.policy_name)} className="btn-small btn-secondary" style={{ fontSize: '11px' }}>Download</button>
                            </div>
                          </td>
                        </tr>
                      ))}
                      {networkPolicies.length === 0 && <tr><td colSpan={7} className="empty-state">No NetworkPolicy manifests generated yet. Use "Generate NetworkPolicy" above with an approved or deployed Segmentra policy version.</td></tr>}
                    </tbody>
                  </table>
                </div>

                {/* Manifest viewer */}
                {selectedManifest && (
                  <div className="card" style={{ border: '1px solid #d4c9b8' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
                      <h4 style={{ margin: 0, color: '#5c4633' }}>NetworkPolicy: {selectedManifest.policy_name}</h4>
                      <div style={{ display: 'flex', gap: 8 }}>
                        <button onClick={() => copyKubectl(selectedManifest.manifestObj, selectedManifest.policy_name)} className="btn-small btn-primary">Copy kubectl apply</button>
                        <button onClick={() => downloadManifest(selectedManifest.manifestObj, selectedManifest.policy_name)} className="btn-small btn-secondary">Download JSON</button>
                        <button onClick={() => setSelectedManifest(null)} className="btn-small btn-secondary">Close</button>
                      </div>
                    </div>

                    <div style={{ padding: 12, background: '#f7f4ef', borderRadius: 6, marginBottom: 12, fontSize: '12.5px', color: '#5c4633' }}>
                      <strong>To apply this policy manually{selectedCluster?.has_credentials ? ' (or use Apply in the table)' : ''}:</strong>
                      <pre style={{ margin: '8px 0 0', padding: 10, background: '#292018', color: '#e8e0d4', borderRadius: 6, fontSize: '12px', overflow: 'auto' }}>
{`kubectl apply -f ${selectedManifest.policy_name}.json`}
                      </pre>
                    </div>

                    <pre style={{ padding: 16, background: '#292018', color: '#e8e0d4', borderRadius: 8, fontSize: '12px', overflow: 'auto', maxHeight: 400, margin: 0, fontFamily: "'JetBrains Mono', 'Fira Code', monospace" }}>
{JSON.stringify(selectedManifest.manifestObj, null, 2)}
                    </pre>

                    {selectedManifest.deployed_hash && (
                      <div style={{ marginTop: 8, fontSize: '11.5px', color: '#97846c' }}>
                        SHA-256: <code>{selectedManifest.deployed_hash}</code>
                      </div>
                    )}
                  </div>
                )}
              </>
            )}
          </div>
        )}

        {!selectedCluster && clusters.length > 0 && (
          <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#97846c', padding: 40 }}>
            Select a cluster from the sidebar.
          </div>
        )}
      </div>
    </div>
  );
}
