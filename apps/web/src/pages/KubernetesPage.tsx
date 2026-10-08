import { useState, useEffect, useRef } from 'react';
import { api } from '../lib/api';
import { useAuth, hasRole } from '../lib/auth-context';

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
  const [form, setForm] = useState({ name: '', description: '', apiServerUrl: '', authType: 'kubeconfig', defaultNamespace: 'default' });
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

  useEffect(() => { load(); }, []);

  const selectCluster = async (c: any) => {
    selectedClusterIdRef.current = c.id;
    setSelectedCluster(c);
    setTab('workloads');
    setSelectedManifest(null);
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

  const createCluster = async () => {
    if (!form.name.trim() || !form.apiServerUrl.trim()) return;
    try {
      await api.k8s.createCluster({ name: form.name, description: form.description || undefined, apiServerUrl: form.apiServerUrl, authType: form.authType, defaultNamespace: form.defaultNamespace });
      setShowCreate(false);
      setForm({ name: '', description: '', apiServerUrl: '', authType: 'kubeconfig', defaultNamespace: 'default' });
      load();
    } catch (e: any) { setError(e.message); }
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
        Plan and generate Kubernetes NetworkPolicy manifests from Segmentra policies. Register clusters, discover workloads,
        and generate NetworkPolicy JSON that you can apply to your clusters using <code>kubectl</code> or your CI/CD pipeline.
      </p>

      <div style={{ padding: 12, background: '#f7f4ef', borderRadius: 8, marginBottom: 16, fontSize: '13px', color: '#5c4633', border: '1px solid #e8e0d4' }}>
        <strong>How it works:</strong> Create a policy in <a href="/policies" style={{ color: '#8b6914' }}>Policy Sets</a>,
        then use "Generate NetworkPolicy" here to translate the rules into K8s NetworkPolicy manifests.
        Copy the <code>kubectl apply</code> command or download the JSON to apply it to your cluster.
        Full K8s API integration (direct apply from Segmentra) is planned for a future release.
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
          <p style={{ fontSize: '12.5px', color: '#78644e', marginBottom: 12 }}>Register a cluster to track its workloads and generate NetworkPolicy manifests.</p>
          <div className="form-grid" style={{ gridTemplateColumns: '1fr 1fr' }}>
            <div className="form-group"><label>Cluster Name *</label><input value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} placeholder="e.g., Production EKS" /></div>
            <div className="form-group"><label>API Server URL</label><input value={form.apiServerUrl} onChange={e => setForm(f => ({ ...f, apiServerUrl: e.target.value }))} placeholder="e.g., https://k8s-api.company.com:6443" /></div>
            <div className="form-group"><label>Description</label><input value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))} placeholder="Optional description" /></div>
            <div className="form-group"><label>Auth Type</label>
              <select value={form.authType} onChange={e => setForm(f => ({ ...f, authType: e.target.value }))}>
                <option value="kubeconfig">Kubeconfig</option>
                <option value="service_account">Service Account</option>
                <option value="token">Bearer Token</option>
              </select>
            </div>
            <div className="form-group"><label>Default Namespace</label><input value={form.defaultNamespace} onChange={e => setForm(f => ({ ...f, defaultNamespace: e.target.value }))} /></div>
          </div>
          <div className="form-actions" style={{ marginTop: 12 }}>
            <button onClick={createCluster} className="btn-primary" disabled={!form.name.trim()}>Register Cluster</button>
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
              <div style={{ fontSize: '11.5px', color: '#97846c', marginTop: 2 }}>{c.api_server_url}</div>
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
                <table className="data-table">
                  <thead><tr><th>Namespace</th><th>Kind</th><th>Name</th><th>Labels</th><th>Tags</th><th>IPs</th></tr></thead>
                  <tbody>
                    {workloads.map(w => (
                      <tr key={w.id}>
                        <td>{w.namespace}</td>
                        <td style={{ fontSize: '12.5px' }}>{w.kind}</td>
                        <td><strong>{w.name}</strong></td>
                        <td style={{ fontSize: '11.5px' }}>{Object.entries(w.labels || {}).map(([k, v]) => <span key={k} style={{ display: 'inline-block', padding: '1px 6px', background: '#f0ebe2', borderRadius: 4, marginRight: 3, marginBottom: 2 }}>{k}={String(v)}</span>) || '-'}</td>
                        <td style={{ fontSize: '12px' }}>{w.tag_names?.join(', ') || '-'}</td>
                        <td style={{ fontSize: '11.5px' }}><code>{w.pod_ips?.join(', ') || w.service_cluster_ip || '-'}</code></td>
                      </tr>
                    ))}
                    {workloads.length === 0 && <tr><td colSpan={6} className="empty-state">No workloads discovered. Workloads are populated via the API or sync.</td></tr>}
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
                <div className="card">
                  <table className="data-table">
                    <thead><tr><th>Namespace</th><th>Policy Name</th><th>Source Policy</th><th>Status</th><th>Generated</th><th>Actions</th></tr></thead>
                    <tbody>
                      {networkPolicies.map(np => (
                        <tr key={np.id} style={{ background: selectedManifest?.id === np.id ? '#f0ebe2' : undefined }}>
                          <td>{np.namespace}</td>
                          <td><strong>{np.policy_name}</strong></td>
                          <td style={{ fontSize: '12.5px' }}>{np.policy_set_name ? `${np.policy_set_name} v${np.version_number}` : '-'}</td>
                          <td><span style={{ color: '#8b6914', fontWeight: 600, fontSize: '12.5px' }}>Generated</span></td>
                          <td style={{ fontSize: '12px', color: '#97846c' }}>{np.deployed_at ? new Date(np.deployed_at).toLocaleString() : '-'}</td>
                          <td>
                            <div style={{ display: 'flex', gap: 4 }}>
                              <button onClick={() => generateManifest(np)} className="btn-small btn-secondary">View</button>
                              <button onClick={() => copyKubectl(typeof np.manifest === 'string' ? JSON.parse(np.manifest) : np.manifest, np.policy_name)} className="btn-small btn-primary" style={{ fontSize: '11px' }}>Copy kubectl</button>
                              <button onClick={() => downloadManifest(typeof np.manifest === 'string' ? JSON.parse(np.manifest) : np.manifest, np.policy_name)} className="btn-small btn-secondary" style={{ fontSize: '11px' }}>Download</button>
                            </div>
                          </td>
                        </tr>
                      ))}
                      {networkPolicies.length === 0 && <tr><td colSpan={6} className="empty-state">No NetworkPolicy manifests generated yet. Use "Generate NetworkPolicy" above with an approved or deployed Segmentra policy version.</td></tr>}
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
                      <strong>To apply this policy to your cluster:</strong>
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
