import { useState, useEffect } from 'react';
import { api } from '../lib/api';

export function KubernetesPage() {
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
  const [form, setForm] = useState({ name: '', description: '', apiServerUrl: '', authType: 'kubeconfig', defaultNamespace: 'default' });

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
    setSelectedCluster(c);
    setTab('workloads');
    try {
      const res = await api.k8s.cluster(c.id);
      setNamespaces(res.namespaces);
      const wRes = await api.k8s.workloads(c.id);
      setWorkloads(wRes.workloads);
      const npRes = await api.k8s.networkPolicies(c.id);
      setNetworkPolicies(npRes.networkPolicies);
    } catch (e: any) { setError(e.message); }
  };

  const filterWorkloads = async () => {
    if (!selectedCluster) return;
    try {
      const res = await api.k8s.workloads(selectedCluster.id, { namespace: selectedNamespace || undefined });
      setWorkloads(res.workloads);
    } catch (e: any) { setError(e.message); }
  };

  useEffect(() => { if (selectedCluster) filterWorkloads(); }, [selectedNamespace]);

  const createCluster = async () => {
    try {
      await api.k8s.createCluster({ name: form.name, description: form.description || undefined, apiServerUrl: form.apiServerUrl, authType: form.authType, defaultNamespace: form.defaultNamespace });
      setShowCreate(false);
      setForm({ name: '', description: '', apiServerUrl: '', authType: 'kubeconfig', defaultNamespace: 'default' });
      load();
    } catch (e: any) { setError(e.message); }
  };

  const syncCluster = async (id: string) => {
    try {
      await api.k8s.syncCluster(id);
      alert('Sync initiated');
      if (selectedCluster?.id === id) selectCluster(selectedCluster);
    } catch (e: any) { setError(e.message); }
  };

  const deleteCluster = async (id: string) => {
    if (!confirm('Delete this cluster?')) return;
    try {
      await api.k8s.deleteCluster(id);
      if (selectedCluster?.id === id) { setSelectedCluster(null); setWorkloads([]); setNetworkPolicies([]); }
      load();
    } catch (e: any) { setError(e.message); }
  };

  if (loading) return <div>Loading...</div>;

  return (
    <div>
      <h2>Kubernetes Microsegmentation</h2>
      {error && <div style={{ color: 'red', marginBottom: 8 }}>{error} <button onClick={() => setError('')}>dismiss</button></div>}

      <div style={{ marginBottom: 16 }}>
        <button onClick={() => setShowCreate(true)}>+ Add Cluster</button>
      </div>

      {showCreate && (
        <div style={{ border: '1px solid #ccc', padding: 16, marginBottom: 16, borderRadius: 4 }}>
          <h3>Add Kubernetes Cluster</h3>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
            <input placeholder="Cluster name" value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} />
            <input placeholder="API Server URL" value={form.apiServerUrl} onChange={e => setForm(f => ({ ...f, apiServerUrl: e.target.value }))} />
            <input placeholder="Description" value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))} />
            <select value={form.authType} onChange={e => setForm(f => ({ ...f, authType: e.target.value }))}>
              <option value="kubeconfig">Kubeconfig</option>
              <option value="service_account">Service Account</option>
              <option value="token">Bearer Token</option>
            </select>
            <input placeholder="Default namespace" value={form.defaultNamespace} onChange={e => setForm(f => ({ ...f, defaultNamespace: e.target.value }))} />
          </div>
          <div style={{ marginTop: 8 }}>
            <button onClick={createCluster}>Add Cluster</button>
            <button onClick={() => setShowCreate(false)} style={{ marginLeft: 8 }}>Cancel</button>
          </div>
        </div>
      )}

      <div style={{ display: 'flex', gap: 24 }}>
        <div style={{ width: 280 }}>
          <h3>Clusters</h3>
          {clusters.map(c => (
            <div key={c.id} onClick={() => selectCluster(c)}
              style={{ padding: 8, cursor: 'pointer', border: '1px solid #ccc', marginBottom: 4, borderRadius: 4, background: selectedCluster?.id === c.id ? '#e8f0fe' : 'white' }}>
              <strong>{c.name}</strong>
              <div style={{ fontSize: '0.8em', color: '#666' }}>{c.api_server_url}</div>
              <div style={{ fontSize: '0.8em' }}>
                <span style={{ color: c.enabled ? 'green' : '#999' }}>{c.enabled ? 'Active' : 'Disabled'}</span>
                {c.last_sync_status && <span> | {c.last_sync_status}</span>}
              </div>
              <div style={{ marginTop: 4 }}>
                <button onClick={(e) => { e.stopPropagation(); syncCluster(c.id); }} style={{ fontSize: '0.8em' }}>Sync</button>
                <button onClick={(e) => { e.stopPropagation(); deleteCluster(c.id); }} style={{ fontSize: '0.8em', marginLeft: 4, color: 'red' }}>Del</button>
              </div>
            </div>
          ))}
          {clusters.length === 0 && <p style={{ color: '#666' }}>No clusters</p>}
        </div>

        {selectedCluster && (
          <div style={{ flex: 1 }}>
            <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
              <button onClick={() => setTab('workloads')} style={{ fontWeight: tab === 'workloads' ? 'bold' : 'normal' }}>Workloads</button>
              <button onClick={() => setTab('policies')} style={{ fontWeight: tab === 'policies' ? 'bold' : 'normal' }}>Network Policies</button>
              <select value={selectedNamespace} onChange={e => setSelectedNamespace(e.target.value)} style={{ marginLeft: 'auto' }}>
                <option value="">All Namespaces</option>
                {namespaces.map(n => <option key={n.namespace} value={n.namespace}>{n.namespace} ({n.count})</option>)}
              </select>
            </div>

            {tab === 'workloads' && (
              <table style={{ width: '100%' }}>
                <thead><tr><th>Namespace</th><th>Kind</th><th>Name</th><th>Labels</th><th>Tags</th><th>IPs</th></tr></thead>
                <tbody>
                  {workloads.map(w => (
                    <tr key={w.id}>
                      <td>{w.namespace}</td>
                      <td>{w.kind}</td>
                      <td>{w.name}</td>
                      <td style={{ fontSize: '0.8em' }}>{Object.entries(w.labels || {}).map(([k, v]) => `${k}=${v}`).join(', ') || '-'}</td>
                      <td>{w.tag_names?.join(', ') || '-'}</td>
                      <td style={{ fontSize: '0.8em' }}>{w.pod_ips?.join(', ') || w.service_cluster_ip || '-'}</td>
                    </tr>
                  ))}
                  {workloads.length === 0 && <tr><td colSpan={6}>No workloads discovered. Try syncing the cluster.</td></tr>}
                </tbody>
              </table>
            )}

            {tab === 'policies' && (
              <table style={{ width: '100%' }}>
                <thead><tr><th>Namespace</th><th>Policy Name</th><th>Source Policy</th><th>Status</th><th>Deployed</th></tr></thead>
                <tbody>
                  {networkPolicies.map(np => (
                    <tr key={np.id}>
                      <td>{np.namespace}</td>
                      <td>{np.policy_name}</td>
                      <td>{np.policy_set_name ? `${np.policy_set_name} v${np.version_number}` : '-'}</td>
                      <td style={{ color: np.status === 'DEPLOYED' ? 'green' : '#999' }}>{np.status}</td>
                      <td>{np.deployed_at ? new Date(np.deployed_at).toLocaleString() : '-'}</td>
                    </tr>
                  ))}
                  {networkPolicies.length === 0 && <tr><td colSpan={5}>No network policies deployed</td></tr>}
                </tbody>
              </table>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
