import { useState, useEffect } from 'react';
import { api } from '../lib/api';

export function TopologyPage() {
  const [views, setViews] = useState<any[]>([]);
  const [selectedView, setSelectedView] = useState<any>(null);
  const [flows, setFlows] = useState<any[]>([]);
  const [discoveredTopology, setDiscoveredTopology] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [showCreate, setShowCreate] = useState(false);
  const [form, setForm] = useState({ name: '', description: '' });
  const [flowForm, setFlowForm] = useState({
    sourceType: 'TAG', sourceValue: '', targetType: 'TAG', targetValue: '',
    direction: 'BOTH', action: 'ALLOW', protocol: 'tcp', ports: '', comment: ''
  });

  const load = async () => {
    setLoading(true);
    try {
      const res = await api.topology.listViews();
      setViews(res.views);
    } catch (e: any) { setError(e.message); }
    setLoading(false);
  };

  useEffect(() => { load(); }, []);

  const selectView = async (v: any) => {
    setSelectedView(v);
    try {
      const res = await api.topology.getView(v.id);
      setFlows(res.flows);
    } catch (e: any) { setError(e.message); }
  };

  const createView = async () => {
    try {
      await api.topology.createView({ name: form.name, description: form.description || undefined });
      setShowCreate(false);
      setForm({ name: '', description: '' });
      load();
    } catch (e: any) { setError(e.message); }
  };

  const deleteView = async (id: string) => {
    if (!confirm('Delete this topology view?')) return;
    try {
      await api.topology.deleteView(id);
      if (selectedView?.id === id) { setSelectedView(null); setFlows([]); }
      load();
    } catch (e: any) { setError(e.message); }
  };

  const addFlow = async () => {
    if (!selectedView) return;
    try {
      await api.topology.addFlow(selectedView.id, {
        sourceType: flowForm.sourceType, sourceValue: flowForm.sourceValue,
        targetType: flowForm.targetType, targetValue: flowForm.targetValue,
        direction: flowForm.direction, action: flowForm.action,
        protocol: flowForm.protocol, ports: flowForm.ports || undefined,
        comment: flowForm.comment || undefined,
      });
      const res = await api.topology.getView(selectedView.id);
      setFlows(res.flows);
      setFlowForm({ sourceType: 'TAG', sourceValue: '', targetType: 'TAG', targetValue: '', direction: 'BOTH', action: 'ALLOW', protocol: 'tcp', ports: '', comment: '' });
    } catch (e: any) { setError(e.message); }
  };

  const removeFlow = async (flowId: string) => {
    try {
      await api.topology.deleteFlow(flowId);
      setFlows(prev => prev.filter(f => f.id !== flowId));
    } catch (e: any) { setError(e.message); }
  };

  const generatePolicies = async () => {
    if (!selectedView) return;
    try {
      const result = await api.topology.generatePolicies(selectedView.id);
      alert(`Generated ${result.policySetsCreated} policy set(s), ${result.versionsCreated} version(s), ${result.rulesCreated} rule(s)`);
    } catch (e: any) { setError(e.message); }
  };

  const autoDiscover = async () => {
    try {
      const result = await api.topology.autoDiscover();
      setDiscoveredTopology(result);
    } catch (e: any) { setError(e.message); }
  };

  if (loading) return <div>Loading...</div>;

  return (
    <div>
      <h2>Visual Topology Design</h2>
      {error && <div style={{ color: 'red', marginBottom: 8 }}>{error} <button onClick={() => setError('')}>dismiss</button></div>}

      <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
        <button onClick={() => setShowCreate(true)}>+ New View</button>
        <button onClick={autoDiscover}>Auto-Discover Topology</button>
      </div>

      {showCreate && (
        <div style={{ border: '1px solid #ccc', padding: 16, marginBottom: 16, borderRadius: 4 }}>
          <h3>Create Topology View</h3>
          <input placeholder="Name" value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} style={{ marginRight: 8 }} />
          <input placeholder="Description" value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))} style={{ marginRight: 8 }} />
          <button onClick={createView}>Create</button>
          <button onClick={() => setShowCreate(false)} style={{ marginLeft: 8 }}>Cancel</button>
        </div>
      )}

      {discoveredTopology && (
        <div style={{ border: '1px solid #2196F3', padding: 16, marginBottom: 16, borderRadius: 4, background: '#E3F2FD' }}>
          <h3>Discovered Topology</h3>
          <p><strong>Nodes:</strong> {discoveredTopology.nodes.length} | <strong>Edges:</strong> {discoveredTopology.edges.length}</p>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
            {discoveredTopology.nodes.map((n: any) => (
              <div key={n.id} style={{ border: '1px solid #90CAF9', padding: '4px 8px', borderRadius: 4, background: 'white', fontSize: '0.9em' }}>
                <strong>{n.type}</strong>: {n.label} ({n.data.hostCount} hosts)
              </div>
            ))}
          </div>
          {discoveredTopology.edges.length > 0 && (
            <table style={{ width: '100%', marginTop: 8, fontSize: '0.9em' }}>
              <thead><tr><th>Source</th><th>Target</th><th>Action</th><th>Protocol</th><th>Ports</th></tr></thead>
              <tbody>
                {discoveredTopology.edges.map((e: any, i: number) => (
                  <tr key={i}><td>{e.source}</td><td>{e.target}</td><td>{e.data.action}</td><td>{e.data.protocol}</td><td>{e.data.ports || '*'}</td></tr>
                ))}
              </tbody>
            </table>
          )}
          <button onClick={() => setDiscoveredTopology(null)} style={{ marginTop: 8 }}>Close</button>
        </div>
      )}

      <div style={{ display: 'flex', gap: 24 }}>
        <div style={{ width: 300 }}>
          <h3>Views</h3>
          {views.map(v => (
            <div key={v.id} onClick={() => selectView(v)}
              style={{ padding: 8, cursor: 'pointer', border: '1px solid #ccc', marginBottom: 4, borderRadius: 4, background: selectedView?.id === v.id ? '#e8f0fe' : 'white' }}>
              <strong>{v.name}</strong> <span style={{ fontSize: '0.8em', color: '#666' }}>({v.flow_count} flows)</span>
              <button onClick={(e) => { e.stopPropagation(); deleteView(v.id); }} style={{ float: 'right', color: 'red', fontSize: '0.8em' }}>Del</button>
            </div>
          ))}
          {views.length === 0 && <p style={{ color: '#666' }}>No topology views yet</p>}
        </div>

        {selectedView && (
          <div style={{ flex: 1 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <h3>{selectedView.name}</h3>
              <button onClick={generatePolicies} style={{ background: '#4CAF50', color: 'white', border: 'none', padding: '8px 16px', borderRadius: 4, cursor: 'pointer' }}>
                Generate Policies
              </button>
            </div>

            <table style={{ width: '100%', marginBottom: 16 }}>
              <thead><tr><th>Source</th><th>Target</th><th>Dir</th><th>Action</th><th>Proto</th><th>Ports</th><th>Comment</th><th></th></tr></thead>
              <tbody>
                {flows.map(f => (
                  <tr key={f.id}>
                    <td>{f.source_type}:{f.source_value}</td>
                    <td>{f.target_type}:{f.target_value}</td>
                    <td>{f.direction}</td>
                    <td style={{ color: f.action === 'ALLOW' ? 'green' : 'red' }}>{f.action}</td>
                    <td>{f.protocol}</td>
                    <td>{f.ports || '*'}</td>
                    <td>{f.comment || ''}</td>
                    <td><button onClick={() => removeFlow(f.id)} style={{ color: 'red' }}>X</button></td>
                  </tr>
                ))}
                {flows.length === 0 && <tr><td colSpan={8} style={{ textAlign: 'center', color: '#666' }}>No flows defined</td></tr>}
              </tbody>
            </table>

            <h4>Add Flow</h4>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 4, fontSize: '0.9em' }}>
              <select value={flowForm.sourceType} onChange={e => setFlowForm(f => ({ ...f, sourceType: e.target.value }))}>
                <option value="TAG">TAG</option><option value="VLAN">VLAN</option><option value="CIDR">CIDR</option>
              </select>
              <input placeholder="Source value" value={flowForm.sourceValue} onChange={e => setFlowForm(f => ({ ...f, sourceValue: e.target.value }))} />
              <select value={flowForm.targetType} onChange={e => setFlowForm(f => ({ ...f, targetType: e.target.value }))}>
                <option value="TAG">TAG</option><option value="VLAN">VLAN</option><option value="CIDR">CIDR</option>
              </select>
              <input placeholder="Target value" value={flowForm.targetValue} onChange={e => setFlowForm(f => ({ ...f, targetValue: e.target.value }))} />
              <select value={flowForm.action} onChange={e => setFlowForm(f => ({ ...f, action: e.target.value }))}>
                <option value="ALLOW">ALLOW</option><option value="DENY">DENY</option>
              </select>
              <select value={flowForm.protocol} onChange={e => setFlowForm(f => ({ ...f, protocol: e.target.value }))}>
                <option value="tcp">TCP</option><option value="udp">UDP</option><option value="icmp">ICMP</option><option value="any">Any</option>
              </select>
              <input placeholder="Ports" value={flowForm.ports} onChange={e => setFlowForm(f => ({ ...f, ports: e.target.value }))} />
              <input placeholder="Comment" value={flowForm.comment} onChange={e => setFlowForm(f => ({ ...f, comment: e.target.value }))} />
              <button onClick={addFlow}>Add Flow</button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
