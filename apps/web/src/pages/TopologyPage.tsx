import { useState, useEffect } from 'react';
import { api } from '../lib/api';

export function TopologyPage() {
  const [views, setViews] = useState<any[]>([]);
  const [selectedView, setSelectedView] = useState<any>(null);
  const [flows, setFlows] = useState<any[]>([]);
  const [tags, setTags] = useState<any[]>([]);
  const [vlans, setVlans] = useState<any[]>([]);
  const [discoveredTopology, setDiscoveredTopology] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [showCreate, setShowCreate] = useState(false);
  const [showAddFlow, setShowAddFlow] = useState(false);
  const [form, setForm] = useState({ name: '', description: '' });
  const [flowForm, setFlowForm] = useState({
    sourceType: 'TAG', sourceValue: '', targetType: 'TAG', targetValue: '',
    direction: 'BOTH', action: 'ALLOW', protocol: 'tcp', ports: '', comment: ''
  });

  const load = async () => {
    setLoading(true);
    try {
      const [viewsRes, tagsRes, vlansRes] = await Promise.all([
        api.topology.listViews(),
        api.tags(),
        api.vlans(),
      ]);
      setViews(viewsRes.views);
      setTags(tagsRes.tags || []);
      setVlans(vlansRes.vlans || []);
    } catch (e: any) { setError(e.message); }
    setLoading(false);
  };

  useEffect(() => { load(); }, []);

  const selectView = async (v: any) => {
    setSelectedView(v);
    setShowAddFlow(false);
    try {
      const res = await api.topology.getView(v.id);
      setFlows(res.flows);
    } catch (e: any) { setError(e.message); }
  };

  const createView = async () => {
    if (!form.name.trim()) return;
    try {
      const res = await api.topology.createView({ name: form.name, description: form.description || undefined });
      setShowCreate(false);
      setForm({ name: '', description: '' });
      load();
      selectView(res.view);
    } catch (e: any) { setError(e.message); }
  };

  const deleteView = async (id: string) => {
    if (!confirm('Delete this topology view and all its flows?')) return;
    try {
      await api.topology.deleteView(id);
      if (selectedView?.id === id) { setSelectedView(null); setFlows([]); }
      load();
    } catch (e: any) { setError(e.message); }
  };

  const addFlow = async () => {
    if (!selectedView || !flowForm.sourceValue || !flowForm.targetValue) return;
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
      setShowAddFlow(false);
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
    if (flows.length === 0) { setError('Add at least one flow before generating policies'); return; }
    const name = prompt(
      `Enter a name for the policy set (${flows.length} flows will be converted to firewall rules):`,
      `${selectedView.name} Policy`
    );
    if (name === null) return; // User cancelled
    try {
      const result = await api.topology.generatePolicies(selectedView.id, name.trim() || undefined);
      alert(`Created policy set with ${result.rulesCreated} rules (DRAFT). Go to Policy Sets to review, approve, and deploy.`);
    } catch (e: any) { setError(e.message); }
  };

  const autoDiscover = async () => {
    try {
      const result = await api.topology.autoDiscover();
      setDiscoveredTopology(result);
    } catch (e: any) { setError(e.message); }
  };

  // Helper to get display name for an entity
  const entityLabel = (type: string, value: string): string => {
    if (type === 'TAG') {
      const tag = tags.find(t => t.id === value);
      return tag ? tag.name : value;
    }
    if (type === 'VLAN') {
      const vlan = vlans.find(v => v.id === value);
      return vlan ? `VLAN ${vlan.vlan_tag}: ${vlan.name}` : value;
    }
    return value;
  };

  // Value selector dropdown based on type
  const renderValueSelect = (type: string, value: string, onChange: (v: string) => void) => {
    if (type === 'TAG') {
      return (
        <select value={value} onChange={e => onChange(e.target.value)} style={{ flex: 1 }}>
          <option value="">Select tag...</option>
          {tags.map(t => <option key={t.id} value={t.id}>{t.name}</option>)}
        </select>
      );
    }
    if (type === 'VLAN') {
      return (
        <select value={value} onChange={e => onChange(e.target.value)} style={{ flex: 1 }}>
          <option value="">Select VLAN...</option>
          {vlans.map(v => <option key={v.id} value={v.id}>VLAN {v.vlan_tag}: {v.name}</option>)}
        </select>
      );
    }
    return <input placeholder="e.g., 10.0.1.0/24" value={value} onChange={e => onChange(e.target.value)} style={{ flex: 1 }} />;
  };

  if (loading) return <div>Loading...</div>;

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <h2 style={{ marginBottom: 4 }}>Network Flow Design</h2>
          <p style={{ margin: 0, color: '#78644e', fontSize: '13.5px' }}>
            Define allowed and denied traffic flows between groups (tags, VLANs, CIDRs), then generate firewall policies automatically.
          </p>
        </div>
      </div>

      {error && <div className="error-banner">{error} <button onClick={() => setError('')} className="btn-small btn-secondary" style={{ marginLeft: 8 }}>dismiss</button></div>}

      {/* How it works — shown when no view is selected */}
      {!selectedView && views.length === 0 && !discoveredTopology && (
        <div className="card" style={{ background: '#f7f4ef', border: '1px solid #e8e0d4' }}>
          <h3 style={{ marginBottom: 12 }}>How It Works</h3>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 16, fontSize: '13.5px', color: '#5c4633' }}>
            <div style={{ padding: 16, background: '#fdfcf9', borderRadius: 8, border: '1px solid #e8e0d4' }}>
              <div style={{ fontSize: '20px', marginBottom: 8 }}>1</div>
              <strong>Create a view</strong>
              <p style={{ margin: '8px 0 0', color: '#78644e' }}>A view is a named collection of traffic flows between your network groups.</p>
            </div>
            <div style={{ padding: 16, background: '#fdfcf9', borderRadius: 8, border: '1px solid #e8e0d4' }}>
              <div style={{ fontSize: '20px', marginBottom: 8 }}>2</div>
              <strong>Define flows</strong>
              <p style={{ margin: '8px 0 0', color: '#78644e' }}>Add connections like "web-servers can reach db-servers on TCP 5432". Each flow specifies source, target, protocol, ports, and action.</p>
            </div>
            <div style={{ padding: 16, background: '#fdfcf9', borderRadius: 8, border: '1px solid #e8e0d4' }}>
              <div style={{ fontSize: '20px', marginBottom: 8 }}>3</div>
              <strong>Generate policies</strong>
              <p style={{ margin: '8px 0 0', color: '#78644e' }}>Segmentra converts your flows into real firewall policies (DRAFT). Each flow creates rules on both sides — IN on the target, OUT on the source.</p>
            </div>
          </div>
        </div>
      )}

      {/* Action buttons */}
      <div style={{ display: 'flex', gap: 8, marginBottom: 20 }}>
        <button onClick={() => setShowCreate(true)} className="btn-primary">+ New View</button>
        <button onClick={autoDiscover} className="btn-secondary">Auto-Discover from Inventory</button>
      </div>

      {/* Create view form */}
      {showCreate && (
        <div className="card" style={{ border: '2px solid #8b6914' }}>
          <h3>Create View</h3>
          <div className="form-grid" style={{ gridTemplateColumns: '1fr 1fr' }}>
            <div className="form-group">
              <label>Name *</label>
              <input placeholder="e.g., Production Network Flows" value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} />
            </div>
            <div className="form-group">
              <label>Description</label>
              <input placeholder="Optional description" value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))} />
            </div>
          </div>
          <div className="form-actions" style={{ marginTop: 12 }}>
            <button onClick={createView} className="btn-primary" disabled={!form.name.trim()}>Create View</button>
            <button onClick={() => setShowCreate(false)} className="btn-secondary">Cancel</button>
          </div>
        </div>
      )}

      {/* Auto-discovered topology */}
      {discoveredTopology && (
        <div className="card" style={{ border: '1px solid #d4c9b8', background: '#f7f4ef' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
            <h3 style={{ margin: 0 }}>Discovered Topology</h3>
            <button onClick={() => setDiscoveredTopology(null)} className="btn-small btn-secondary">Close</button>
          </div>
          <p style={{ color: '#5c4633', fontSize: '13.5px', marginBottom: 12 }}>
            Found <strong>{discoveredTopology.nodes.length}</strong> groups and <strong>{discoveredTopology.edges.length}</strong> connections from your existing inventory and deployed policies.
          </p>
          {discoveredTopology.nodes.length > 0 && (
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginBottom: 12 }}>
              {discoveredTopology.nodes.map((n: any) => (
                <span key={n.id} style={{ padding: '4px 10px', background: '#fdfcf9', borderRadius: 6, fontSize: '12.5px', border: '1px solid #d4c9b8', color: '#5c4633' }}>
                  <strong>{n.type}</strong> {n.label} <span style={{ color: '#97846c' }}>({n.data.hostCount} hosts)</span>
                </span>
              ))}
            </div>
          )}
          {discoveredTopology.edges.length > 0 && (
            <table className="data-table">
              <thead><tr><th>Source</th><th>Target</th><th>Action</th><th>Protocol</th><th>Ports</th></tr></thead>
              <tbody>
                {discoveredTopology.edges.map((e: any, i: number) => (
                  <tr key={i}>
                    <td>{e.source}</td><td>{e.target}</td>
                    <td><span style={{ color: e.data.action === 'ALLOW' ? '#5a7a3a' : '#a63d2f', fontWeight: 600 }}>{e.data.action}</span></td>
                    <td>{e.data.protocol}</td><td>{e.data.ports || 'any'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {discoveredTopology.nodes.length === 0 && (
            <p style={{ color: '#97846c', fontStyle: 'italic' }}>No groups with hosts found. Add hosts with tags or VLANs in the Inventory first.</p>
          )}
        </div>
      )}

      {/* Main content: views list + selected view */}
      <div style={{ display: 'flex', gap: 20 }}>
        {/* Views sidebar */}
        <div style={{ width: 260, flexShrink: 0 }}>
          <h4 style={{ color: '#5c4633', marginTop: 0, marginBottom: 12 }}>Saved Views</h4>
          {views.map(v => (
            <div key={v.id} onClick={() => selectView(v)}
              style={{
                padding: '10px 12px', cursor: 'pointer', marginBottom: 6, borderRadius: 8,
                background: selectedView?.id === v.id ? '#f0ebe2' : '#fdfcf9',
                border: `1px solid ${selectedView?.id === v.id ? '#d4c9b8' : '#e8e0d4'}`,
                transition: 'all 0.1s ease',
              }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <strong style={{ color: '#3d2e1e', fontSize: '13.5px' }}>{v.name}</strong>
                <button onClick={(e) => { e.stopPropagation(); deleteView(v.id); }} className="btn-small btn-danger" style={{ padding: '2px 8px', minHeight: 'auto' }}>Del</button>
              </div>
              <div style={{ fontSize: '12px', color: '#97846c', marginTop: 2 }}>{v.flow_count || 0} flow(s)</div>
            </div>
          ))}
          {views.length === 0 && <p style={{ color: '#97846c', fontSize: '13px', fontStyle: 'italic' }}>No views yet. Create one above.</p>}
        </div>

        {/* Selected view content */}
        {selectedView && (
          <div style={{ flex: 1 }}>
            {/* View header */}
            <div className="card">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <h3 style={{ margin: 0 }}>{selectedView.name}</h3>
                  {selectedView.description && <p style={{ margin: '4px 0 0', color: '#78644e', fontSize: '13px' }}>{selectedView.description}</p>}
                </div>
                <div style={{ display: 'flex', gap: 8 }}>
                  <button onClick={() => setShowAddFlow(true)} className="btn-primary">+ Add Flow</button>
                  <button onClick={generatePolicies} className="btn-secondary" style={{ background: '#5a7a3a', color: '#fdfcf9', border: 'none' }}>
                    Generate Policies
                  </button>
                </div>
              </div>
            </div>

            {/* Visual flow diagram */}
            {flows.length > 0 && (
              <div className="card" style={{ background: '#f7f4ef' }}>
                <h4 style={{ margin: '0 0 12px', color: '#5c4633', fontSize: '13px', textTransform: 'uppercase', letterSpacing: '0.04em' }}>Flow Diagram</h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                  {flows.map(f => (
                    <div key={f.id} style={{
                      display: 'flex', alignItems: 'center', gap: 8, padding: '8px 12px',
                      background: '#fdfcf9', borderRadius: 8, border: '1px solid #e8e0d4',
                    }}>
                      {/* Source */}
                      <div style={{
                        padding: '4px 10px', borderRadius: 6, fontSize: '12.5px', fontWeight: 600,
                        background: f.source_type === 'TAG' ? '#f0ebe2' : f.source_type === 'VLAN' ? '#e8e0d4' : '#fdfcf9',
                        border: '1px solid #d4c9b8', color: '#3d2e1e', whiteSpace: 'nowrap',
                      }}>
                        <span style={{ color: '#97846c', fontSize: '10px', marginRight: 4 }}>{f.source_type}</span>
                        {entityLabel(f.source_type, f.source_value)}
                      </div>

                      {/* Arrow with protocol info */}
                      <div style={{ flex: 1, display: 'flex', alignItems: 'center', position: 'relative', minWidth: 120 }}>
                        <div style={{ flex: 1, height: 0, borderTop: `2px ${f.action === 'ALLOW' ? 'solid' : 'dashed'} ${f.action === 'ALLOW' ? '#5a7a3a' : '#a63d2f'}` }} />
                        <div style={{
                          position: 'absolute', left: '50%', transform: 'translateX(-50%)',
                          padding: '1px 8px', borderRadius: 10, fontSize: '11px', fontWeight: 500,
                          background: f.action === 'ALLOW' ? '#eef4e8' : '#faf0ee',
                          color: f.action === 'ALLOW' ? '#5a7a3a' : '#a63d2f',
                          border: `1px solid ${f.action === 'ALLOW' ? '#c5dbb0' : '#e8c4bf'}`,
                          whiteSpace: 'nowrap',
                        }}>
                          {f.protocol.toUpperCase()}{f.ports ? `/${f.ports}` : ''} {f.action}
                        </div>
                        {/* Arrowhead */}
                        <svg width="10" height="10" viewBox="0 0 10 10" style={{ flex: '0 0 10px' }}>
                          <path d="M0 0 L10 5 L0 10 Z" fill={f.action === 'ALLOW' ? '#5a7a3a' : '#a63d2f'} />
                        </svg>
                      </div>

                      {/* Target */}
                      <div style={{
                        padding: '4px 10px', borderRadius: 6, fontSize: '12.5px', fontWeight: 600,
                        background: f.target_type === 'TAG' ? '#f0ebe2' : f.target_type === 'VLAN' ? '#e8e0d4' : '#fdfcf9',
                        border: '1px solid #d4c9b8', color: '#3d2e1e', whiteSpace: 'nowrap',
                      }}>
                        <span style={{ color: '#97846c', fontSize: '10px', marginRight: 4 }}>{f.target_type}</span>
                        {entityLabel(f.target_type, f.target_value)}
                      </div>

                      {/* Remove button */}
                      <button onClick={() => removeFlow(f.id)} className="btn-small btn-danger" style={{ padding: '2px 8px', minHeight: 'auto', fontSize: '11px' }}>x</button>
                    </div>
                  ))}
                </div>
                {flows.length > 0 && (
                  <div style={{ marginTop: 12, display: 'flex', gap: 16, fontSize: '11.5px', color: '#97846c' }}>
                    <span><span style={{ display: 'inline-block', width: 20, height: 2, background: '#5a7a3a', verticalAlign: 'middle', marginRight: 4 }} /> ALLOW</span>
                    <span><span style={{ display: 'inline-block', width: 20, height: 0, borderTop: '2px dashed #a63d2f', verticalAlign: 'middle', marginRight: 4 }} /> DENY</span>
                  </div>
                )}
              </div>
            )}

            {/* Empty state */}
            {flows.length === 0 && !showAddFlow && (
              <div className="card" style={{ textAlign: 'center', padding: '40px 24px', background: '#f7f4ef' }}>
                <p style={{ color: '#97846c', marginBottom: 12, fontSize: '14px' }}>No flows defined yet. Add your first traffic flow to start designing your network policy.</p>
                <button onClick={() => setShowAddFlow(true)} className="btn-primary">+ Add First Flow</button>
              </div>
            )}

            {/* Add flow form */}
            {showAddFlow && (
              <div className="card" style={{ border: '2px solid #8b6914' }}>
                <h3 style={{ marginBottom: 4 }}>Add Traffic Flow</h3>
                <p style={{ color: '#78644e', fontSize: '13px', marginBottom: 16 }}>
                  Define a connection: which group can (or cannot) reach which group, on which protocol and ports.
                </p>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr auto 1fr', gap: 16, alignItems: 'end', marginBottom: 16 }}>
                  {/* Source */}
                  <div>
                    <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: '#5c4633', marginBottom: 4, textTransform: 'uppercase', letterSpacing: '0.04em' }}>Source</label>
                    <div style={{ display: 'flex', gap: 6 }}>
                      <select value={flowForm.sourceType} onChange={e => setFlowForm(f => ({ ...f, sourceType: e.target.value, sourceValue: '' }))} style={{ width: 90 }}>
                        <option value="TAG">Tag</option><option value="VLAN">VLAN</option><option value="CIDR">CIDR</option>
                      </select>
                      {renderValueSelect(flowForm.sourceType, flowForm.sourceValue, v => setFlowForm(f => ({ ...f, sourceValue: v })))}
                    </div>
                  </div>

                  {/* Arrow */}
                  <div style={{ display: 'flex', alignItems: 'center', paddingBottom: 4 }}>
                    <svg width="40" height="16" viewBox="0 0 40 16">
                      <path d="M2 8 L30 8 M26 3 L32 8 L26 13" fill="none" stroke="#8b6914" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                    </svg>
                  </div>

                  {/* Target */}
                  <div>
                    <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: '#5c4633', marginBottom: 4, textTransform: 'uppercase', letterSpacing: '0.04em' }}>Target</label>
                    <div style={{ display: 'flex', gap: 6 }}>
                      <select value={flowForm.targetType} onChange={e => setFlowForm(f => ({ ...f, targetType: e.target.value, targetValue: '' }))} style={{ width: 90 }}>
                        <option value="TAG">Tag</option><option value="VLAN">VLAN</option><option value="CIDR">CIDR</option>
                      </select>
                      {renderValueSelect(flowForm.targetType, flowForm.targetValue, v => setFlowForm(f => ({ ...f, targetValue: v })))}
                    </div>
                  </div>
                </div>

                {/* Flow details */}
                <div className="form-grid" style={{ gridTemplateColumns: '1fr 1fr 1fr 1fr' }}>
                  <div className="form-group">
                    <label>Action</label>
                    <select value={flowForm.action} onChange={e => setFlowForm(f => ({ ...f, action: e.target.value }))}>
                      <option value="ALLOW">ALLOW</option><option value="DENY">DENY</option>
                    </select>
                  </div>
                  <div className="form-group">
                    <label>Protocol</label>
                    <select value={flowForm.protocol} onChange={e => setFlowForm(f => ({ ...f, protocol: e.target.value }))}>
                      <option value="tcp">TCP</option><option value="udp">UDP</option><option value="icmp">ICMP</option><option value="any">Any</option>
                    </select>
                  </div>
                  <div className="form-group">
                    <label>Ports</label>
                    <input placeholder="e.g., 443 or 80,443" value={flowForm.ports} onChange={e => setFlowForm(f => ({ ...f, ports: e.target.value }))} />
                  </div>
                  <div className="form-group">
                    <label>Comment</label>
                    <input placeholder="Optional note" value={flowForm.comment} onChange={e => setFlowForm(f => ({ ...f, comment: e.target.value }))} />
                  </div>
                </div>

                <div className="form-actions" style={{ marginTop: 12 }}>
                  <button onClick={addFlow} className="btn-primary" disabled={!flowForm.sourceValue || !flowForm.targetValue}>Add Flow</button>
                  <button onClick={() => setShowAddFlow(false)} className="btn-secondary">Cancel</button>
                </div>
              </div>
            )}

            {/* Flows table (compact detail view) */}
            {flows.length > 0 && (
              <div className="card">
                <h4 style={{ margin: '0 0 8px', color: '#5c4633' }}>All Flows ({flows.length})</h4>
                <table className="data-table">
                  <thead>
                    <tr><th>Source</th><th>Target</th><th>Action</th><th>Protocol</th><th>Ports</th><th>Comment</th><th></th></tr>
                  </thead>
                  <tbody>
                    {flows.map(f => (
                      <tr key={f.id}>
                        <td><span style={{ color: '#97846c', fontSize: '11px' }}>{f.source_type}:</span> {entityLabel(f.source_type, f.source_value)}</td>
                        <td><span style={{ color: '#97846c', fontSize: '11px' }}>{f.target_type}:</span> {entityLabel(f.target_type, f.target_value)}</td>
                        <td><span style={{ color: f.action === 'ALLOW' ? '#5a7a3a' : '#a63d2f', fontWeight: 600 }}>{f.action}</span></td>
                        <td>{f.protocol.toUpperCase()}</td>
                        <td><code>{f.ports || 'any'}</code></td>
                        <td style={{ color: '#78644e', fontSize: '12.5px' }}>{f.comment || '-'}</td>
                        <td><button onClick={() => removeFlow(f.id)} className="btn-small btn-danger" style={{ padding: '2px 8px', minHeight: 'auto' }}>x</button></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {/* No view selected */}
        {!selectedView && views.length > 0 && (
          <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#97846c', fontSize: '14px', padding: 40 }}>
            Select a view from the sidebar, or create a new one.
          </div>
        )}
      </div>
    </div>
  );
}
