import { useState, useEffect } from 'react';
import { api } from '../lib/api';

const ASSET_TYPES = ['plc', 'hmi', 'sensor', 'camera', 'printer', 'hvac', 'medical', 'other'];
const CRITICALITY_COLORS: Record<string, string> = { critical: '#f44336', high: '#FF9800', medium: '#FFC107', low: '#4CAF50' };

export function IoTPage() {
  const [assets, setAssets] = useState<any[]>([]);
  const [selectedAsset, setSelectedAsset] = useState<any>(null);
  const [assetFlows, setAssetFlows] = useState<any[]>([]);
  const [_assetTags, setAssetTags] = useState<any[]>([]);
  const [collectors, setCollectors] = useState<any[]>([]);
  const [enforcementPoints, setEnforcementPoints] = useState<any[]>([]);
  const [vlans, setVlans] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [tab, setTab] = useState<'assets' | 'collectors' | 'enforcement'>('assets');
  const [filterType, setFilterType] = useState('');
  const [filterZone, setFilterZone] = useState('');
  const [showCreate, setShowCreate] = useState(false);
  const [form, setForm] = useState({ name: '', assetType: 'sensor', vendor: '', model: '', macAddress: '', ipAddress: '', vlanId: '', zone: '', criticality: 'medium' });

  const load = async () => {
    setLoading(true);
    try {
      const [aRes, vRes] = await Promise.all([
        api.iot.assets({ assetType: filterType || undefined, zone: filterZone || undefined }),
        api.vlans(),
      ]);
      setAssets(aRes.assets);
      setVlans(vRes.vlans);
    } catch (e: any) { setError(e.message); }
    setLoading(false);
  };

  useEffect(() => { load(); }, [filterType, filterZone]);

  const loadCollectors = async () => {
    setTab('collectors');
    try {
      const res = await api.iot.collectors();
      setCollectors(res.collectors);
    } catch (e: any) { setError(e.message); }
  };

  const loadEnforcement = async () => {
    setTab('enforcement');
    try {
      const res = await api.iot.enforcementPoints();
      setEnforcementPoints(res.enforcementPoints);
    } catch (e: any) { setError(e.message); }
  };

  const selectAsset = async (a: any) => {
    try {
      const res = await api.iot.asset(a.id);
      setSelectedAsset(res.asset);
      setAssetFlows(res.observedFlows);
      setAssetTags(res.tags);
    } catch (e: any) { setError(e.message); }
  };

  const createAsset = async () => {
    try {
      await api.iot.createAsset({
        name: form.name, assetType: form.assetType, vendor: form.vendor || undefined,
        model: form.model || undefined, macAddress: form.macAddress || undefined,
        ipAddress: form.ipAddress || undefined, vlanId: form.vlanId || undefined,
        zone: form.zone || undefined, criticality: form.criticality,
      });
      setShowCreate(false);
      setForm({ name: '', assetType: 'sensor', vendor: '', model: '', macAddress: '', ipAddress: '', vlanId: '', zone: '', criticality: 'medium' });
      load();
    } catch (e: any) { setError(e.message); }
  };

  const deleteAsset = async (id: string) => {
    if (!confirm('Delete this asset?')) return;
    try {
      await api.iot.deleteAsset(id);
      if (selectedAsset?.id === id) setSelectedAsset(null);
      load();
    } catch (e: any) { setError(e.message); }
  };

  const baselineAsset = async (id: string) => {
    try {
      const res = await api.iot.baseline(id);
      alert(`Baseline captured: ${res.baselineFlows} flows`);
    } catch (e: any) { setError(e.message); }
  };

  if (loading) return <div>Loading...</div>;

  return (
    <div>
      <h2>OT/IoT Microsegmentation</h2>
      {error && <div style={{ color: 'red', marginBottom: 8 }}>{error} <button onClick={() => setError('')}>dismiss</button></div>}

      <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
        <button onClick={() => { setTab('assets'); load(); }} style={{ fontWeight: tab === 'assets' ? 'bold' : 'normal' }}>Assets</button>
        <button onClick={loadCollectors} style={{ fontWeight: tab === 'collectors' ? 'bold' : 'normal' }}>Flow Collectors</button>
        <button onClick={loadEnforcement} style={{ fontWeight: tab === 'enforcement' ? 'bold' : 'normal' }}>Enforcement Points</button>
      </div>

      {tab === 'assets' && (
        <>
          <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
            <select value={filterType} onChange={e => setFilterType(e.target.value)}>
              <option value="">All Types</option>
              {ASSET_TYPES.map(t => <option key={t} value={t}>{t.toUpperCase()}</option>)}
            </select>
            <input placeholder="Filter by zone" value={filterZone} onChange={e => setFilterZone(e.target.value)} />
            <button onClick={() => setShowCreate(true)}>+ Add Asset</button>
          </div>

          {showCreate && (
            <div style={{ border: '1px solid #ccc', padding: 16, marginBottom: 16, borderRadius: 4 }}>
              <h3>Add IoT/OT Asset</h3>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 8 }}>
                <input placeholder="Name" value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} />
                <select value={form.assetType} onChange={e => setForm(f => ({ ...f, assetType: e.target.value }))}>
                  {ASSET_TYPES.map(t => <option key={t} value={t}>{t.toUpperCase()}</option>)}
                </select>
                <select value={form.criticality} onChange={e => setForm(f => ({ ...f, criticality: e.target.value }))}>
                  <option value="critical">Critical</option><option value="high">High</option>
                  <option value="medium">Medium</option><option value="low">Low</option>
                </select>
                <input placeholder="Vendor" value={form.vendor} onChange={e => setForm(f => ({ ...f, vendor: e.target.value }))} />
                <input placeholder="Model" value={form.model} onChange={e => setForm(f => ({ ...f, model: e.target.value }))} />
                <input placeholder="MAC Address" value={form.macAddress} onChange={e => setForm(f => ({ ...f, macAddress: e.target.value }))} />
                <input placeholder="IP Address" value={form.ipAddress} onChange={e => setForm(f => ({ ...f, ipAddress: e.target.value }))} />
                <select value={form.vlanId} onChange={e => setForm(f => ({ ...f, vlanId: e.target.value }))}>
                  <option value="">No VLAN</option>
                  {vlans.map(v => <option key={v.id} value={v.id}>VLAN {v.vlan_tag}: {v.name}</option>)}
                </select>
                <input placeholder="Zone (e.g., Level 0, Level 1, DMZ)" value={form.zone} onChange={e => setForm(f => ({ ...f, zone: e.target.value }))} />
              </div>
              <div style={{ marginTop: 8 }}>
                <button onClick={createAsset}>Add Asset</button>
                <button onClick={() => setShowCreate(false)} style={{ marginLeft: 8 }}>Cancel</button>
              </div>
            </div>
          )}

          <div style={{ display: 'flex', gap: 24 }}>
            <div style={{ flex: 1 }}>
              <table style={{ width: '100%' }}>
                <thead><tr><th>Name</th><th>Type</th><th>Vendor</th><th>IP</th><th>Zone</th><th>Criticality</th><th>Tags</th><th>Actions</th></tr></thead>
                <tbody>
                  {assets.map(a => (
                    <tr key={a.id} onClick={() => selectAsset(a)} style={{ cursor: 'pointer', background: selectedAsset?.id === a.id ? '#e8f0fe' : undefined }}>
                      <td>{a.name}</td>
                      <td>{a.asset_type.toUpperCase()}</td>
                      <td>{a.vendor || '-'}</td>
                      <td><code>{a.ip_address || '-'}</code></td>
                      <td>{a.zone || '-'}</td>
                      <td><span style={{ color: CRITICALITY_COLORS[a.criticality] }}>{a.criticality}</span></td>
                      <td>{a.tag_names?.join(', ') || '-'}</td>
                      <td>
                        <button onClick={(e) => { e.stopPropagation(); baselineAsset(a.id); }} style={{ fontSize: '0.8em' }}>Baseline</button>
                        <button onClick={(e) => { e.stopPropagation(); deleteAsset(a.id); }} style={{ fontSize: '0.8em', marginLeft: 4, color: 'red' }}>Del</button>
                      </td>
                    </tr>
                  ))}
                  {assets.length === 0 && <tr><td colSpan={8}>No IoT/OT assets</td></tr>}
                </tbody>
              </table>
            </div>

            {selectedAsset && (
              <div style={{ width: 450, border: '1px solid #ccc', padding: 16, borderRadius: 4 }}>
                <h3>{selectedAsset.name}</h3>
                <div style={{ fontSize: '0.9em', marginBottom: 8 }}>
                  <div><strong>Type:</strong> {selectedAsset.asset_type} | <strong>Criticality:</strong> <span style={{ color: CRITICALITY_COLORS[selectedAsset.criticality] }}>{selectedAsset.criticality}</span></div>
                  <div><strong>Vendor:</strong> {selectedAsset.vendor || '-'} | <strong>Model:</strong> {selectedAsset.model || '-'}</div>
                  <div><strong>IP:</strong> {selectedAsset.ip_address || '-'} | <strong>MAC:</strong> {selectedAsset.mac_address || '-'}</div>
                  <div><strong>Zone:</strong> {selectedAsset.zone || '-'} | <strong>VLAN:</strong> {selectedAsset.vlan_name || '-'}</div>
                </div>
                <h4>Observed Traffic ({assetFlows.length} flows)</h4>
                <div style={{ maxHeight: 300, overflow: 'auto' }}>
                  <table style={{ width: '100%', fontSize: '0.8em' }}>
                    <thead><tr><th>Src</th><th>Dst</th><th>Proto</th><th>Port</th><th>Pkts</th><th>Last</th></tr></thead>
                    <tbody>
                      {assetFlows.slice(0, 30).map(f => (
                        <tr key={f.id}>
                          <td>{f.source_ip}</td><td>{f.dest_ip}</td><td>{f.protocol}</td>
                          <td>{f.dest_port || '*'}</td><td>{f.packets_total}</td>
                          <td>{new Date(f.last_seen_at).toLocaleString()}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        </>
      )}

      {tab === 'collectors' && (
        <table style={{ width: '100%' }}>
          <thead><tr><th>Name</th><th>Type</th><th>Listen</th><th>Status</th><th>Flows</th><th>Last Received</th></tr></thead>
          <tbody>
            {collectors.map(c => (
              <tr key={c.id}>
                <td>{c.name}</td><td>{c.type}</td>
                <td>{c.listen_address}:{c.listen_port}</td>
                <td style={{ color: c.enabled ? 'green' : '#999' }}>{c.enabled ? 'Active' : 'Disabled'}</td>
                <td>{c.flow_count}</td>
                <td>{c.last_received_at ? new Date(c.last_received_at).toLocaleString() : 'Never'}</td>
              </tr>
            ))}
            {collectors.length === 0 && <tr><td colSpan={6}>No flow collectors configured</td></tr>}
          </tbody>
        </table>
      )}

      {tab === 'enforcement' && (
        <table style={{ width: '100%' }}>
          <thead><tr><th>Name</th><th>Type</th><th>Vendor</th><th>IP</th><th>Status</th><th>ACLs</th></tr></thead>
          <tbody>
            {enforcementPoints.map(ep => (
              <tr key={ep.id}>
                <td>{ep.name}</td><td>{ep.type}</td><td>{ep.vendor || '-'}</td>
                <td><code>{ep.mgmt_ip}</code></td>
                <td style={{ color: ep.enabled ? 'green' : '#999' }}>{ep.enabled ? 'Active' : 'Disabled'}</td>
                <td>{ep.acl_count}</td>
              </tr>
            ))}
            {enforcementPoints.length === 0 && <tr><td colSpan={6}>No enforcement points configured</td></tr>}
          </tbody>
        </table>
      )}
    </div>
  );
}
