import { useState, useEffect } from 'react';
import { api } from '../lib/api';
import { useAuth, hasRole } from '../lib/auth-context';
import { IotCoverageTab } from '../components/IotCoverageTab';
import { IotDiscoveryTab } from '../components/IotDiscoveryTab';

const ASSET_TYPES = ['plc', 'hmi', 'sensor', 'camera', 'printer', 'hvac', 'medical', 'other'];
const CRITICALITY_COLORS: Record<string, string> = { critical: '#a63d2f', high: '#c47a1a', medium: '#8b6914', low: '#5a7a3a' };

export function IoTPage() {
  const { roles } = useAuth();
  // Asset create/update/delete, gateway assignment and tagging are operator/admin only in the API
  const canEdit = hasRole(roles, 'operator', 'admin');
  const [assets, setAssets] = useState<any[]>([]);
  const [gateways, setGateways] = useState<any[]>([]);
  const [selectedGateway, setSelectedGateway] = useState<any>(null);
  const [gatewayDetail, setGatewayDetail] = useState<any>(null);
  const [vlans, setVlans] = useState<any[]>([]);
  const [allGatewayHosts, setAllGatewayHosts] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [tab, setTab] = useState<'assets' | 'coverage' | 'gateways' | 'discovery'>('assets');
  const [filterType, setFilterType] = useState('');
  const [filterGateway, setFilterGateway] = useState('');
  const [filterVlan, setFilterVlan] = useState('');
  const [showCreate, setShowCreate] = useState(false);
  const [selectedAsset, setSelectedAsset] = useState<any>(null);
  const [assetGateways, setAssetGateways] = useState<any[]>([]);
  const [form, setForm] = useState({ name: '', assetType: 'sensor', vendor: '', model: '', macAddress: '', ipAddress: '', vlanId: '', criticality: 'medium', gatewayIds: [] as string[] });

  const load = async () => {
    setLoading(true);
    try {
      const [aRes, vRes, gRes] = await Promise.all([
        api.iot.assets({ assetType: filterType || undefined, gatewayId: filterGateway || undefined, vlanId: filterVlan || undefined }),
        api.vlans(),
        api.iot.gateways(),
      ]);
      setAssets(aRes.assets);
      setVlans(vRes.vlans);
      setGateways(gRes.gateways);
      setAllGatewayHosts(gRes.gateways);
    } catch (e: any) { setError(e.message); }
    setLoading(false);
  };

  useEffect(() => { load(); }, [filterType, filterGateway, filterVlan]);

  const loadGateways = async () => {
    setTab('gateways');
    try {
      const res = await api.iot.gateways();
      setGateways(res.gateways);
    } catch (e: any) { setError(e.message); }
  };

  const selectGateway = async (gw: any) => {
    setSelectedGateway(gw);
    try {
      const res = await api.iot.gateway(gw.id);
      setGatewayDetail(res);
    } catch (e: any) { setError(e.message); }
  };

  const selectAsset = async (a: any) => {
    try {
      const res = await api.iot.asset(a.id);
      setSelectedAsset(res.asset);
      setAssetGateways(res.gateways);
    } catch (e: any) { setError(e.message); }
  };

  const createAsset = async () => {
    try {
      await api.iot.createAsset({
        name: form.name, assetType: form.assetType, vendor: form.vendor || undefined,
        model: form.model || undefined, macAddress: form.macAddress || undefined,
        ipAddress: form.ipAddress || undefined, vlanId: form.vlanId || undefined,
        criticality: form.criticality,
        gatewayIds: form.gatewayIds.length > 0 ? form.gatewayIds : undefined,
      });
      setShowCreate(false);
      setForm({ name: '', assetType: 'sensor', vendor: '', model: '', macAddress: '', ipAddress: '', vlanId: '', criticality: 'medium', gatewayIds: [] });
      load();
    } catch (e: any) { setError(e.message); }
  };

  const deleteAsset = async (id: string) => {
    if (!confirm('Delete this IoT asset?')) return;
    try { await api.iot.deleteAsset(id); if (selectedAsset?.id === id) setSelectedAsset(null); load(); } catch (e: any) { setError(e.message); }
  };

  const assignGateway = async (assetId: string, gatewayId: string) => {
    try {
      await api.iot.assignGateways(assetId, [gatewayId]);
      if (selectedAsset?.id === assetId) selectAsset(selectedAsset);
      load();
    } catch (e: any) { setError(e.message); }
  };

  const removeGateway = async (assetId: string, hostId: string) => {
    try {
      await api.iot.removeGateway(assetId, hostId);
      if (selectedAsset?.id === assetId) selectAsset(selectedAsset);
      load();
    } catch (e: any) { setError(e.message); }
  };

  // Helper: get VLAN display name
  const vlanName = (vlanId: string | null) => {
    if (!vlanId) return null;
    const v = vlans.find(vl => vl.id === vlanId);
    return v ? `VLAN ${v.vlan_tag}: ${v.name}` : null;
  };

  if (loading) return <div>Loading...</div>;

  return (
    <div>
      <h2>OT/IoT Microsegmentation</h2>
      <p style={{ color: '#78644e', fontSize: '13.5px', marginTop: -4, marginBottom: 16, lineHeight: 1.6 }}>
        Manage devices that cannot run agents or host-based firewalls. IoT/OT devices are registered here and assigned to
        <strong> gateway firewalls</strong> — Linux servers from the <a href="/inventory" style={{ color: '#8b6914' }}>Inventory</a> tagged <code>iot-gateway</code>.
        Firewall policies are deployed to the gateways using the normal policy pipeline (Policy Sets &#8594; Approve &#8594; Deploy).
        Use <a href="/inventory" style={{ color: '#8b6914' }}>VLANs</a> to define OT/IoT network zones (e.g., "OT Level 1", "Building Systems").
        To discover what IoT devices actually communicate, run <a href="/troubleshoot" style={{ color: '#8b6914' }}>Firewall Learning</a> on the gateway host.
      </p>

      {/* Workflow steps */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', marginBottom: 20, gap: 0 }}>
        {[
          { num: '1', label: 'Add Gateway to Inventory', href: '/inventory', done: allGatewayHosts.length > 0 },
          { num: '2', label: 'Register IoT Devices', href: null, done: assets.length > 0 },
          { num: '3', label: 'Create Policy (iot-gateway)', href: '/policies', done: false },
          { num: '4', label: 'Deploy to Gateway', href: '/deployments', done: false },
        ].map((step, i, arr) => {
          // Check if gateways have deployments
          const gatewaysHavePolicy = allGatewayHosts.some((g: any) => g.last_deployment);
          const stepDone = i === 0 ? step.done : i === 1 ? step.done : i === 2 ? gatewaysHavePolicy : gatewaysHavePolicy;
          return (
            <div key={i} style={{ display: 'contents' }}>
              <a href={step.href || '#'} onClick={e => { if (!step.href) e.preventDefault(); }}
                style={{
                  display: 'flex', alignItems: 'center', gap: 8,
                  padding: '8px 16px', borderRadius: 20, fontSize: '12.5px', textDecoration: 'none',
                  fontWeight: stepDone ? 500 : 400,
                  background: stepDone ? '#eef4e8' : '#f7f4ef',
                  color: stepDone ? '#5a7a3a' : '#78644e',
                  border: `1px solid ${stepDone ? '#c5dbb0' : '#e8e0d4'}`,
                  whiteSpace: 'nowrap', cursor: step.href ? 'pointer' : 'default',
                }}>
                <span style={{
                  display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
                  width: 20, height: 20, borderRadius: '50%', fontSize: '11px', fontWeight: 700,
                  background: stepDone ? '#5a7a3a' : '#e8e0d4',
                  color: stepDone ? '#fdfcf9' : '#78644e',
                }}>{stepDone ? '\u2713' : step.num}</span>
                {step.label}
              </a>
              {i < arr.length - 1 && (
                <svg width="24" height="12" viewBox="0 0 24 12" style={{ flex: '0 0 24px', margin: '0 4px' }}>
                  <path d="M4 6 L16 6 M13 2.5 L17 6 L13 9.5" fill="none" stroke={stepDone ? '#b8a890' : '#d4c9b8'} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
              )}
            </div>
          );
        })}
      </div>

      {error && <div style={{ color: '#a63d2f', marginBottom: 12, padding: 10, background: '#faf0ee', borderRadius: 8, borderLeft: '4px solid #a63d2f' }}>{error} <button onClick={() => setError('')} className="btn-small btn-secondary" style={{ marginLeft: 8 }}>dismiss</button></div>}

      {allGatewayHosts.length === 0 && (
        <div style={{ padding: 16, background: '#fdf6ec', border: '1px solid #e8d5a8', borderRadius: 8, marginBottom: 16, fontSize: '13.5px', color: '#5c4633' }}>
          <strong>No IoT gateways found.</strong> To get started:
          <ol style={{ margin: '8px 0 0', paddingLeft: 20, lineHeight: 2 }}>
            <li>Create VLANs for your OT zones in <a href="/inventory" style={{ color: '#8b6914' }}>Inventory &#8594; VLANs</a> (e.g., "OT Level 1 - PLCs", "OT Level 2 - HMIs")</li>
            <li>Add a Linux gateway host to <a href="/inventory" style={{ color: '#8b6914' }}>Inventory &#8594; Hosts</a> and tag it as <code>iot-gateway</code></li>
            <li>Register your IoT devices here and assign them to the gateway</li>
            <li>Create a policy in <a href="/policies" style={{ color: '#8b6914' }}>Policy Sets</a> scoped to TAG <code>iot-gateway</code> with rules for IoT device IPs</li>
          </ol>
        </div>
      )}

      <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
        <button onClick={() => { setTab('assets'); load(); }} className={tab === 'assets' ? 'btn-primary' : 'btn-secondary'}>Assets ({assets.length})</button>
        <button onClick={() => setTab('coverage')} className={tab === 'coverage' ? 'btn-primary' : 'btn-secondary'}>Coverage</button>
        <button onClick={loadGateways} className={tab === 'gateways' ? 'btn-primary' : 'btn-secondary'}>Gateways ({allGatewayHosts.length})</button>
        <button onClick={() => setTab('discovery')} className={tab === 'discovery' ? 'btn-primary' : 'btn-secondary'}>Discovery</button>
      </div>

      {/* ============ ASSETS TAB ============ */}
      {tab === 'assets' && (
        <>
          <div style={{ display: 'flex', gap: 8, marginBottom: 16, alignItems: 'center', flexWrap: 'wrap' }}>
            <select value={filterType} onChange={e => setFilterType(e.target.value)}>
              <option value="">All Types</option>
              {ASSET_TYPES.map(t => <option key={t} value={t}>{t.toUpperCase()}</option>)}
            </select>
            <select value={filterVlan} onChange={e => setFilterVlan(e.target.value)}>
              <option value="">All VLANs / Zones</option>
              {vlans.map(v => <option key={v.id} value={v.id}>VLAN {v.vlan_tag}: {v.name}</option>)}
            </select>
            <select value={filterGateway} onChange={e => setFilterGateway(e.target.value)}>
              <option value="">All Gateways</option>
              {allGatewayHosts.map(g => <option key={g.id} value={g.id}>{g.hostname}</option>)}
            </select>
            {canEdit && <button onClick={() => setShowCreate(true)} className="btn-primary" style={{ marginLeft: 'auto' }}>+ Add IoT Asset</button>}
          </div>

          {/* Create form */}
          {canEdit && showCreate && (
            <div className="card" style={{ border: '2px solid #8b6914' }}>
              <h3>Add IoT/OT Asset</h3>
              <div className="form-grid" style={{ gridTemplateColumns: '1fr 1fr 1fr' }}>
                <div className="form-group"><label>Name *</label><input value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} placeholder="e.g., PLC-Assembly-Line-1" /></div>
                <div className="form-group"><label>Type</label>
                  <select value={form.assetType} onChange={e => setForm(f => ({ ...f, assetType: e.target.value }))}>
                    {ASSET_TYPES.map(t => <option key={t} value={t}>{t.toUpperCase()}</option>)}
                  </select>
                </div>
                <div className="form-group"><label>Criticality</label>
                  <select value={form.criticality} onChange={e => setForm(f => ({ ...f, criticality: e.target.value }))}>
                    <option value="critical">Critical</option><option value="high">High</option>
                    <option value="medium">Medium</option><option value="low">Low</option>
                  </select>
                </div>
                <div className="form-group"><label>IP Address</label><input value={form.ipAddress} onChange={e => setForm(f => ({ ...f, ipAddress: e.target.value }))} placeholder="e.g., 10.0.60.10" /></div>
                <div className="form-group"><label>MAC Address</label><input value={form.macAddress} onChange={e => setForm(f => ({ ...f, macAddress: e.target.value }))} placeholder="e.g., 00:1A:2B:3C:4D:01" /></div>
                <div className="form-group"><label>Vendor</label><input value={form.vendor} onChange={e => setForm(f => ({ ...f, vendor: e.target.value }))} placeholder="e.g., Siemens" /></div>
                <div className="form-group"><label>Model</label><input value={form.model} onChange={e => setForm(f => ({ ...f, model: e.target.value }))} placeholder="e.g., S7-1500" /></div>
                <div className="form-group">
                  <label>VLAN / Zone</label>
                  <select value={form.vlanId} onChange={e => setForm(f => ({ ...f, vlanId: e.target.value }))}>
                    <option value="">Select VLAN / Zone...</option>
                    {vlans.map(v => <option key={v.id} value={v.id}>VLAN {v.vlan_tag}: {v.name}{v.subnet ? ` (${v.subnet})` : ''}</option>)}
                  </select>
                  <small>VLANs serve as OT/IoT zones. Create zones in <a href="/inventory" style={{ color: '#8b6914' }}>Inventory &#8594; VLANs</a>.</small>
                </div>
              </div>
              {allGatewayHosts.length > 0 && (
                <div className="form-group" style={{ marginTop: 12 }}>
                  <label>Protecting Gateway(s)</label>
                  <p style={{ fontSize: '12px', color: '#97846c', margin: '4px 0 8px' }}>Select which gateway firewall(s) protect this device. Policies will be deployed to these gateways.</p>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                    {allGatewayHosts.map(g => (
                      <label key={g.id} style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer', padding: '4px 10px', borderRadius: 6, background: form.gatewayIds.includes(g.id) ? '#f0ebe2' : '#fdfcf9', border: `1px solid ${form.gatewayIds.includes(g.id) ? '#d4c9b8' : '#e8e0d4'}` }}>
                        <input type="checkbox" checked={form.gatewayIds.includes(g.id)}
                          onChange={e => setForm(f => ({ ...f, gatewayIds: e.target.checked ? [...f.gatewayIds, g.id] : f.gatewayIds.filter(id => id !== g.id) }))} />
                        <span style={{ fontSize: '13px' }}>{g.hostname} <code style={{ fontSize: '11px' }}>({g.mgmt_ip})</code></span>
                      </label>
                    ))}
                  </div>
                </div>
              )}
              <div className="form-actions" style={{ marginTop: 16 }}>
                <button onClick={createAsset} className="btn-primary" disabled={!form.name.trim()}>Add Asset</button>
                <button onClick={() => setShowCreate(false)} className="btn-secondary">Cancel</button>
              </div>
            </div>
          )}

          {/* Assets table + detail panel */}
          <div style={{ display: 'flex', gap: 20 }}>
            <div style={{ flex: 1, overflow: 'auto' }}>
              <table className="data-table">
                <thead><tr><th>Name</th><th>Type</th><th>IP</th><th>Vendor / Model</th><th>VLAN / Zone</th><th>Criticality</th><th>Gateway(s)</th><th></th></tr></thead>
                <tbody>
                  {assets.map(a => (
                    <tr key={a.id} onClick={() => selectAsset(a)} style={{ cursor: 'pointer', background: selectedAsset?.id === a.id ? '#f0ebe2' : undefined }}>
                      <td><strong>{a.name}</strong></td>
                      <td style={{ fontSize: '12px' }}>{a.asset_type?.toUpperCase()}</td>
                      <td><code style={{ fontSize: '12px' }}>{a.ip_address || '-'}</code></td>
                      <td style={{ fontSize: '12.5px' }}>{[a.vendor, a.model].filter(Boolean).join(' ') || '-'}</td>
                      <td style={{ fontSize: '12.5px' }}>{vlanName(a.vlan_id) || a.zone || '-'}</td>
                      <td><span style={{ color: CRITICALITY_COLORS[a.criticality], fontWeight: 600, fontSize: '12.5px' }}>{a.criticality}</span></td>
                      <td style={{ fontSize: '12px' }}>
                        {a.gateways && a.gateways.filter(Boolean).length > 0
                          ? a.gateways.filter(Boolean).map((g: any) => g.hostname).join(', ')
                          : <span style={{ color: '#a63d2f', fontWeight: 600 }}>Unprotected</span>}
                      </td>
                      <td onClick={e => e.stopPropagation()}>
                        {canEdit && <button onClick={() => deleteAsset(a.id)} className="btn-small btn-danger" style={{ padding: '2px 8px', minHeight: 'auto' }}>Del</button>}
                      </td>
                    </tr>
                  ))}
                  {assets.length === 0 && <tr><td colSpan={8} className="empty-state">No IoT/OT assets registered. Click "+ Add IoT Asset" to start.</td></tr>}
                </tbody>
              </table>
            </div>

            {/* Asset detail panel */}
            {selectedAsset && (
              <div style={{ width: 360, flexShrink: 0 }}>
                <div className="card">
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                    <h4 style={{ margin: '0 0 8px' }}>{selectedAsset.name}</h4>
                    <button onClick={() => setSelectedAsset(null)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#97846c', fontSize: '16px' }}>x</button>
                  </div>
                  <div style={{ fontSize: '13px', color: '#5c4633', lineHeight: 1.8 }}>
                    <div><strong>Type:</strong> {selectedAsset.asset_type?.toUpperCase()} | <strong>Criticality:</strong> <span style={{ color: CRITICALITY_COLORS[selectedAsset.criticality] }}>{selectedAsset.criticality}</span></div>
                    <div><strong>IP:</strong> {selectedAsset.ip_address || '-'} | <strong>MAC:</strong> {selectedAsset.mac_address || '-'}</div>
                    <div><strong>Vendor:</strong> {selectedAsset.vendor || '-'} | <strong>Model:</strong> {selectedAsset.model || '-'}</div>
                    <div><strong>VLAN / Zone:</strong> {vlanName(selectedAsset.vlan_id) || '-'}</div>
                  </div>
                </div>
                <div className="card">
                  <h4 style={{ margin: '0 0 8px', color: '#5c4633' }}>Protecting Gateways</h4>
                  {assetGateways.length > 0 ? assetGateways.map(g => (
                    <div key={g.id} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '6px 0', borderBottom: '1px solid #f0ebe2', fontSize: '13px' }}>
                      <span>{g.hostname} <code style={{ fontSize: '11px' }}>({g.mgmt_ip})</code></span>
                      {canEdit && <button onClick={() => removeGateway(selectedAsset.id, g.id)} className="btn-small btn-danger" style={{ padding: '1px 6px', minHeight: 'auto', fontSize: '11px' }}>x</button>}
                    </div>
                  )) : (
                    <div style={{ padding: 10, background: '#faf0ee', borderRadius: 6, fontSize: '13px', color: '#a63d2f', borderLeft: '3px solid #a63d2f' }}>
                      No gateway assigned — this device is <strong>unprotected</strong>. Assign a gateway below.
                    </div>
                  )}
                  {canEdit && allGatewayHosts.length > 0 && (
                    <div style={{ marginTop: 10 }}>
                      <select onChange={e => { if (e.target.value) { assignGateway(selectedAsset.id, e.target.value); e.target.value = ''; } }} style={{ fontSize: '12.5px', width: '100%' }}>
                        <option value="">+ Assign gateway...</option>
                        {allGatewayHosts.filter(g => !assetGateways.some((ag: any) => ag.id === g.id)).map(g => (
                          <option key={g.id} value={g.id}>{g.hostname} ({g.mgmt_ip})</option>
                        ))}
                      </select>
                    </div>
                  )}
                </div>
                <div style={{ padding: 12, background: '#f7f4ef', borderRadius: 8, fontSize: '12.5px', color: '#78644e' }}>
                  <strong>How to protect this device:</strong>
                  <ol style={{ margin: '6px 0 0', paddingLeft: 18, lineHeight: 1.8 }}>
                    <li>Assign a gateway above</li>
                    <li>Create a policy in <a href="/policies" style={{ color: '#8b6914' }}>Policy Sets</a> scoped to <code>iot-gateway</code></li>
                    <li>Add <code>FORWARD</code> rules with destination "IoT device: {selectedAsset.name}" ({selectedAsset.ip_address || 'IP not set'}) for each allowed flow</li>
                    <li>Approve and deploy to the gateway</li>
                  </ol>
                </div>
              </div>
            )}
          </div>
        </>
      )}

      {tab === 'coverage' && <IotCoverageTab />}
      {tab === 'discovery' && <IotDiscoveryTab canEdit={canEdit} isAdmin={hasRole(roles, 'admin')} />}

      {/* ============ GATEWAYS TAB ============ */}
      {tab === 'gateways' && (
        <>
          <p style={{ color: '#78644e', fontSize: '13px', marginBottom: 16, lineHeight: 1.6 }}>
            Gateways are Linux hosts from the <a href="/inventory" style={{ color: '#8b6914' }}>Inventory</a> tagged <code>iot-gateway</code>.
            They sit between the OT/IoT network and the IT network, filtering traffic on behalf of devices that cannot run their own firewalls.
            Policies are deployed to gateways using the normal <a href="/policies" style={{ color: '#8b6914' }}>Policy Sets</a> &#8594; Approve &#8594; <a href="/deployments" style={{ color: '#8b6914' }}>Deploy</a> workflow.
            To discover what traffic flows through a gateway, run <a href="/troubleshoot" style={{ color: '#8b6914' }}>Firewall Learning</a> on it.
          </p>
          <p style={{ color: '#78644e', fontSize: '13px', marginTop: -8, marginBottom: 16, lineHeight: 1.6 }}>
            <strong>Enforcement:</strong> when a policy is deployed to a gateway, forwarded traffic to its protected devices is
            <strong> denied by default</strong>; only flows allowed by <code>FORWARD</code> rules (source &#8594; destination, e.g. an IoT device)
            pass. Other traffic routed through the gateway is not affected. Assigning or removing devices takes effect on the next deployment.
          </p>

          <div style={{ display: 'flex', gap: 20 }}>
            <div style={{ flex: 1 }}>
              <table className="data-table">
                <thead><tr><th>Hostname</th><th>IP</th><th>Backend</th><th>Protected Devices</th><th>Last Deployed Policy</th><th>Active FORWARD Rules</th><th>Status</th></tr></thead>
                <tbody>
                  {gateways.map(g => (
                    <tr key={g.id} onClick={() => selectGateway(g)} style={{ cursor: 'pointer', background: selectedGateway?.id === g.id ? '#f0ebe2' : undefined }}>
                      <td><strong>{g.hostname}</strong></td>
                      <td><code style={{ fontSize: '12px' }}>{g.mgmt_ip}</code></td>
                      <td style={{ fontSize: '12.5px' }}>{g.firewall_backend}</td>
                      <td>
                        <strong>{g.protected_asset_count}</strong> device(s)
                        {g.protected_asset_count === 0 && <span style={{ color: '#97846c', fontSize: '11px', marginLeft: 4 }}>(none assigned)</span>}
                        {Array.isArray(g.protected_assets) && g.protected_assets.length > 0 && (
                          <div style={{ fontSize: '11.5px', color: '#78644e', marginTop: 2 }}>
                            {g.protected_assets.map((a: any) => `${a.name}${a.ip_address ? ` (${a.ip_address})` : ''}${a.enabled === false ? ' [disabled, not enforced]' : ''}`).join(', ')}
                          </div>
                        )}
                      </td>
                      <td style={{ fontSize: '12.5px' }}>
                        {g.last_deployment ? `${g.last_deployment.policySetName} v${g.last_deployment.versionNumber}` : <span style={{ color: '#a63d2f' }}>No policy deployed</span>}
                        {g.last_deployment?.removedByExpiry && <div style={{ fontSize: '11px', color: '#a63d2f' }}>removed by expiry</div>}
                      </td>
                      <td style={{ fontSize: '12.5px' }}>
                        {g.last_deployment && !g.last_deployment.removedByExpiry
                          ? <strong>{g.last_deployment.forwardRuleCount ?? 0}</strong>
                          : <span style={{ color: '#97846c' }}>-</span>}
                      </td>
                      <td>
                        {g.last_deployment
                          ? <span style={{ color: g.last_deployment.status === 'SUCCEEDED' ? '#5a7a3a' : '#a63d2f', fontWeight: 600, fontSize: '12.5px' }}>{g.last_deployment.status}</span>
                          : <span style={{ color: '#97846c', fontSize: '12.5px' }}>-</span>}
                      </td>
                    </tr>
                  ))}
                  {gateways.length === 0 && (
                    <tr><td colSpan={7} className="empty-state">
                      No IoT gateways found. Add a host to the <a href="/inventory">Inventory</a> and tag it as <code>iot-gateway</code>.
                    </td></tr>
                  )}
                </tbody>
              </table>
            </div>

            {/* Gateway detail */}
            {gatewayDetail && (
              <div style={{ width: 400, flexShrink: 0 }}>
                <div className="card">
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                    <h4 style={{ margin: '0 0 8px' }}>{gatewayDetail.gateway.hostname}</h4>
                    <button onClick={() => { setSelectedGateway(null); setGatewayDetail(null); }} style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#97846c', fontSize: '16px' }}>x</button>
                  </div>
                  <div style={{ fontSize: '13px', color: '#5c4633', lineHeight: 1.8, marginBottom: 12 }}>
                    <div><strong>IP:</strong> {gatewayDetail.gateway.mgmt_ip} | <strong>Backend:</strong> {gatewayDetail.gateway.firewall_backend}</div>
                    {gatewayDetail.gateway.vlan_name && <div><strong>VLAN:</strong> VLAN {gatewayDetail.gateway.vlan_tag}: {gatewayDetail.gateway.vlan_name}</div>}
                  </div>

                  <h5 style={{ color: '#5c4633', marginBottom: 8 }}>Protected Devices ({gatewayDetail.protectedAssets.length})</h5>
                  {gatewayDetail.protectedAssets.length > 0 ? (
                    <div style={{ maxHeight: 220, overflow: 'auto' }}>
                      {gatewayDetail.protectedAssets.map((a: any) => (
                        <div key={a.id} style={{ padding: '5px 0', borderBottom: '1px solid #f0ebe2', fontSize: '12.5px', display: 'flex', justifyContent: 'space-between' }}>
                          <span>
                            <strong>{a.name}</strong>
                            <span style={{ color: '#97846c', marginLeft: 4 }}>({a.asset_type})</span>
                          </span>
                          {a.ip_address && <code style={{ fontSize: '11px' }}>{a.ip_address}</code>}
                        </div>
                      ))}
                    </div>
                  ) : <p style={{ color: '#97846c', fontSize: '13px', margin: 0 }}>No devices assigned. Go to the Assets tab and assign devices to this gateway.</p>}
                </div>

                <div className="card">
                  <h5 style={{ color: '#5c4633', marginBottom: 8 }}>Deployed Policies</h5>
                  {gatewayDetail.recentDeployments.length > 0 ? (
                    <table className="data-table" style={{ marginTop: 0 }}>
                      <thead><tr><th>Policy</th><th>Status</th><th>Date</th></tr></thead>
                      <tbody>
                        {gatewayDetail.recentDeployments.map((d: any) => (
                          <tr key={d.id}>
                            <td style={{ fontSize: '12px' }}>{d.policy_set_name} v{d.version_number}</td>
                            <td><span style={{ color: d.status === 'SUCCEEDED' ? '#5a7a3a' : '#a63d2f', fontSize: '12px', fontWeight: 600 }}>{d.status}</span></td>
                            <td style={{ fontSize: '11px', color: '#97846c' }}>{new Date(d.finished_at || d.created_at).toLocaleDateString()}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  ) : (
                    <div style={{ padding: 10, background: '#fdf6ec', borderRadius: 6, fontSize: '12.5px', color: '#5c4633' }}>
                      No policies deployed yet. Create a policy scoped to TAG <code>iot-gateway</code> and deploy it.
                    </div>
                  )}
                </div>

                <div style={{ padding: 12, background: '#f7f4ef', borderRadius: 8, fontSize: '12.5px', color: '#78644e' }}>
                  <strong>Next steps for this gateway:</strong>
                  <ul style={{ margin: '6px 0 0', paddingLeft: 18, lineHeight: 1.8 }}>
                    <li><a href="/troubleshoot" style={{ color: '#8b6914' }}>Run Firewall Learning</a> on this host to discover IoT traffic</li>
                    <li><a href="/policies" style={{ color: '#8b6914' }}>Create a policy</a> with <code>FORWARD</code> rules whose destination is one of the devices listed above (everything else to them is denied)</li>
                    <li><a href="/deployments" style={{ color: '#8b6914' }}>Deploy</a> the policy to this gateway</li>
                  </ul>
                </div>
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}
