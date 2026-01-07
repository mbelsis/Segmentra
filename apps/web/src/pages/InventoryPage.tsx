import { useEffect, useState } from 'react';

import { api } from '../lib/api';

type Tab = 'hosts' | 'tags' | 'vlans';

export function InventoryPage() {
  const [activeTab, setActiveTab] = useState<Tab>('hosts');
  
  // Hosts state
  const [hosts, setHosts] = useState<any[]>([]);
  const [hostname, setHostname] = useState('');
  const [mgmtIp, setMgmtIp] = useState('');
  const [hostVlanId, setHostVlanId] = useState<string>('');
  const [hostTagIds, setHostTagIds] = useState<string[]>([]);
  const [editingHost, setEditingHost] = useState<string | null>(null);
  
  // Tags state
  const [tags, setTags] = useState<any[]>([]);
  const [tagName, setTagName] = useState('');
  const [tagDescription, setTagDescription] = useState('');
  const [editingTag, setEditingTag] = useState<string | null>(null);
  
  // VLANs state
  const [vlans, setVlans] = useState<any[]>([]);
  const [vlanTag, setVlanTag] = useState('');
  const [vlanName, setVlanName] = useState('');
  const [vlanDescription, setVlanDescription] = useState('');
  const [editingVlan, setEditingVlan] = useState<string | null>(null);
  
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadData();
  }, []);

  async function loadData() {
    try {
      const [hostsRes, tagsRes, vlansRes] = await Promise.all([
        api.hosts().catch(() => ({ hosts: [] })),
        api.tags().catch(() => ({ tags: [] })),
        api.vlans().catch(() => ({ vlans: [] }))
      ]);
      setHosts(hostsRes.hosts || []);
      setTags(tagsRes.tags || []);
      setVlans(vlansRes.vlans || []);
    } catch (e: any) {
      setError(String(e?.message ?? e));
    }
  }

  // Host functions
  function resetHostForm() {
    setHostname('');
    setMgmtIp('');
    setHostVlanId('');
    setHostTagIds([]);
    setEditingHost(null);
    setError(null);
  }

  async function saveHost() {
    if (!hostname.trim()) {
      setError('Hostname is required');
      return;
    }
    setError(null);
    try {
      const payload: any = {
        hostname: hostname.trim(),
        mgmtIp: mgmtIp.trim() || undefined,
        vlanId: hostVlanId || undefined,
        tagIds: hostTagIds
      };
      
      if (editingHost) {
        const r = await api.updateHost(editingHost, payload);
        setHosts((prev) => prev.map(h => h.id === editingHost ? r.host : h));
      } else {
        const r = await api.createHost(payload);
        setHosts((prev) => [...prev, r.host]);
      }
      resetHostForm();
      loadData(); // Reload to get fresh data
    } catch (e: any) {
      setError(String(e?.message ?? e));
    }
  }

  function editHost(host: any) {
    setHostname(host.hostname);
    setMgmtIp(host.mgmt_ip || '');
    setHostVlanId(host.vlan_id || '');
    setHostTagIds((host.tags || []).map((t: any) => t.id));
    setEditingHost(host.id);
  }

  function toggleHostTag(tagId: string) {
    setHostTagIds((prev) => 
      prev.includes(tagId) 
        ? prev.filter(id => id !== tagId)
        : [...prev, tagId]
    );
  }

  // Tag functions
  function resetTagForm() {
    setTagName('');
    setTagDescription('');
    setEditingTag(null);
    setError(null);
  }

  async function saveTag() {
    if (!tagName.trim()) {
      setError('Tag name is required');
      return;
    }
    setError(null);
    try {
      if (editingTag) {
        const r = await api.updateTag(editingTag, {
          name: tagName.trim(),
          description: tagDescription.trim() || undefined
        });
        setTags((prev) => prev.map(t => t.id === editingTag ? r.tag : t));
      } else {
        const r = await api.createTag({
          name: tagName.trim(),
          description: tagDescription.trim() || undefined
        });
        setTags((prev) => [...prev, r.tag]);
      }
      resetTagForm();
    } catch (e: any) {
      setError(String(e?.message ?? e));
    }
  }

  async function deleteTag(id: string) {
    if (!confirm('Are you sure you want to delete this tag?')) return;
    setError(null);
    try {
      await api.deleteTag(id);
      setTags((prev) => prev.filter(t => t.id !== id));
    } catch (e: any) {
      setError(String(e?.message ?? e));
    }
  }

  function editTag(tag: any) {
    setTagName(tag.name);
    setTagDescription(tag.description || '');
    setEditingTag(tag.id);
  }

  // VLAN functions
  function resetVlanForm() {
    setVlanTag('');
    setVlanName('');
    setVlanDescription('');
    setEditingVlan(null);
    setError(null);
  }

  async function saveVlan() {
    if (!vlanName.trim()) {
      setError('VLAN name is required');
      return;
    }
    const tagNum = parseInt(vlanTag.trim());
    if (isNaN(tagNum) || tagNum < 1 || tagNum > 4094) {
      setError('VLAN tag must be a number between 1 and 4094');
      return;
    }
    setError(null);
    try {
      if (editingVlan) {
        const r = await api.updateVlan(editingVlan, {
          vlanTag: tagNum,
          name: vlanName.trim(),
          description: vlanDescription.trim() || undefined
        });
        setVlans((prev) => prev.map(v => v.id === editingVlan ? r.vlan : v));
      } else {
        const r = await api.createVlan({
          vlanTag: tagNum,
          name: vlanName.trim(),
          description: vlanDescription.trim() || undefined
        });
        setVlans((prev) => [...prev, r.vlan]);
      }
      resetVlanForm();
    } catch (e: any) {
      setError(String(e?.message ?? e));
    }
  }

  async function deleteVlan(id: string) {
    if (!confirm('Are you sure you want to delete this VLAN?')) return;
    setError(null);
    try {
      await api.deleteVlan(id);
      setVlans((prev) => prev.filter(v => v.id !== id));
    } catch (e: any) {
      setError(String(e?.message ?? e));
    }
  }

  function editVlan(vlan: any) {
    setVlanTag(String(vlan.vlan_tag));
    setVlanName(vlan.name);
    setVlanDescription(vlan.description || '');
    setEditingVlan(vlan.id);
  }

  return (
    <div className="page">
      <div className="page-header">
        <h2>Inventory</h2>
      </div>

      {/* Tabs */}
      <div style={{ display: 'flex', gap: 8, marginBottom: 24, borderBottom: '2px solid #e0e0e0' }}>
        <button
          onClick={() => setActiveTab('hosts')}
          className={activeTab === 'hosts' ? 'btn-primary' : 'btn-secondary'}
          style={{ borderBottom: activeTab === 'hosts' ? '2px solid #646cff' : 'none', borderRadius: 0, marginBottom: -2 }}
        >
          Hosts
        </button>
        <button
          onClick={() => setActiveTab('tags')}
          className={activeTab === 'tags' ? 'btn-primary' : 'btn-secondary'}
          style={{ borderBottom: activeTab === 'tags' ? '2px solid #646cff' : 'none', borderRadius: 0, marginBottom: -2 }}
        >
          Tags
        </button>
        <button
          onClick={() => setActiveTab('vlans')}
          className={activeTab === 'vlans' ? 'btn-primary' : 'btn-secondary'}
          style={{ borderBottom: activeTab === 'vlans' ? '2px solid #646cff' : 'none', borderRadius: 0, marginBottom: -2 }}
        >
          VLANs
        </button>
      </div>

      {error && <div className="error-banner">{error}</div>}

      {/* Hosts Tab */}
      {activeTab === 'hosts' && (
        <>
          <div className="card">
            <h3>{editingHost ? 'Edit Host' : 'Add Host'}</h3>
            <div className="form-grid">
              <div className="form-group">
                <label>Hostname *</label>
                <input
                  type="text"
                  value={hostname}
                  onChange={(e) => setHostname(e.target.value)}
                  placeholder="e.g., web-server-01"
                />
              </div>
              <div className="form-group">
                <label>Management IP</label>
                <input
                  type="text"
                  value={mgmtIp}
                  onChange={(e) => setMgmtIp(e.target.value)}
                  placeholder="e.g., 10.0.0.100"
                />
              </div>
              <div className="form-group">
                <label>VLAN</label>
                <select
                  value={hostVlanId}
                  onChange={(e) => setHostVlanId(e.target.value)}
                >
                  <option value="">None</option>
                  {vlans.map((v) => (
                    <option key={v.id} value={v.id}>
                      {v.name} (VLAN {v.vlan_tag})
                    </option>
                  ))}
                </select>
              </div>
            </div>
            <div className="form-group">
              <label>Tags</label>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginTop: 8 }}>
                {tags.map((tag) => (
                  <label key={tag.id} style={{ display: 'flex', alignItems: 'center', cursor: 'pointer' }}>
                    <input
                      type="checkbox"
                      checked={hostTagIds.includes(tag.id)}
                      onChange={() => toggleHostTag(tag.id)}
                      style={{ marginRight: 6 }}
                    />
                    <span>{tag.name}</span>
                  </label>
                ))}
                {tags.length === 0 && (
                  <span style={{ color: '#999', fontStyle: 'italic' }}>No tags available. Create tags in the Tags tab.</span>
                )}
              </div>
            </div>
            <div className="form-actions">
              <button
                disabled={!hostname.trim()}
                onClick={saveHost}
                className="btn-primary"
              >
                {editingHost ? 'Update' : 'Add'} Host
              </button>
              {editingHost && (
                <button onClick={resetHostForm} className="btn-secondary">
                  Cancel
                </button>
              )}
            </div>
          </div>

          <div className="card">
            <h3>Hosts</h3>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Hostname</th>
                  <th>Mgmt IP</th>
                  <th>VLAN</th>
                  <th>Tags</th>
                  <th>Backend</th>
                  <th>Enabled</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {hosts.map((h) => (
                  <tr key={h.id}>
                    <td><strong>{h.hostname}</strong></td>
                    <td>{h.mgmt_ip || '-'}</td>
                    <td>
                      {h.vlan_name ? (
                        <span>{h.vlan_name} <code>({h.vlan_tag})</code></span>
                      ) : (
                        '-'
                      )}
                    </td>
                    <td>
                      {h.tags && h.tags.length > 0 ? (
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                          {h.tags.map((tag: any) => (
                            <span key={tag.id} style={{ background: '#e3f2fd', padding: '2px 8px', borderRadius: 4, fontSize: '0.85em' }}>
                              {tag.name}
                            </span>
                          ))}
                        </div>
                      ) : (
                        '-'
                      )}
                    </td>
                    <td><code>{h.firewall_backend || 'auto'}</code></td>
                    <td>{h.enabled ? '✓' : '✗'}</td>
                    <td>
                      <button onClick={() => editHost(h)} className="btn-small btn-secondary">Edit</button>
                    </td>
                  </tr>
                ))}
                {hosts.length === 0 && (
                  <tr>
                    <td colSpan={7} className="empty-state">
                      No hosts found. Add a host above.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </>
      )}

      {/* Tags Tab */}
      {activeTab === 'tags' && (
        <>
          <div className="card">
            <h3>{editingTag ? 'Edit Tag' : 'Create Tag'}</h3>
            <div className="form-grid">
              <div className="form-group">
                <label>Name *</label>
                <input
                  type="text"
                  value={tagName}
                  onChange={(e) => setTagName(e.target.value)}
                  placeholder="e.g., web-servers"
                />
              </div>
              <div className="form-group">
                <label>Description</label>
                <input
                  type="text"
                  value={tagDescription}
                  onChange={(e) => setTagDescription(e.target.value)}
                  placeholder="Optional description"
                />
              </div>
            </div>
            <div className="form-actions">
              <button
                disabled={!tagName.trim()}
                onClick={saveTag}
                className="btn-primary"
              >
                {editingTag ? 'Update' : 'Create'} Tag
              </button>
              {editingTag && (
                <button onClick={resetTagForm} className="btn-secondary">
                  Cancel
                </button>
              )}
            </div>
          </div>

          <div className="card">
            <h3>Tags</h3>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Description</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {tags.map((t) => (
                  <tr key={t.id}>
                    <td><strong>{t.name}</strong></td>
                    <td>{t.description || '-'}</td>
                    <td>
                      <button onClick={() => editTag(t)} className="btn-small btn-secondary" style={{ marginRight: 8 }}>Edit</button>
                      <button onClick={() => deleteTag(t.id)} className="btn-small btn-danger">Delete</button>
                    </td>
                  </tr>
                ))}
                {tags.length === 0 && (
                  <tr>
                    <td colSpan={3} className="empty-state">
                      No tags found. Create a tag above.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </>
      )}

      {/* VLANs Tab */}
      {activeTab === 'vlans' && (
        <>
          <div className="card">
            <h3>{editingVlan ? 'Edit VLAN' : 'Create VLAN'}</h3>
            <div className="form-grid">
              <div className="form-group">
                <label>VLAN Tag *</label>
                <input
                  type="number"
                  value={vlanTag}
                  onChange={(e) => setVlanTag(e.target.value)}
                  placeholder="1-4094"
                  min="1"
                  max="4094"
                />
                <small>VLAN tag number (1-4094)</small>
              </div>
              <div className="form-group">
                <label>Name *</label>
                <input
                  type="text"
                  value={vlanName}
                  onChange={(e) => setVlanName(e.target.value)}
                  placeholder="e.g., Production Network"
                />
              </div>
              <div className="form-group">
                <label>Description</label>
                <input
                  type="text"
                  value={vlanDescription}
                  onChange={(e) => setVlanDescription(e.target.value)}
                  placeholder="Optional description"
                />
              </div>
            </div>
            <div className="form-actions">
              <button
                disabled={!vlanName.trim() || !vlanTag.trim()}
                onClick={saveVlan}
                className="btn-primary"
              >
                {editingVlan ? 'Update' : 'Create'} VLAN
              </button>
              {editingVlan && (
                <button onClick={resetVlanForm} className="btn-secondary">
                  Cancel
                </button>
              )}
            </div>
          </div>

          <div className="card">
            <h3>VLANs</h3>
            <table className="data-table">
              <thead>
                <tr>
                  <th>VLAN Tag</th>
                  <th>Name</th>
                  <th>Description</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {vlans.map((v) => (
                  <tr key={v.id}>
                    <td><code>{v.vlan_tag}</code></td>
                    <td><strong>{v.name}</strong></td>
                    <td>{v.description || '-'}</td>
                    <td>
                      <button onClick={() => editVlan(v)} className="btn-small btn-secondary" style={{ marginRight: 8 }}>Edit</button>
                      <button onClick={() => deleteVlan(v.id)} className="btn-small btn-danger">Delete</button>
                    </td>
                  </tr>
                ))}
                {vlans.length === 0 && (
                  <tr>
                    <td colSpan={4} className="empty-state">
                      No VLANs found. Create a VLAN above.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  );
}
