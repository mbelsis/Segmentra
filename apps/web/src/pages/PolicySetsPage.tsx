import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';

import { api } from '../lib/api';

export function PolicySetsPage() {
  const navigate = useNavigate();
  const [policySets, setPolicySets] = useState<any[]>([]);
  const [tags, setTags] = useState<any[]>([]);
  const [vlans, setVlans] = useState<any[]>([]);
  const [hosts, setHosts] = useState<any[]>([]);
  const [showCreate, setShowCreate] = useState(false);
  const [error, setError] = useState<string>('');
  const [loading, setLoading] = useState(true);

  // Form state
  const [formName, setFormName] = useState('');
  const [formDescription, setFormDescription] = useState('');
  const [formScopeType, setFormScopeType] = useState<'TAG' | 'VLAN' | 'HOST_LIST'>('TAG');
  const [formScopeTagId, setFormScopeTagId] = useState('');
  const [formScopeVlanId, setFormScopeVlanId] = useState('');
  const [formHostIds, setFormHostIds] = useState<string[]>([]);
  
  // Host selection filtering state
  const [hostSearchQuery, setHostSearchQuery] = useState('');
  const [hostFilterVlan, setHostFilterVlan] = useState<string>('');

  useEffect(() => {
    loadData();
  }, []);

  async function loadData() {
    try {
      setLoading(true);
      setError('');
      const [psRes, tagsRes, vlansRes, hostsRes] = await Promise.all([
        api.policySets(),
        api.tags(),
        api.vlans(),
        api.hosts()
      ]);
      console.log('Policy sets loaded:', psRes.policySets);
      setPolicySets(psRes.policySets || []);
      setTags(tagsRes.tags || []);
      setVlans(vlansRes.vlans || []);
      setHosts(hostsRes.hosts || []);
    } catch (e: any) {
      const errorMsg = e.message || String(e);
      setError(`Failed to load data: ${errorMsg}`);
      console.error('Error loading policy sets:', e);
      // Set empty arrays on error to prevent undefined issues
      setPolicySets([]);
      setTags([]);
      setVlans([]);
      setHosts([]);
    } finally {
      setLoading(false);
    }
  }

  function resetForm() {
    setFormName('');
    setFormDescription('');
    setFormScopeType('TAG');
    setFormScopeTagId('');
    setFormScopeVlanId('');
    setFormHostIds([]);
    setShowCreate(false);
    setError('');
  }

  async function createPolicySet() {
    if (!formName.trim()) {
      setError('Name is required');
      return;
    }

    try {
      const payload: any = {
        name: formName.trim(),
        description: formDescription.trim() || undefined,
        scopeType: formScopeType
      };

      if (formScopeType === 'TAG') {
        if (!formScopeTagId) {
          setError('Please select a tag');
          return;
        }
        payload.scopeTagId = formScopeTagId;
      } else if (formScopeType === 'VLAN') {
        if (!formScopeVlanId) {
          setError('Please select a VLAN');
          return;
        }
        payload.scopeVlanId = formScopeVlanId;
      } else if (formScopeType === 'HOST_LIST') {
        if (formHostIds.length === 0) {
          setError('Please select at least one host');
          return;
        }
        payload.hostIds = formHostIds;
      }

      await api.createPolicySet(payload);
      resetForm();
      loadData();
    } catch (e: any) {
      setError(String(e.message || e));
    }
  }

  async function createVersion(policySetId: string) {
    try {
      const v = await api.createVersion(policySetId, {
        interfaceScopeType: 'INTERFACE_ROLE',
        interfaceScopeRoles: ['data']
      });
      navigate(`/policy-version/${v.version.id}`);
    } catch (e: any) {
      setError(String(e.message || e));
    }
  }

  function getScopeDisplay(ps: any) {
    if (ps.scope_type === 'TAG') {
      const tag = tags.find(t => t.id === ps.scope_tag_id);
      return tag ? `Tag: ${tag.name}` : 'Tag (unknown)';
    } else if (ps.scope_type === 'VLAN') {
      const vlan = vlans.find(v => v.id === ps.scope_vlan_id);
      return vlan ? `VLAN: ${vlan.name} (${vlan.vlan_tag})` : 'VLAN (unknown)';
    } else {
      return 'Host List';
    }
  }

  return (
    <div className="page">
      <div className="page-header">
        <h2>Policy Sets</h2>
        <button onClick={() => setShowCreate(true)} className="btn-primary">+ Create Policy Set</button>
      </div>

      {error && <div className="error-banner">{error}</div>}

      {loading && (
        <div style={{ padding: 20, textAlign: 'center', color: '#666' }}>Loading policy sets...</div>
      )}

      {!loading && showCreate && (
        <div className="card">
          <h3>Create Policy Set</h3>
          <div className="form-grid">
            <div className="form-group">
              <label>Name *</label>
              <input
                type="text"
                value={formName}
                onChange={(e) => setFormName(e.target.value)}
                placeholder="e.g., Web Servers Policy"
              />
            </div>
            <div className="form-group">
              <label>Description</label>
              <textarea
                value={formDescription}
                onChange={(e) => setFormDescription(e.target.value)}
                placeholder="Optional description"
                rows={3}
              />
            </div>
            <div className="form-group">
              <label>Scope Type *</label>
              <select value={formScopeType} onChange={(e) => setFormScopeType(e.target.value as any)}>
                <option value="TAG">Tag (all hosts with a tag)</option>
                <option value="VLAN">VLAN (all hosts in a VLAN)</option>
                <option value="HOST_LIST">Host List (specific hosts)</option>
              </select>
            </div>

            {formScopeType === 'TAG' && (
              <div className="form-group">
                <label>Tag *</label>
                <select value={formScopeTagId} onChange={(e) => setFormScopeTagId(e.target.value)}>
                  <option value="">Select tag</option>
                  {tags.map((t) => (
                    <option key={t.id} value={t.id}>{t.name}</option>
                  ))}
                </select>
              </div>
            )}

            {formScopeType === 'VLAN' && (
              <div className="form-group">
                <label>VLAN *</label>
                <select value={formScopeVlanId} onChange={(e) => setFormScopeVlanId(e.target.value)}>
                  <option value="">Select VLAN</option>
                  {vlans.map((v) => (
                    <option key={v.id} value={v.id}>{v.name} (VLAN {v.vlan_tag})</option>
                  ))}
                </select>
              </div>
            )}

            {formScopeType === 'HOST_LIST' && (
              <div className="form-group" style={{ gridColumn: '1 / -1' }}>
                <label>Hosts * (select multiple)</label>
                
                {/* Host Selection Filters */}
                <div style={{ marginBottom: 12, padding: 12, background: '#f5f5f5', borderRadius: 8 }}>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 12, marginBottom: 8 }}>
                    <div>
                      <label style={{ display: 'block', marginBottom: 4, fontSize: '0.9em', fontWeight: 500 }}>Search Hostname</label>
                      <input
                        type="text"
                        value={hostSearchQuery}
                        onChange={(e) => setHostSearchQuery(e.target.value)}
                        placeholder="e.g., *.nginx.domain.com or web-*"
                        style={{ width: '100%', padding: '6px 8px', border: '1px solid #ddd', borderRadius: 4 }}
                      />
                      <small style={{ display: 'block', marginTop: 4, fontSize: '0.8em', color: '#666' }}>
                        Supports wildcards: * matches any characters
                      </small>
                    </div>
                    <div>
                      <label style={{ display: 'block', marginBottom: 4, fontSize: '0.9em', fontWeight: 500 }}>Filter by VLAN</label>
                      <select
                        value={hostFilterVlan}
                        onChange={(e) => setHostFilterVlan(e.target.value)}
                        style={{ width: '100%', padding: '6px 8px', border: '1px solid #ddd', borderRadius: 4 }}
                      >
                        <option value="">All VLANs</option>
                        {vlans.map((v) => (
                          <option key={v.id} value={v.id}>{v.name} (VLAN {v.vlan_tag})</option>
                        ))}
                      </select>
                    </div>
                  </div>
                  {(hostSearchQuery || hostFilterVlan) && (
                    <button
                      onClick={() => {
                        setHostSearchQuery('');
                        setHostFilterVlan('');
                      }}
                      className="btn-small btn-secondary"
                    >
                      Clear Filters
                    </button>
                  )}
                </div>

                {/* Filtered Hosts Table */}
                {(() => {
                  // Filter hosts based on search and VLAN
                  let filteredHosts = hosts;
                  
                  // Filter by VLAN
                  if (hostFilterVlan) {
                    filteredHosts = filteredHosts.filter((h) => h.vlan_id === hostFilterVlan);
                  }
                  
                  // Filter by search query (supports wildcards)
                  if (hostSearchQuery.trim()) {
                    const searchPattern = hostSearchQuery.trim().toLowerCase();
                    // Convert wildcard pattern to regex
                    const regexPattern = searchPattern
                      .replace(/[.*+?^${}()|[\]\\]/g, '\\$&') // Escape special regex chars
                      .replace(/\\\*/g, '.*') // Convert \* to .*
                      .replace(/\\\?/g, '.'); // Convert \? to . (optional, for future)
                    const regex = new RegExp(`^${regexPattern}$`, 'i');
                    
                    filteredHosts = filteredHosts.filter((h) => {
                      const hostname = (h.hostname || '').toLowerCase();
                      const mgmtIp = (h.mgmt_ip || '').toLowerCase();
                      return regex.test(hostname) || regex.test(mgmtIp);
                    });
                  }
                  
                  return (
                    <div style={{ border: '1px solid #ddd', borderRadius: 4, overflow: 'hidden' }}>
                      <div style={{ maxHeight: '400px', overflowY: 'auto' }}>
                        <table className="data-table" style={{ margin: 0 }}>
                          <thead style={{ position: 'sticky', top: 0, background: '#f5f5f5', zIndex: 10 }}>
                            <tr>
                              <th style={{ width: 40 }}>
                                <input
                                  type="checkbox"
                                  checked={filteredHosts.length > 0 && filteredHosts.every(h => formHostIds.includes(h.id))}
                                  onChange={(e) => {
                                    if (e.target.checked) {
                                      // Add all filtered hosts
                                      const newIds = [...new Set([...formHostIds, ...filteredHosts.map(h => h.id)])];
                                      setFormHostIds(newIds);
                                    } else {
                                      // Remove all filtered hosts
                                      const filteredIds = new Set(filteredHosts.map(h => h.id));
                                      setFormHostIds(formHostIds.filter(id => !filteredIds.has(id)));
                                    }
                                  }}
                                />
                              </th>
                              <th>Hostname</th>
                              <th>Mgmt IP</th>
                              <th>VLAN</th>
                              <th>Tags</th>
                            </tr>
                          </thead>
                          <tbody>
                            {filteredHosts.map((h) => (
                              <tr key={h.id}>
                                <td>
                                  <input
                                    type="checkbox"
                                    checked={formHostIds.includes(h.id)}
                                    onChange={(e) => {
                                      if (e.target.checked) {
                                        setFormHostIds([...formHostIds, h.id]);
                                      } else {
                                        setFormHostIds(formHostIds.filter(id => id !== h.id));
                                      }
                                    }}
                                  />
                                </td>
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
                              </tr>
                            ))}
                            {filteredHosts.length === 0 && (
                              <tr>
                                <td colSpan={5} className="empty-state" style={{ textAlign: 'center', padding: '24px' }}>
                                  {hostSearchQuery || hostFilterVlan
                                    ? 'No hosts match your filters. Try adjusting your search criteria.'
                                    : 'No hosts available.'}
                                </td>
                              </tr>
                            )}
                          </tbody>
                        </table>
                      </div>
                      <div style={{ padding: 8, background: '#f5f5f5', borderTop: '1px solid #ddd', fontSize: '0.9em', color: '#666' }}>
                        Showing {filteredHosts.length} of {hosts.length} hosts
                        {formHostIds.length > 0 && (
                          <span style={{ marginLeft: 16, fontWeight: 500 }}>
                            • {formHostIds.length} selected
                          </span>
                        )}
                      </div>
                    </div>
                  );
                })()}
              </div>
            )}
          </div>

          <div className="form-actions">
            <button onClick={createPolicySet} className="btn-primary">Create</button>
            <button onClick={resetForm} className="btn-secondary">Cancel</button>
          </div>
        </div>
      )}

      {!loading && (
        <div className="card">
          <div style={{ 
          padding: 12, 
          marginBottom: 16, 
          background: '#e3f2fd', 
          borderRadius: 4, 
          border: '1px solid #90caf9',
          display: 'flex',
          alignItems: 'center',
          gap: 8
        }}>
          <span style={{ fontSize: '1.2em' }}>💡</span>
          <div style={{ flex: 1 }}>
            <strong>Tip:</strong> To add firewall rules, click <strong>"New Version"</strong> on a policy set. 
            This will create a new policy version where you can add, edit, and manage firewall rules.
          </div>
        </div>
        <table className="data-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Description</th>
              <th>Scope</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {policySets.map((ps) => (
              <tr key={ps.id}>
                <td><strong>{ps.name}</strong></td>
                <td>{ps.description || '-'}</td>
                <td>{getScopeDisplay(ps)}</td>
                <td>
                  <button 
                    onClick={() => createVersion(ps.id)} 
                    className="btn-small btn-primary"
                    title="Click to create a new policy version where you can add firewall rules"
                  >
                    New Version
                  </button>
                  <button onClick={() => navigate(`/policy-set/${ps.id}`)} className="btn-small">View</button>
                </td>
              </tr>
            ))}
            {policySets.length === 0 && (
              <tr>
                <td colSpan={4} className="empty-state">
                  No policy sets yet. Click "Create Policy Set" to create one.
                </td>
              </tr>
            )}
          </tbody>
        </table>
        </div>
      )}
    </div>
  );
}
