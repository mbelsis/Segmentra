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
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: 8, maxHeight: '200px', overflowY: 'auto', border: '1px solid #ddd', padding: 8, borderRadius: 4 }}>
                  {hosts.map((h) => (
                    <label key={h.id} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
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
                      <span>{h.hostname} {h.mgmt_ip && `(${h.mgmt_ip})`}</span>
                    </label>
                  ))}
                </div>
                {formHostIds.length > 0 && (
                  <div style={{ marginTop: 8, fontSize: '0.9em', color: '#666' }}>
                    Selected: {formHostIds.length} host(s)
                  </div>
                )}
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
