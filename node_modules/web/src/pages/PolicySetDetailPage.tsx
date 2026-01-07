import { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';

import { api } from '../lib/api';

export function PolicySetDetailPage() {
  const { policySetId } = useParams();
  const navigate = useNavigate();
  const [policySet, setPolicySet] = useState<any>(null);
  const [versions, setVersions] = useState<any[]>([]);
  const [tags, setTags] = useState<any[]>([]);
  const [vlans, setVlans] = useState<any[]>([]);
  const [error, setError] = useState<string>('');

  useEffect(() => {
    if (!policySetId) return;
    loadData();
  }, [policySetId]);

  async function loadData() {
    if (!policySetId) return;
    try {
      const [psRes, vRes, tagsRes, vlansRes] = await Promise.all([
        api.policySet(policySetId),
        api.versions(policySetId),
        api.tags(),
        api.vlans()
      ]);
      setPolicySet(psRes.policySet);
      setVersions(vRes.versions.sort((a: any, b: any) => b.version_number - a.version_number));
      setTags(tagsRes.tags);
      setVlans(vlansRes.vlans);
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

  function getStatusBadge(status: string) {
    const colors: Record<string, string> = {
      DRAFT: '#888',
      PENDING_APPROVAL: '#2196F3',
      APPROVED: '#4CAF50',
      REJECTED: '#F44336',
      ARCHIVED: '#999'
    };
    return <span style={{ color: colors[status] || '#000', fontWeight: 'bold' }}>{status}</span>;
  }

  async function createVersion() {
    if (!policySetId) return;
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

  if (!policySetId) return <div className="error">Missing policy set ID</div>;
  if (!policySet) return <div>Loading...</div>;

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <button onClick={() => navigate('/policies')} className="btn-secondary" style={{ marginBottom: 8 }}>← Back to Policy Sets</button>
          <h2>{policySet.name}</h2>
        </div>
        <button onClick={createVersion} className="btn-primary">+ New Version</button>
      </div>

      {error && <div className="error-banner">{error}</div>}

      <div className="card">
        <h3>Policy Set Details</h3>
        <div className="form-grid">
          <div className="form-group">
            <label><strong>Name</strong></label>
            <div>{policySet.name}</div>
          </div>
          <div className="form-group">
            <label><strong>Description</strong></label>
            <div>{policySet.description || '-'}</div>
          </div>
          <div className="form-group">
            <label><strong>Scope</strong></label>
            <div>{getScopeDisplay(policySet)}</div>
          </div>
          <div className="form-group">
            <label><strong>Created</strong></label>
            <div>{new Date(policySet.created_at).toLocaleString()}</div>
          </div>
        </div>
      </div>

      <div className="card">
        <h3>Policy Versions</h3>
        <table className="data-table">
          <thead>
            <tr>
              <th>Version</th>
              <th>Version ID</th>
              <th>Status</th>
              <th>Interface Scope</th>
              <th>Change Summary</th>
              <th>Created</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {versions.map((v) => (
              <tr key={v.id}>
                <td><strong>v{v.version_number}</strong></td>
                <td>
                  <code
                    onClick={() => {
                      navigator.clipboard.writeText(v.id);
                      alert('Version ID copied to clipboard!');
                    }}
                    style={{ 
                      cursor: 'pointer', 
                      background: '#f0f0f0', 
                      padding: '4px 8px', 
                      borderRadius: 4,
                      fontSize: '0.85em',
                      userSelect: 'all'
                    }}
                    title="Click to copy"
                  >
                    {v.id}
                  </code>
                </td>
                <td>{getStatusBadge(v.status)}</td>
                <td>
                  <code>{v.interface_scope_type}</code>
                  {v.interface_scope_roles && v.interface_scope_roles.length > 0 && (
                    <div style={{ fontSize: '0.85em', color: '#666', marginTop: 4 }}>
                      Roles: {v.interface_scope_roles.join(', ')}
                    </div>
                  )}
                  {v.interface_scope_names && v.interface_scope_names.length > 0 && (
                    <div style={{ fontSize: '0.85em', color: '#666', marginTop: 4 }}>
                      Names: {v.interface_scope_names.join(', ')}
                    </div>
                  )}
                </td>
                <td>{v.change_summary || '-'}</td>
                <td>{new Date(v.created_at).toLocaleString()}</td>
                <td>
                  <button onClick={() => navigate(`/policy-version/${v.id}`)} className="btn-small btn-primary">View Rules</button>
                </td>
              </tr>
            ))}
            {versions.length === 0 && (
              <tr>
                <td colSpan={7} className="empty-state">
                  No versions yet. Click "New Version" to create one.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

