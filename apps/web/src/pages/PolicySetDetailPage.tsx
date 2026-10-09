import { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';

import { api, errorMessage } from '../lib/api';
import { Modal } from '../components/Modal';
import { useAuth, hasRole } from '../lib/auth-context';

export function PolicySetDetailPage() {
  const { policySetId } = useParams();
  const navigate = useNavigate();
  const { roles } = useAuth();
  const canManage = hasRole(roles, 'operator', 'admin');
  const [policySet, setPolicySet] = useState<any>(null);
  const [versions, setVersions] = useState<any[]>([]);
  const [tags, setTags] = useState<any[]>([]);
  const [vlans, setVlans] = useState<any[]>([]);
  const [error, setError] = useState<string>('');
  const [submitTarget, setSubmitTarget] = useState<any | null>(null);
  const [submitReason, setSubmitReason] = useState('');
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    if (!policySetId) return;
    loadData();
  }, [policySetId]);

  async function exportVersion(v: any, format: 'yaml' | 'json') {
    if (!policySetId) return;
    try {
      const r = await api.exportPolicySet(policySetId, format, v.version_number);
      const blob = new Blob([r.text], { type: format === 'json' ? 'application/json' : 'application/yaml' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = r.filename;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e: any) {
      setError(errorMessage(e));
    }
  }

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
      setError(errorMessage(e));
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
      DEPLOYED: '#2e7d32',
      REJECTED: '#F44336',
      ARCHIVED: '#999'
    };
    return <span style={{ color: colors[status] || '#000', fontWeight: 'bold' }}>{status}</span>;
  }

  async function createVersion() {
    if (!policySetId) return;
    try {
      const v = await api.createVersion(policySetId, {
        interfaceScopeType: 'ALL_INTERFACES'
      });
      navigate(`/policy-version/${v.version.id}`);
    } catch (e: any) {
      setError(errorMessage(e));
    }
  }

  // Opens the dialog where the author says why the version is sent for approval; the approver sees it and it is
  // written to the audit log together with who asked and when.
  function submitForApproval(versionId: string) {
    const v = versions.find((x) => x.id === versionId);
    setSubmitTarget(v ?? { id: versionId });
    setSubmitReason('');
  }

  async function confirmSubmit() {
    if (!submitTarget) return;
    setSubmitting(true);
    try {
      await api.submitApproval(submitTarget.id, submitReason);
      setSubmitTarget(null);
      loadData();
    } catch (e: any) {
      setError(errorMessage(e));
      setSubmitTarget(null);
    } finally {
      setSubmitting(false);
    }
  }

  async function cloneVersion(versionId: string) {
    if (!confirm('Clone this policy version? This will create a new DRAFT version with all the same rules.')) return;
    try {
      const v = await api.cloneVersion(versionId);
      loadData();
      navigate(`/policy-version/${v.version.id}`);
    } catch (e: any) {
      setError(errorMessage(e));
    }
  }

  async function deleteVersion(versionId: string) {
    if (!confirm('Delete this DRAFT version? This will permanently remove the version and all its rules.')) return;
    try {
      await api.deleteVersion(versionId);
      loadData();
    } catch (e: any) {
      setError(errorMessage(e));
    }
  }

  async function archiveVersion(versionId: string) {
    if (!confirm('Archive this policy version? Archived versions cannot be deployed but remain visible for reference.')) return;
    try {
      await api.archiveVersion(versionId);
      loadData();
    } catch (e: any) {
      setError(errorMessage(e));
    }
  }

  if (!policySetId) return <div className="error">Missing policy set ID</div>;
  if (!policySet) {
    if (error) return <div className="error-banner">Failed to load policy set: {error}</div>;
    return <div>Loading...</div>;
  }

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <button onClick={() => navigate('/policies')} className="btn-secondary" style={{ marginBottom: 8 }}>← Back to Policy Sets</button>
          <h2>{policySet.name}</h2>
        </div>
        {canManage && <button onClick={createVersion} className="btn-primary">+ New Version</button>}
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
              <th>Approved By</th>
              <th>Interface Scope</th>
              <th>Change Summary</th>
              <th>Created</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {versions.map((v) => {
              const isDraft = v.status === 'DRAFT';
              const isApproved = v.status === 'APPROVED';
              const isDeployed = v.status === 'DEPLOYED';
              const isRejected = v.status === 'REJECTED';
              return (
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
                  <td>
                    {getStatusBadge(v.status)}
                    {v.active_host_count > 0 ? (
                      <div style={{ fontSize: '0.78em', color: '#2e7d32', marginTop: 4, fontWeight: 600 }}>
                        Active on {v.active_host_count} host{v.active_host_count === 1 ? '' : 's'}
                      </div>
                    ) : isDeployed ? (
                      <div style={{ fontSize: '0.78em', color: '#97846c', marginTop: 4 }}>Not active (superseded or removed)</div>
                    ) : null}
                  </td>
                  <td style={{ fontSize: '12.5px' }}>
                    {v.approved_by_username ? (
                      <span style={{ color: '#5a7a3a' }}>{v.approved_by_username}</span>
                    ) : v.rejected_by_username ? (
                      <span style={{ color: '#a63d2f' }}>{v.rejected_by_username} (rejected)</span>
                    ) : (
                      <span style={{ color: '#97846c' }}>-</span>
                    )}
                  </td>
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
                  <td>
                    {v.change_summary || (v.submission_note ? null : '-')}
                    {v.submission_note && (
                      <div style={{ fontSize: '0.85em', color: '#5c4633', marginTop: v.change_summary ? 4 : 0 }}>
                        Reason for approval: {v.submission_note}
                      </div>
                    )}
                    {isRejected && v.rejection_reason && (
                      <div style={{ color: '#a63d2f', fontSize: '0.85em', marginTop: 4 }}>
                        Reason: {v.rejection_reason}
                      </div>
                    )}
                  </td>
                  <td>{new Date(v.created_at).toLocaleString()}</td>
                  <td>
                    <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                      <button onClick={() => navigate(`/policy-version/${v.id}`)} className="btn-small btn-primary">View Rules</button>
                      <button onClick={() => exportVersion(v, 'yaml')} className="btn-small btn-secondary" title="Download this version as a policy-as-code document">Export YAML</button>
                      <button onClick={() => exportVersion(v, 'json')} className="btn-small btn-secondary">JSON</button>
                      {canManage && isDraft && (
                        <button onClick={() => submitForApproval(v.id)} className="btn-small btn-secondary">Submit for Approval</button>
                      )}
                      {canManage && isRejected && (
                        <button onClick={() => submitForApproval(v.id)} className="btn-small btn-secondary">Resubmit for Approval</button>
                      )}
                      {canManage && (isApproved || isDeployed) && (
                        <button onClick={() => cloneVersion(v.id)} className="btn-small btn-secondary">Clone</button>
                      )}
                      {canManage && (isApproved || isDeployed || v.status === 'PENDING_APPROVAL') && (
                        <button onClick={() => archiveVersion(v.id)} className="btn-small btn-secondary" style={{ color: '#78644e' }}>Archive</button>
                      )}
                      {canManage && (isDraft || isRejected) && (
                        <button onClick={() => deleteVersion(v.id)} className="btn-small btn-danger">Delete</button>
                      )}
                    </div>
                  </td>
                </tr>
              );
            })}
            {versions.length === 0 && (
              <tr>
                <td colSpan={8} className="empty-state">
                  No versions yet.{canManage && ' Click "New Version" to create one.'}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      {submitTarget && (
        <Modal
          title={submitTarget.version_number ? `Send version ${submitTarget.version_number} for approval` : 'Send for approval'}
          onClose={() => setSubmitTarget(null)}
          footer={
            <>
              <button className="btn-secondary" onClick={() => setSubmitTarget(null)} disabled={submitting}>Cancel</button>
              <button className="btn-primary" onClick={confirmSubmit} disabled={submitting}>{submitting ? 'Sending...' : 'Send for approval'}</button>
            </>
          }
        >
          <p style={{ marginTop: 0, color: '#5c4633' }}>
            An approver will review this version before it can be deployed. Tell them what changed and why: the approver sees this text, and it is stored in the audit log with who asked and when.
          </p>
          {submitTarget.status === 'REJECTED' && submitTarget.rejection_reason && (
            <div style={{ background: '#faf0ee', border: '1px solid #e8c4bf', borderRadius: 8, padding: '8px 12px', marginBottom: 12, fontSize: 13, color: '#a63d2f' }}>
              Previously rejected: {submitTarget.rejection_reason}
            </div>
          )}
          <label htmlFor="submit-reason" style={{ display: 'block', fontWeight: 600, marginBottom: 6 }}>Reason / description</label>
          <textarea
            id="submit-reason"
            value={submitReason}
            onChange={(e) => setSubmitReason(e.target.value)}
            maxLength={1000}
            rows={5}
            placeholder="For example: open 443 for the new web tier, ticket CHG-1234. Needed before Friday's release."
            style={{ width: '100%', boxSizing: 'border-box' }}
            autoFocus
          />
          <div style={{ fontSize: 12, color: '#97846c', textAlign: 'right' }}>{submitReason.length}/1000, optional</div>
        </Modal>
      )}
    </div>
  );
}

