import { useEffect, useState } from 'react';

import { api } from '../lib/api';

export function ApprovalsPage() {
  const [versionId, setVersionId] = useState('');
  const [reason, setReason] = useState('');
  const [version, setVersion] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string>('');
  const [success, setSuccess] = useState<string>('');

  async function loadVersion() {
    if (!versionId.trim()) {
      setVersion(null);
      return;
    }
    setLoading(true);
    setError('');
    setSuccess('');
    try {
      const res = await api.version(versionId.trim());
      setVersion(res.version);
    } catch (e: any) {
      setError(String(e.message || e));
      setVersion(null);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    const timer = setTimeout(() => {
      loadVersion();
    }, 500);
    return () => clearTimeout(timer);
  }, [versionId]);

  async function handleApprove() {
    if (!versionId.trim()) return;
    setLoading(true);
    setError('');
    setSuccess('');
    try {
      await api.approve(versionId.trim());
      setSuccess(`Policy version ${version?.version_number || versionId} approved successfully`);
      setVersionId('');
      setVersion(null);
    } catch (e: any) {
      const errorMsg = e.message || String(e);
      if (errorMsg.includes('approver_must_differ')) {
        setError('You cannot approve a policy version that you created. If you are an admin, this should now work. If you still see this error, please have another user with approver role review it.');
      } else {
        setError(errorMsg);
      }
    } finally {
      setLoading(false);
    }
  }

  async function handleReject() {
    if (!versionId.trim() || !reason.trim()) {
      setError('Rejection reason is required');
      return;
    }
    setLoading(true);
    setError('');
    setSuccess('');
    try {
      await api.reject(versionId.trim(), reason.trim());
      setSuccess(`Policy version ${version?.version_number || versionId} rejected`);
      setVersionId('');
      setReason('');
      setVersion(null);
    } catch (e: any) {
      setError(String(e.message || e));
    } finally {
      setLoading(false);
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

  return (
    <div className="page">
      <div className="page-header">
        <h2>Policy Approvals</h2>
      </div>

      <div className="card">
        <h3>Quick Approve/Reject</h3>
        <p style={{ marginBottom: 20, color: '#666' }}>
          Paste a <code>policy_version.id</code> to view details and approve or reject it.
        </p>

        <div className="form-group">
          <label><strong>Policy Version ID</strong></label>
          <input
            type="text"
            value={versionId}
            onChange={(e) => setVersionId(e.target.value)}
            placeholder="Enter UUID..."
            style={{ fontFamily: 'monospace', fontSize: '13px' }}
            disabled={loading}
          />
        </div>

        {error && <div className="error-banner">{error}</div>}
        {success && <div style={{ background: '#e8f5e9', color: '#2e7d32', padding: 12, borderRadius: 8, marginBottom: 20, borderLeft: '4px solid #4CAF50' }}>{success}</div>}

        {loading && versionId && !version && (
          <div style={{ padding: 20, textAlign: 'center', color: '#666' }}>Loading...</div>
        )}

        {version && (
          <div style={{ marginTop: 24, padding: 20, background: '#f8f9fa', borderRadius: 8 }}>
            <h4 style={{ marginTop: 0 }}>Policy Version Details</h4>
            <div className="form-grid">
              <div className="form-group">
                <label><strong>Version</strong></label>
                <div>v{version.version_number}</div>
              </div>
              <div className="form-group">
                <label><strong>Status</strong></label>
                <div>{getStatusBadge(version.status)}</div>
              </div>
              <div className="form-group">
                <label><strong>Change Summary</strong></label>
                <div>{version.change_summary || '-'}</div>
              </div>
              <div className="form-group">
                <label><strong>Created</strong></label>
                <div>{new Date(version.created_at).toLocaleString()}</div>
              </div>
              {version.submitted_at && (
                <div className="form-group">
                  <label><strong>Submitted</strong></label>
                  <div>{new Date(version.submitted_at).toLocaleString()}</div>
                </div>
              )}
              {version.interface_scope_type && (
                <div className="form-group">
                  <label><strong>Interface Scope</strong></label>
                  <div>
                    <code>{version.interface_scope_type}</code>
                    {version.interface_scope_roles && version.interface_scope_roles.length > 0 && (
                      <div style={{ fontSize: '0.85em', color: '#666', marginTop: 4 }}>
                        Roles: {version.interface_scope_roles.join(', ')}
                      </div>
                    )}
                    {version.interface_scope_names && version.interface_scope_names.length > 0 && (
                      <div style={{ fontSize: '0.85em', color: '#666', marginTop: 4 }}>
                        Names: {version.interface_scope_names.join(', ')}
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>

            {version.status === 'PENDING_APPROVAL' && (
              <div style={{ marginTop: 24, paddingTop: 20, borderTop: '2px solid #e0e0e0' }}>
                <div className="form-group" style={{ marginBottom: 16 }}>
                  <label><strong>Rejection Reason</strong> (required for rejection)</label>
                  <textarea
                    value={reason}
                    onChange={(e) => setReason(e.target.value)}
                    placeholder="Enter reason for rejection..."
                    rows={3}
                    disabled={loading}
                  />
                </div>
                <div className="form-actions">
                  <button
                    onClick={handleApprove}
                    className="btn-primary"
                    disabled={loading}
                  >
                    ✓ Approve
                  </button>
                  <button
                    onClick={handleReject}
                    className="btn-danger"
                    disabled={loading || !reason.trim()}
                  >
                    ✗ Reject
                  </button>
                </div>
              </div>
            )}

            {version.status !== 'PENDING_APPROVAL' && (
              <div style={{ marginTop: 24, padding: 16, background: '#fff3cd', borderRadius: 8, color: '#856404' }}>
                This version is not pending approval. Current status: <strong>{version.status}</strong>
                {version.rejection_reason && (
                  <div style={{ marginTop: 8 }}>
                    <strong>Rejection reason:</strong> {version.rejection_reason}
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {!version && !loading && versionId && (
          <div style={{ marginTop: 20, padding: 16, background: '#ffebee', borderRadius: 8, color: '#c62828' }}>
            Version not found or could not be loaded.
          </div>
        )}
      </div>
    </div>
  );
}
