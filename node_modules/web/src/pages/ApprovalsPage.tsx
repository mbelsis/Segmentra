import { useEffect, useState } from 'react';

import { api } from '../lib/api';

export function ApprovalsPage() {
  const [versionId, setVersionId] = useState('');
  const [reason, setReason] = useState('');
  const [version, setVersion] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string>('');
  const [success, setSuccess] = useState<string>('');
  const [currentVersionId, setCurrentVersionId] = useState('');
  const [impactDiff, setImpactDiff] = useState<any>(null);
  const [loadingDiff, setLoadingDiff] = useState(false);
  const [sampleHostIds, setSampleHostIds] = useState<string[]>([]);
  const [hosts, setHosts] = useState<any[]>([]);

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

  useEffect(() => {
    async function loadHosts() {
      try {
        const res = await api.hosts();
        setHosts(res.hosts || []);
      } catch (e) {
        // Ignore errors
      }
    }
    loadHosts();
  }, []);

  async function loadImpactDiff() {
    if (!versionId || !currentVersionId || sampleHostIds.length === 0) {
      setImpactDiff(null);
      return;
    }
    setLoadingDiff(true);
    try {
      const result = await api.policyImpactDiff(versionId, currentVersionId, sampleHostIds);
      setImpactDiff(result.diff);
    } catch (e: any) {
      setError(`Failed to load impact diff: ${e.message}`);
      setImpactDiff(null);
    } finally {
      setLoadingDiff(false);
    }
  }

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

            {/* Policy Impact Diff */}
            {version && version.status === 'PENDING_APPROVAL' && (
              <div style={{ marginTop: 24, paddingTop: 20, borderTop: '2px solid #e0e0e0' }}>
                <h4>Policy Impact Analysis</h4>
                <p style={{ color: '#666', fontSize: '0.9em', marginBottom: 16 }}>
                  Compare this candidate version against the current deployed version to see what changes.
                </p>
                <div className="form-group">
                  <label><strong>Current Version ID</strong> (to compare against)</label>
                  <input
                    type="text"
                    value={currentVersionId}
                    onChange={(e) => setCurrentVersionId(e.target.value)}
                    placeholder="Enter current deployed version UUID..."
                    style={{ fontFamily: 'monospace', fontSize: '13px' }}
                  />
                </div>
                <div className="form-group">
                  <label><strong>Sample Hosts</strong> (select 1-3 hosts to analyze)</label>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: 8, maxHeight: '150px', overflowY: 'auto', border: '1px solid #ddd', padding: 8, borderRadius: 4 }}>
                    {hosts.slice(0, 20).map((h) => (
                      <label key={h.id} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                        <input
                          type="checkbox"
                          checked={sampleHostIds.includes(h.id)}
                          onChange={(e) => {
                            if (e.target.checked) {
                              setSampleHostIds([...sampleHostIds, h.id].slice(0, 3));
                            } else {
                              setSampleHostIds(sampleHostIds.filter(id => id !== h.id));
                            }
                          }}
                        />
                        <span>{h.hostname}</span>
                      </label>
                    ))}
                  </div>
                </div>
                <button 
                  onClick={loadImpactDiff} 
                  className="btn-secondary"
                  disabled={!currentVersionId || sampleHostIds.length === 0 || loadingDiff}
                  style={{ marginBottom: 16 }}
                >
                  {loadingDiff ? 'Loading...' : 'Analyze Impact'}
                </button>

                {impactDiff && impactDiff.length > 0 && (
                  <div style={{ marginTop: 16 }}>
                    {impactDiff.map((diff: any) => (
                      <div key={diff.hostId} style={{ marginBottom: 16, padding: 12, background: '#f8f9fa', borderRadius: 8 }}>
                        <strong>{diff.hostname}</strong>
                        <div style={{ marginTop: 8, display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 12 }}>
                          <div>
                            <strong style={{ color: '#4caf50' }}>New Allows: {diff.summary.totalNewAllows}</strong>
                            {diff.changes.newAllows.length > 0 && (
                              <ul style={{ fontSize: '0.85em', marginTop: 4 }}>
                                {diff.changes.newAllows.slice(0, 5).map((r: any, i: number) => (
                                  <li key={i}>
                                    {r.protocol} {r.ports || '*'}: {r.sourceType} {r.sourceValue}
                                  </li>
                                ))}
                              </ul>
                            )}
                          </div>
                          <div>
                            <strong style={{ color: '#f44336' }}>New Denies: {diff.summary.totalNewDenies}</strong>
                            {diff.changes.newDenies.length > 0 && (
                              <ul style={{ fontSize: '0.85em', marginTop: 4 }}>
                                {diff.changes.newDenies.slice(0, 5).map((r: any, i: number) => (
                                  <li key={i}>
                                    {r.protocol} {r.ports || '*'}: {r.sourceType} {r.sourceValue}
                                  </li>
                                ))}
                              </ul>
                            )}
                          </div>
                          <div>
                            <strong style={{ color: '#ff9800' }}>Removed Allows: {diff.summary.totalRemovedAllows}</strong>
                          </div>
                          <div>
                            <strong style={{ color: '#ff9800' }}>Removed Denies: {diff.summary.totalRemovedDenies}</strong>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

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
