import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';

import { api, isApiError } from '../lib/api';

export function ApprovalsPage() {
  const navigate = useNavigate();
  const [pendingVersions, setPendingVersions] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string>('');
  const [success, setSuccess] = useState<string>('');
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [rejectReasons, setRejectReasons] = useState<Record<string, string>>({});
  const [expandedId, setExpandedId] = useState<string | null>(null);

  // Impact diff state
  const [diffVersionId, setDiffVersionId] = useState<string | null>(null);
  const [currentVersionId, setCurrentVersionId] = useState('');
  const [approvedVersions, setApprovedVersions] = useState<any[]>([]);
  const [sampleHostIds, setSampleHostIds] = useState<string[]>([]);
  const [hosts, setHosts] = useState<any[]>([]);
  const [impactDiff, setImpactDiff] = useState<any>(null);
  const [loadingDiff, setLoadingDiff] = useState(false);

  useEffect(() => {
    loadPending();
    loadHosts();
  }, []);

  async function loadPending() {
    setLoading(true);
    setError('');
    try {
      const res = await api.pendingApprovals();
      setPendingVersions(res.versions || []);
    } catch (e: any) {
      setError(String(e.message || e));
    } finally {
      setLoading(false);
    }
  }

  async function loadHosts() {
    try {
      const res = await api.allHosts();
      setHosts(res.hosts || []);
    } catch {
      // Ignore
    }
  }

  async function loadApprovedVersions(policySetId: string) {
    try {
      const res = await api.versions(policySetId);
      const approved = (res.versions || [])
        .filter((v: any) => v.status === 'APPROVED' || v.status === 'DEPLOYED')
        .sort((a: any, b: any) => b.version_number - a.version_number);
      setApprovedVersions(approved);
    } catch {
      setApprovedVersions([]);
    }
  }

  async function handleApprove(versionId: string, versionLabel: string) {
    setActionLoading(versionId);
    setError('');
    setSuccess('');
    try {
      await api.approve(versionId);
      setSuccess(`Policy version ${versionLabel} approved successfully`);
      loadPending();
    } catch (e: any) {
      const msg = e.message || String(e);
      if (isApiError(e) && (e.code === 'cannot_approve_own_changes' || e.code === 'approver_must_differ')) {
        setError('You cannot approve a policy version that you created, edited or submitted. A different user with approver/admin role must review it.');
      } else {
        setError(msg);
      }
    } finally {
      setActionLoading(null);
    }
  }

  async function handleReject(versionId: string, versionLabel: string) {
    const reason = rejectReasons[versionId]?.trim();
    if (!reason) {
      setError('Rejection reason is required');
      return;
    }
    setActionLoading(versionId);
    setError('');
    setSuccess('');
    try {
      await api.reject(versionId, reason);
      setSuccess(`Policy version ${versionLabel} rejected`);
      setRejectReasons(prev => { const n = { ...prev }; delete n[versionId]; return n; });
      setExpandedId(null);
      loadPending();
    } catch (e: any) {
      setError(String(e.message || e));
    } finally {
      setActionLoading(null);
    }
  }

  async function loadImpactDiff() {
    if (!diffVersionId || !currentVersionId || sampleHostIds.length === 0) return;
    setLoadingDiff(true);
    try {
      const result = await api.policyImpactDiff(diffVersionId, currentVersionId, sampleHostIds);
      setImpactDiff(result.diff);
    } catch (e: any) {
      setError(`Failed to load impact diff: ${e.message}`);
      setImpactDiff(null);
    } finally {
      setLoadingDiff(false);
    }
  }

  function toggleExpand(v: any) {
    if (expandedId === v.id) {
      setExpandedId(null);
      setDiffVersionId(null);
      setImpactDiff(null);
    } else {
      setExpandedId(v.id);
      setDiffVersionId(v.id);
      setCurrentVersionId('');
      setImpactDiff(null);
      setSampleHostIds([]);
      loadApprovedVersions(v.policy_set_id);
    }
  }

  function timeAgo(dateStr: string) {
    const diff = Date.now() - new Date(dateStr).getTime();
    const mins = Math.floor(diff / 60000);
    if (mins < 60) return `${mins}m ago`;
    const hours = Math.floor(mins / 60);
    if (hours < 24) return `${hours}h ago`;
    const days = Math.floor(hours / 24);
    return `${days}d ago`;
  }

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <h2>Policy Approvals</h2>
          <p style={{ margin: 0, color: '#78644e', fontSize: '14px' }}>
            Review and approve or reject policy versions submitted for approval.
          </p>
        </div>
        <button onClick={loadPending} className="btn-secondary" disabled={loading}>
          Refresh
        </button>
      </div>

      {error && <div className="error-banner" style={{ marginBottom: 16 }}>{error} <button onClick={() => setError('')} style={{ marginLeft: 8, background: 'none', border: 'none', cursor: 'pointer', textDecoration: 'underline', color: 'inherit' }}>dismiss</button></div>}
      {success && (
        <div style={{ background: '#e8f5e9', color: '#2e7d32', padding: 12, borderRadius: 8, marginBottom: 16, borderLeft: '4px solid #5a7a3a' }}>
          {success}
          <button onClick={() => setSuccess('')} style={{ marginLeft: 8, background: 'none', border: 'none', cursor: 'pointer', textDecoration: 'underline', color: 'inherit' }}>dismiss</button>
        </div>
      )}

      {/* Pending Approvals Table */}
      <div className="card">
        <h3 style={{ marginTop: 0 }}>
          Pending Approvals
          {!loading && (
            <span style={{ fontSize: '14px', fontWeight: 400, color: '#78644e', marginLeft: 8 }}>
              ({pendingVersions.length} {pendingVersions.length === 1 ? 'version' : 'versions'} awaiting review)
            </span>
          )}
        </h3>

        {loading && (
          <div style={{ padding: 30, textAlign: 'center', color: '#78644e' }}>Loading pending approvals...</div>
        )}

        {!loading && pendingVersions.length === 0 && (
          <div style={{ padding: 30, textAlign: 'center', color: '#97846c' }}>
            No policy versions are currently awaiting approval.
          </div>
        )}

        {!loading && pendingVersions.length > 0 && (
          <table className="data-table">
            <thead>
              <tr>
                <th>Policy Set</th>
                <th>Version</th>
                <th>Rules</th>
                <th>Submitted By</th>
                <th>Submitted</th>
                <th>Change Summary</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {pendingVersions.map(v => (
                <>
                  <tr key={v.id} style={{ cursor: 'pointer', background: expandedId === v.id ? '#f0ebe2' : undefined }}
                    onClick={() => toggleExpand(v)}>
                    <td>
                      <strong
                        style={{ color: '#8b6914', cursor: 'pointer' }}
                        onClick={(e) => { e.stopPropagation(); navigate(`/policy-set/${v.policy_set_id}`); }}
                      >
                        {v.policy_set_name}
                      </strong>
                      <div style={{ fontSize: '11px', color: '#97846c' }}>
                        Scope: {v.policy_set_scope_type}
                      </div>
                    </td>
                    <td>
                      <span
                        style={{ fontWeight: 600, color: '#5c4633', cursor: 'pointer' }}
                        onClick={(e) => { e.stopPropagation(); navigate(`/policy-version/${v.id}`); }}
                      >
                        v{v.version_number}
                      </span>
                      {v.is_high_risk && (
                        <span style={{ display: 'inline-block', marginLeft: 6, padding: '1px 6px', borderRadius: 10, fontSize: '10px', fontWeight: 600, background: '#faf0ee', color: '#a63d2f', border: '1px solid #e8c4bf' }}>
                          HIGH RISK
                        </span>
                      )}
                    </td>
                    <td style={{ textAlign: 'center' }}>
                      <span style={{ fontWeight: 600 }}>{v.rule_count}</span>
                    </td>
                    <td>
                      {v.created_by_display_name || v.created_by_username || '—'}
                    </td>
                    <td>
                      <span title={new Date(v.submitted_at || v.created_at).toLocaleString()}>
                        {v.submitted_at ? timeAgo(v.submitted_at) : timeAgo(v.created_at)}
                      </span>
                      <div style={{ fontSize: '11px', color: '#97846c' }}>
                        {new Date(v.submitted_at || v.created_at).toLocaleDateString()}
                      </div>
                    </td>
                    <td style={{ maxWidth: 250 }}>
                      <span style={{ fontSize: '13px', color: '#5c4633' }}>
                        {v.change_summary || <span style={{ color: '#b8a890', fontStyle: 'italic' }}>No summary</span>}
                      </span>
                    </td>
                    <td onClick={e => e.stopPropagation()}>
                      <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                        <button
                          onClick={() => handleApprove(v.id, `${v.policy_set_name} v${v.version_number}`)}
                          disabled={actionLoading === v.id}
                          style={{
                            padding: '5px 12px',
                            background: '#5a7a3a',
                            color: '#fdfcf9',
                            border: 'none',
                            borderRadius: 5,
                            fontWeight: 600,
                            fontSize: '12px',
                            cursor: actionLoading === v.id ? 'not-allowed' : 'pointer',
                            opacity: actionLoading === v.id ? 0.6 : 1,
                          }}
                        >
                          Approve
                        </button>
                        <button
                          onClick={(e) => { e.stopPropagation(); toggleExpand(v); }}
                          style={{
                            padding: '5px 12px',
                            background: 'transparent',
                            color: '#a63d2f',
                            border: '1px solid #e8c4bf',
                            borderRadius: 5,
                            fontWeight: 600,
                            fontSize: '12px',
                            cursor: 'pointer',
                          }}
                        >
                          Reject
                        </button>
                        <button
                          onClick={() => navigate(`/policy-version/${v.id}`)}
                          className="btn-small"
                          style={{ fontSize: '12px' }}
                        >
                          View Rules
                        </button>
                      </div>
                    </td>
                  </tr>

                  {/* Expanded row for rejection reason + impact diff */}
                  {expandedId === v.id && (
                    <tr key={`${v.id}-expanded`}>
                      <td colSpan={7} style={{ background: '#fdfcf9', padding: 20, borderTop: 'none' }}>
                        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20 }}>
                          {/* Left: Reject */}
                          <div>
                            <h4 style={{ margin: '0 0 8px 0', color: '#5c4633' }}>Reject with Reason</h4>
                            <textarea
                              value={rejectReasons[v.id] || ''}
                              onChange={(e) => setRejectReasons(prev => ({ ...prev, [v.id]: e.target.value }))}
                              placeholder="Enter reason for rejection..."
                              rows={3}
                              style={{ width: '100%', padding: '8px 10px', border: '1px solid #d4c9b8', borderRadius: 6, fontSize: '13px', resize: 'vertical' }}
                            />
                            <button
                              onClick={() => handleReject(v.id, `${v.policy_set_name} v${v.version_number}`)}
                              disabled={actionLoading === v.id || !(rejectReasons[v.id]?.trim())}
                              style={{
                                marginTop: 8,
                                padding: '7px 16px',
                                background: (actionLoading === v.id || !(rejectReasons[v.id]?.trim())) ? '#ddd' : '#a63d2f',
                                color: (actionLoading === v.id || !(rejectReasons[v.id]?.trim())) ? '#999' : '#fdfcf9',
                                border: 'none',
                                borderRadius: 6,
                                fontWeight: 600,
                                fontSize: '13px',
                                cursor: (actionLoading === v.id || !(rejectReasons[v.id]?.trim())) ? 'not-allowed' : 'pointer',
                              }}
                            >
                              Confirm Rejection
                            </button>
                          </div>

                          {/* Right: Impact Diff */}
                          <div>
                            <h4 style={{ margin: '0 0 8px 0', color: '#5c4633' }}>Impact Analysis (Optional)</h4>
                            <div style={{ marginBottom: 8 }}>
                              <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: '#5c4633', marginBottom: 4 }}>Compare Against</label>
                              {approvedVersions.length > 0 ? (
                                <select
                                  value={currentVersionId}
                                  onChange={(e) => setCurrentVersionId(e.target.value)}
                                  style={{ width: '100%', padding: '6px 8px', border: '1px solid #d4c9b8', borderRadius: 6, fontSize: '13px' }}
                                >
                                  <option value="">Select a version...</option>
                                  {approvedVersions.map((av: any) => (
                                    <option key={av.id} value={av.id}>
                                      v{av.version_number} ({av.status}) {av.change_summary ? `— ${av.change_summary}` : ''}
                                    </option>
                                  ))}
                                </select>
                              ) : (
                                <div style={{ fontSize: '12px', color: '#97846c' }}>No approved/deployed versions to compare against.</div>
                              )}
                            </div>
                            <div style={{ marginBottom: 8 }}>
                              <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: '#5c4633', marginBottom: 4 }}>Sample Hosts (1-3)</label>
                              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, maxHeight: 80, overflowY: 'auto' }}>
                                {hosts.slice(0, 15).map(h => (
                                  <label key={h.id} style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: '12px' }}>
                                    <input
                                      type="checkbox"
                                      checked={sampleHostIds.includes(h.id)}
                                      onChange={(e) => {
                                        if (e.target.checked) {
                                          setSampleHostIds(prev => [...prev, h.id].slice(0, 3));
                                        } else {
                                          setSampleHostIds(prev => prev.filter(id => id !== h.id));
                                        }
                                      }}
                                    />
                                    {h.hostname}
                                  </label>
                                ))}
                              </div>
                            </div>
                            <button
                              onClick={loadImpactDiff}
                              disabled={!currentVersionId || sampleHostIds.length === 0 || loadingDiff}
                              style={{
                                padding: '6px 14px',
                                background: (!currentVersionId || sampleHostIds.length === 0) ? '#ddd' : '#8b6914',
                                color: (!currentVersionId || sampleHostIds.length === 0) ? '#999' : '#fdfcf9',
                                border: 'none',
                                borderRadius: 6,
                                fontSize: '12px',
                                fontWeight: 600,
                                cursor: (!currentVersionId || sampleHostIds.length === 0 || loadingDiff) ? 'not-allowed' : 'pointer',
                              }}
                            >
                              {loadingDiff ? 'Analyzing...' : 'Analyze Impact'}
                            </button>

                            {impactDiff && impactDiff.length > 0 && (
                              <div style={{ marginTop: 12 }}>
                                {impactDiff.map((diff: any) => (
                                  <div key={diff.hostId} style={{ padding: 8, background: '#f0ebe2', borderRadius: 6, marginBottom: 6, fontSize: '12px' }}>
                                    <strong>{diff.hostname}</strong>
                                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 4, marginTop: 4 }}>
                                      <span style={{ color: '#5a7a3a' }}>+{diff.summary.totalNewAllows} new allows</span>
                                      <span style={{ color: '#a63d2f' }}>+{diff.summary.totalNewDenies} new denies</span>
                                      <span style={{ color: '#e65100' }}>-{diff.summary.totalRemovedAllows} removed allows</span>
                                      <span style={{ color: '#e65100' }}>-{diff.summary.totalRemovedDenies} removed denies</span>
                                    </div>
                                  </div>
                                ))}
                              </div>
                            )}
                          </div>
                        </div>
                      </td>
                    </tr>
                  )}
                </>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
