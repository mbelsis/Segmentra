import { Fragment, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';

import { Modal } from '../components/Modal';
import { api, isApiError } from '../lib/api';

function timeAgo(dateStr: string) {
  const diff = Date.now() - new Date(dateStr).getTime();
  const mins = Math.max(0, Math.floor(diff / 60000));
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

const label = (v: any) => `${v.policy_set_name} v${v.version_number}`;

export function ApprovalsPage() {
  const navigate = useNavigate();
  const [pendingVersions, setPendingVersions] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string>('');
  const [success, setSuccess] = useState<string>('');
  const [actionLoading, setActionLoading] = useState<string | null>(null);

  // Dialogs: the version whose rules are shown, and the version being rejected
  const [rulesFor, setRulesFor] = useState<any | null>(null);
  const [rules, setRules] = useState<any[]>([]);
  const [rulesLoading, setRulesLoading] = useState(false);
  const [rejectFor, setRejectFor] = useState<any | null>(null);
  const [rejectReason, setRejectReason] = useState('');

  // Impact analysis (inside the rules dialog)
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
      // The impact analysis is optional.
    }
  }

  async function openRules(v: any) {
    setRulesFor(v);
    setRules([]);
    setCurrentVersionId('');
    setImpactDiff(null);
    setSampleHostIds([]);
    setApprovedVersions([]);
    setRulesLoading(true);
    try {
      const [r, vs] = await Promise.all([api.rules(v.id), api.versions(v.policy_set_id)]);
      setRules((r.rules || []).slice().sort((a: any, b: any) => a.order_index - b.order_index));
      setApprovedVersions(
        (vs.versions || [])
          .filter((x: any) => x.status === 'APPROVED' || x.status === 'DEPLOYED')
          .sort((a: any, b: any) => b.version_number - a.version_number)
      );
    } catch (e: any) {
      setError(String(e.message || e));
    } finally {
      setRulesLoading(false);
    }
  }

  async function handleApprove(v: any) {
    setActionLoading(v.id);
    setError('');
    setSuccess('');
    try {
      await api.approve(v.id);
      setSuccess(`Policy version ${label(v)} approved successfully`);
      setRulesFor(null);
      loadPending();
    } catch (e: any) {
      if (isApiError(e) && (e.code === 'cannot_approve_own_changes' || e.code === 'approver_must_differ')) {
        setError('You cannot approve a policy version that you created, edited or submitted. A different user with approver/admin role must review it.');
      } else {
        setError(e.message || String(e));
      }
    } finally {
      setActionLoading(null);
    }
  }

  async function confirmReject() {
    if (!rejectFor) return;
    const reason = rejectReason.trim();
    if (!reason) return;
    setActionLoading(rejectFor.id);
    setError('');
    setSuccess('');
    try {
      await api.reject(rejectFor.id, reason);
      setSuccess(`Policy version ${label(rejectFor)} rejected`);
      setRejectFor(null);
      setRejectReason('');
      setRulesFor(null);
      loadPending();
    } catch (e: any) {
      setError(String(e.message || e));
    } finally {
      setActionLoading(null);
    }
  }

  async function loadImpactDiff() {
    if (!rulesFor || !currentVersionId || sampleHostIds.length === 0) return;
    setLoadingDiff(true);
    try {
      const result = await api.policyImpactDiff(rulesFor.id, currentVersionId, sampleHostIds);
      setImpactDiff(result.diff);
    } catch (e: any) {
      setError(`Failed to load impact diff: ${e.message}`);
      setImpactDiff(null);
    } finally {
      setLoadingDiff(false);
    }
  }

  const requestedBy = (v: any) => v.submitted_by_display_name || v.submitted_by_username || v.created_by_display_name || v.created_by_username || '—';
  const requestedAt = (v: any) => v.submitted_at || v.created_at;
  const reasonOf = (v: any) => v.submission_note || v.change_summary;

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

      <div className="card">
        <h3 style={{ marginTop: 0 }}>
          Pending Approvals
          {!loading && (
            <span style={{ fontSize: '14px', fontWeight: 400, color: '#78644e', marginLeft: 8 }}>
              ({pendingVersions.length} {pendingVersions.length === 1 ? 'version' : 'versions'} awaiting review)
            </span>
          )}
        </h3>

        {loading && <div style={{ padding: 30, textAlign: 'center', color: '#78644e' }}>Loading pending approvals...</div>}

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
                <th>Requested By</th>
                <th>Requested</th>
                <th>Reason</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {pendingVersions.map((v) => (
                <Fragment key={v.id}>
                  <tr>
                    <td>
                      <strong
                        style={{ color: '#8b6914', cursor: 'pointer' }}
                        onClick={() => navigate(`/policy-set/${v.policy_set_id}`)}
                      >
                        {v.policy_set_name}
                      </strong>
                      <div style={{ fontSize: '11px', color: '#97846c' }}>Scope: {v.policy_set_scope_type}</div>
                    </td>
                    <td>
                      <span style={{ fontWeight: 600, color: '#5c4633' }}>v{v.version_number}</span>
                      {v.is_high_risk && (
                        <span style={{ display: 'inline-block', marginLeft: 6, padding: '1px 6px', borderRadius: 10, fontSize: '10px', fontWeight: 600, background: '#faf0ee', color: '#a63d2f', border: '1px solid #e8c4bf' }}>
                          HIGH RISK
                        </span>
                      )}
                    </td>
                    <td style={{ textAlign: 'center' }}><span style={{ fontWeight: 600 }}>{v.rule_count}</span></td>
                    <td>{requestedBy(v)}</td>
                    <td>
                      <span title={new Date(requestedAt(v)).toLocaleString()}>{timeAgo(requestedAt(v))}</span>
                      <div style={{ fontSize: '11px', color: '#97846c' }}>{new Date(requestedAt(v)).toLocaleDateString()}</div>
                    </td>
                    <td style={{ maxWidth: 280 }}>
                      <span style={{ fontSize: '13px', color: '#5c4633', whiteSpace: 'pre-wrap' }}>
                        {reasonOf(v) || <span style={{ color: '#b8a890', fontStyle: 'italic' }}>No reason given</span>}
                      </span>
                    </td>
                    <td>
                      <div className="host-actions">
                        <button
                          className="btn-small btn-primary"
                          onClick={() => handleApprove(v)}
                          disabled={actionLoading === v.id}
                        >
                          Approve
                        </button>
                        <button
                          className="btn-small btn-danger"
                          onClick={() => { setRejectFor(v); setRejectReason(''); }}
                          disabled={actionLoading === v.id}
                        >
                          Reject
                        </button>
                        <button className="btn-small btn-action" onClick={() => openRules(v)}>View Rules</button>
                      </div>
                    </td>
                  </tr>
                </Fragment>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Rules dialog */}
      {rulesFor && !rejectFor && (
        <Modal
          title={`${label(rulesFor)}: rules`}
          width={960}
          onClose={() => setRulesFor(null)}
          footer={
            <>
              <button className="btn-secondary" onClick={() => navigate(`/policy-version/${rulesFor.id}`)}>Open full page</button>
              <button className="btn-danger" onClick={() => { setRejectFor(rulesFor); setRejectReason(''); }}>Reject</button>
              <button className="btn-primary" onClick={() => handleApprove(rulesFor)} disabled={actionLoading === rulesFor.id}>Approve</button>
            </>
          }
        >
          <div style={{ fontSize: 13, color: '#5c4633', marginBottom: 12 }}>
            Requested by <strong>{requestedBy(rulesFor)}</strong> {timeAgo(requestedAt(rulesFor))}
            {' · '}Interface scope: <code>{rulesFor.interface_scope_type}</code>
            <div style={{ marginTop: 6 }}>
              Reason: {reasonOf(rulesFor) ? <span style={{ whiteSpace: 'pre-wrap' }}>{reasonOf(rulesFor)}</span> : <span style={{ color: '#b8a890', fontStyle: 'italic' }}>none given</span>}
            </div>
          </div>

          {rulesLoading ? (
            <div style={{ padding: 20, textAlign: 'center', color: '#78644e' }}>Loading rules...</div>
          ) : rules.length === 0 ? (
            <div style={{ padding: 20, textAlign: 'center', color: '#97846c' }}>This version has no rules.</div>
          ) : (
            <table className="data-table">
              <thead>
                <tr>
                  <th>#</th><th>Direction</th><th>Action</th><th>Protocol</th><th>Ports</th><th>Source</th><th>Destination</th><th>Comment</th>
                </tr>
              </thead>
              <tbody>
                {rules.map((r) => (
                  <tr key={r.id}>
                    <td>{r.order_index}</td>
                    <td><code>{r.direction}</code></td>
                    <td style={{ fontWeight: 600, color: r.action === 'ALLOW' ? '#5a7a3a' : '#a63d2f' }}>{r.action}</td>
                    <td><code>{r.protocol}</code></td>
                    <td>{r.ports || '-'}</td>
                    <td><code>{r.source_type}</code> {r.source_value}</td>
                    <td>{r.destination_type ? <><code>{r.destination_type}</code> {r.destination_value}</> : '-'}</td>
                    <td>{r.comment || '-'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          <p style={{ fontSize: 12, color: '#97846c', margin: '10px 0 0' }}>
            Loopback, established/related connections and management SSH are added by the compiler at deploy time and are not listed.
          </p>

          <details style={{ marginTop: 16 }}>
            <summary style={{ cursor: 'pointer', fontWeight: 600, color: '#5c4633' }}>Impact analysis (optional)</summary>
            <div style={{ marginTop: 10 }}>
              <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: '#5c4633', marginBottom: 4 }}>Compare against</label>
              {approvedVersions.length > 0 ? (
                <select
                  value={currentVersionId}
                  onChange={(e) => setCurrentVersionId(e.target.value)}
                  style={{ width: '100%', padding: '6px 8px', border: '1px solid #d4c9b8', borderRadius: 6, fontSize: '13px' }}
                >
                  <option value="">Select a version...</option>
                  {approvedVersions.map((av: any) => (
                    <option key={av.id} value={av.id}>
                      v{av.version_number} ({av.status}) {av.change_summary ? `: ${av.change_summary}` : ''}
                    </option>
                  ))}
                </select>
              ) : (
                <div style={{ fontSize: '12px', color: '#97846c' }}>No approved or deployed version to compare against.</div>
              )}
              <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: '#5c4633', margin: '10px 0 4px' }}>Sample hosts (1 to 3)</label>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px 14px', maxHeight: 90, overflowY: 'auto' }}>
                {hosts.slice(0, 15).map((h) => (
                  <label key={h.id} style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: '12px' }}>
                    <input
                      type="checkbox"
                      checked={sampleHostIds.includes(h.id)}
                      onChange={(e) => setSampleHostIds((prev) => (e.target.checked ? [...prev, h.id].slice(0, 3) : prev.filter((id) => id !== h.id)))}
                    />
                    {h.hostname}
                  </label>
                ))}
              </div>
              <button
                className="btn-small btn-primary"
                style={{ marginTop: 10 }}
                onClick={loadImpactDiff}
                disabled={!currentVersionId || sampleHostIds.length === 0 || loadingDiff}
              >
                {loadingDiff ? 'Analyzing...' : 'Analyze impact'}
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
          </details>
        </Modal>
      )}

      {/* Rejection dialog: only opened by the Reject button */}
      {rejectFor && (
        <Modal
          title={`Reject ${label(rejectFor)}`}
          onClose={() => { setRejectFor(null); setRejectReason(''); }}
          footer={
            <>
              <button className="btn-secondary" onClick={() => { setRejectFor(null); setRejectReason(''); }}>Cancel</button>
              <button className="btn-danger" onClick={confirmReject} disabled={!rejectReason.trim() || actionLoading === rejectFor.id}>Confirm rejection</button>
            </>
          }
        >
          <p style={{ marginTop: 0, color: '#5c4633' }}>
            The author sees this reason and can fix the version and send it again. It is stored in the audit log with your name and the time.
          </p>
          {reasonOf(rejectFor) && (
            <div style={{ background: '#f0ebe2', borderRadius: 8, padding: '8px 12px', marginBottom: 12, fontSize: 13 }}>
              The author's reason: <span style={{ whiteSpace: 'pre-wrap' }}>{reasonOf(rejectFor)}</span>
            </div>
          )}
          <label htmlFor="reject-reason" style={{ display: 'block', fontWeight: 600, marginBottom: 6 }}>Reason for rejection *</label>
          <textarea
            id="reject-reason"
            value={rejectReason}
            onChange={(e) => setRejectReason(e.target.value)}
            rows={4}
            placeholder="For example: port 3306 must not be open to 0.0.0.0/0; restrict it to the app subnet."
            style={{ width: '100%', boxSizing: 'border-box' }}
            autoFocus
          />
        </Modal>
      )}
    </div>
  );
}
