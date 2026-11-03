import { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';

import { api } from '../lib/api';

type ApprovalRequest = Awaited<ReturnType<typeof api.myApprovalRequests>>['requests'][number];

const when = (d: string | null) => (d ? new Date(d).toLocaleString() : '');

type Filter = 'ALL' | 'PENDING_APPROVAL' | 'APPROVED' | 'DEPLOYED' | 'REJECTED';

const FILTERS: Array<{ value: Filter; label: string }> = [
  { value: 'ALL', label: 'All' },
  { value: 'PENDING_APPROVAL', label: 'Pending' },
  { value: 'APPROVED', label: 'Approved' },
  { value: 'DEPLOYED', label: 'Deployed' },
  { value: 'REJECTED', label: 'Rejected' },
];

const STATUS: Record<string, { text: string; className: string }> = {
  PENDING_APPROVAL: { text: 'Pending', className: 'approval-request-pending' },
  APPROVED: { text: 'Approved', className: 'approval-request-approved' },
  DEPLOYED: { text: 'Deployed', className: 'approval-request-deployed' },
  REJECTED: { text: 'Rejected', className: 'approval-request-rejected' },
};

/** The one line that says what happened, and what to do next when something is expected of the author. */
function describe(r: ApprovalRequest): { detail: string; next: string | null } {
  if (r.status === 'REJECTED') {
    const next = r.superseded ? 'A newer version is already waiting, approved or deployed.' : 'Fix the rules, then use "Resubmit for Approval".';
    return { detail: `By ${r.rejected_by_username} on ${when(r.rejected_at)}: ${r.rejection_reason}`, next };
  }
  if (r.status === 'PENDING_APPROVAL') return { detail: `Sent on ${when(r.submitted_at)}; no decision yet`, next: null };
  return { detail: `By ${r.approved_by_username} on ${when(r.approved_at)}`, next: r.status === 'APPROVED' ? 'Ready to deploy.' : null };
}

/**
 * What became of the policy versions I sent for approval: waiting, approved (with who and when) or rejected (with the
 * reason). Lets the author find out without opening every policy set.
 */
export function MyApprovalRequests() {
  const navigate = useNavigate();
  const [requests, setRequests] = useState<ApprovalRequest[]>([]);
  const [filter, setFilter] = useState<Filter>('ALL');

  useEffect(() => {
    let alive = true;
    const load = () => api.myApprovalRequests().then((r) => { if (alive) setRequests(r.requests); }).catch(() => {});
    load();
    const t = setInterval(load, 30000);
    return () => { alive = false; clearInterval(t); };
  }, []);

  const shown = useMemo(() => (filter === 'ALL' ? requests : requests.filter((r) => r.status === filter)), [requests, filter]);

  if (requests.length === 0) return null;

  return (
    <div className="card">
      <div className="approval-requests-header">
        <h3 style={{ margin: 0 }}>Your approval requests <span style={{ fontSize: 13, fontWeight: 400, color: '#78644e' }}>(last 30 days)</span></h3>
        <div className="approval-requests-filter" role="group" aria-label="Filter by status">
          {FILTERS.map((f) => {
            const count = f.value === 'ALL' ? requests.length : requests.filter((r) => r.status === f.value).length;
            return (
              <button key={f.value} type="button" onClick={() => setFilter(f.value)} className={filter === f.value ? 'btn-small btn-primary' : 'btn-small btn-secondary'} aria-pressed={filter === f.value}>
                {f.label} ({count})
              </button>
            );
          })}
        </div>
      </div>

      {shown.length === 0 ? (
        <p style={{ color: '#78644e', fontSize: 13.5, margin: '12px 0 0' }}>No {FILTERS.find((f) => f.value === filter)?.label.toLowerCase()} requests.</p>
      ) : (
        <div className="approval-requests-grid">
          {shown.map((r) => {
            const status = STATUS[r.status] ?? STATUS.PENDING_APPROVAL;
            const { detail, next } = describe(r);
            const note = r.submission_note ? `Your reason: ${r.submission_note}` : null;
            return (
              <button key={r.id} type="button" className={`approval-request ${status.className}`} onClick={() => navigate(`/policy-set/${r.policy_set_id}`)} title={[detail, note, next].filter(Boolean).join('\n')}>
                <span className="approval-request-title">
                  <strong>{r.policy_set_name} v{r.version_number}</strong>
                  <span className="approval-request-status">{status.text}</span>
                </span>
                <span className="approval-request-detail">{detail}</span>
                {note && <span className="approval-request-note">{note}</span>}
                {next && <span className="approval-request-note">{next}</span>}
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}
