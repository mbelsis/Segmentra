import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';

import { api } from '../lib/api';

const when = (d: string | null) => (d ? new Date(d).toLocaleString() : '');

/**
 * What became of the policy versions I sent for approval: waiting, approved (with who and when) or rejected (with the
 * reason). Lets the author find out without opening every policy set.
 */
export function MyApprovalRequests() {
  const navigate = useNavigate();
  const [requests, setRequests] = useState<any[]>([]);

  useEffect(() => {
    let alive = true;
    const load = () => api.myApprovalRequests().then((r) => { if (alive) setRequests(r.requests); }).catch(() => {});
    load();
    const t = setInterval(load, 30000);
    return () => { alive = false; clearInterval(t); };
  }, []);

  if (requests.length === 0) return null;

  return (
    <div className="card">
      <h3 style={{ marginTop: 0 }}>Your approval requests <span style={{ fontSize: 13, fontWeight: 400, color: '#78644e' }}>(last 30 days)</span></h3>
      <div style={{ display: 'grid', gap: 8 }}>
        {requests.map((r) => {
          const rejected = r.status === 'REJECTED';
          const approved = r.status === 'APPROVED' || r.status === 'DEPLOYED';
          const color = rejected ? '#a63d2f' : approved ? '#3f6b2a' : '#8b6914';
          const bg = rejected ? '#faf0ee' : approved ? '#eef4e8' : '#f7f4ef';
          return (
            <div
              key={r.id}
              onClick={() => navigate(`/policy-set/${r.policy_set_id}`)}
              style={{ border: `1px solid ${rejected ? '#e8c4bf' : '#e6dfd2'}`, background: bg, borderRadius: 8, padding: '10px 14px', cursor: 'pointer' }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12, flexWrap: 'wrap' }}>
                <strong>{r.policy_set_name} v{r.version_number}</strong>
                <span style={{ fontWeight: 700, color, fontSize: 12.5 }}>
                  {rejected ? '✗ Rejected' : r.status === 'DEPLOYED' ? '✓ Approved and deployed' : approved ? '✓ Approved, ready to deploy' : '… Waiting for approval'}
                </span>
              </div>
              <div style={{ fontSize: 12.5, color: '#5c4633', marginTop: 4 }}>
                {rejected && <>Rejected by <strong>{r.rejected_by_username}</strong> on {when(r.rejected_at)}: {r.rejection_reason}</>}
                {approved && <>Approved by <strong>{r.approved_by_username}</strong> on {when(r.approved_at)}</>}
                {r.status === 'PENDING_APPROVAL' && <>Sent on {when(r.submitted_at)}; no decision yet</>}
              </div>
              {r.submission_note && <div style={{ fontSize: 12, color: '#78644e', marginTop: 2 }}>Your reason: {r.submission_note}</div>}
              {rejected && !r.superseded && <div style={{ fontSize: 12, color: '#78644e', marginTop: 2 }}>Fix the rules in the policy set, then use "Resubmit for Approval".</div>}
              {rejected && r.superseded && <div style={{ fontSize: 12, color: '#78644e', marginTop: 2 }}>A newer version of this policy set is already waiting, approved or deployed.</div>}
            </div>
          );
        })}
      </div>
    </div>
  );
}
