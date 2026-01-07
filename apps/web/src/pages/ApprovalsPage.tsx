import { useState } from 'react';

import { api } from '../lib/api';

export function ApprovalsPage() {
  const [versionId, setVersionId] = useState('');
  const [reason, setReason] = useState('Not approved');
  const [status, setStatus] = useState<string>('');

  return (
    <div style={{ display: 'grid', gap: 12 }}>
      <h2>Approvals</h2>
      <div style={{ opacity: 0.8 }}>
        v1 UI shortcut: paste a <code>policy_version.id</code> and approve/reject it.
      </div>

      <label>
        Policy version ID
        <input value={versionId} onChange={(e) => setVersionId(e.target.value)} />
      </label>

      <div style={{ display: 'flex', gap: 8 }}>
        <button
          disabled={!versionId}
          onClick={async () => {
            await api.approve(versionId);
            setStatus('Approved');
          }}
        >
          Approve
        </button>
        <button
          disabled={!versionId}
          onClick={async () => {
            await api.reject(versionId, reason);
            setStatus('Rejected');
          }}
        >
          Reject
        </button>
        <input value={reason} onChange={(e) => setReason(e.target.value)} style={{ flex: 1 }} />
      </div>

      {status ? <div className="card">{status}</div> : null}
    </div>
  );
}


