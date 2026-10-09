import { useEffect, useRef, useState } from 'react';

import { api } from '../lib/api';

/** Convert a datetime-local value (local wall-clock time) to an ISO string, or undefined if invalid/empty. */
function localToIso(v: string): string | undefined {
  if (!v) return undefined;
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? undefined : d.toISOString();
}

function mergeSorted(prev: string[], next: Iterable<string>): string[] {
  const set = new Set(prev);
  let changed = false;
  for (const v of next) {
    if (!set.has(v)) { set.add(v); changed = true; }
  }
  return changed ? Array.from(set).sort() : prev;
}

export function AuditPage() {
  const [events, setEvents] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  
  // Filters
  const [filterActor, setFilterActor] = useState('');
  const [filterAction, setFilterAction] = useState('');
  const [filterEntityType, setFilterEntityType] = useState('');
  const [filterFrom, setFilterFrom] = useState('');
  const [filterTo, setFilterTo] = useState('');
  
  // Dropdown options. Seeded from the initial unfiltered load and only ever
  // grown afterwards, so applying a filter never hides the other choices.
  const [allActors, setAllActors] = useState<string[]>([]);
  const [allActions, setAllActions] = useState<string[]>([]);
  const [allEntityTypes, setAllEntityTypes] = useState<string[]>([]);

  const requestIdRef = useRef(0);
  const firstLoadRef = useRef(true);

  useEffect(() => {
    // Initial load runs immediately; subsequent filter changes are debounced.
    const delay = firstLoadRef.current ? 0 : 300;
    firstLoadRef.current = false;
    const handle = setTimeout(() => {
      void loadData();
    }, delay);
    return () => clearTimeout(handle);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filterActor, filterAction, filterEntityType, filterFrom, filterTo]);

  async function loadData() {
    const requestId = ++requestIdRef.current;
    setLoading(true);
    try {
      const params: any = {};
      if (filterActor) params.actor = filterActor;
      if (filterAction) params.action = filterAction;
      if (filterEntityType) params.entityType = filterEntityType;
      const fromIso = localToIso(filterFrom);
      const toIso = localToIso(filterTo);
      if (fromIso) params.from = fromIso;
      if (toIso) params.to = toIso;
      
      const res = await api.audit(params);
      if (requestId !== requestIdRef.current) return; // stale response
      const list = res.events || [];
      setEvents(list);
      setError('');
      
      setAllActors(prev => mergeSorted(prev, list.map((e: any) => e.actor_username).filter(Boolean)));
      setAllActions(prev => mergeSorted(prev, list.map((e: any) => e.action).filter(Boolean)));
      setAllEntityTypes(prev => mergeSorted(prev, list.map((e: any) => e.entity_type).filter(Boolean)));
    } catch (e: any) {
      if (requestId !== requestIdRef.current) return;
      console.error('Failed to load audit events:', e);
      setError(String(e?.message ?? e));
    } finally {
      if (requestId === requestIdRef.current) setLoading(false);
    }
  }

  function clearFilters() {
    setFilterActor('');
    setFilterAction('');
    setFilterEntityType('');
    setFilterFrom('');
    setFilterTo('');
  }

  function formatTimestamp(ts: string) {
    try {
      const date = new Date(ts);
      return date.toLocaleString();
    } catch {
      return ts;
    }
  }

  function formatAction(action: string) {
    return action
      .split('_')
      .map(word => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
      .join(' ');
  }

  function formatEntityType(type: string) {
    return type
      .split('_')
      .map(word => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
      .join(' ');
  }

  function getActionColor(action: string) {
    if (action.includes('APPROVE') || action.includes('CREATE')) return '#4CAF50';
    if (action.includes('REJECT') || action.includes('DELETE')) return '#F44336';
    if (action.includes('SUBMIT') || action.includes('START')) return '#2196F3';
    if (action.includes('UPDATE') || action.includes('EDIT')) return '#FF9800';
    if (action.includes('DEPLOYMENT')) return '#9C27B0';
    return '#666';
  }

  const fmtTime = (t: any) => (t ? new Date(t).toLocaleString() : '');

  /** Submit / approve / reject of a policy version, as readable lines (the raw JSON stays under "Raw details"). */
  function renderApprovalMetadata(metadata: any, action: string) {
    const approved = action === 'POLICY_APPROVE';
    const rejected = action === 'POLICY_REJECT';
    return (
      <div style={{ fontSize: '0.85em' }}>
        <div><strong>Policy:</strong> {metadata.policySet ?? 'Unknown'}{metadata.versionNumber ? ` v${metadata.versionNumber}` : ''}{metadata.isHighRisk ? ' (high risk)' : ''}</div>
        <div><strong>Requested by:</strong> {metadata.requestedBy ?? metadata.by ?? 'unknown'}{metadata.requestedAt ? ` on ${fmtTime(metadata.requestedAt)}` : ''}</div>
        {metadata.reason && <div><strong>Reason given:</strong> <span style={{ whiteSpace: 'pre-wrap' }}>{metadata.reason}</span></div>}
        {(approved || rejected) && (
          <div style={{ marginTop: 4, color: approved ? '#3f6b2a' : '#a63d2f' }}>
            <strong>{approved ? 'Approved' : 'Rejected'} by:</strong> {metadata.decidedBy ?? metadata.by}{metadata.decidedAt ? ` on ${fmtTime(metadata.decidedAt)}` : ''}
          </div>
        )}
        {rejected && metadata.rejectionReason && <div style={{ color: '#a63d2f' }}><strong>Rejection reason:</strong> {metadata.rejectionReason}</div>}
        <details style={{ marginTop: 4 }}>
          <summary style={{ cursor: 'pointer', color: '#646cff' }}>Raw details</summary>
          <pre style={{ marginTop: 6, padding: 8, background: '#f5f5f5', borderRadius: 4, fontSize: '0.8em', overflow: 'auto', maxWidth: '400px' }}>{JSON.stringify(metadata, null, 2)}</pre>
        </details>
      </div>
    );
  }

  function renderDeploymentMetadata(metadata: any, entityType: string, action: string) {
    if (metadata && ['POLICY_SUBMIT', 'POLICY_APPROVE', 'POLICY_REJECT'].includes(action)) return renderApprovalMetadata(metadata, action);
    // Only render deployment metadata for deployment events
    if (entityType !== 'DEPLOYMENT' || !metadata) {
      return (
        <details style={{ fontSize: '0.85em' }}>
          <summary style={{ cursor: 'pointer', color: '#646cff' }}>View</summary>
          <pre style={{ 
            marginTop: 8, 
            padding: 8, 
            background: '#f5f5f5', 
            borderRadius: 4,
            fontSize: '0.8em',
            overflow: 'auto',
            maxWidth: '400px'
          }}>
            {JSON.stringify(metadata, null, 2)}
          </pre>
        </details>
      );
    }

    // Render deployment-specific information
    if (action === 'DEPLOYMENT_CREATED') {
      return (
        <div style={{ fontSize: '0.85em' }}>
          <div><strong>Policy:</strong> {metadata.policySetName || 'Unknown'}</div>
          {metadata.policyVersionNumber && <div><strong>Version:</strong> v{metadata.policyVersionNumber}</div>}
          <div><strong>Mode:</strong> {metadata.deploymentMode}</div>
          <div><strong>Target Type:</strong> {metadata.targetType}</div>
          {metadata.targetTags && metadata.targetTags.length > 0 && (
            <div><strong>Tags:</strong> {metadata.targetTags.join(', ')}</div>
          )}
          {metadata.targetVlans && metadata.targetVlans.length > 0 && (
            <div><strong>VLANs:</strong> {metadata.targetVlans.join(', ')}</div>
          )}
          {metadata.targetHosts && metadata.targetHosts.length > 0 && (
            <div><strong>Hosts:</strong> {metadata.targetHosts.slice(0, 5).join(', ')}{metadata.targetHosts.length > 5 ? ` (+${metadata.targetHosts.length - 5} more)` : ''}</div>
          )}
          <div><strong>Target Count:</strong> {metadata.targetCount}</div>
        </div>
      );
    }

    if (action === 'DEPLOYMENT_FINISHED') {
      const resultColor = metadata.result === 'SUCCEEDED' ? '#4CAF50' : 
                         metadata.result === 'PARTIAL' ? '#FF9800' : '#F44336';
      
      return (
        <div style={{ fontSize: '0.85em' }}>
          <div><strong>Policy:</strong> {metadata.policySetName || 'Unknown'}</div>
          {metadata.policyVersionNumber && <div><strong>Version:</strong> v{metadata.policyVersionNumber}</div>}
          <div><strong>Mode:</strong> {metadata.deploymentMode}</div>
          <div><strong>Target Type:</strong> {metadata.targetType}</div>
          {metadata.targetTags && metadata.targetTags.length > 0 && (
            <div><strong>Tags:</strong> {metadata.targetTags.join(', ')}</div>
          )}
          {metadata.targetVlans && metadata.targetVlans.length > 0 && (
            <div><strong>VLANs:</strong> {metadata.targetVlans.join(', ')}</div>
          )}
          {metadata.targetHosts && metadata.targetHosts.length > 0 && (
            <div><strong>Hosts:</strong> {metadata.targetHosts.slice(0, 5).join(', ')}{metadata.targetHosts.length > 5 ? ` (+${metadata.targetHosts.length - 5} more)` : ''}</div>
          )}
          <div style={{ marginTop: 4 }}>
            <strong>Result:</strong>{' '}
            <span style={{ color: resultColor, fontWeight: 'bold' }}>{metadata.result}</span>
          </div>
          {metadata.hostCounts && (
            <div style={{ marginTop: 4, fontSize: '0.9em' }}>
              <strong>Hosts:</strong> {metadata.hostCounts.succeeded || 0} succeeded, {metadata.hostCounts.failed || 0} failed
              {metadata.hostCounts.skipped > 0 && `, ${metadata.hostCounts.skipped} skipped`}
            </div>
          )}
          {metadata.startedAt && (
            <div style={{ marginTop: 4, fontSize: '0.85em', color: '#666' }}>
              Duration: {formatDuration(metadata.startedAt, metadata.finishedAt)}
            </div>
          )}
        </div>
      );
    }

    // Fallback to JSON view
    return (
      <details style={{ fontSize: '0.85em' }}>
        <summary style={{ cursor: 'pointer', color: '#646cff' }}>View</summary>
        <pre style={{ 
          marginTop: 8, 
          padding: 8, 
          background: '#f5f5f5', 
          borderRadius: 4,
          fontSize: '0.8em',
          overflow: 'auto',
          maxWidth: '400px'
        }}>
          {JSON.stringify(metadata, null, 2)}
        </pre>
      </details>
    );
  }

  function formatDuration(startedAt: string, finishedAt: string): string {
    try {
      const start = new Date(startedAt);
      const finish = new Date(finishedAt);
      const diffMs = finish.getTime() - start.getTime();
      const diffSec = Math.floor(diffMs / 1000);
      const diffMin = Math.floor(diffSec / 60);
      const diffHour = Math.floor(diffMin / 60);
      
      if (diffHour > 0) {
        return `${diffHour}h ${diffMin % 60}m ${diffSec % 60}s`;
      } else if (diffMin > 0) {
        return `${diffMin}m ${diffSec % 60}s`;
      } else {
        return `${diffSec}s`;
      }
    } catch {
      return 'N/A';
    }
  }

  const hasFilters = filterActor || filterAction || filterEntityType || filterFrom || filterTo;

  return (
    <div className="page">
      <div className="page-header">
        <h2>Audit Log</h2>
        {hasFilters && (
          <button onClick={clearFilters} className="btn-secondary">
            Clear Filters
          </button>
        )}
      </div>

      {error && <div className="error-banner">{error}</div>}

      {/* Filters */}
      <div className="card">
        <h3>Filters</h3>
        <div className="form-grid">
          <div className="form-group">
            <label>Actor (User)</label>
            <select
              value={filterActor}
              onChange={(e) => setFilterActor(e.target.value)}
            >
              <option value="">All Users</option>
              {allActors.map((actor) => (
                <option key={actor} value={actor}>
                  {actor}
                </option>
              ))}
            </select>
          </div>
          <div className="form-group">
            <label>Action</label>
            <select
              value={filterAction}
              onChange={(e) => setFilterAction(e.target.value)}
            >
              <option value="">All Actions</option>
              {allActions.map((action) => (
                <option key={action} value={action}>
                  {formatAction(action)}
                </option>
              ))}
            </select>
          </div>
          <div className="form-group">
            <label>Entity Type</label>
            <select
              value={filterEntityType}
              onChange={(e) => setFilterEntityType(e.target.value)}
            >
              <option value="">All Types</option>
              {allEntityTypes.map((type) => (
                <option key={type} value={type}>
                  {formatEntityType(type)}
                </option>
              ))}
            </select>
          </div>
          <div className="form-group">
            <label>From Date</label>
            <input
              type="datetime-local"
              value={filterFrom}
              onChange={(e) => setFilterFrom(e.target.value)}
            />
          </div>
          <div className="form-group">
            <label>To Date</label>
            <input
              type="datetime-local"
              value={filterTo}
              onChange={(e) => setFilterTo(e.target.value)}
            />
          </div>
        </div>
      </div>

      {/* Results */}
      <div className="card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
          <h3 style={{ margin: 0 }}>Events</h3>
          <div style={{ color: '#666', fontSize: '0.9em' }}>
            {loading ? 'Loading...' : `${events.length} event${events.length !== 1 ? 's' : ''}`}
          </div>
        </div>
        
        {loading && events.length === 0 ? (
          <div style={{ padding: 40, textAlign: 'center', color: '#666' }}>Loading audit events...</div>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Actor</th>
                <th>Action</th>
                <th>Entity Type</th>
                <th>Entity ID</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {events.map((e) => (
                <tr key={e.id}>
                  <td style={{ whiteSpace: 'nowrap', fontSize: '0.9em' }}>
                    {formatTimestamp(e.timestamp)}
                  </td>
                  <td>
                    <strong>{e.actor_username || '(system)'}</strong>
                  </td>
                  <td>
                    <span style={{ color: getActionColor(e.action), fontWeight: 'bold' }}>
                      {formatAction(e.action)}
                    </span>
                  </td>
                  <td>
                    <code style={{ fontSize: '0.85em' }}>{formatEntityType(e.entity_type)}</code>
                  </td>
                  <td>
                    <code style={{ fontSize: '0.85em', color: '#666' }}>
                      {String(e.entity_id).slice(0, 8)}...
                    </code>
                  </td>
                  <td>
                    {e.metadata && typeof e.metadata === 'object' ? (
                      renderDeploymentMetadata(e.metadata, e.entity_type, e.action)
                    ) : (
                      <span style={{ color: '#999' }}>-</span>
                    )}
                  </td>
                </tr>
              ))}
              {events.length === 0 && !loading && (
                <tr>
                  <td colSpan={6} className="empty-state">
                    {hasFilters 
                      ? 'No events match the selected filters.' 
                      : 'No audit events found.'}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
