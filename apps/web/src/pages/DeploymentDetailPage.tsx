import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';

import { api, errorMessage } from '../lib/api';
import { hasRole, useAuth } from '../lib/auth-context';

// Deployment statuses that may still change and therefore warrant polling.
const ACTIVE_STATUSES = ['RUNNING', 'QUEUED', 'PAUSED', 'SCHEDULED'];

export function DeploymentDetailPage() {
  const { deploymentId } = useParams();
  const navigate = useNavigate();
  const [deployment, setDeployment] = useState<any>(null);
  const [hosts, setHosts] = useState<any[]>([]);
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string>('');
  const [actionError, setActionError] = useState<string>('');
  const { roles } = useAuth();
  const canOperate = hasRole(roles, 'operator', 'admin');
  const canApprove = hasRole(roles, 'approver', 'admin');
  const requestIdRef = useRef(0);

  const loadData = useCallback(async () => {
    if (!deploymentId) return;
    const requestId = ++requestIdRef.current;
    try {
      const [depRes, hostsRes] = await Promise.all([
        api.deployment(deploymentId),
        api.deploymentHosts(deploymentId)
      ]);
      if (requestId !== requestIdRef.current) return;
      setDeployment(depRes.deployment);
      setHosts(hostsRes.hosts);
      setError('');
    } catch (e: any) {
      if (requestId !== requestIdRef.current) return;
      setError(String(e.message || e));
    } finally {
      if (requestId === requestIdRef.current) setLoading(false);
    }
  }, [deploymentId]);

  // Initial load (and reload when navigating to a different deployment).
  useEffect(() => {
    setLoading(true);
    setDeployment(null);
    loadData();
  }, [loadData]);

  // Auto-refresh every 5 seconds while the deployment is in a non-terminal state.
  // Depending on the status (not the whole object) re-creates the interval only
  // when the status changes, and stops polling once it becomes terminal.
  const deploymentStatus: string | undefined = deployment?.status;
  useEffect(() => {
    if (!deploymentStatus || !ACTIVE_STATUSES.includes(deploymentStatus)) return;
    const interval = setInterval(() => {
      loadData();
    }, 5000);
    return () => clearInterval(interval);
  }, [deploymentStatus, loadData]);

  async function runAction(fn: () => Promise<unknown>, confirmText: string) {
    if (!confirm(confirmText)) return;
    setActionError('');
    try {
      await fn();
    } catch (e: any) {
      setActionError(errorMessage(e));
    } finally {
      loadData();
    }
  }

  const filteredHosts = useMemo(() => {
    let filtered = [...hosts];

    // Filter by status
    if (statusFilter !== 'ALL') {
      filtered = filtered.filter(h => h.status === statusFilter);
    }

    // Filter by search query (hostname or IP)
    if (searchQuery.trim()) {
      const query = searchQuery.toLowerCase();
      filtered = filtered.filter(h =>
        h.hostname?.toLowerCase().includes(query) ||
        h.mgmt_ip?.toLowerCase().includes(query)
      );
    }
    return filtered;
  }, [hosts, statusFilter, searchQuery]);

  const hasExpiryResults = hosts.some((h) => h.expiry_status);

  function getStatusBadge(status: string) {
    const colors: Record<string, string> = {
      PENDING: '#888',
      SCHEDULED: '#7E57C2',
      QUEUED: '#888',
      PAUSED: '#FF9800',
      PARTIAL: '#FF9800',
      CANCELLED: '#999',
      RUNNING: '#2196F3',
      SUCCEEDED: '#4CAF50',
      FAILED: '#F44336',
      SKIPPED: '#999',
      ROLLED_BACK: '#FF9800'
    };
    const labels: Record<string, string> = {
      PENDING: 'Pending',
      SCHEDULED: 'Scheduled',
      QUEUED: 'Queued',
      PAUSED: 'Paused',
      PARTIAL: 'Partial',
      CANCELLED: 'Cancelled',
      RUNNING: 'Running',
      SUCCEEDED: 'Succeeded',
      FAILED: 'Failed',
      SKIPPED: 'Skipped',
      ROLLED_BACK: 'Rolled Back'
    };
    return (
      <span style={{ color: colors[status] || '#000', fontWeight: 'bold' }}>
        {labels[status] || status}
      </span>
    );
  }

  function getStatusCounts() {
    const counts: Record<string, number> = {};
    hosts.forEach(h => {
      counts[h.status] = (counts[h.status] || 0) + 1;
    });
    return counts;
  }

  const statusCounts = getStatusCounts();
  const allStatuses = ['ALL', 'SUCCEEDED', 'FAILED', 'RUNNING', 'PENDING', 'SKIPPED', 'ROLLED_BACK'];

  if (loading) {
    return (
      <div className="page">
        <div style={{ padding: 40, textAlign: 'center' }}>Loading deployment details...</div>
      </div>
    );
  }

  // Only replace the page with an error when we have nothing to show; a failed
  // background refresh keeps the last good data and shows a banner instead.
  if (!deployment) {
    return (
      <div className="page">
        <div className="error-banner">{error || 'Deployment not found'}</div>
        <button onClick={() => navigate('/deployments')} className="btn-secondary">Back to Deployments</button>
      </div>
    );
  }

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <button onClick={() => navigate('/deployments')} className="btn-secondary" style={{ marginRight: 12 }}>
            ← Back
          </button>
          <h2>Deployment Details</h2>
        </div>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          {canApprove && deployment.requires_approval && !deployment.approved_by && ['QUEUED', 'SCHEDULED'].includes(deployment.status) && (
            <button
              className="btn-small"
              style={{ background: '#8b6914', color: 'white' }}
              onClick={() => runAction(() => api.approveDeployment(deployment.id), 'Approve this deployment so it can be started?')}
            >
              Approve
            </button>
          )}
          {canOperate && deployment.status === 'QUEUED' && (
            <button
              className="btn-small btn-primary"
              disabled={deployment.requires_approval && !deployment.approved_by}
              title={deployment.requires_approval && !deployment.approved_by ? 'Awaiting approval' : undefined}
              onClick={() => runAction(() => api.startDeployment(deployment.id), 'Start this deployment? This will apply firewall rules to target hosts.')}
            >
              Start
            </button>
          )}
          {canOperate && (deployment.status === 'FAILED' || deployment.status === 'PARTIAL') && (
            <button
              className="btn-small btn-primary"
              onClick={() => runAction(async () => {
                // retry-failed resets failed hosts and puts the deployment back to QUEUED; then start it.
                await api.retryFailedHosts(deployment.id);
                await api.startDeployment(deployment.id);
              }, 'Retry the failed hosts? Only hosts that failed are redeployed; succeeded hosts are left alone.')}
            >
              Retry Failed Hosts
            </button>
          )}
          {canOperate && (deployment.status === 'QUEUED' || deployment.status === 'SCHEDULED') && (
            <button
              className="btn-small"
              style={{ background: '#999', color: 'white' }}
              onClick={() => runAction(() => api.cancelDeployment(deployment.id), 'Cancel this deployment? It will not be run.')}
            >
              Cancel
            </button>
          )}
        </div>
      </div>

      {error && <div className="error-banner">Refresh failed: {error}</div>}
      {actionError && <div className="error-banner">{actionError}</div>}

      {/* Deployment Overview */}
      <div className="card" style={{ marginBottom: 24 }}>
        <h3>Deployment Information</h3>
        <div className="form-grid">
          <div className="form-group">
            <label>Deployment ID</label>
            <code style={{ fontSize: '0.9em', display: 'block', padding: '8px', background: '#f5f5f5', borderRadius: 4 }}>
              {deployment.id}
            </code>
          </div>
          <div className="form-group">
            <label>Status</label>
            <div>
              {getStatusBadge(deployment.status)}
              {deployment.requires_approval && (
                <span style={{ marginLeft: 8, fontSize: '12px', color: deployment.approved_by ? '#4CAF50' : '#8b6914', fontWeight: 600 }}>
                  {deployment.approved_by ? `Approved by ${deployment.approved_by_username || deployment.approved_by}` : 'Needs approval'}
                </span>
              )}
            </div>
          </div>
          <div className="form-group">
            <label>Mode</label>
            <div>{deployment.mode}</div>
          </div>
          <div className="form-group">
            <label>Target Count</label>
            <div>{deployment.target_count} host(s)</div>
          </div>
          <div className="form-group">
            <label>Created By</label>
            <div>{deployment.created_by_display_name || deployment.created_by_username || '—'}</div>
          </div>
          <div className="form-group">
            <label>Created</label>
            <div>{new Date(deployment.created_at).toLocaleString()}</div>
          </div>
          {deployment.scheduled_at && (
            <div className="form-group">
              <label>Scheduled For</label>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <span style={{ color: new Date(deployment.scheduled_at) > new Date() ? '#8b6914' : '#5a7a3a', fontWeight: 600 }}>
                  {new Date(deployment.scheduled_at).toLocaleString()}
                </span>
                {new Date(deployment.scheduled_at) > new Date() && (
                  <span style={{ fontSize: '0.8em', padding: '2px 6px', background: '#fdf6ec', border: '1px solid #e8d5a8', borderRadius: 4, color: '#8b6914' }}>Pending</span>
                )}
              </div>
            </div>
          )}
          {deployment.expires_at && (
            <div className="form-group">
              <label>Expires At</label>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <span style={{ color: new Date(deployment.expires_at) < new Date() ? '#a63d2f' : '#78644e', fontWeight: 600 }}>
                  {new Date(deployment.expires_at).toLocaleString()}
                </span>
                {new Date(deployment.expires_at) < new Date() ? (
                  <span style={{ fontSize: '0.8em', padding: '2px 6px', background: '#faf0ee', border: '1px solid #e8c4bf', borderRadius: 4, color: '#a63d2f' }}>Expired</span>
                ) : (
                  <span style={{ fontSize: '0.8em', padding: '2px 6px', background: '#f0f5eb', border: '1px solid #c5d4b3', borderRadius: 4, color: '#5a7a3a' }}>Active</span>
                )}
              </div>
            </div>
          )}
          {deployment.expiry_action && deployment.expires_at && (
            <div className="form-group">
              <label>Expiry Action</label>
              <div>{deployment.expiry_action === 'NOTIFY_ONLY' ? 'Notify only (rules stay active)' : deployment.expiry_action === 'REMOVE' ? 'Remove (automatically remove Segmentra rules from hosts)' : deployment.expiry_action === 'REVERT' ? 'Revert (automatically re-deploy the previous version)' : deployment.expiry_action}</div>
            </div>
          )}
          {deployment.revert_of_deployment_id && (
            <div className="form-group" style={{ gridColumn: '1 / -1' }}>
              <label>Automatic Revert</label>
              <div style={{ fontSize: '13px', color: '#5c4633' }}>
                Created by the system because deployment{' '}
                <a href={`/deployments/${deployment.revert_of_deployment_id}`} onClick={(e) => { e.preventDefault(); navigate(`/deployments/${deployment.revert_of_deployment_id}`); }}>
                  <code>{String(deployment.revert_of_deployment_id).slice(0, 8)}</code>
                </a>{' '}expired (pre-authorised; no separate approval).
              </div>
            </div>
          )}
          {deployment.notes && !deployment.revert_of_deployment_id && (
            <div className="form-group" style={{ gridColumn: '1 / -1' }}>
              <label>Notes</label>
              <div style={{ fontSize: '13px' }}>{deployment.notes}</div>
            </div>
          )}
          {deployment.expiry_outcome && (() => {
            const o = typeof deployment.expiry_outcome === 'string' ? JSON.parse(deployment.expiry_outcome) : deployment.expiry_outcome;
            const good = ['REMOVED', 'REVERT_STARTED', 'NOTIFIED', 'NOTHING_TO_REMOVE', 'NO_HOSTS'].includes(o.result);
            const resultLabels: Record<string, string> = {
              NOTIFIED: 'Notified',
              REMOVED: 'Rules removed',
              REMOVE_PARTIAL: 'Removal partially failed',
              REMOVE_FAILED: 'Removal failed',
              NOTHING_TO_REMOVE: 'Nothing to remove',
              REVERT_STARTED: 'Revert started',
              NO_PREVIOUS_VERSION: 'No previous version to revert to',
              REVERT_NOT_DEPLOYABLE: 'Previous version not deployable',
              REVERT_NOT_STARTED: 'Revert created but not started',
              NO_HOSTS: 'No hosts to act on',
              ERROR: 'Automatic action failed',
            };
            return (
              <div className="form-group" style={{ gridColumn: '1 / -1' }}>
                <label>Expiry Outcome</label>
                <div style={{ padding: '8px 10px', borderRadius: 4, fontSize: '13px', background: good ? '#f0f5eb' : '#faf0ee', border: `1px solid ${good ? '#c5d4b3' : '#e8c4bf'}`, color: good ? '#3f5a28' : '#a63d2f' }}>
                  <strong>{resultLabels[o.result] ?? o.result}</strong>
                  {o.processedAt && <span style={{ color: '#78644e' }}> — {new Date(o.processedAt).toLocaleString()}</span>}
                  {o.message && <div style={{ marginTop: 4, color: '#5c4633' }}>{o.message}</div>}
                  {o.revertDeploymentId && (
                    <div style={{ marginTop: 4 }}>
                      Revert deployment:{' '}
                      <a href={`/deployments/${o.revertDeploymentId}`} onClick={(e) => { e.preventDefault(); navigate(`/deployments/${o.revertDeploymentId}`); }}>
                        <code>{String(o.revertDeploymentId).slice(0, 8)}</code>
                      </a>
                      {o.revertToVersionNumber != null && <span> (v{o.revertToVersionNumber})</span>}
                    </div>
                  )}
                </div>
              </div>
            );
          })()}
          {deployment.started_at && (
            <div className="form-group">
              <label>Started</label>
              <div>{new Date(deployment.started_at).toLocaleString()}</div>
            </div>
          )}
          {/* Progress bar for running deployments */}
          {deployment.progress && deployment.status === 'RUNNING' && (() => {
            const p = typeof deployment.progress === 'string' ? JSON.parse(deployment.progress) : deployment.progress;
            const phaseLabel = p.phase === 'checking' ? 'Pre-flight checks' : p.phase === 'deploying' ? 'Deploying rules' : p.phase === 'complete' ? 'Complete' : p.phase;
            const total = p.totalToDeploy || 1;
            const done = p.phase === 'checking' ? p.checked : p.phase === 'deploying' ? p.deployed : total;
            const pct = Math.round((done / total) * 100);
            return (
              <div style={{ gridColumn: '1 / -1', marginTop: 8 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4, fontSize: '13px' }}>
                  <span style={{ color: '#5c4633', fontWeight: 600 }}>{phaseLabel}</span>
                  <span style={{ color: '#78644e' }}>{done} / {total} hosts ({pct}%){p.currentHost ? ` — ${p.currentHost}` : ''}</span>
                </div>
                <div style={{ height: 8, background: '#e8e0d4', borderRadius: 4, overflow: 'hidden' }}>
                  <div style={{ height: '100%', width: `${pct}%`, background: p.phase === 'checking' ? '#8b6914' : '#5a7a3a', borderRadius: 4, transition: 'width 0.3s ease' }} />
                </div>
              </div>
            );
          })()}
          {deployment.finished_at && (
            <div className="form-group">
              <label>Finished</label>
              <div>{new Date(deployment.finished_at).toLocaleString()}</div>
            </div>
          )}
        </div>
      </div>

      {/* Host Status Summary */}
      <div className="card" style={{ marginBottom: 24 }}>
        <h3>Host Status Summary</h3>
        <div style={{ display: 'flex', gap: 24, flexWrap: 'wrap', marginBottom: 16 }}>
          {allStatuses.slice(1).map(status => (
            statusCounts[status] > 0 && (
              <div key={status} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                {getStatusBadge(status)}
                <span style={{ fontSize: '1.1em', fontWeight: 'bold' }}>{statusCounts[status]}</span>
              </div>
            )
          ))}
        </div>
      </div>

      {/* Hosts Table with Search/Filter */}
      <div className="card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
          <h3>Hosts ({filteredHosts.length} of {hosts.length})</h3>
          <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
            <input
              type="text"
              placeholder="Search by hostname or IP..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              style={{ padding: '6px 12px', border: '1px solid #ddd', borderRadius: 4, minWidth: 250 }}
            />
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              style={{ padding: '6px 12px', border: '1px solid #ddd', borderRadius: 4 }}
            >
              {allStatuses.map(status => (
                <option key={status} value={status}>
                  {status === 'ALL' ? 'All Statuses' : status}
                  {status !== 'ALL' && statusCounts[status] ? ` (${statusCounts[status]})` : ''}
                </option>
              ))}
            </select>
          </div>
        </div>

        {filteredHosts.length === 0 ? (
          <div className="empty-state" style={{ padding: 40, textAlign: 'center' }}>
            {hosts.length === 0 
              ? 'No hosts found for this deployment.'
              : 'No hosts match the current filters.'}
          </div>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Hostname</th>
                <th>Management IP</th>
                <th>Status</th>
                <th>Started</th>
                <th>Finished</th>
                <th>Message</th>
                <th>Rollback</th>
                {hasExpiryResults && <th>On Expiry</th>}
              </tr>
            </thead>
            <tbody>
              {filteredHosts.map((host) => (
                <tr key={`${host.deployment_id}-${host.host_id}`}>
                  <td>
                    <strong>{host.hostname}</strong>
                  </td>
                  <td>{host.mgmt_ip || '-'}</td>
                  <td>{getStatusBadge(host.status)}</td>
                  <td>
                    {host.started_at ? new Date(host.started_at).toLocaleString() : '-'}
                  </td>
                  <td>
                    {host.finished_at ? new Date(host.finished_at).toLocaleString() : '-'}
                  </td>
                  <td>
                    {host.message ? (
                      <span style={{ 
                        color: host.status === 'FAILED' ? '#F44336' : '#666',
                        fontSize: '0.9em'
                      }}>
                        {host.message}
                      </span>
                    ) : '-'}
                  </td>
                  <td>
                    {host.rollback_performed ? (
                      <span style={{ color: '#FF9800', fontWeight: 'bold' }}>Yes</span>
                    ) : '-'}
                  </td>
                  {hasExpiryResults && (
                    <td>
                      {host.expiry_status ? (
                        <span style={{ fontSize: '0.9em' }} title={host.expiry_message || ''}>
                          <strong style={{ color: host.expiry_status === 'FAILED' ? '#a63d2f' : host.expiry_status === 'SKIPPED' ? '#78644e' : '#5a7a3a' }}>
                            {host.expiry_status === 'REVERT_QUEUED' ? 'Reverting' : host.expiry_status.charAt(0) + host.expiry_status.slice(1).toLowerCase()}
                          </strong>
                          {host.expiry_message && <div style={{ color: '#666' }}>{host.expiry_message}</div>}
                        </span>
                      ) : '-'}
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

