import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';

import { api } from '../lib/api';

export function DeploymentsPage() {
  const navigate = useNavigate();
  const [deployments, setDeployments] = useState<any[]>([]);
  const [tags, setTags] = useState<any[]>([]);
  const [vlans, setVlans] = useState<any[]>([]);
  const [hosts, setHosts] = useState<any[]>([]);
  const [showCreate, setShowCreate] = useState(false);
  const [error, setError] = useState<string>('');

  // Filtering and pagination state
  const [searchQuery, setSearchQuery] = useState('');
  const [filterMode, setFilterMode] = useState<string>('');
  const [filterStatus, setFilterStatus] = useState<string>('');
  const [filterTag, setFilterTag] = useState<string>('');
  const [filterVlan, setFilterVlan] = useState<string>('');
  const [filterFromDate, setFilterFromDate] = useState('');
  const [filterToDate, setFilterToDate] = useState('');
  const [sortBy, setSortBy] = useState<string>('created_at');
  const [sortOrder, setSortOrder] = useState<'ASC' | 'DESC'>('DESC');
  const [currentPage, setCurrentPage] = useState(1);
  const [pagination, setPagination] = useState<{ page: number; limit: number; total: number; totalPages: number } | null>(null);

  // Form state
  const [formPolicyVersionId, setFormPolicyVersionId] = useState('');
  const [formMode, setFormMode] = useState<'CANARY' | 'PROGRESSIVE' | 'FULL'>('CANARY');
  const [formTargetType, setFormTargetType] = useState<'TAG' | 'VLAN' | 'HOST'>('TAG');
  const [formTagIds, setFormTagIds] = useState<string[]>([]);
  const [formVlanIds, setFormVlanIds] = useState<string[]>([]);
  const [formHostIds, setFormHostIds] = useState<string[]>([]);
  const [formCanarySize, setFormCanarySize] = useState(1);
  const [formBatchSize, setFormBatchSize] = useState(5);
  const [formScheduledAt, setFormScheduledAt] = useState('');
  const [safetyCheck, setSafetyCheck] = useState<any>(null);

  useEffect(() => {
    loadData();
  }, []);

  useEffect(() => {
    loadDeployments();
  }, [currentPage, searchQuery, filterMode, filterStatus, filterTag, filterVlan, filterFromDate, filterToDate, sortBy, sortOrder]);

  async function loadData() {
    try {
      const [tagsRes, vlansRes, hostsRes] = await Promise.all([
        api.tags(),
        api.vlans(),
        api.hosts()
      ]);
      setTags(tagsRes.tags);
      setVlans(vlansRes.vlans);
      setHosts(hostsRes.hosts);
    } catch (e: any) {
      setError(String(e.message || e));
    }
  }

  async function loadDeployments() {
    try {
      const params: any = {
        page: currentPage,
        limit: 50,
        sortBy,
        sortOrder
      };
      if (searchQuery.trim()) params.search = searchQuery.trim();
      if (filterMode) params.mode = filterMode;
      if (filterStatus) params.status = filterStatus;
      if (filterTag) params.tag = filterTag;
      if (filterVlan) params.vlan = filterVlan;
      if (filterFromDate) params.fromDate = filterFromDate;
      if (filterToDate) params.toDate = filterToDate;

      const dRes = await api.deployments(params);
      setDeployments(dRes.deployments);
      setPagination(dRes.pagination);
    } catch (e: any) {
      setError(String(e.message || e));
    }
  }

  function resetForm() {
    setFormPolicyVersionId('');
    setFormMode('CANARY');
    setFormTargetType('TAG');
    setFormTagIds([]);
    setFormVlanIds([]);
    setFormHostIds([]);
    setFormCanarySize(1);
    setFormBatchSize(5);
    setFormScheduledAt('');
    setSafetyCheck(null);
    setShowCreate(false);
    setError('');
  }

  async function createDeployment() {
    if (!formPolicyVersionId.trim()) {
      setError('Policy version ID is required');
      return;
    }

    try {
      const targetQuery: any = {
        tags: [],
        vlans: [],
        hosts: []
      };

      if (formTargetType === 'TAG') {
        if (formTagIds.length === 0) {
          setError('Please select at least one tag');
          return;
        }
        targetQuery.tags = formTagIds;
      } else if (formTargetType === 'VLAN') {
        if (formVlanIds.length === 0) {
          setError('Please select at least one VLAN');
          return;
        }
        targetQuery.vlans = formVlanIds;
      } else if (formTargetType === 'HOST') {
        if (formHostIds.length === 0) {
          setError('Please select at least one host');
          return;
        }
        targetQuery.hosts = formHostIds;
      }

      const payload: any = {
        policyVersionId: formPolicyVersionId.trim(),
        mode: formMode,
        targetQuery
      };

      if (formMode === 'CANARY') {
        payload.canarySize = formCanarySize;
      } else if (formMode === 'PROGRESSIVE') {
        payload.batchSize = formBatchSize;
      }

      if (formScheduledAt) {
        payload.scheduledAt = formScheduledAt;
      }

      await api.createDeployment(payload);
      resetForm();
      loadDeployments();
    } catch (e: any) {
      const errorMsg = e.message || String(e);
      // Try to extract a more user-friendly error message
      if (errorMsg.includes('policy_version_not_approved') || errorMsg.includes('not_approved')) {
        setError('Cannot deploy: Policy version must be APPROVED. Please approve the policy version first before deploying.');
      } else if (errorMsg.includes('policy_version_not_found') || errorMsg.includes('not_found')) {
        setError('Policy version not found. Please check the version ID.');
      } else {
        setError(errorMsg);
      }
    }
  }

  async function startDeployment(deploymentId: string) {
    if (!confirm('Start this deployment? This will apply firewall rules to target hosts.')) return;
    try {
      await api.startDeployment(deploymentId);
      loadDeployments();
    } catch (e: any) {
      setError(String(e.message || e));
    }
  }

  function getStatusBadge(status: string) {
    const colors: Record<string, string> = {
      QUEUED: '#888',
      RUNNING: '#2196F3',
      PAUSED: '#FF9800',
      SUCCEEDED: '#4CAF50',
      FAILED: '#F44336',
      PARTIAL: '#FF9800',
      CANCELLED: '#999'
    };
    return <span style={{ color: colors[status] || '#000', fontWeight: 'bold' }}>{status}</span>;
  }

  async function pauseDeployment(deploymentId: string) {
    if (!confirm('Pause this deployment? You can resume it later.')) return;
    try {
      await api.pauseDeployment(deploymentId);
      loadDeployments();
    } catch (e: any) {
      setError(String(e.message || e));
    }
  }

  async function resumeDeployment(deploymentId: string) {
    if (!confirm('Resume this deployment?')) return;
    try {
      await api.resumeDeployment(deploymentId);
      loadDeployments();
    } catch (e: any) {
      setError(String(e.message || e));
    }
  }

  async function stopDeployment(deploymentId: string) {
    if (!confirm('Stop this deployment? This will cancel all pending hosts and cannot be undone.')) return;
    try {
      await api.stopDeployment(deploymentId);
      loadDeployments();
    } catch (e: any) {
      setError(String(e.message || e));
    }
  }

  return (
    <div className="page">
      <div className="page-header">
        <h2>Deployments</h2>
        <button onClick={() => setShowCreate(true)} className="btn-primary">+ Create Deployment</button>
      </div>

      {error && <div className="error-banner">{error}</div>}

      {showCreate && (
        <div className="card">
          <h3>Create Deployment</h3>
          <div className="form-grid">
            <div className="form-group">
              <label>Policy Version ID *</label>
              <input
                type="text"
                value={formPolicyVersionId}
                onChange={(e) => setFormPolicyVersionId(e.target.value)}
                placeholder="Paste approved policy version UUID"
              />
              <small style={{ color: '#666', fontSize: '0.85em' }}>
                Use an APPROVED policy version. Get the ID from the Policy Sets page.
              </small>
            </div>
            <div className="form-group" style={{ position: 'relative' }}>
              <label style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                Deployment Mode *
                <span 
                  style={{ 
                    position: 'relative',
                    cursor: 'help',
                    display: 'inline-flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    width: '18px',
                    height: '18px',
                    borderRadius: '50%',
                    background: '#646cff',
                    color: 'white',
                    fontSize: '12px',
                    fontWeight: 'bold'
                  }}
                  onMouseEnter={(e) => {
                    const tooltip = document.getElementById('deployment-mode-tooltip');
                    if (tooltip) {
                      const rect = e.currentTarget.getBoundingClientRect();
                      tooltip.style.display = 'block';
                      tooltip.style.left = `${rect.right + 10}px`;
                      tooltip.style.top = `${rect.top - 10}px`;
                    }
                  }}
                  onMouseLeave={() => {
                    const tooltip = document.getElementById('deployment-mode-tooltip');
                    if (tooltip) tooltip.style.display = 'none';
                  }}
                >
                  ?
                </span>
              </label>
              <select value={formMode} onChange={(e) => setFormMode(e.target.value as any)}>
                <option value="CANARY">Canary (small subset first)</option>
                <option value="PROGRESSIVE">Progressive (batches)</option>
                <option value="FULL">Full (all targets)</option>
              </select>
              <div
                id="deployment-mode-tooltip"
                style={{
                  display: 'none',
                  position: 'fixed',
                  background: '#333',
                  color: 'white',
                  padding: '12px 16px',
                  borderRadius: '6px',
                  fontSize: '0.85em',
                  maxWidth: '400px',
                  zIndex: 10000,
                  boxShadow: '0 4px 12px rgba(0,0,0,0.3)',
                  pointerEvents: 'none',
                  lineHeight: '1.5'
                }}
              >
                <div style={{ fontWeight: 'bold', marginBottom: '8px', borderBottom: '1px solid #555', paddingBottom: '4px' }}>
                  Deployment Modes:
                </div>
                <div style={{ marginBottom: '8px' }}>
                  <strong>CANARY:</strong> Deploys to a small subset of hosts first (specified by Canary Size). 
                  Use this to test the policy on a few hosts before rolling out to all targets. 
                  Ideal for validating changes before full deployment.
                </div>
                <div style={{ marginBottom: '8px' }}>
                  <strong>PROGRESSIVE:</strong> Deploys in batches (specified by Batch Size). 
                  Each batch is deployed sequentially, allowing you to monitor progress and stop if issues arise. 
                  Best for gradual rollouts across large fleets.
                </div>
                <div>
                  <strong>FULL:</strong> Deploys to all target hosts simultaneously. 
                  Fastest deployment method but provides less control. 
                  Use when you're confident the policy is safe and tested.
                </div>
              </div>
            </div>
            {formMode === 'CANARY' && (
              <div className="form-group">
                <label>Canary Size</label>
                <input
                  type="number"
                  value={formCanarySize}
                  onChange={(e) => setFormCanarySize(Number(e.target.value))}
                  min="1"
                />
              </div>
            )}
            {formMode === 'PROGRESSIVE' && (
              <div className="form-group">
                <label>Batch Size</label>
                <input
                  type="number"
                  value={formBatchSize}
                  onChange={(e) => setFormBatchSize(Number(e.target.value))}
                  min="1"
                />
              </div>
            )}
            <div className="form-group">
              <label>Target Type *</label>
              <select value={formTargetType} onChange={(e) => setFormTargetType(e.target.value as any)}>
                <option value="TAG">Tag (all hosts with tag)</option>
                <option value="VLAN">VLAN (all hosts in VLAN)</option>
                <option value="HOST">Specific Hosts</option>
              </select>
            </div>

            {formTargetType === 'TAG' && (
              <div className="form-group" style={{ gridColumn: '1 / -1' }}>
                <label>Tags * (select multiple)</label>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: 8, maxHeight: '200px', overflowY: 'auto', border: '1px solid #ddd', padding: 8, borderRadius: 4 }}>
                  {tags.map((t) => (
                    <label key={t.id} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      <input
                        type="checkbox"
                        checked={formTagIds.includes(t.id)}
                        onChange={(e) => {
                          if (e.target.checked) {
                            setFormTagIds([...formTagIds, t.id]);
                          } else {
                            setFormTagIds(formTagIds.filter(id => id !== t.id));
                          }
                        }}
                      />
                      <span>{t.name}</span>
                    </label>
                  ))}
                </div>
              </div>
            )}

            {formTargetType === 'VLAN' && (
              <div className="form-group" style={{ gridColumn: '1 / -1' }}>
                <label>VLANs * (select multiple)</label>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: 8, maxHeight: '200px', overflowY: 'auto', border: '1px solid #ddd', padding: 8, borderRadius: 4 }}>
                  {vlans.map((v) => (
                    <label key={v.id} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      <input
                        type="checkbox"
                        checked={formVlanIds.includes(v.id)}
                        onChange={(e) => {
                          if (e.target.checked) {
                            setFormVlanIds([...formVlanIds, v.id]);
                          } else {
                            setFormVlanIds(formVlanIds.filter(id => id !== v.id));
                          }
                        }}
                      />
                      <span>{v.name} (VLAN {v.vlan_tag})</span>
                    </label>
                  ))}
                </div>
              </div>
            )}

            {formTargetType === 'HOST' && (
              <div className="form-group" style={{ gridColumn: '1 / -1' }}>
                <label>Hosts * (select multiple)</label>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: 8, maxHeight: '200px', overflowY: 'auto', border: '1px solid #ddd', padding: 8, borderRadius: 4 }}>
                  {hosts.map((h) => (
                    <label key={h.id} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      <input
                        type="checkbox"
                        checked={formHostIds.includes(h.id)}
                        onChange={(e) => {
                          if (e.target.checked) {
                            setFormHostIds([...formHostIds, h.id]);
                          } else {
                            setFormHostIds(formHostIds.filter(id => id !== h.id));
                          }
                        }}
                      />
                      <span>{h.hostname} {h.mgmt_ip && `(${h.mgmt_ip})`}</span>
                    </label>
                  ))}
                </div>
              </div>
            )}
          </div>

            {/* Scheduled Deployment */}
            <div className="form-group">
              <label>Schedule Deployment (Optional)</label>
              <input
                type="datetime-local"
                value={formScheduledAt}
                onChange={(e) => setFormScheduledAt(e.target.value)}
              />
              <small style={{ color: '#666', fontSize: '0.85em' }}>
                Leave empty to deploy immediately. Scheduled deployments will start automatically at the specified time.
              </small>
            </div>

            {/* Safety Check Warnings */}
            {safetyCheck && (
              <div className="form-group" style={{ gridColumn: '1 / -1' }}>
                {!safetyCheck.sshAccessPreserved && safetyCheck.errors.length > 0 && (
                  <div style={{ 
                    padding: 12, 
                    background: formMode === 'FULL' ? '#ffebee' : '#fff3e0', 
                    border: `1px solid ${formMode === 'FULL' ? '#f44336' : '#ff9800'}`,
                    borderRadius: 4,
                    marginBottom: 8
                  }}>
                    <strong style={{ color: formMode === 'FULL' ? '#d32f2f' : '#f57c00' }}>
                      {formMode === 'FULL' ? '⚠️ BLOCKED: ' : '⚠️ WARNING: '}
                    </strong>
                    Deployment would block SSH access from management VLAN
                    <ul style={{ marginTop: 8, marginBottom: 0, paddingLeft: 20 }}>
                      {safetyCheck.errors.map((err: string, i: number) => (
                        <li key={i}>{err}</li>
                      ))}
                    </ul>
                    {formMode === 'FULL' && (
                      <div style={{ marginTop: 8, fontWeight: 500 }}>
                        FULL mode deployments require SSH access to be preserved. Please review your policy rules.
                      </div>
                    )}
                  </div>
                )}
                {safetyCheck.warnings.length > 0 && (
                  <div style={{ 
                    padding: 12, 
                    background: '#fff9c4', 
                    border: '1px solid #fbc02d',
                    borderRadius: 4
                  }}>
                    <strong style={{ color: '#f57c00' }}>⚠️ Warnings:</strong>
                    <ul style={{ marginTop: 8, marginBottom: 0, paddingLeft: 20 }}>
                      {safetyCheck.warnings.map((warn: string, i: number) => (
                        <li key={i}>{warn}</li>
                      ))}
                    </ul>
                  </div>
                )}
                {safetyCheck.sshAccessPreserved && safetyCheck.errors.length === 0 && safetyCheck.warnings.length === 0 && (
                  <div style={{ 
                    padding: 12, 
                    background: '#e8f5e9', 
                    border: '1px solid #4caf50',
                    borderRadius: 4
                  }}>
                    <strong style={{ color: '#2e7d32' }}>✓ Safety Check Passed</strong>
                    <div style={{ marginTop: 4 }}>SSH access from management VLAN will be preserved.</div>
                  </div>
                )}
              </div>
            )}

          <div className="form-actions">
            <button 
              onClick={createDeployment} 
              className="btn-primary"
              disabled={formMode === 'FULL' && safetyCheck && !safetyCheck.sshAccessPreserved && safetyCheck.errors.length > 0}
            >
              Create Deployment
            </button>
            <button onClick={resetForm} className="btn-secondary">Cancel</button>
          </div>
        </div>
      )}

      <div className="card">
        <h3>Deployments</h3>
        
        {/* Filters */}
        <div style={{ marginBottom: 16, padding: 16, background: '#f5f5f5', borderRadius: 8 }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 12, marginBottom: 12 }}>
            <div>
              <label style={{ display: 'block', marginBottom: 4, fontSize: '0.9em', fontWeight: 500 }}>Search</label>
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => { setSearchQuery(e.target.value); setCurrentPage(1); }}
                placeholder="Deployment or Policy Version ID"
                style={{ width: '100%', padding: '6px 8px', border: '1px solid #ddd', borderRadius: 4 }}
              />
            </div>
            <div>
              <label style={{ display: 'block', marginBottom: 4, fontSize: '0.9em', fontWeight: 500 }}>Mode</label>
              <select
                value={filterMode}
                onChange={(e) => { setFilterMode(e.target.value); setCurrentPage(1); }}
                style={{ width: '100%', padding: '6px 8px', border: '1px solid #ddd', borderRadius: 4 }}
              >
                <option value="">All Modes</option>
                <option value="CANARY">Canary</option>
                <option value="PROGRESSIVE">Progressive</option>
                <option value="FULL">Full</option>
              </select>
            </div>
            <div>
              <label style={{ display: 'block', marginBottom: 4, fontSize: '0.9em', fontWeight: 500 }}>Status</label>
              <select
                value={filterStatus}
                onChange={(e) => { setFilterStatus(e.target.value); setCurrentPage(1); }}
                style={{ width: '100%', padding: '6px 8px', border: '1px solid #ddd', borderRadius: 4 }}
              >
                <option value="">All Statuses</option>
                <option value="QUEUED">Queued</option>
                <option value="RUNNING">Running</option>
                <option value="PAUSED">Paused</option>
                <option value="SUCCEEDED">Succeeded</option>
                <option value="FAILED">Failed</option>
                <option value="PARTIAL">Partial</option>
                <option value="CANCELLED">Cancelled</option>
              </select>
            </div>
            <div>
              <label style={{ display: 'block', marginBottom: 4, fontSize: '0.9em', fontWeight: 500 }}>Tag</label>
              <select
                value={filterTag}
                onChange={(e) => { setFilterTag(e.target.value); setCurrentPage(1); }}
                style={{ width: '100%', padding: '6px 8px', border: '1px solid #ddd', borderRadius: 4 }}
              >
                <option value="">All Tags</option>
                {tags.map((t) => (
                  <option key={t.id} value={t.name}>{t.name}</option>
                ))}
              </select>
            </div>
            <div>
              <label style={{ display: 'block', marginBottom: 4, fontSize: '0.9em', fontWeight: 500 }}>VLAN</label>
              <select
                value={filterVlan}
                onChange={(e) => { setFilterVlan(e.target.value); setCurrentPage(1); }}
                style={{ width: '100%', padding: '6px 8px', border: '1px solid #ddd', borderRadius: 4 }}
              >
                <option value="">All VLANs</option>
                {vlans.map((v) => (
                  <option key={v.id} value={v.name}>{v.name} (VLAN {v.vlan_tag})</option>
                ))}
              </select>
            </div>
            <div>
              <label style={{ display: 'block', marginBottom: 4, fontSize: '0.9em', fontWeight: 500 }}>From Date</label>
              <input
                type="date"
                value={filterFromDate}
                onChange={(e) => { setFilterFromDate(e.target.value); setCurrentPage(1); }}
                style={{ width: '100%', padding: '6px 8px', border: '1px solid #ddd', borderRadius: 4 }}
              />
            </div>
            <div>
              <label style={{ display: 'block', marginBottom: 4, fontSize: '0.9em', fontWeight: 500 }}>To Date</label>
              <input
                type="date"
                value={filterToDate}
                onChange={(e) => { setFilterToDate(e.target.value); setCurrentPage(1); }}
                style={{ width: '100%', padding: '6px 8px', border: '1px solid #ddd', borderRadius: 4 }}
              />
            </div>
            <div>
              <label style={{ display: 'block', marginBottom: 4, fontSize: '0.9em', fontWeight: 500 }}>Sort By</label>
              <select
                value={sortBy}
                onChange={(e) => { setSortBy(e.target.value); setCurrentPage(1); }}
                style={{ width: '100%', padding: '6px 8px', border: '1px solid #ddd', borderRadius: 4 }}
              >
                <option value="created_at">Created Date</option>
                <option value="started_at">Started Date</option>
                <option value="finished_at">Finished Date</option>
                <option value="status">Status</option>
                <option value="mode">Mode</option>
                <option value="target_count">Target Count</option>
              </select>
            </div>
            <div>
              <label style={{ display: 'block', marginBottom: 4, fontSize: '0.9em', fontWeight: 500 }}>Order</label>
              <select
                value={sortOrder}
                onChange={(e) => { setSortOrder(e.target.value as 'ASC' | 'DESC'); setCurrentPage(1); }}
                style={{ width: '100%', padding: '6px 8px', border: '1px solid #ddd', borderRadius: 4 }}
              >
                <option value="DESC">Newest First</option>
                <option value="ASC">Oldest First</option>
              </select>
            </div>
          </div>
          {(searchQuery || filterMode || filterStatus || filterTag || filterVlan || filterFromDate || filterToDate) && (
            <button
              onClick={() => {
                setSearchQuery('');
                setFilterMode('');
                setFilterStatus('');
                setFilterTag('');
                setFilterVlan('');
                setFilterFromDate('');
                setFilterToDate('');
                setCurrentPage(1);
              }}
              className="btn-small btn-secondary"
              style={{ marginTop: 8 }}
            >
              Clear Filters
            </button>
          )}
          {pagination && (
            <div style={{ fontSize: '0.9em', color: '#666', marginTop: 12 }}>
              Showing {((currentPage - 1) * (pagination.limit || 50)) + 1} to {Math.min(currentPage * (pagination.limit || 50), pagination.total)} of {pagination.total} deployments
            </div>
          )}
        </div>

        <table className="data-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Policy Version</th>
              <th>Mode</th>
              <th>Targets</th>
              <th>Status</th>
              <th>Created</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {deployments.map((d) => (
              <tr key={d.id}>
                <td><code style={{ fontSize: '0.85em' }}>{d.id.slice(0, 8)}...</code></td>
                <td><code style={{ fontSize: '0.85em' }}>{d.policy_version_id.slice(0, 8)}...</code></td>
                <td>{d.mode}</td>
                <td>{d.target_count} host(s)</td>
                <td>{getStatusBadge(d.status)}</td>
                <td>{new Date(d.created_at).toLocaleString()}</td>
                <td>
                  <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                    {d.status === 'QUEUED' && (
                      <button onClick={() => startDeployment(d.id)} className="btn-small btn-primary">Start</button>
                    )}
                    {d.status === 'RUNNING' && (
                      <>
                        <button onClick={() => pauseDeployment(d.id)} className="btn-small" style={{ background: '#FF9800', color: 'white' }}>Pause</button>
                        <button onClick={() => stopDeployment(d.id)} className="btn-small" style={{ background: '#F44336', color: 'white' }}>Stop</button>
                      </>
                    )}
                    {d.status === 'PAUSED' && (
                      <>
                        <button onClick={() => resumeDeployment(d.id)} className="btn-small btn-primary">Resume</button>
                        <button onClick={() => stopDeployment(d.id)} className="btn-small" style={{ background: '#F44336', color: 'white' }}>Stop</button>
                      </>
                    )}
                    <button onClick={() => navigate(`/deployment/${d.id}`)} className="btn-small">View</button>
                  </div>
                </td>
              </tr>
            ))}
            {deployments.length === 0 && (
              <tr>
                <td colSpan={7} className="empty-state" style={{ textAlign: 'center', padding: '24px' }}>
                  {searchQuery || filterMode || filterStatus || filterTag || filterVlan || filterFromDate || filterToDate
                    ? 'No deployments match your filters. Try adjusting your search criteria.'
                    : 'No deployments yet. Click "Create Deployment" to create one.'}
                </td>
              </tr>
            )}
          </tbody>
        </table>

        {/* Pagination */}
        {pagination && pagination.totalPages > 1 && (
          <div style={{ marginTop: 16, display: 'flex', justifyContent: 'center', alignItems: 'center', gap: 8 }}>
            <button
              onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
              disabled={currentPage === 1}
              className="btn-small"
            >
              Previous
            </button>
            <span style={{ padding: '0 16px' }}>
              Page {pagination.page} of {pagination.totalPages}
            </span>
            <button
              onClick={() => setCurrentPage(p => Math.min(pagination.totalPages, p + 1))}
              disabled={currentPage === pagination.totalPages}
              className="btn-small"
            >
              Next
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
