import { useCallback, useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';

import { api, errorMessage, isApiError } from '../lib/api';
import { hasRole, useAuth } from '../lib/auth-context';

/** Convert a datetime-local value (local wall-clock time) to an ISO-8601 UTC string. */
function localDateTimeToIso(v: string): string {
  return new Date(v).toISOString();
}

/** Convert a date-only value (YYYY-MM-DD, local) to an ISO string at local start/end of day. */
function localDateToIso(v: string, endOfDay: boolean): string {
  return new Date(`${v}T${endOfDay ? '23:59:59.999' : '00:00:00'}`).toISOString();
}

/** What each deployment mode does, in plain words. Shown as tooltips, next to the mode filter and under the mode picker. */
const MODE_HELP: Record<string, string> = {
  CANARY: 'Canary: deploy to a few hosts first (the canary size). If a canary host fails, the other hosts are skipped and nothing else is touched. Use it for a new or risky policy.',
  PROGRESSIVE: 'Progressive: deploy in batches, one after another. If a host in a batch fails, the rollout stops after that batch. You can pause or stop it at any time.',
  FULL: 'Full: deploy to every target host in one go and keep going even if some fail. Least control; use it for a policy you have already proven.',
};
const MODE_HELP_ALL = Object.values(MODE_HELP).join('\n\n');

export function DeploymentsPage() {
  const navigate = useNavigate();
  const { roles } = useAuth();
  const canOperate = hasRole(roles, 'operator', 'admin');
  const canApprove = hasRole(roles, 'approver', 'admin');
  const [deployments, setDeployments] = useState<any[]>([]);
  const [tags, setTags] = useState<any[]>([]);
  const [vlans, setVlans] = useState<any[]>([]);
  const [hosts, setHosts] = useState<any[]>([]);
  const [showCreate, setShowCreate] = useState(false);
  const [error, setError] = useState<string>('');

  // Filtering and pagination state
  const [searchQuery, setSearchQuery] = useState('');
  const [debouncedSearch, setDebouncedSearch] = useState('');
  const requestIdRef = useRef(0);
  const [filterMode, setFilterMode] = useState<string>('');
  const [filterStatus, setFilterStatus] = useState<string>('');
  const [filterCreator, setFilterCreator] = useState<string>('');
  const [creators, setCreators] = useState<Array<{ username: string; display_name: string | null; deployments: number }>>([]);
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
  const [formExpiresAt, setFormExpiresAt] = useState('');
  const [formExpiryAction, setFormExpiryAction] = useState<'NOTIFY_ONLY' | 'REMOVE' | 'REVERT'>('NOTIFY_ONLY');
  const [safetyCheck, setSafetyCheck] = useState<any>(null);
  const [deployableVersions, setDeployableVersions] = useState<Array<{ id: string; label: string }>>([]);

  useEffect(() => {
    async function loadData() {
      try {
        const [tagsRes, vlansRes, hostsRes] = await Promise.all([
          api.tags(),
          api.vlans(),
          api.allHosts()
        ]);
        setTags(tagsRes.tags);
        setVlans(vlansRes.vlans);
        setHosts(hostsRes.hosts);
      } catch (e: any) {
        setError(String(e.message || e));
      }
    }
    loadData();
  }, []);

  // Only APPROVED or DEPLOYED versions can be deployed; offer them in a picker.
  useEffect(() => {
    if (!showCreate) return;
    let cancelled = false;
    (async () => {
      try {
        const { policySets } = await api.policySets();
        const lists = await Promise.all(policySets.map(async (ps: any) => {
          const { versions } = await api.versions(ps.id);
          return versions
            .filter((v: any) => v.status === 'APPROVED' || v.status === 'DEPLOYED')
            .sort((a: any, b: any) => b.version_number - a.version_number)
            .map((v: any) => ({ id: v.id, label: `${ps.name} v${v.version_number} (${v.status})` }));
        }));
        if (!cancelled) setDeployableVersions(lists.flat());
      } catch (e: any) {
        if (!cancelled) setError(String(e.message || e));
      }
    })();
    return () => { cancelled = true; };
  }, [showCreate]);

  // Debounce free-text search so we don't fire a request per keystroke.
  useEffect(() => {
    const t = setTimeout(() => setDebouncedSearch(searchQuery), 300);
    return () => clearTimeout(t);
  }, [searchQuery]);

  const loadDeployments = useCallback(async () => {
    // Ignore responses from requests superseded by a newer one.
    const requestId = ++requestIdRef.current;
    try {
      const params: any = {
        page: currentPage,
        limit: 50,
        sortBy,
        sortOrder
      };
      if (debouncedSearch.trim()) params.search = debouncedSearch.trim();
      if (filterMode) params.mode = filterMode;
      if (filterStatus) params.status = filterStatus;
      if (filterCreator) params.createdBy = filterCreator;
      if (filterTag) params.tag = filterTag;
      if (filterVlan) params.vlan = filterVlan;
      if (filterFromDate) params.fromDate = localDateToIso(filterFromDate, false);
      if (filterToDate) params.toDate = localDateToIso(filterToDate, true);

      const dRes = await api.deployments(params);
      if (requestId !== requestIdRef.current) return;
      setDeployments(dRes.deployments);
      setPagination(dRes.pagination);
    } catch (e: any) {
      if (requestId !== requestIdRef.current) return;
      setError(String(e.message || e));
    }
  }, [currentPage, debouncedSearch, filterMode, filterStatus, filterCreator, filterTag, filterVlan, filterFromDate, filterToDate, sortBy, sortOrder]);

  useEffect(() => {
    loadDeployments();
  }, [loadDeployments]);

  useEffect(() => {
    api.deploymentCreators().then((r) => setCreators(r.creators)).catch(() => {});
  }, []);

  // Keep the list current while any deployment is in progress.
  const hasActive = deployments.some((d) => ['RUNNING', 'QUEUED', 'PAUSED'].includes(d.status));
  useEffect(() => {
    if (!hasActive) return;
    const t = setInterval(loadDeployments, 5000);
    return () => clearInterval(t);
  }, [hasActive, loadDeployments]);

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
    setFormExpiresAt('');
    setFormExpiryAction('NOTIFY_ONLY');
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
        payload.scheduledAt = localDateTimeToIso(formScheduledAt);
      }

      if (formExpiresAt) {
        payload.expiresAt = localDateTimeToIso(formExpiresAt);
        payload.expiryAction = formExpiryAction;
      }

      await api.createDeployment(payload);
      resetForm();
      loadDeployments();
    } catch (e: any) {
      if (isApiError(e) && e.code === 'safety_check_failed' && e.body?.safetyCheck) {
        setSafetyCheck(e.body.safetyCheck);
        setError(e.message);
        return;
      }
      const code = isApiError(e) ? e.code ?? '' : '';
      const errorMsg = errorMessage(e);
      // Try to extract a more user-friendly error message
      if (code === 'policy_version_not_approved' || errorMsg.includes('not_approved')) {
        setError('Cannot deploy: Policy version must be APPROVED (or previously DEPLOYED). Please approve the policy version first before deploying.');
      } else if (code === 'policy_version_not_found' || code === 'not_found') {
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
      if (isApiError(e) && e.code === 'deployment_requires_approval') {
        setError('This deployment requires approval by an approver before it can be started.');
      } else {
        setError(errorMessage(e));
      }
      loadDeployments();
    }
  }

  async function cancelDeployment(deploymentId: string) {
    if (!confirm('Cancel this deployment? It will not be run.')) return;
    try {
      await api.cancelDeployment(deploymentId);
      loadDeployments();
    } catch (e: any) {
      setError(errorMessage(e));
    }
  }

  async function approveDeployment(deploymentId: string) {
    if (!confirm('Approve this deployment so it can be started?')) return;
    try {
      await api.approveDeployment(deploymentId);
      loadDeployments();
    } catch (e: any) {
      setError(errorMessage(e));
    }
  }

  function getStatusBadge(status: string) {
    const colors: Record<string, string> = {
      SCHEDULED: '#7E57C2',
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
        {canOperate && (
          <button onClick={() => setShowCreate(true)} className="btn-primary">+ Create Deployment</button>
        )}
      </div>

      {error && <div className="error-banner">{error}</div>}

      {showCreate && canOperate && (
        <div className="card">
          <h3>Create Deployment</h3>
          <div style={{ padding: '10px 14px', background: '#fdf6ec', border: '1px solid #e8d5a8', borderRadius: 8, marginBottom: 16, fontSize: '13px', color: '#5c4633' }}>
            <strong>Important:</strong> Deploying a policy <strong>replaces all Segmentra rules</strong> on the target hosts with this version
            (Segmentra's <code style={{ background: '#f5ebe0', padding: '1px 4px', borderRadius: 3 }}>table inet segmentra</code> or
            <code style={{ background: '#f5ebe0', padding: '1px 4px', borderRadius: 3 }}>SEGMENTRA-IN/OUT</code> chains). Rules of other tools
            (Docker, Kubernetes, fail2ban) are left alone. Segmentra's previous rules are backed up to
            <code style={{ background: '#f5ebe0', padding: '1px 4px', borderRadius: 3 }}>/var/backups/segmentra/</code> on each host first.
            To add rules to an existing policy, create a new version of the policy set that includes both the existing and new rules.
          </div>
          <div className="form-grid">
            <div className="form-group">
              <label>Policy Version *</label>
              <select value={formPolicyVersionId} onChange={(e) => setFormPolicyVersionId(e.target.value)}>
                <option value="">Select an approved or deployed version</option>
                {deployableVersions.map((v) => <option key={v.id} value={v.id}>{v.label}</option>)}
              </select>
              <small style={{ color: '#666', fontSize: '0.85em' }}>
                Only APPROVED or DEPLOYED versions can be deployed. New versions must be approved first (Approvals page).
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
              <small style={{ display: 'block', marginTop: 4, color: '#78644e', lineHeight: 1.4 }}>{MODE_HELP[formMode]}</small>
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
                  <strong>CANARY:</strong> Deploys to a canary group first: the first hosts by hostname (Canary Size). 
                  If a canary host fails, the remaining hosts are not deployed (they are marked skipped and 
                  can be deployed later with Retry failed). SSH executor only; the Ansible executor deploys all hosts in one run.
                </div>
                <div style={{ marginBottom: '8px' }}>
                  <strong>PROGRESSIVE:</strong> Deploys in batches (specified by Batch Size), one batch after another. 
                  If a host fails, the rollout stops after that batch; you can also pause or stop it at any time. 
                  SSH executor only; the Ansible executor deploys all hosts in one run.
                </div>
                <div>
                  <strong>FULL:</strong> Deploys to all target hosts without stopping on failures. 
                  Provides the least control. 
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

            {/* Policy Expiry */}
            <div className="form-group">
              <label>Policy Expires At (Optional)</label>
              <input
                type="datetime-local"
                value={formExpiresAt}
                onChange={(e) => setFormExpiresAt(e.target.value)}
              />
              <small style={{ color: '#666', fontSize: '0.85em' }}>
                Leave empty for no expiry. Set a date to create a time-limited deployment (e.g., temporary vendor access, maintenance window). When it expires, Segmentra performs the action chosen below automatically (checked every minute).
              </small>
            </div>

            {formExpiresAt && (
              <div className="form-group">
                <label>On Expiry</label>
                <select
                  value={formExpiryAction}
                  onChange={(e) => setFormExpiryAction(e.target.value as any)}
                >
                  <option value="NOTIFY_ONLY">Notify Only — send alert, rules stay active</option>
                  <option value="REMOVE">Remove — automatically remove Segmentra rules from the hosts</option>
                  <option value="REVERT">Revert — automatically re-deploy the previous policy version</option>
                </select>
                <small style={{ color: '#666', fontSize: '0.85em' }}>
                  {formExpiryAction === 'NOTIFY_ONLY' && (<span>
                    A notification will be sent when the policy expires. The deployed rules remain active on hosts until you manually remove or replace them.
                    <br /><br />To restore the previous ruleset, SSH into the host and run:
                    <br /><strong>nftables:</strong> <code style={{ background: '#f5ebe0', padding: '1px 4px', borderRadius: 3, fontSize: '0.9em' }}>sudo nft -f /var/backups/segmentra/nft.ruleset.&lt;timestamp&gt;</code>
                    <br /><strong>iptables:</strong> <code style={{ background: '#f5ebe0', padding: '1px 4px', borderRadius: 3, fontSize: '0.9em' }}>sudo iptables-restore &lt; /var/backups/segmentra/iptables.&lt;timestamp&gt;</code>
                  </span>)}
                  {formExpiryAction === 'REMOVE' && (<span>
                    On expiry Segmentra connects to every host where this deployment succeeded (using each host's SSH credential) and removes the Segmentra nftables table / iptables chains, so the host falls back to its non-Segmentra rules. Hosts whose rules were since replaced by a later deployment are skipped. Per-host results appear on the deployment page and a notification is sent; hosts where removal failed still enforce the expired policy and need manual cleanup.
                  </span>)}
                  {formExpiryAction === 'REVERT' && (<span>
                    On expiry Segmentra finds the most recent earlier deployment of the same policy set (a different version that succeeded on these hosts) and automatically starts a new deployment of that version to the hosts that ran it. The expiry is pre-authorised by this deployment, so no new approval is needed, but the previous version must still be APPROVED or DEPLOYED. If there is no previous version, nothing is changed and a notification is sent instead.
                  </span>)}
                </small>
              </div>
            )}

            {/* IoT Gateway Warning */}
            {(() => {
              // Check if any selected targets include hosts tagged "iot-gateway"
              const selectedHosts = formTargetType === 'HOST' ? hosts.filter(h => formHostIds.includes(h.id)) : [];
              const selectedTagNames = formTargetType === 'TAG' ? tags.filter(t => formTagIds.includes(t.id)).map(t => t.name) : [];
              const isIotGateway = selectedHosts.some((h: any) => h.tags?.some((t: any) => t.name === 'iot-gateway'))
                || selectedTagNames.includes('iot-gateway');
              if (!isIotGateway) return null;
              return (
                <div className="form-group" style={{ gridColumn: '1 / -1' }}>
                  <div style={{ padding: 12, background: '#fdf6ec', border: '1px solid #e8d5a8', borderRadius: 8 }}>
                    <strong style={{ color: '#8b6914' }}>IoT/OT Gateway Deployment</strong>
                    <p style={{ margin: '8px 0 0', color: '#5c4633', fontSize: '13.5px' }}>
                      This deployment targets one or more <strong>IoT/OT gateways</strong>. Changes to gateway firewall rules
                      will affect all IoT devices protected by these gateways. Review the rules carefully before deploying —
                      incorrect rules may isolate OT/IoT devices from their controllers or monitoring systems.
                    </p>
                  </div>
                </div>
              );
            })()}

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
              <label style={{ display: 'block', marginBottom: 4, fontSize: '0.9em', fontWeight: 500 }}>
                Mode <span title={MODE_HELP_ALL} style={{ cursor: 'help', color: '#8b6914', borderBottom: '1px dotted #8b6914' }}>what is this?</span>
              </label>
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
              <label style={{ display: 'block', marginBottom: 4, fontSize: '0.9em', fontWeight: 500 }}>Created by</label>
              <select
                value={filterCreator}
                onChange={(e) => { setFilterCreator(e.target.value); setCurrentPage(1); }}
                style={{ width: '100%', padding: '6px 8px', border: '1px solid #ddd', borderRadius: 4 }}
              >
                <option value="">Anyone</option>
                {creators.map((c) => (
                  <option key={c.username} value={c.username}>{c.display_name && c.display_name !== c.username ? `${c.display_name} (${c.username})` : c.username} ({c.deployments})</option>
                ))}
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
                <option value="SCHEDULED">Scheduled</option>
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
          {(searchQuery || filterMode || filterStatus || filterCreator || filterTag || filterVlan || filterFromDate || filterToDate) && (
            <button
              onClick={() => {
                setSearchQuery('');
                setFilterMode('');
                setFilterStatus('');
                setFilterCreator('');
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
              <th>Created By</th>
              <th>Created</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {deployments.map((d) => (
              <tr key={d.id}>
                <td><code style={{ fontSize: '0.85em' }}>{d.id.slice(0, 8)}...</code></td>
                <td><code style={{ fontSize: '0.85em' }}>{d.policy_version_id.slice(0, 8)}...</code></td>
                <td><span title={MODE_HELP[d.mode] ?? d.mode} style={{ cursor: 'help', borderBottom: '1px dotted #97846c' }}>{d.mode}</span></td>
                <td>{d.target_count} host(s)</td>
                <td>
                  {getStatusBadge(d.status)}
                  {d.requires_approval && !d.approved_by && (
                    <span style={{ marginLeft: 6, padding: '1px 6px', borderRadius: 4, background: '#fdf6ec', border: '1px solid #e8d5a8', color: '#8b6914', fontSize: '11px', fontWeight: 600 }}>
                      Needs approval
                    </span>
                  )}
                  {d.status === 'SCHEDULED' && d.scheduled_at && (
                    <div style={{ fontSize: '11px', color: '#666' }}>{new Date(d.scheduled_at).toLocaleString()}</div>
                  )}
                </td>
                <td style={{ fontSize: '12.5px' }}>{d.created_by_username || '-'}</td>
                <td>{new Date(d.created_at).toLocaleString()}</td>
                <td>
                  <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                    {canApprove && d.requires_approval && !d.approved_by && ['QUEUED', 'SCHEDULED'].includes(d.status) && (
                      <button onClick={() => approveDeployment(d.id)} className="btn-small" style={{ background: '#8b6914', color: 'white' }}>Approve</button>
                    )}
                    {canOperate && d.status === 'QUEUED' && (
                      <button
                        onClick={() => startDeployment(d.id)}
                        className="btn-small btn-primary"
                        disabled={d.requires_approval && !d.approved_by}
                        title={d.requires_approval && !d.approved_by ? 'Awaiting approval' : undefined}
                      >
                        Start
                      </button>
                    )}
                    {canOperate && (d.status === 'QUEUED' || d.status === 'SCHEDULED') && (
                      <button onClick={() => cancelDeployment(d.id)} className="btn-small" style={{ background: '#999', color: 'white' }}>Cancel</button>
                    )}
                    {canOperate && d.status === 'RUNNING' && (
                      <>
                        <button onClick={() => pauseDeployment(d.id)} className="btn-small" style={{ background: '#FF9800', color: 'white' }}>Pause</button>
                        <button onClick={() => stopDeployment(d.id)} className="btn-small" style={{ background: '#F44336', color: 'white' }}>Stop</button>
                      </>
                    )}
                    {canOperate && d.status === 'PAUSED' && (
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
                <td colSpan={8} className="empty-state" style={{ textAlign: 'center', padding: '24px' }}>
                  {searchQuery || filterMode || filterStatus || filterCreator || filterTag || filterVlan || filterFromDate || filterToDate
                    ? 'No deployments match your filters. Try adjusting your search criteria.'
                    : canOperate ? 'No deployments yet. Click "Create Deployment" to create one.' : 'No deployments yet.'}
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
