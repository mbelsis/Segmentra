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

  // Form state
  const [formPolicyVersionId, setFormPolicyVersionId] = useState('');
  const [formMode, setFormMode] = useState<'CANARY' | 'PROGRESSIVE' | 'FULL'>('CANARY');
  const [formTargetType, setFormTargetType] = useState<'TAG' | 'VLAN' | 'HOST'>('TAG');
  const [formTagIds, setFormTagIds] = useState<string[]>([]);
  const [formVlanIds, setFormVlanIds] = useState<string[]>([]);
  const [formHostIds, setFormHostIds] = useState<string[]>([]);
  const [formCanarySize, setFormCanarySize] = useState(1);
  const [formBatchSize, setFormBatchSize] = useState(5);

  useEffect(() => {
    loadData();
  }, []);

  async function loadData() {
    try {
      const [dRes, tagsRes, vlansRes, hostsRes] = await Promise.all([
        api.deployments(),
        api.tags(),
        api.vlans(),
        api.hosts()
      ]);
      setDeployments(dRes.deployments);
      setTags(tagsRes.tags);
      setVlans(vlansRes.vlans);
      setHosts(hostsRes.hosts);

      // Load policy versions (simplified - would need to fetch from policy sets)
      // For now, we'll let user paste version ID
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

      await api.createDeployment(payload);
      resetForm();
      loadData();
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
      loadData();
    } catch (e: any) {
      setError(String(e.message || e));
    }
  }

  function getStatusBadge(status: string) {
    const colors: Record<string, string> = {
      QUEUED: '#888',
      RUNNING: '#2196F3',
      SUCCEEDED: '#4CAF50',
      FAILED: '#F44336',
      PARTIAL: '#FF9800',
      CANCELLED: '#999'
    };
    return <span style={{ color: colors[status] || '#000', fontWeight: 'bold' }}>{status}</span>;
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
            <div className="form-group">
              <label>Deployment Mode *</label>
              <select value={formMode} onChange={(e) => setFormMode(e.target.value as any)}>
                <option value="CANARY">Canary (small subset first)</option>
                <option value="PROGRESSIVE">Progressive (batches)</option>
                <option value="FULL">Full (all targets)</option>
              </select>
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

          <div className="form-actions">
            <button onClick={createDeployment} className="btn-primary">Create Deployment</button>
            <button onClick={resetForm} className="btn-secondary">Cancel</button>
          </div>
        </div>
      )}

      <div className="card">
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
                  {d.status === 'QUEUED' && (
                    <button onClick={() => startDeployment(d.id)} className="btn-small btn-primary">Start</button>
                  )}
                  <button onClick={() => navigate(`/deployment/${d.id}`)} className="btn-small">View</button>
                </td>
              </tr>
            ))}
            {deployments.length === 0 && (
              <tr>
                <td colSpan={7} className="empty-state">
                  No deployments yet. Click "Create Deployment" to create one.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
