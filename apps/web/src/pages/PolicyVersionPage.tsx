import { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';

import { api } from '../lib/api';

export function PolicyVersionPage() {
  const { versionId } = useParams();
  const navigate = useNavigate();
  const [version, setVersion] = useState<any>(null);
  const [rules, setRules] = useState<any[]>([]);
  const [hosts, setHosts] = useState<any[]>([]);
  const [tags, setTags] = useState<any[]>([]);
  const [vlans, setVlans] = useState<any[]>([]);
  const [managementVlan, setManagementVlan] = useState<any>(null);
  const [showAddRule, setShowAddRule] = useState(false);
  const [editingRule, setEditingRule] = useState<string | null>(null);
  const [error, setError] = useState<string>('');

  // Form state
  const [formOrderIndex, setFormOrderIndex] = useState(0);
  const [formDirection, setFormDirection] = useState<'IN' | 'OUT' | 'BOTH'>('IN');
  const [formAction, setFormAction] = useState<'ALLOW' | 'DENY'>('ALLOW');
  const [formProtocol, setFormProtocol] = useState<'tcp' | 'udp' | 'icmp' | 'any'>('tcp');
  const [formPorts, setFormPorts] = useState('');
  const [formSourceType, setFormSourceType] = useState<'CIDR' | 'TAG' | 'VLAN' | 'HOST'>('CIDR');
  const [formSourceValue, setFormSourceValue] = useState('');
  const [formLogMode, setFormLogMode] = useState<'NONE' | 'LOG' | 'LOG_RATE_LIMITED'>('NONE');
  const [formComment, setFormComment] = useState('');
  const [formUsePolicyInterfaceScope, setFormUsePolicyInterfaceScope] = useState(true);
  const [formInterfaceScopeType, setFormInterfaceScopeType] = useState<'ALL_INTERFACES' | 'INTERFACE_ROLE' | 'INTERFACE_NAME'>('ALL_INTERFACES');
  const [formInterfaceScopeRoles, setFormInterfaceScopeRoles] = useState<string[]>([]);
  const [formInterfaceScopeNames, setFormInterfaceScopeNames] = useState<string[]>([]);

  // Interface scope for policy version
  const [policyInterfaceScopeType, setPolicyInterfaceScopeType] = useState<'ALL_INTERFACES' | 'INTERFACE_ROLE' | 'INTERFACE_NAME'>('INTERFACE_ROLE');
  const [policyInterfaceScopeRoles, setPolicyInterfaceScopeRoles] = useState<string[]>([]);
  const [policyInterfaceScopeNames, setPolicyInterfaceScopeNames] = useState<string[]>([]);

  useEffect(() => {
    if (!versionId) return;
    loadData();
    api.hosts().then((r) => setHosts(r.hosts)).catch(() => undefined);
    api.tags().then((r) => setTags(r.tags)).catch(() => undefined);
    api.vlans().then((r) => setVlans(r.vlans)).catch(() => undefined);
    api.managementVlanSetting().then((r) => setManagementVlan(r.managementVlan)).catch(() => undefined);
  }, [versionId]);

  async function loadData() {
    if (!versionId) return;
    try {
      const [vRes, rRes] = await Promise.all([
        api.version(versionId),
        api.rules(versionId)
      ]);
      const v = vRes.version;
      setVersion(v);
      setRules(rRes.rules.sort((a: any, b: any) => a.order_index - b.order_index));
      setPolicyInterfaceScopeType(v.interface_scope_type);
      setPolicyInterfaceScopeRoles(v.interface_scope_roles || []);
      setPolicyInterfaceScopeNames(v.interface_scope_names || []);
    } catch (e: any) {
      setError(String(e.message || e));
    }
  }

  function resetForm() {
    setFormOrderIndex(rules.length);
    setFormDirection('IN');
    setFormAction('ALLOW');
    setFormProtocol('tcp');
    setFormPorts('');
    setFormSourceType('CIDR');
    setFormSourceValue('');
    setFormLogMode('NONE');
    setFormComment('');
    setFormUsePolicyInterfaceScope(true);
    setFormInterfaceScopeType('ALL_INTERFACES');
    setFormInterfaceScopeRoles([]);
    setFormInterfaceScopeNames([]);
    setShowAddRule(false);
    setEditingRule(null);
    setError('');
  }

  async function saveRule() {
    if (!versionId) return;
    if (version?.status !== 'DRAFT' && version?.status !== 'REJECTED') {
      setError('Only DRAFT or REJECTED versions can be edited');
      return;
    }
    if (!formSourceValue.trim()) {
      setError('Source value is required');
      return;
    }

    try {
      const payload: any = {
        orderIndex: formOrderIndex,
        direction: formDirection,
        action: formAction,
        protocol: formProtocol,
        ports: formPorts.trim() || null,
        sourceType: formSourceType,
        sourceValue: formSourceValue.trim(),
        logMode: formLogMode,
        comment: formComment.trim() || null,
        usePolicyInterfaceScope: formUsePolicyInterfaceScope
      };

      if (!formUsePolicyInterfaceScope) {
        payload.interfaceScopeType = formInterfaceScopeType;
        if (formInterfaceScopeType === 'INTERFACE_ROLE') {
          payload.interfaceScopeRoles = formInterfaceScopeRoles;
        } else if (formInterfaceScopeType === 'INTERFACE_NAME') {
          payload.interfaceScopeNames = formInterfaceScopeNames;
        }
      }

      if (editingRule) {
        await api.updateRule(editingRule, payload);
      } else {
        await api.addRule(versionId, payload);
      }
      resetForm();
      loadData();
    } catch (e: any) {
      setError(String(e.message || e));
    }
  }

  async function deleteRule(ruleId: string) {
    if (version?.status !== 'DRAFT' && version?.status !== 'REJECTED') {
      setError('Only DRAFT or REJECTED versions can be edited');
      return;
    }
    if (!confirm('Delete this rule?')) return;
    try {
      await api.deleteRule(ruleId);
      loadData();
    } catch (e: any) {
      setError(String(e.message || e));
    }
  }

  function editRule(rule: any) {
    setEditingRule(rule.id);
    setFormOrderIndex(rule.order_index);
    setFormDirection(rule.direction);
    setFormAction(rule.action);
    setFormProtocol(rule.protocol);
    setFormPorts(rule.ports || '');
    setFormSourceType(rule.source_type);
    setFormSourceValue(rule.source_value);
    setFormLogMode(rule.log_mode);
    setFormComment(rule.comment || '');
    setFormUsePolicyInterfaceScope(rule.use_policy_interface_scope);
    setFormInterfaceScopeType(rule.interface_scope_type || 'ALL_INTERFACES');
    setFormInterfaceScopeRoles(rule.interface_scope_roles || []);
    setFormInterfaceScopeNames(rule.interface_scope_names || []);
    setShowAddRule(true);
  }

  async function updatePolicyInterfaceScope() {
    if (!versionId) return;
    if (version?.status !== 'DRAFT' && version?.status !== 'REJECTED') {
      setError('Only DRAFT or REJECTED versions can be edited');
      return;
    }
    try {
      await api.updateVersion(versionId, {
        interfaceScopeType: policyInterfaceScopeType,
        interfaceScopeRoles: policyInterfaceScopeType === 'INTERFACE_ROLE' ? policyInterfaceScopeRoles : undefined,
        interfaceScopeNames: policyInterfaceScopeType === 'INTERFACE_NAME' ? policyInterfaceScopeNames : undefined
      });
      loadData();
    } catch (e: any) {
      setError(String(e.message || e));
    }
  }

  if (!versionId) return <div className="error">Missing version ID</div>;
  if (!version) return <div>Loading...</div>;

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <button 
            onClick={() => navigate(`/policy-set/${version.policy_set_id}`)} 
            className="btn-secondary" 
            style={{ marginBottom: 8 }}
          >
            ← Back to Policy Set
          </button>
          <h2>Policy Version {version.version_number} - {version.status}</h2>
        </div>
      </div>

      {version.status === 'APPROVED' && (
        <div style={{ 
          padding: 12, 
          marginBottom: 16, 
          background: '#fff3cd', 
          borderRadius: 4, 
          border: '1px solid #ffc107',
          display: 'flex',
          alignItems: 'center',
          gap: 8
        }}>
          <span style={{ fontSize: '1.2em' }}>🔒</span>
          <div>
            <strong>This policy version is approved and cannot be edited.</strong> To make changes, clone this version from the Policy Set page.
          </div>
        </div>
      )}

      {error && <div className="error-banner">{error}</div>}

      {/* Policy-level interface scope */}
      <div className="card">
        <h3>Interface Scope (Policy Level)</h3>
        <div className="form-group">
          <label>
            Scope Type
            <select
              value={policyInterfaceScopeType}
              onChange={(e) => setPolicyInterfaceScopeType(e.target.value as any)}
              disabled={version.status !== 'DRAFT' && version.status !== 'REJECTED'}
            >
              <option value="ALL_INTERFACES">All Interfaces</option>
              <option value="INTERFACE_ROLE">Interface Role</option>
              <option value="INTERFACE_NAME">Interface Name</option>
            </select>
          </label>
        </div>
        {policyInterfaceScopeType === 'INTERFACE_ROLE' && (
          <div className="form-group">
            <label>Roles (comma-separated)</label>
            <input
              type="text"
              value={policyInterfaceScopeRoles.join(', ')}
              onChange={(e) => setPolicyInterfaceScopeRoles(e.target.value.split(',').map(s => s.trim()).filter(Boolean))}
              placeholder="data, backup"
              disabled={version.status !== 'DRAFT' && version.status !== 'REJECTED'}
            />
          </div>
        )}
        {policyInterfaceScopeType === 'INTERFACE_NAME' && (
          <div className="form-group">
            <label>Interface Names (comma-separated)</label>
            <input
              type="text"
              value={policyInterfaceScopeNames.join(', ')}
              onChange={(e) => setPolicyInterfaceScopeNames(e.target.value.split(',').map(s => s.trim()).filter(Boolean))}
              placeholder="eth0, eth1"
              disabled={version.status !== 'DRAFT' && version.status !== 'REJECTED'}
            />
          </div>
        )}
        {(version.status === 'DRAFT' || version.status === 'REJECTED') && (
          <button onClick={updatePolicyInterfaceScope} className="btn-secondary">Update Interface Scope</button>
        )}
      </div>

      {/* Rules list */}
      <div className="card">
        <div className="card-header">
          <h3>Firewall Rules</h3>
          {(version.status === 'DRAFT' || version.status === 'REJECTED') && (
            <button onClick={() => { resetForm(); setShowAddRule(true); }} className="btn-primary">+ Add Rule</button>
          )}
          {version.status !== 'DRAFT' && version.status !== 'REJECTED' && (
            <span style={{ color: '#666', fontStyle: 'italic' }}>Rules cannot be edited for {version.status} versions</span>
          )}
        </div>

        {showAddRule && (version.status === 'DRAFT' || version.status === 'REJECTED') && (
          <div className="rule-form">
            <h4>{editingRule ? 'Edit Rule' : 'Add Rule'}</h4>
            <div className="form-grid">
              <div className="form-group">
                <label>Order Index</label>
                <input
                  type="number"
                  value={formOrderIndex}
                  onChange={(e) => setFormOrderIndex(Number(e.target.value))}
                  min="0"
                />
              </div>
              <div className="form-group">
                <label>Direction</label>
                <select value={formDirection} onChange={(e) => setFormDirection(e.target.value as any)}>
                  <option value="IN">IN</option>
                  <option value="OUT">OUT</option>
                  <option value="BOTH">BOTH</option>
                </select>
              </div>
              <div className="form-group">
                <label>Action</label>
                <select value={formAction} onChange={(e) => setFormAction(e.target.value as any)}>
                  <option value="ALLOW">ALLOW</option>
                  <option value="DENY">DENY</option>
                </select>
              </div>
              <div className="form-group">
                <label>Protocol</label>
                <select value={formProtocol} onChange={(e) => setFormProtocol(e.target.value as any)}>
                  <option value="tcp">TCP</option>
                  <option value="udp">UDP</option>
                  <option value="icmp">ICMP</option>
                  <option value="any">Any</option>
                </select>
              </div>
              <div className="form-group">
                <label>Ports (optional)</label>
                <input
                  type="text"
                  value={formPorts}
                  onChange={(e) => setFormPorts(e.target.value)}
                  placeholder="22, 80-90, 443"
                />
              </div>
              <div className="form-group">
                <label>Source Type</label>
                <select value={formSourceType} onChange={(e) => setFormSourceType(e.target.value as any)}>
                  <option value="CIDR">CIDR</option>
                  <option value="TAG">TAG</option>
                  <option value="VLAN">VLAN</option>
                  <option value="HOST">HOST</option>
                </select>
              </div>
              <div className="form-group">
                <label>Source Value</label>
                {formSourceType === 'CIDR' && (
                  <input
                    type="text"
                    value={formSourceValue}
                    onChange={(e) => setFormSourceValue(e.target.value)}
                    placeholder="10.0.0.0/24"
                  />
                )}
                {formSourceType === 'TAG' && (
                  <select value={formSourceValue} onChange={(e) => setFormSourceValue(e.target.value)}>
                    <option value="">Select tag</option>
                    {tags.map((t) => (
                      <option key={t.id} value={t.id}>{t.name}</option>
                    ))}
                  </select>
                )}
                {formSourceType === 'VLAN' && (
                  <select value={formSourceValue} onChange={(e) => setFormSourceValue(e.target.value)}>
                    <option value="">Select VLAN</option>
                    {vlans.map((v) => (
                      <option key={v.id} value={v.id}>{v.name} (VLAN {v.vlan_tag})</option>
                    ))}
                  </select>
                )}
                {formSourceType === 'HOST' && (
                  <select value={formSourceValue} onChange={(e) => setFormSourceValue(e.target.value)}>
                    <option value="">Select host</option>
                    {hosts.map((h) => (
                      <option key={h.id} value={h.id}>{h.hostname} ({h.mgmt_ip})</option>
                    ))}
                  </select>
                )}
              </div>
              <div className="form-group">
                <label>Log Mode</label>
                <select value={formLogMode} onChange={(e) => setFormLogMode(e.target.value as any)}>
                  <option value="NONE">None</option>
                  <option value="LOG">Log</option>
                  <option value="LOG_RATE_LIMITED">Log (Rate Limited)</option>
                </select>
              </div>
              <div className="form-group">
                <label>Comment</label>
                <input
                  type="text"
                  value={formComment}
                  onChange={(e) => setFormComment(e.target.value)}
                  placeholder="Optional description"
                />
              </div>
            </div>

            {/* Per-rule interface scope override */}
            <div className="form-group">
              <label>
                <input
                  type="checkbox"
                  checked={formUsePolicyInterfaceScope}
                  onChange={(e) => setFormUsePolicyInterfaceScope(e.target.checked)}
                />
                Use policy-level interface scope
              </label>
            </div>
            {!formUsePolicyInterfaceScope && (
              <div className="form-group">
                <label>Rule Interface Scope Type</label>
                <select value={formInterfaceScopeType} onChange={(e) => setFormInterfaceScopeType(e.target.value as any)}>
                  <option value="ALL_INTERFACES">All Interfaces</option>
                  <option value="INTERFACE_ROLE">Interface Role</option>
                  <option value="INTERFACE_NAME">Interface Name</option>
                </select>
                {formInterfaceScopeType === 'INTERFACE_ROLE' && (
                  <div className="form-group">
                    <label>Roles (comma-separated)</label>
                    <input
                      type="text"
                      value={formInterfaceScopeRoles.join(', ')}
                      onChange={(e) => setFormInterfaceScopeRoles(e.target.value.split(',').map(s => s.trim()).filter(Boolean))}
                      placeholder="data, backup"
                    />
                  </div>
                )}
                {formInterfaceScopeType === 'INTERFACE_NAME' && (
                  <div className="form-group">
                    <label>Interface Names (comma-separated)</label>
                    <input
                      type="text"
                      value={formInterfaceScopeNames.join(', ')}
                      onChange={(e) => setFormInterfaceScopeNames(e.target.value.split(',').map(s => s.trim()).filter(Boolean))}
                      placeholder="eth0, eth1"
                    />
                  </div>
                )}
              </div>
            )}

            <div className="form-actions">
              <button onClick={saveRule} className="btn-primary">Save Rule</button>
              <button onClick={resetForm} className="btn-secondary">Cancel</button>
            </div>
          </div>
        )}

        <table className="data-table">
          <thead>
            <tr>
              <th>#</th>
              <th>Direction</th>
              <th>Action</th>
              <th>Protocol</th>
              <th>Ports</th>
              <th>Source</th>
              <th>Log</th>
              <th>Comment</th>
              {version.status === 'DRAFT' && <th>Actions</th>}
            </tr>
          </thead>
          <tbody>
            {/* Baseline Rules - Always shown first */}
            <tr style={{ background: '#f5f5f5', fontWeight: 'bold' }}>
              <td colSpan={(version.status === 'DRAFT' || version.status === 'REJECTED') ? 9 : 8} style={{ padding: 12, borderBottom: '2px solid #ddd' }}>
                Baseline Rules (System-Generated)
              </td>
            </tr>
            <tr style={{ background: '#fafafa' }}>
              <td>0</td>
              <td><code>IN</code></td>
              <td><strong className="allow">ALLOW</strong></td>
              <td><code>any</code></td>
              <td>-</td>
              <td><code>CIDR</code>: <code>lo</code> (loopback)</td>
              <td>NONE</td>
              <td>Loopback interface</td>
              {(version.status === 'DRAFT' || version.status === 'REJECTED') && <td></td>}
            </tr>
            <tr style={{ background: '#fafafa' }}>
              <td>1</td>
              <td><code>IN</code></td>
              <td><strong className="allow">ALLOW</strong></td>
              <td><code>any</code></td>
              <td>-</td>
              <td><code>CIDR</code>: Established/Related connections</td>
              <td>NONE</td>
              <td>Connection tracking</td>
              {(version.status === 'DRAFT' || version.status === 'REJECTED') && <td></td>}
            </tr>
            {managementVlan?.subnet && (
              <tr style={{ background: '#fafafa' }}>
                <td>2</td>
                <td><code>IN</code></td>
                <td><strong className="allow">ALLOW</strong></td>
                <td><code>tcp</code></td>
                <td>22</td>
                <td><code>CIDR</code>: {managementVlan.subnet} (Management VLAN: {managementVlan.name})</td>
                <td>NONE</td>
                <td>Baseline SSH access from management network</td>
                {(version.status === 'DRAFT' || version.status === 'REJECTED') && <td></td>}
              </tr>
            )}
            {!managementVlan && (
              <tr style={{ background: '#fff3cd' }}>
                <td colSpan={(version.status === 'DRAFT' || version.status === 'REJECTED') ? 9 : 8} style={{ padding: 8, fontSize: '0.9em', color: '#856404' }}>
                  ⚠️ No management VLAN configured. Configure it in Admin → Management VLAN to enable baseline SSH access.
                </td>
              </tr>
            )}
            {/* Policy Rules */}
            {rules.length > 0 && (
              <tr style={{ background: '#f5f5f5', fontWeight: 'bold' }}>
                <td colSpan={(version.status === 'DRAFT' || version.status === 'REJECTED') ? 9 : 8} style={{ padding: 12, borderTop: '2px solid #ddd', borderBottom: '2px solid #ddd' }}>
                  Policy Rules
                </td>
              </tr>
            )}
            {rules.map((r) => (
              <tr key={r.id}>
                <td>{r.order_index}</td>
                <td><code>{r.direction}</code></td>
                <td><strong className={r.action === 'ALLOW' ? 'allow' : 'deny'}>{r.action}</strong></td>
                <td><code>{r.protocol}</code></td>
                <td>{r.ports || '-'}</td>
                <td>
                  <code>{r.source_type}</code>: {r.source_type === 'CIDR' ? r.source_value : (
                    r.source_type === 'TAG' ? tags.find(t => t.id === r.source_value)?.name || r.source_value :
                    r.source_type === 'VLAN' ? vlans.find(v => v.id === r.source_value)?.name || r.source_value :
                    hosts.find(h => h.id === r.source_value)?.hostname || r.source_value
                  )}
                </td>
                <td>{r.log_mode}</td>
                <td>{r.comment || '-'}</td>
                {(version.status === 'DRAFT' || version.status === 'REJECTED') && (
                  <td>
                    <button onClick={() => editRule(r)} className="btn-small">Edit</button>
                    <button onClick={() => deleteRule(r.id)} className="btn-small btn-danger">Delete</button>
                  </td>
                )}
              </tr>
            ))}
            {rules.length === 0 && (
              <tr>
                <td colSpan={(version.status === 'DRAFT' || version.status === 'REJECTED') ? 9 : 8} className="empty-state">
                  No rules yet. {(version.status === 'DRAFT' || version.status === 'REJECTED') && 'Click "Add Rule" to create one.'}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
