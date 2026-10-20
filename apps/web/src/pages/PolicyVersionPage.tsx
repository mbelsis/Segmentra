import { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';

import { api, errorMessage } from '../lib/api';
import { useAuth, hasRole } from '../lib/auth-context';
import { servicesForRule, type CatalogProtocol } from '../lib/iot-services';

export function PolicyVersionPage() {
  const { versionId } = useParams();
  const navigate = useNavigate();
  const { roles, loading: authLoading } = useAuth();
  const isAdmin = hasRole(roles, 'admin');
  const canEditRules = hasRole(roles, 'operator', 'admin');
  const [version, setVersion] = useState<any>(null);
  const [rules, setRules] = useState<any[]>([]);
  const [hosts, setHosts] = useState<any[]>([]);
  const [tags, setTags] = useState<any[]>([]);
  const [vlans, setVlans] = useState<any[]>([]);
  const [iotAssets, setIotAssets] = useState<any[]>([]);
  const [pendingDelete, setPendingDelete] = useState<string | null>(null);
  const [managementVlan, setManagementVlan] = useState<any>(null);
  // undefined = not loaded / not visible to this user (setting is admin-only)
  const [managementVlanLoaded, setManagementVlanLoaded] = useState(false);
  const [catalog, setCatalog] = useState<CatalogProtocol[]>([]);
  const [showAddRule, setShowAddRule] = useState(false);
  const [editingRule, setEditingRule] = useState<string | null>(null);
  const [error, setError] = useState<string>('');

  // Form state
  const [formOrderIndex, setFormOrderIndex] = useState(0);
  const [formDirection, setFormDirection] = useState<'IN' | 'OUT' | 'BOTH' | 'FORWARD'>('IN');
  const [formAction, setFormAction] = useState<'ALLOW' | 'DENY'>('ALLOW');
  const [formProtocol, setFormProtocol] = useState<'tcp' | 'udp' | 'icmp' | 'any'>('tcp');
  const [formPorts, setFormPorts] = useState('');
  const [formSourceType, setFormSourceType] = useState<'CIDR' | 'TAG' | 'VLAN' | 'HOST'>('CIDR');
  const [formSourceValue, setFormSourceValue] = useState('');
  const [formDestinationType, setFormDestinationType] = useState<'CIDR' | 'TAG' | 'VLAN' | 'HOST' | 'IOT_ASSET'>('IOT_ASSET');
  const [formDestinationValue, setFormDestinationValue] = useState('');
  const [formLogMode, setFormLogMode] = useState<'NONE' | 'LOG' | 'LOG_RATE_LIMITED'>('NONE');
  const [formComment, setFormComment] = useState('');
  const [formUsePolicyInterfaceScope, setFormUsePolicyInterfaceScope] = useState(true);
  const [formInterfaceScopeType, setFormInterfaceScopeType] = useState<'ALL_INTERFACES' | 'INTERFACE_ROLE' | 'INTERFACE_NAME'>('ALL_INTERFACES');
  const [formInterfaceScopeRoles, setFormInterfaceScopeRoles] = useState<string[]>([]);
  const [formInterfaceScopeNames, setFormInterfaceScopeNames] = useState<string[]>([]);

  // Interface scope for policy version
  const [policyInterfaceScopeType, setPolicyInterfaceScopeType] = useState<'ALL_INTERFACES' | 'INTERFACE_ROLE' | 'INTERFACE_NAME'>('ALL_INTERFACES');
  const [policyInterfaceScopeRoles, setPolicyInterfaceScopeRoles] = useState<string[]>([]);
  const [policyInterfaceScopeNames, setPolicyInterfaceScopeNames] = useState<string[]>([]);

  useEffect(() => {
    // Catalog of common OT/IoT services (labels in the rule table, picker in the rule form); optional, so failures are ignored
    api.iot.protocols().then((r) => setCatalog(r.protocols as CatalogProtocol[])).catch(() => {});
  }, []);

  useEffect(() => {
    if (!versionId) return;
    loadData();
    api.allHosts().then((r) => setHosts(r.hosts)).catch(() => undefined);
    api.tags().then((r) => setTags(r.tags)).catch(() => undefined);
    api.vlans().then((r) => setVlans(r.vlans)).catch(() => undefined);
    api.iot.assets().then((r) => setIotAssets(r.assets)).catch(() => undefined);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [versionId]);

  // Management VLAN setting is admin-only; only fetch it (and warn about it) for admins.
  useEffect(() => {
    if (authLoading || !isAdmin) return;
    let cancelled = false;
    api.managementVlanSetting()
      .then((r) => { if (!cancelled) { setManagementVlan(r.managementVlan); setManagementVlanLoaded(true); } })
      .catch(() => undefined);
    return () => { cancelled = true; };
  }, [authLoading, isAdmin]);

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
      setError(errorMessage(e));
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
    setFormDestinationType('IOT_ASSET');
    setFormDestinationValue('');
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
    if (formDirection === 'FORWARD' && !formDestinationValue.trim()) {
      setError('FORWARD rules need a destination');
      return;
    }

    try {
      const payload: any = {
        orderIndex: formOrderIndex,
        direction: formDirection,
        action: formAction,
        protocol: formProtocol,
        // Explicit null clears the field on update (omitted = keep)
        ports: formPorts.trim() || null,
        sourceType: formSourceType,
        sourceValue: formSourceValue.trim(),
        // Only FORWARD rules carry a destination; explicit null clears it on update
        destinationType: formDirection === 'FORWARD' ? formDestinationType : null,
        destinationValue: formDirection === 'FORWARD' ? formDestinationValue.trim() : null,
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
      setError(errorMessage(e));
    }
  }

  async function deleteRule(ruleId: string) {
    if (version?.status !== 'DRAFT' && version?.status !== 'REJECTED') {
      setError('Only DRAFT or REJECTED versions can be edited');
      return;
    }
    setPendingDelete(null);
    try {
      await api.deleteRule(ruleId);
      loadData();
    } catch (e: any) {
      setError(errorMessage(e));
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
    setFormDestinationType(rule.destination_type || 'IOT_ASSET');
    setFormDestinationValue(rule.destination_value || '');
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
      setError(errorMessage(e));
    }
  }

  if (!versionId) return <div className="error">Missing version ID</div>;
  if (!version) {
    if (error) {
      return (
        <div className="page">
          <button onClick={() => navigate('/policies')} className="btn-secondary" style={{ marginBottom: 8 }}>← Back to Policy Sets</button>
          <div className="error-banner">Failed to load policy version: {error}</div>
          <button onClick={() => { setError(''); loadData(); }} className="btn-secondary">Retry</button>
        </div>
      );
    }
    return <div>Loading...</div>;
  }

  const isEditableStatus = version.status === 'DRAFT' || version.status === 'REJECTED';
  const canEdit = isEditableStatus && canEditRules;
  const colCount = canEdit ? 10 : 9;
  const describeEndpoint = (type: string | null | undefined, value: string | null | undefined) => {
    if (!type) return '-';
    if (type === 'CIDR') return value;
    if (type === 'TAG') return tags.find((t) => t.id === value)?.name || value;
    if (type === 'VLAN') return vlans.find((v) => v.id === value)?.name || value;
    if (type === 'IOT_ASSET') {
      const a = iotAssets.find((x) => x.id === value);
      return a ? `${a.name}${a.ip_address ? ` (${a.ip_address})` : ''}` : value;
    }
    return hosts.find((h) => h.id === value)?.hostname || value;
  };

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

      {version.status === 'REJECTED' && (
        <div style={{ padding: 12, marginBottom: 16, background: '#faf0ee', border: '1px solid #e8c4bf', borderRadius: 8, color: '#a63d2f' }}>
          <strong>Rejected{version.rejected_at ? ` on ${new Date(version.rejected_at).toLocaleString()}` : ''}.</strong>{' '}
          {version.rejection_reason ? <>Reason: {version.rejection_reason}</> : null}
          <div style={{ color: '#5c4633', fontSize: 13, marginTop: 4 }}>
            Change the rules below, then go back to the policy set and use "Resubmit for Approval".
          </div>
        </div>
      )}
      {version.status === 'PENDING_APPROVAL' && (
        <div style={{ padding: 12, marginBottom: 16, background: '#f7f4ef', border: '1px solid #e6dfd2', borderRadius: 8, color: '#5c4633' }}>
          <strong>Waiting for approval</strong>{version.submitted_at ? ` since ${new Date(version.submitted_at).toLocaleString()}` : ''}.
          {version.submission_note ? <> Reason given: {version.submission_note}</> : null}
        </div>
      )}
      {(version.status === 'APPROVED' || version.status === 'DEPLOYED') && (
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
            <strong>This policy version is {version.status === 'DEPLOYED' ? 'deployed' : 'approved'} and cannot be edited.</strong> To make changes, clone this version from the Policy Set page.
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
              disabled={!canEdit}
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
              disabled={!canEdit}
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
              disabled={!canEdit}
            />
          </div>
        )}
        {canEdit && (
          <button onClick={updatePolicyInterfaceScope} className="btn-secondary">Update Interface Scope</button>
        )}
      </div>

      {/* Rules list */}
      <div className="card">
        <div className="card-header">
          <h3>Firewall Rules</h3>
          {canEdit && (
            <button onClick={() => { resetForm(); setShowAddRule(true); }} className="btn-primary">+ Add Rule</button>
          )}
          {!isEditableStatus && (
            <span style={{ color: '#666', fontStyle: 'italic' }}>Rules cannot be edited for {version.status} versions</span>
          )}
          {isEditableStatus && !canEditRules && (
            <span style={{ color: '#666', fontStyle: 'italic' }}>Read-only: editing rules requires the operator or admin role</span>
          )}
        </div>
        <div style={{ padding: '8px 12px', background: '#f7f4ef', borderRadius: 6, marginBottom: 12, fontSize: '12.5px', color: '#78644e', borderLeft: '3px solid #d4c9b8' }}>
          <strong>Baseline rules applied automatically:</strong> Loopback allow, established/related connections, and management SSH access on each host's SSH port (from the configured management VLAN, or from any source if none is configured) are added by the compiler at deploy time. Define only your application-specific rules here.
        </div>

        {showAddRule && canEdit && (
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
                  <option value="FORWARD">FORWARD (through gateway)</option>
                </select>
              </div>
              <div className="form-group">
                <label>Action</label>
                <select value={formAction} onChange={(e) => setFormAction(e.target.value as any)}>
                  <option value="ALLOW">ALLOW</option>
                  <option value="DENY">DENY</option>
                </select>
              </div>
              {catalog.length > 0 && (
                <div className="form-group">
                  <label>Common service (optional)</label>
                  <select
                    value=""
                    onChange={(e) => {
                      const [proto, ports] = e.target.value.split('|');
                      if (!proto) return;
                      setFormProtocol(proto as 'tcp' | 'udp');
                      setFormPorts(ports);
                    }}
                  >
                    <option value="">Fill protocol and ports from a service...</option>
                    {Array.from(new Set(catalog.map((c) => c.category))).map((cat) => (
                      <optgroup key={cat} label={cat[0].toUpperCase() + cat.slice(1)}>
                        {catalog.filter((c) => c.category === cat).flatMap((c) =>
                          c.transports.map((t) => (
                            <option key={`${c.id}-${t.protocol}-${t.ports}`} value={`${t.protocol}|${t.ports}`}>
                              {c.name} ({t.protocol} {t.ports}){c.security === 'cleartext' ? ' - cleartext' : ''}
                            </option>
                          ))
                        )}
                      </optgroup>
                    ))}
                  </select>
                  <small>Default ports; a service that uses both tcp and udp needs one rule each.</small>
                </div>
              )}
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
              {formDirection === 'FORWARD' && (
                <>
                  <div className="form-group">
                    <label>Destination Type</label>
                    <select
                      value={formDestinationType}
                      onChange={(e) => { setFormDestinationType(e.target.value as any); setFormDestinationValue(''); }}
                    >
                      <option value="IOT_ASSET">IoT device</option>
                      <option value="CIDR">CIDR</option>
                      <option value="VLAN">VLAN</option>
                      <option value="TAG">TAG</option>
                      <option value="HOST">HOST</option>
                    </select>
                  </div>
                  <div className="form-group">
                    <label>Destination Value</label>
                    {formDestinationType === 'CIDR' && (
                      <input
                        type="text"
                        value={formDestinationValue}
                        onChange={(e) => setFormDestinationValue(e.target.value)}
                        placeholder="172.31.0.0/24"
                      />
                    )}
                    {formDestinationType === 'IOT_ASSET' && (
                      <select value={formDestinationValue} onChange={(e) => setFormDestinationValue(e.target.value)}>
                        <option value="">Select IoT device</option>
                        {iotAssets.map((a) => (
                          <option key={a.id} value={a.id}>{a.name}{a.ip_address ? ` (${a.ip_address})` : ' (no IP)'}</option>
                        ))}
                      </select>
                    )}
                    {formDestinationType === 'TAG' && (
                      <select value={formDestinationValue} onChange={(e) => setFormDestinationValue(e.target.value)}>
                        <option value="">Select tag</option>
                        {tags.map((t) => (
                          <option key={t.id} value={t.id}>{t.name}</option>
                        ))}
                      </select>
                    )}
                    {formDestinationType === 'VLAN' && (
                      <select value={formDestinationValue} onChange={(e) => setFormDestinationValue(e.target.value)}>
                        <option value="">Select VLAN</option>
                        {vlans.map((v) => (
                          <option key={v.id} value={v.id}>{v.name} (VLAN {v.vlan_tag})</option>
                        ))}
                      </select>
                    )}
                    {formDestinationType === 'HOST' && (
                      <select value={formDestinationValue} onChange={(e) => setFormDestinationValue(e.target.value)}>
                        <option value="">Select host</option>
                        {hosts.map((h) => (
                          <option key={h.id} value={h.id}>{h.hostname} ({h.mgmt_ip})</option>
                        ))}
                      </select>
                    )}
                  </div>
                </>
              )}
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

            {formDirection === 'FORWARD' && (
              <div style={{ padding: '8px 12px', background: '#f7f4ef', borderRadius: 6, marginBottom: 12, fontSize: '12.5px', color: '#78644e', borderLeft: '3px solid #d4c9b8' }}>
                FORWARD rules filter traffic routed <em>through</em> the host (e.g. an IoT/OT gateway), matched on source and destination.
                On a gateway, traffic to its protected devices (IoT assets assigned on the OT/IoT page) is denied unless a FORWARD rule allows it;
                other forwarded traffic is not affected. Interface scopes do not apply to FORWARD rules.
              </div>
            )}
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
              <th>Destination</th>
              <th>Log</th>
              <th>Comment</th>
              {canEdit && <th>Actions</th>}
            </tr>
          </thead>
          <tbody>
            {/* Baseline Rules - Always shown first */}
            <tr style={{ background: '#f5f5f5', fontWeight: 'bold' }}>
              <td colSpan={colCount} style={{ padding: 12, borderBottom: '2px solid #ddd' }}>
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
              <td>-</td>
              <td>NONE</td>
              <td>Loopback interface</td>
              {canEdit && <td></td>}
            </tr>
            <tr style={{ background: '#fafafa' }}>
              <td>1</td>
              <td><code>IN</code></td>
              <td><strong className="allow">ALLOW</strong></td>
              <td><code>any</code></td>
              <td>-</td>
              <td><code>CIDR</code>: Established/Related connections</td>
              <td>-</td>
              <td>NONE</td>
              <td>Connection tracking</td>
              {canEdit && <td></td>}
            </tr>
            {managementVlan?.subnet && (
              <tr style={{ background: '#fafafa' }}>
                <td>2</td>
                <td><code>IN</code></td>
                <td><strong className="allow">ALLOW</strong></td>
                <td><code>tcp</code></td>
                <td>22</td>
                <td><code>CIDR</code>: {managementVlan.subnet} (Management VLAN: {managementVlan.name})</td>
                <td>-</td>
                <td>NONE</td>
                <td>Baseline SSH access from management network</td>
                {canEdit && <td></td>}
              </tr>
            )}
            {isAdmin && managementVlanLoaded && !managementVlan && (
              <tr style={{ background: '#fff3cd' }}>
                <td colSpan={colCount} style={{ padding: 8, fontSize: '0.9em', color: '#856404' }}>
                  ⚠️ No management VLAN configured: SSH is allowed from any source so hosts can't be locked out. Configure Admin → Management VLAN to restrict SSH to that subnet.
                </td>
              </tr>
            )}
            {/* Policy Rules */}
            {rules.length > 0 && (
              <tr style={{ background: '#f5f5f5', fontWeight: 'bold' }}>
                <td colSpan={colCount} style={{ padding: 12, borderTop: '2px solid #ddd', borderBottom: '2px solid #ddd' }}>
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
                <td>
                  {r.ports || '-'}
                  {servicesForRule(catalog, r.protocol, r.ports).map((s) => (
                    <span key={s.id} title={s.note} style={{ display: 'inline-block', marginLeft: 4, padding: '0 6px', borderRadius: 4, fontSize: '11px', background: s.security === 'cleartext' ? '#fdf6ec' : '#eef4e8', color: s.security === 'cleartext' ? '#8b5a14' : '#3f5a26', border: '1px solid #e0d6c6' }}>{s.name}</span>
                  ))}
                </td>
                <td>
                  <code>{r.source_type}</code>: {describeEndpoint(r.source_type, r.source_value)}
                </td>
                <td>
                  {r.direction === 'FORWARD' && r.destination_type
                    ? <><code>{r.destination_type === 'IOT_ASSET' ? 'IoT device' : r.destination_type}</code>: {describeEndpoint(r.destination_type, r.destination_value)}</>
                    : '-'}
                </td>
                <td>{r.log_mode}</td>
                <td>{r.comment || '-'}</td>
                {canEdit && (
                  <td>
                    <button onClick={() => editRule(r)} className="btn-small">Edit</button>
                    {pendingDelete === r.id ? (
                      <>
                        <button onClick={() => deleteRule(r.id)} className="btn-small btn-danger">Confirm delete</button>
                        <button onClick={() => setPendingDelete(null)} className="btn-small">Cancel</button>
                      </>
                    ) : (
                      <button onClick={() => setPendingDelete(r.id)} className="btn-small btn-danger">Delete</button>
                    )}
                  </td>
                )}
              </tr>
            ))}
            {rules.length === 0 && (
              <tr>
                <td colSpan={colCount} className="empty-state">
                  No rules yet. {canEdit && 'Click "Add Rule" to create one.'}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
