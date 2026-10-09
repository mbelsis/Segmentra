import { useState, useEffect } from 'react';
import { api, errorMessage } from '../lib/api';
import { useAuth, hasRole } from '../lib/auth-context';

const EMPTY_RULE_FORM = { direction: 'IN', action: 'ALLOW', protocol: 'tcp', ports: '', sourceType: 'CIDR', sourceValue: '0.0.0.0/0', logMode: 'NONE', comment: '', destinationType: 'CIDR', destinationValue: '' };

export function PolicyTemplatesPage() {
  const { roles } = useAuth();
  const canManage = hasRole(roles, 'operator', 'admin');
  const [templates, setTemplates] = useState<any[]>([]);
  const [categories, setCategories] = useState<string[]>([]);
  const [selectedCategory, setSelectedCategory] = useState('');
  const [tags, setTags] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [showCreate, setShowCreate] = useState(false);
  const [selectedTemplate, setSelectedTemplate] = useState<any>(null);
  const [templateRules, setTemplateRules] = useState<any[]>([]);
  const [form, setForm] = useState({ name: '', description: '', category: '', targetTagId: '', autoApply: false, interfaceScopeType: 'ALL_INTERFACES' as string });
  const [ruleForm, setRuleForm] = useState(EMPTY_RULE_FORM);
  // Pickers for FORWARD rule destinations (loaded on first use)
  const [destOptions, setDestOptions] = useState<{ vlans: any[]; hosts: any[]; iotAssets: any[] } | null>(null);

  const load = async () => {
    setLoading(true);
    try {
      const [tRes, cRes, tagsRes] = await Promise.all([
        api.templates.list(selectedCategory || undefined),
        api.templates.categories(),
        api.tags(),
      ]);
      setTemplates(tRes.templates);
      setCategories(cRes.categories);
      setTags(tagsRes.tags);
    } catch (e: any) { setError(errorMessage(e)); }
    setLoading(false);
  };

  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => { load(); }, [selectedCategory]);

  const selectTemplate = async (t: any) => {
    setSelectedTemplate(t);
    try {
      const res = await api.templates.get(t.id);
      setTemplateRules(res.rules);
    } catch (e: any) { setError(errorMessage(e)); }
  };

  const createTemplate = async () => {
    try {
      await api.templates.create({
        name: form.name,
        description: form.description || undefined,
        category: form.category || undefined,
        targetTagId: form.targetTagId || undefined,
        autoApply: form.autoApply,
        interfaceScopeType: form.interfaceScopeType,
      });
      setShowCreate(false);
      setForm({ name: '', description: '', category: '', targetTagId: '', autoApply: false, interfaceScopeType: 'ALL_INTERFACES' });
      load();
    } catch (e: any) { setError(errorMessage(e)); }
  };

  useEffect(() => {
    const needed = ruleForm.direction === 'FORWARD' || templateRules.some((r) => r.direction === 'FORWARD');
    if (!needed || destOptions) return;
    Promise.all([
      api.vlans().then((r) => r.vlans).catch(() => []),
      api.allHosts().then((r) => r.hosts).catch(() => []),
      api.iot.assets().then((r) => r.assets).catch(() => []),
    ]).then(([vlans, hosts, iotAssets]) => setDestOptions({ vlans, hosts, iotAssets }));
  }, [ruleForm.direction, templateRules, destOptions]);

  const describeDestination = (type: string, value: string) => {
    if (type === 'TAG') return tags.find((t) => t.id === value)?.name ?? value;
    if (type === 'VLAN') { const v = destOptions?.vlans.find((x) => x.id === value); return v ? `${v.name} (${v.vlan_tag})` : value; }
    if (type === 'HOST') return destOptions?.hosts.find((x) => x.id === value)?.hostname ?? value;
    if (type === 'IOT_ASSET') return destOptions?.iotAssets.find((x) => x.id === value)?.name ?? value;
    return value;
  };

  const addRule = async () => {
    if (!selectedTemplate) return;
    const isForward = ruleForm.direction === 'FORWARD';
    if (isForward && !ruleForm.destinationValue.trim()) {
      setError('FORWARD rules need a destination');
      return;
    }
    try {
      await api.templates.addRule(selectedTemplate.id, {
        orderIndex: templateRules.length,
        direction: ruleForm.direction,
        action: ruleForm.action,
        protocol: ruleForm.protocol,
        ports: ruleForm.ports || undefined,
        sourceType: ruleForm.sourceType,
        sourceValue: ruleForm.sourceValue,
        logMode: ruleForm.logMode,
        comment: ruleForm.comment || undefined,
        ...(isForward ? { destinationType: ruleForm.destinationType, destinationValue: ruleForm.destinationValue.trim() } : {}),
      });
      const res = await api.templates.get(selectedTemplate.id);
      setTemplateRules(res.rules);
      setRuleForm(EMPTY_RULE_FORM);
    } catch (e: any) { setError(errorMessage(e)); }
  };

  const deleteRule = async (ruleId: string) => {
    try {
      await api.templates.deleteRule(ruleId);
      setTemplateRules(prev => prev.filter(r => r.id !== ruleId));
    } catch (e: any) { setError(errorMessage(e)); }
  };

  const instantiate = async (templateId: string) => {
    // Check if template has rules
    const template = templates.find(t => t.id === templateId);
    if (template && parseInt(template.rule_count) === 0) {
      if (!confirm('This template has 0 rules. The instantiated policy will have no firewall rules (only baseline rules will apply at deploy time). Continue anyway?')) return;
    }
    try {
      const result = await api.templates.instantiate(templateId);
      alert(`Created policy set "${result.policySet.name}" with ${result.rulesCreated} rules (DRAFT). Go to Policy Sets to review and add more rules.`);
      load();
    } catch (e: any) { setError(errorMessage(e)); }
  };

  const deleteTemplate = async (id: string) => {
    if (!confirm('Delete this template?')) return;
    try {
      await api.templates.delete(id);
      if (selectedTemplate?.id === id) { setSelectedTemplate(null); setTemplateRules([]); }
      load();
    } catch (e: any) { setError(errorMessage(e)); }
  };

  if (loading) return <div>Loading...</div>;

  return (
    <div>
      <h2>Policy Templates</h2>
      <p style={{ color: '#78644e', fontSize: '13.5px', marginTop: -4, marginBottom: 16, lineHeight: 1.6 }}>
        Templates are reusable firewall rule blueprints for common server roles (e.g., a "Web Server" template with allow 80/443 inbound and allow 53 outbound).
        Templates are <strong>not</strong> policies — they don't get deployed to hosts directly.
        Click <strong>Instantiate</strong> to create a real policy set from a template. The generated policy starts in DRAFT status and must go through the normal approval workflow before it can be deployed.
        <br /><br />
        <strong>Auto-apply:</strong> When enabled on a template with a target tag, Segmentra will automatically create a DRAFT policy set from this template
        whenever a host is assigned that tag (manually or via auto-tagging rules). For example, if a template targets the tag "web-server" with auto-apply enabled,
        any host that gains the "web-server" tag will automatically get a DRAFT policy created from this template — still requiring approval before deployment.
      </p>
      {error && <div style={{ color: 'red', marginBottom: 8 }}>{error} <button onClick={() => setError('')}>dismiss</button></div>}

      <div style={{ display: 'flex', gap: 16, marginBottom: 16 }}>
        <select value={selectedCategory} onChange={e => setSelectedCategory(e.target.value)}>
          <option value="">All Categories</option>
          {categories.map(c => <option key={c} value={c}>{c}</option>)}
        </select>
        {canManage && <button onClick={() => setShowCreate(true)} className="btn-primary">+ New Template</button>}
      </div>

      {showCreate && canManage && (
        <div style={{ border: '1px solid #d4c9b8', padding: 20, marginBottom: 16, borderRadius: 8, background: '#fdfcf9' }}>
          <h3 style={{ marginTop: 0, marginBottom: 12, color: '#292018' }}>Create Template</h3>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
            <input placeholder="Name" value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} />
            <input placeholder="Category" value={form.category} onChange={e => setForm(f => ({ ...f, category: e.target.value }))} />
            <input placeholder="Description" value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))} />
            <select value={form.targetTagId} onChange={e => setForm(f => ({ ...f, targetTagId: e.target.value }))}>
              <option value="">No target tag</option>
              {tags.map(t => <option key={t.id} value={t.id}>{t.name}</option>)}
            </select>
            <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: '13px', color: '#5c4633' }}>
              <input type="checkbox" checked={form.autoApply} onChange={e => setForm(f => ({ ...f, autoApply: e.target.checked }))} /> Auto-apply when tag assigned
            </label>
          </div>
          <div style={{ marginTop: 16, display: 'flex', gap: 8 }}>
            <button
              onClick={createTemplate}
              disabled={!form.name.trim()}
              style={{
                padding: '9px 20px',
                background: !form.name.trim() ? '#b8a890' : '#5a7a3a',
                color: '#fdfcf9',
                border: 'none',
                borderRadius: 6,
                fontWeight: 600,
                fontSize: '14px',
                cursor: !form.name.trim() ? 'not-allowed' : 'pointer',
                opacity: !form.name.trim() ? 0.6 : 1,
              }}
            >
              Create Template
            </button>
            <button
              onClick={() => setShowCreate(false)}
              style={{
                padding: '9px 20px',
                background: 'transparent',
                color: '#5c4633',
                border: '1px solid #d4c9b8',
                borderRadius: 6,
                fontWeight: 500,
                fontSize: '14px',
                cursor: 'pointer',
              }}
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      <div style={{ display: 'flex', gap: 24, alignItems: 'flex-start' }}>
        <div className="card" style={{ flex: 1, padding: 0, overflow: 'hidden' }}>
          <div style={{ padding: '14px 18px', borderBottom: '1px solid #e8e0d4', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <h3 style={{ margin: 0, fontSize: '15px', color: '#292018' }}>Templates</h3>
            <span style={{ fontSize: '12px', color: '#97846c' }}>{templates.length} template{templates.length !== 1 ? 's' : ''} — click a row to view rules</span>
          </div>
          <table className="data-table" style={{ margin: 0 }}>
            <thead>
              <tr>
                <th>Name</th>
                <th>Category</th>
                <th>Target Tag</th>
                <th style={{ textAlign: 'center' }}>Rules</th>
                <th style={{ textAlign: 'center' }}>Auto-Apply</th>
                <th style={{ textAlign: 'center' }}>Used</th>
                {canManage && <th>Actions</th>}
              </tr>
            </thead>
            <tbody>
              {templates.map(t => (
                <tr
                  key={t.id}
                  onClick={() => selectTemplate(t)}
                  style={{
                    cursor: 'pointer',
                    background: selectedTemplate?.id === t.id ? '#f0ebe2' : undefined,
                    borderLeft: selectedTemplate?.id === t.id ? '3px solid #8b6914' : '3px solid transparent',
                  }}
                >
                  <td><strong style={{ color: '#292018' }}>{t.name}</strong>{t.description && <div style={{ fontSize: '11px', color: '#97846c', marginTop: 2 }}>{t.description}</div>}</td>
                  <td>{t.category ? <span style={{ padding: '2px 8px', background: '#f0ebe2', borderRadius: 10, fontSize: '11px', color: '#5c4633' }}>{t.category}</span> : <span style={{ color: '#b8a890' }}>—</span>}</td>
                  <td>{t.target_tag_name ? <span style={{ padding: '2px 8px', background: '#e8f5e9', borderRadius: 10, fontSize: '11px', color: '#2e7d32' }}>{t.target_tag_name}</span> : <span style={{ color: '#b8a890' }}>—</span>}</td>
                  <td style={{ textAlign: 'center', fontWeight: 600 }}>{t.rule_count}</td>
                  <td style={{ textAlign: 'center' }}>{t.auto_apply ? <span style={{ color: '#5a7a3a', fontWeight: 600 }}>Yes</span> : <span style={{ color: '#b8a890' }}>No</span>}</td>
                  <td style={{ textAlign: 'center' }}>{t.instantiation_count}x</td>
                  {canManage && <td>
                    <div style={{ display: 'flex', gap: 4 }}>
                      <button onClick={(e) => { e.stopPropagation(); instantiate(t.id); }} className="btn-small" style={{ background: '#8b6914', color: '#fdfcf9', border: 'none', borderRadius: 5, padding: '4px 10px', fontSize: '12px', fontWeight: 600, cursor: 'pointer' }}>Instantiate</button>
                      <button onClick={(e) => { e.stopPropagation(); deleteTemplate(t.id); }} className="btn-small btn-danger">Delete</button>
                    </div>
                  </td>}
                </tr>
              ))}
              {templates.length === 0 && (
                <tr>
                  <td colSpan={canManage ? 7 : 6} className="empty-state" style={{ textAlign: 'center', padding: 30 }}>
                    No templates found.{canManage && ' Click "+ New Template" to create one.'}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {selectedTemplate && (
          <div className="card" style={{ flex: 1, padding: 0, overflow: 'hidden' }}>
            <div style={{ padding: '14px 18px', borderBottom: '1px solid #e8e0d4', background: '#f7f4ef' }}>
              <h3 style={{ margin: 0, fontSize: '15px', color: '#292018' }}>{selectedTemplate.name} — Rules</h3>
            </div>
            <div style={{ padding: 16 }}>
            <div style={{ padding: '8px 12px', background: '#f7f4ef', borderRadius: 6, marginBottom: 12, fontSize: '12.5px', color: '#78644e', borderLeft: '3px solid #d4c9b8' }}>
              <strong>Note:</strong> Baseline rules (loopback, established/related connections, management SSH access) are automatically added by the compiler when policies are deployed. You only need to define your application-specific rules here.
            </div>
            {templateRules.length === 0 && (
              <div style={{ padding: 20, textAlign: 'center', color: '#97846c', fontSize: '13px' }}>
                No rules yet.{canManage && ' Add rules below.'}
              </div>
            )}
            {templateRules.length > 0 && (
            <table className="data-table" style={{ fontSize: '0.9em' }}>
              <thead><tr><th>#</th><th>Dir</th><th>Action</th><th>Proto</th><th>Ports</th><th>Source</th><th>Destination</th><th>Comment</th>{canManage && <th style={{ width: 40 }}></th>}</tr></thead>
              <tbody>
                {templateRules.map(r => (
                  <tr key={r.id}>
                    <td style={{ color: '#97846c' }}>{r.order_index}</td>
                    <td><span style={{ fontWeight: 500 }}>{r.direction}</span></td>
                    <td><span style={{ color: r.action === 'ALLOW' ? '#5a7a3a' : '#a63d2f', fontWeight: 600 }}>{r.action}</span></td>
                    <td>{r.protocol}</td>
                    <td><code style={{ background: '#f0ebe2', padding: '1px 4px', borderRadius: 3, fontSize: '0.9em' }}>{r.ports || '*'}</code></td>
                    <td style={{ fontSize: '12px' }}>{r.source_type}:{r.source_value}</td>
                    <td style={{ fontSize: '12px' }}>{r.direction === 'FORWARD' && r.destination_type ? `${r.destination_type === 'IOT_ASSET' ? 'IoT device' : r.destination_type}:${describeDestination(r.destination_type, r.destination_value)}` : ''}</td>
                    <td style={{ color: '#78644e', fontSize: '12px' }}>{r.comment || ''}</td>
                    {canManage && (
                      <td>
                        <button
                          onClick={() => deleteRule(r.id)}
                          className="btn-small btn-danger"
                          style={{ padding: '2px 8px', fontSize: '11px' }}
                        >
                          X
                        </button>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
            )}
            {canManage && <div style={{ marginTop: 16, padding: 12, background: '#f7f4ef', borderRadius: 8, border: '1px solid #e8e0d4' }}>
              <h4 style={{ margin: '0 0 10px', color: '#5c4633', fontSize: '14px' }}>Add Rule</h4>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 1fr', gap: 8, fontSize: '0.9em' }}>
                <div><label style={{ fontSize: '11px', color: '#78644e', display: 'block', marginBottom: 2 }}>Direction</label>
                <select value={ruleForm.direction} onChange={e => setRuleForm(f => ({ ...f, direction: e.target.value }))} style={{ width: '100%' }}>
                  <option value="IN">IN</option><option value="OUT">OUT</option><option value="BOTH">BOTH</option>
                  <option value="FORWARD">FORWARD (through gateway)</option>
                </select></div>
                <div><label style={{ fontSize: '11px', color: '#78644e', display: 'block', marginBottom: 2 }}>Action</label>
                <select value={ruleForm.action} onChange={e => setRuleForm(f => ({ ...f, action: e.target.value }))} style={{ width: '100%' }}>
                  <option value="ALLOW">ALLOW</option><option value="DENY">DENY</option>
                </select></div>
                <div><label style={{ fontSize: '11px', color: '#78644e', display: 'block', marginBottom: 2 }}>Protocol</label>
                <select value={ruleForm.protocol} onChange={e => setRuleForm(f => ({ ...f, protocol: e.target.value }))} style={{ width: '100%' }}>
                  <option value="tcp">TCP</option><option value="udp">UDP</option><option value="icmp">ICMP</option><option value="any">Any</option>
                </select></div>
                <div><label style={{ fontSize: '11px', color: '#78644e', display: 'block', marginBottom: 2 }}>Ports</label>
                <input placeholder="e.g., 80,443" value={ruleForm.ports} onChange={e => setRuleForm(f => ({ ...f, ports: e.target.value }))} style={{ width: '100%' }} /></div>
                <div><label style={{ fontSize: '11px', color: '#78644e', display: 'block', marginBottom: 2 }}>Source Type</label>
                <select value={ruleForm.sourceType} onChange={e => setRuleForm(f => ({ ...f, sourceType: e.target.value }))} style={{ width: '100%' }}>
                  <option value="CIDR">CIDR</option><option value="TAG">TAG</option><option value="VLAN">VLAN</option>
                </select></div>
                <div><label style={{ fontSize: '11px', color: '#78644e', display: 'block', marginBottom: 2 }}>Source Value</label>
                <input placeholder="e.g., 0.0.0.0/0" value={ruleForm.sourceValue} onChange={e => setRuleForm(f => ({ ...f, sourceValue: e.target.value }))} style={{ width: '100%' }} /></div>
                {ruleForm.direction === 'FORWARD' && <>
                <div><label style={{ fontSize: '11px', color: '#78644e', display: 'block', marginBottom: 2 }}>Destination Type</label>
                <select value={ruleForm.destinationType} onChange={e => setRuleForm(f => ({ ...f, destinationType: e.target.value, destinationValue: '' }))} style={{ width: '100%' }}>
                  <option value="CIDR">CIDR</option><option value="IOT_ASSET">IoT device</option><option value="VLAN">VLAN</option><option value="TAG">TAG</option><option value="HOST">HOST</option>
                </select></div>
                <div><label style={{ fontSize: '11px', color: '#78644e', display: 'block', marginBottom: 2 }}>Destination Value</label>
                {ruleForm.destinationType === 'CIDR' ? (
                  <input placeholder="e.g., 172.31.0.0/24" value={ruleForm.destinationValue} onChange={e => setRuleForm(f => ({ ...f, destinationValue: e.target.value }))} style={{ width: '100%' }} />
                ) : (
                  <select value={ruleForm.destinationValue} onChange={e => setRuleForm(f => ({ ...f, destinationValue: e.target.value }))} style={{ width: '100%' }}>
                    <option value="">Select…</option>
                    {ruleForm.destinationType === 'TAG' && tags.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
                    {ruleForm.destinationType === 'VLAN' && (destOptions?.vlans ?? []).map((v) => <option key={v.id} value={v.id}>{v.name} ({v.vlan_tag})</option>)}
                    {ruleForm.destinationType === 'HOST' && (destOptions?.hosts ?? []).map((h) => <option key={h.id} value={h.id}>{h.hostname}{h.mgmt_ip ? ` (${h.mgmt_ip})` : ''}</option>)}
                    {ruleForm.destinationType === 'IOT_ASSET' && (destOptions?.iotAssets ?? []).map((a) => <option key={a.id} value={a.id}>{a.name}{a.ip_address ? ` (${a.ip_address})` : ' (no IP)'}</option>)}
                  </select>
                )}</div>
                </>}
                <div><label style={{ fontSize: '11px', color: '#78644e', display: 'block', marginBottom: 2 }}>Comment</label>
                <input placeholder="Optional" value={ruleForm.comment} onChange={e => setRuleForm(f => ({ ...f, comment: e.target.value }))} style={{ width: '100%' }} /></div>
                <div style={{ display: 'flex', alignItems: 'flex-end' }}>
                <button onClick={addRule} className="btn-primary" style={{ width: '100%' }}>Add Rule</button></div>
              </div>
            </div>}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
