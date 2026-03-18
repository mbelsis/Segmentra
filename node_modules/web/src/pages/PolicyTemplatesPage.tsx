import { useState, useEffect } from 'react';
import { api } from '../lib/api';

export function PolicyTemplatesPage() {
  const [templates, setTemplates] = useState<any[]>([]);
  const [categories, setCategories] = useState<string[]>([]);
  const [selectedCategory, setSelectedCategory] = useState('');
  const [tags, setTags] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [showCreate, setShowCreate] = useState(false);
  const [selectedTemplate, setSelectedTemplate] = useState<any>(null);
  const [templateRules, setTemplateRules] = useState<any[]>([]);
  const [form, setForm] = useState({ name: '', description: '', category: '', targetTagId: '', autoApply: false, interfaceScopeType: 'INTERFACE_ROLE' as string });
  const [ruleForm, setRuleForm] = useState({ direction: 'IN', action: 'ALLOW', protocol: 'tcp', ports: '', sourceType: 'CIDR', sourceValue: '0.0.0.0/0', logMode: 'NONE', comment: '' });

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
    } catch (e: any) { setError(e.message); }
    setLoading(false);
  };

  useEffect(() => { load(); }, [selectedCategory]);

  const selectTemplate = async (t: any) => {
    setSelectedTemplate(t);
    try {
      const res = await api.templates.get(t.id);
      setTemplateRules(res.rules);
    } catch (e: any) { setError(e.message); }
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
      setForm({ name: '', description: '', category: '', targetTagId: '', autoApply: false, interfaceScopeType: 'INTERFACE_ROLE' });
      load();
    } catch (e: any) { setError(e.message); }
  };

  const addRule = async () => {
    if (!selectedTemplate) return;
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
      });
      const res = await api.templates.get(selectedTemplate.id);
      setTemplateRules(res.rules);
      setRuleForm({ direction: 'IN', action: 'ALLOW', protocol: 'tcp', ports: '', sourceType: 'CIDR', sourceValue: '0.0.0.0/0', logMode: 'NONE', comment: '' });
    } catch (e: any) { setError(e.message); }
  };

  const deleteRule = async (ruleId: string) => {
    try {
      await api.templates.deleteRule(ruleId);
      setTemplateRules(prev => prev.filter(r => r.id !== ruleId));
    } catch (e: any) { setError(e.message); }
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
    } catch (e: any) { setError(e.message); }
  };

  const deleteTemplate = async (id: string) => {
    if (!confirm('Delete this template?')) return;
    try {
      await api.templates.delete(id);
      if (selectedTemplate?.id === id) { setSelectedTemplate(null); setTemplateRules([]); }
      load();
    } catch (e: any) { setError(e.message); }
  };

  if (loading) return <div>Loading...</div>;

  return (
    <div>
      <h2>Policy Templates</h2>
      <p style={{ color: '#78644e', fontSize: '13.5px', marginTop: -4, marginBottom: 16, lineHeight: 1.6 }}>
        Reusable policy blueprints for common server roles. Create a template (e.g., "Web Server" = allow 80/443 in, allow 53 out),
        then <strong>instantiate</strong> it to generate a real policy set with rules in DRAFT status — ready for the normal approval workflow.
        Enable <strong>auto-apply</strong> on a template to automatically create DRAFT policies whenever a host gains the template's target tag.
      </p>
      {error && <div style={{ color: 'red', marginBottom: 8 }}>{error} <button onClick={() => setError('')}>dismiss</button></div>}

      <div style={{ display: 'flex', gap: 16, marginBottom: 16 }}>
        <select value={selectedCategory} onChange={e => setSelectedCategory(e.target.value)}>
          <option value="">All Categories</option>
          {categories.map(c => <option key={c} value={c}>{c}</option>)}
        </select>
        <button onClick={() => setShowCreate(true)} className="btn-primary">+ New Template</button>
      </div>

      {showCreate && (
        <div style={{ border: '1px solid #ccc', padding: 16, marginBottom: 16, borderRadius: 4 }}>
          <h3>Create Template</h3>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
            <input placeholder="Name" value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} />
            <input placeholder="Category" value={form.category} onChange={e => setForm(f => ({ ...f, category: e.target.value }))} />
            <input placeholder="Description" value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))} />
            <select value={form.targetTagId} onChange={e => setForm(f => ({ ...f, targetTagId: e.target.value }))}>
              <option value="">No target tag</option>
              {tags.map(t => <option key={t.id} value={t.id}>{t.name}</option>)}
            </select>
            <label><input type="checkbox" checked={form.autoApply} onChange={e => setForm(f => ({ ...f, autoApply: e.target.checked }))} /> Auto-apply when tag assigned</label>
          </div>
          <div style={{ marginTop: 8 }}>
            <button onClick={createTemplate}>Create</button>
            <button onClick={() => setShowCreate(false)} style={{ marginLeft: 8 }}>Cancel</button>
          </div>
        </div>
      )}

      <div style={{ display: 'flex', gap: 24 }}>
        <div style={{ flex: 1 }}>
          <table style={{ width: '100%' }}>
            <thead><tr><th>Name</th><th>Category</th><th>Target Tag</th><th>Rules</th><th>Auto</th><th>Used</th><th>Actions</th></tr></thead>
            <tbody>
              {templates.map(t => (
                <tr key={t.id} onClick={() => selectTemplate(t)} style={{ cursor: 'pointer', background: selectedTemplate?.id === t.id ? '#e8f0fe' : undefined }}>
                  <td>{t.name}</td>
                  <td>{t.category || '-'}</td>
                  <td>{t.target_tag_name || '-'}</td>
                  <td>{t.rule_count}</td>
                  <td>{t.auto_apply ? 'Yes' : 'No'}</td>
                  <td>{t.instantiation_count}x</td>
                  <td>
                    <button onClick={(e) => { e.stopPropagation(); instantiate(t.id); }}>Instantiate</button>
                    <button onClick={(e) => { e.stopPropagation(); deleteTemplate(t.id); }} style={{ marginLeft: 4, color: 'red' }}>Delete</button>
                  </td>
                </tr>
              ))}
              {templates.length === 0 && <tr><td colSpan={7}>No templates found</td></tr>}
            </tbody>
          </table>
        </div>

        {selectedTemplate && (
          <div style={{ flex: 1, border: '1px solid #ccc', padding: 16, borderRadius: 4 }}>
            <h3>{selectedTemplate.name} — Rules</h3>
            <div style={{ padding: '8px 12px', background: '#f7f4ef', borderRadius: 6, marginBottom: 12, fontSize: '12.5px', color: '#78644e', borderLeft: '3px solid #d4c9b8' }}>
              <strong>Note:</strong> Baseline rules (loopback, established/related connections, management SSH access) are automatically added by the compiler when policies are deployed. You only need to define your application-specific rules here.
            </div>
            <table style={{ width: '100%', fontSize: '0.9em' }}>
              <thead><tr><th>#</th><th>Dir</th><th>Action</th><th>Proto</th><th>Ports</th><th>Source</th><th>Comment</th><th></th></tr></thead>
              <tbody>
                {templateRules.map(r => (
                  <tr key={r.id}>
                    <td>{r.order_index}</td>
                    <td>{r.direction}</td>
                    <td style={{ color: r.action === 'ALLOW' ? 'green' : 'red' }}>{r.action}</td>
                    <td>{r.protocol}</td>
                    <td>{r.ports || '*'}</td>
                    <td>{r.source_type}:{r.source_value}</td>
                    <td>{r.comment || ''}</td>
                    <td><button onClick={() => deleteRule(r.id)} style={{ color: 'red' }}>X</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
            <div style={{ marginTop: 16, padding: 12, background: '#f7f4ef', borderRadius: 8, border: '1px solid #e8e0d4' }}>
              <h4 style={{ margin: '0 0 10px', color: '#5c4633', fontSize: '14px' }}>Add Rule</h4>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 1fr', gap: 8, fontSize: '0.9em' }}>
                <div><label style={{ fontSize: '11px', color: '#78644e', display: 'block', marginBottom: 2 }}>Direction</label>
                <select value={ruleForm.direction} onChange={e => setRuleForm(f => ({ ...f, direction: e.target.value }))} style={{ width: '100%' }}>
                  <option value="IN">IN</option><option value="OUT">OUT</option><option value="BOTH">BOTH</option>
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
                <div><label style={{ fontSize: '11px', color: '#78644e', display: 'block', marginBottom: 2 }}>Comment</label>
                <input placeholder="Optional" value={ruleForm.comment} onChange={e => setRuleForm(f => ({ ...f, comment: e.target.value }))} style={{ width: '100%' }} /></div>
                <div style={{ display: 'flex', alignItems: 'flex-end' }}>
                <button onClick={addRule} className="btn-primary" style={{ width: '100%' }}>Add Rule</button></div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
