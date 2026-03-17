import { useEffect, useState } from 'react';

import { api } from '../lib/api';
import { HostPolicyVisualization } from '../components/HostPolicyVisualization';

type Tab = 'hosts' | 'tags' | 'vlans' | 'tag-rules';

export function InventoryPage() {
  const [activeTab, setActiveTab] = useState<Tab>('hosts');
  
  // Hosts state
  const [hosts, setHosts] = useState<any[]>([]);
  const [hostname, setHostname] = useState('');
  const [mgmtIp, setMgmtIp] = useState('');
  const [hostSshPort, setHostSshPort] = useState<string>('22');
  const [hostVlanId, setHostVlanId] = useState<string>('');
  const [hostTagIds, setHostTagIds] = useState<string[]>([]);
  const [hostFirewallBackend, setHostFirewallBackend] = useState<string>('auto');
  const [editingHost, setEditingHost] = useState<string | null>(null);
  
  // Host filtering and pagination
  const [searchQuery, setSearchQuery] = useState('');
  const [filterTag, setFilterTag] = useState<string>('');
  const [filterVlan, setFilterVlan] = useState<string>('');
  const [filterEnabled, setFilterEnabled] = useState<string>('all'); // 'all', 'true', 'false'
  const [selectedHostIds, setSelectedHostIds] = useState<Set<string>>(new Set());
  const [currentPage, setCurrentPage] = useState(1);
  const [pagination, setPagination] = useState<{ page: number; limit: number; total: number; totalPages: number } | null>(null);
  const [bulkVlanId, setBulkVlanId] = useState<string>('');
  const [bulkTagId, setBulkTagId] = useState<string>('');
  const [showImport, setShowImport] = useState(false);
  const [csvFile, setCsvFile] = useState<File | null>(null);
  const [importResults, setImportResults] = useState<any>(null);
  const [importing, setImporting] = useState(false);
  
  // Compliance and readiness state
  const [complianceStatuses, setComplianceStatuses] = useState<Map<string, any>>(new Map());
  const [checkingCompliance, setCheckingCompliance] = useState<Set<string>>(new Set());
  const [readinessResults, setReadinessResults] = useState<Map<string, any>>(new Map());
  const [checkingReadiness, setCheckingReadiness] = useState<Set<string>>(new Set());
  
  // Modal state
  const [showAddHost, setShowAddHost] = useState(false);

  // Visualization modal state
  const [visualizationHost, setVisualizationHost] = useState<{ id: string; hostname: string } | null>(null);
  
  // Tags state
  const [tags, setTags] = useState<any[]>([]);
  const [tagName, setTagName] = useState('');
  const [tagDescription, setTagDescription] = useState('');
  const [editingTag, setEditingTag] = useState<string | null>(null);
  
  // VLANs state
  const [vlans, setVlans] = useState<any[]>([]);
  const [vlanTag, setVlanTag] = useState('');
  const [vlanName, setVlanName] = useState('');
  const [vlanDescription, setVlanDescription] = useState('');
  const [vlanSubnet, setVlanSubnet] = useState('');
  const [editingVlan, setEditingVlan] = useState<string | null>(null);
  
  // Tag Rules state
  const [tagRules, setTagRules] = useState<any[]>([]);
  const [tagRulesLoading, setTagRulesLoading] = useState(false);
  const [showTagRuleForm, setShowTagRuleForm] = useState(false);
  const [editingTagRule, setEditingTagRule] = useState<any>(null);
  const [tagRuleForm, setTagRuleForm] = useState({
    name: '', tagId: '', enabled: true, priority: 0,
    logic: 'AND' as 'AND' | 'OR',
    conditions: [{ field: 'hostname', operator: 'matches', value: '' }] as Array<{ field: string; operator: string; value: string }>,
  });
  const [previewHosts, setPreviewHosts] = useState<any[] | null>(null);
  const [evaluatingAll, setEvaluatingAll] = useState(false);

  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadData();
  }, []);

  useEffect(() => {
    if (activeTab === 'hosts') {
      loadHosts();
    }
  }, [activeTab, currentPage, searchQuery, filterTag, filterVlan, filterEnabled]);

  async function loadData() {
    try {
      const [tagsRes, vlansRes] = await Promise.all([
        api.tags().catch(() => ({ tags: [] })),
        api.vlans().catch(() => ({ vlans: [] }))
      ]);
      setTags(tagsRes.tags || []);
      setVlans(vlansRes.vlans || []);
    } catch (e: any) {
      setError(String(e?.message ?? e));
    }
  }

  // === Tag Rules functions ===
  const FIELD_OPTIONS = [
    { value: 'hostname', label: 'Hostname' },
    { value: 'mgmt_ip', label: 'Management IP' },
    { value: 'os_family', label: 'OS Family' },
    { value: 'environment', label: 'Environment' },
    { value: 'firewall_backend', label: 'Firewall Backend' },
    { value: 'vlan_tag', label: 'VLAN Tag' },
    { value: 'tag', label: 'Has Tag' },
  ];
  const OPERATOR_OPTIONS: Record<string, Array<{ value: string; label: string }>> = {
    hostname: [
      { value: 'equals', label: 'equals' }, { value: 'not_equals', label: 'not equals' },
      { value: 'matches', label: 'matches (regex)' }, { value: 'contains', label: 'contains' },
    ],
    mgmt_ip: [
      { value: 'equals', label: 'equals' }, { value: 'in_cidr', label: 'in CIDR range' },
      { value: 'matches', label: 'matches (regex)' },
    ],
    os_family: [
      { value: 'equals', label: 'equals' }, { value: 'not_equals', label: 'not equals' },
      { value: 'matches', label: 'matches (regex)' }, { value: 'contains', label: 'contains' },
    ],
    environment: [
      { value: 'equals', label: 'equals' }, { value: 'not_equals', label: 'not equals' },
      { value: 'matches', label: 'matches (regex)' }, { value: 'contains', label: 'contains' },
    ],
    firewall_backend: [
      { value: 'equals', label: 'equals' }, { value: 'not_equals', label: 'not equals' },
    ],
    vlan_tag: [
      { value: 'equals', label: 'equals' }, { value: 'not_equals', label: 'not equals' },
    ],
    tag: [
      { value: 'has_tag', label: 'has tag' },
    ],
  };

  async function loadTagRules() {
    setTagRulesLoading(true);
    try {
      const res = await api.tagRules.list();
      setTagRules(res.tagRules || []);
    } catch (e: any) { setError(String(e?.message ?? e)); }
    setTagRulesLoading(false);
  }

  function resetTagRuleForm() {
    setShowTagRuleForm(false);
    setEditingTagRule(null);
    setPreviewHosts(null);
    setTagRuleForm({
      name: '', tagId: '', enabled: true, priority: 0,
      logic: 'AND', conditions: [{ field: 'hostname', operator: 'matches', value: '' }],
    });
  }

  function startEditTagRule(rule: any) {
    const criteria = typeof rule.criteria === 'string' ? JSON.parse(rule.criteria) : rule.criteria;
    setEditingTagRule(rule);
    setTagRuleForm({
      name: rule.name,
      tagId: rule.tag_id,
      enabled: rule.enabled,
      priority: rule.priority,
      logic: criteria.logic || 'AND',
      conditions: criteria.conditions?.length > 0 ? criteria.conditions : [{ field: 'hostname', operator: 'matches', value: '' }],
    });
    setShowTagRuleForm(true);
    setPreviewHosts(null);
  }

  function addCondition() {
    setTagRuleForm(f => ({
      ...f,
      conditions: [...f.conditions, { field: 'hostname', operator: 'matches', value: '' }],
    }));
  }

  function removeCondition(index: number) {
    setTagRuleForm(f => ({
      ...f,
      conditions: f.conditions.filter((_, i) => i !== index),
    }));
  }

  function updateCondition(index: number, field: string, value: string) {
    setTagRuleForm(f => {
      const conditions = [...f.conditions];
      const cond = { ...conditions[index], [field]: value };
      // Reset operator when field changes
      if (field === 'field') {
        const ops = OPERATOR_OPTIONS[value] || [];
        cond.operator = ops[0]?.value || 'equals';
        cond.value = '';
      }
      conditions[index] = cond;
      return { ...f, conditions };
    });
  }

  async function saveTagRule() {
    if (!tagRuleForm.name.trim() || !tagRuleForm.tagId) {
      setError('Rule name and target tag are required');
      return;
    }
    if (tagRuleForm.conditions.some(c => !c.value.trim())) {
      setError('All condition values are required');
      return;
    }
    try {
      const body = {
        name: tagRuleForm.name,
        tagId: tagRuleForm.tagId,
        enabled: tagRuleForm.enabled,
        priority: tagRuleForm.priority,
        criteria: { conditions: tagRuleForm.conditions, logic: tagRuleForm.logic },
      };
      if (editingTagRule) {
        await api.tagRules.update(editingTagRule.id, body);
      } else {
        await api.tagRules.create(body);
      }
      resetTagRuleForm();
      loadTagRules();
    } catch (e: any) { setError(String(e?.message ?? e)); }
  }

  async function deleteTagRule(id: string) {
    if (!confirm('Delete this tag rule? Auto-assigned tags from this rule will be removed.')) return;
    try {
      await api.tagRules.delete(id);
      loadTagRules();
    } catch (e: any) { setError(String(e?.message ?? e)); }
  }

  async function evaluateSingleRule(id: string) {
    try {
      const result = await api.tagRules.evaluate(id);
      alert(`Evaluated: ${result.matched} of ${result.total} hosts matched`);
      loadTagRules();
    } catch (e: any) { setError(String(e?.message ?? e)); }
  }

  async function evaluateAllRules() {
    setEvaluatingAll(true);
    try {
      const result = await api.tagRules.evaluateAll();
      alert(`Evaluated ${result.rulesEvaluated} rules, ${result.totalMatches} total matches`);
      loadTagRules();
    } catch (e: any) { setError(String(e?.message ?? e)); }
    setEvaluatingAll(false);
  }

  async function previewTagRule() {
    if (tagRuleForm.conditions.some(c => !c.value.trim())) {
      setError('All condition values are required for preview');
      return;
    }
    try {
      // Save temporarily, evaluate, then show results
      // For preview, we create the rule, evaluate it, get matched hosts, then show
      if (editingTagRule) {
        // If editing, just evaluate existing rule
        const res = await api.tagRules.get(editingTagRule.id);
        setPreviewHosts(res.matchedHosts || []);
      } else {
        // For new rules, save first then evaluate and show
        const body = {
          name: tagRuleForm.name || 'Preview Rule',
          tagId: tagRuleForm.tagId,
          enabled: false, // Create disabled so it doesn't auto-assign
          priority: tagRuleForm.priority,
          criteria: { conditions: tagRuleForm.conditions, logic: tagRuleForm.logic },
        };
        const createRes = await api.tagRules.create(body);
        const ruleId = createRes.tagRule.id;
        await api.tagRules.evaluate(ruleId);
        const detailRes = await api.tagRules.get(ruleId);
        setPreviewHosts(detailRes.matchedHosts || []);
        // Delete the temp rule
        await api.tagRules.delete(ruleId);
      }
    } catch (e: any) { setError(String(e?.message ?? e)); }
  }

  async function handleBulkImport() {
    if (!csvFile) {
      setError('Please select a CSV file');
      return;
    }

    setImporting(true);
    setError(null);
    setImportResults(null);

    try {
      const text = await csvFile.text();
      const result = await api.bulkImportHosts(text);
      setImportResults(result);
      if (result.imported > 0) {
        // Reload hosts to show imported ones
        loadHosts();
      }
    } catch (e: any) {
      setError(String(e?.message ?? e));
    } finally {
      setImporting(false);
    }
  }

  async function loadHosts() {
    try {
      const params: any = {
        page: currentPage,
        limit: 50
      };
      if (searchQuery.trim()) {
        // Try to detect if it's an IP or hostname
        if (/^\d+\.\d+\.\d+\.\d+/.test(searchQuery.trim())) {
          params.ip = searchQuery.trim();
        } else {
          params.hostname = searchQuery.trim();
        }
      }
      if (filterTag) params.tag = filterTag;
      if (filterVlan) params.vlan = filterVlan;
      if (filterEnabled !== 'all') params.enabled = filterEnabled === 'true';
      
      const hostsRes = await api.hosts(params);
      setHosts(hostsRes.hosts || []);
      setPagination(hostsRes.pagination || null);
    } catch (e: any) {
      setError(String(e?.message ?? e));
    }
  }

  // Host functions
  function resetHostForm() {
    setHostname('');
    setMgmtIp('');
    setHostSshPort('22');
    setHostVlanId('');
    setHostTagIds([]);
    setHostFirewallBackend('auto');
    setEditingHost(null);
    setError(null);
  }

  async function saveHost() {
    if (!hostname.trim()) {
      setError('Hostname is required');
      return;
    }
    setError(null);
    try {
      const sshPortNum = parseInt(hostSshPort.trim(), 10);
      if (isNaN(sshPortNum) || sshPortNum < 1 || sshPortNum > 65535) {
        setError('SSH port must be a number between 1 and 65535');
        return;
      }

      const payload: any = {
        hostname: hostname.trim(),
        mgmtIp: mgmtIp.trim() || undefined,
        sshPort: sshPortNum,
        vlanId: hostVlanId || undefined,
        tagIds: hostTagIds,
        firewallBackend: hostFirewallBackend || 'auto'
      };
      
      if (editingHost) {
        const r = await api.updateHost(editingHost, payload);
        setHosts((prev) => prev.map(h => h.id === editingHost ? r.host : h));
      } else {
        const r = await api.createHost(payload);
        setHosts((prev) => [...prev, r.host]);
      }
      resetHostForm();
      loadHosts(); // Reload to get fresh data
    } catch (e: any) {
      setError(String(e?.message ?? e));
    }
  }

  function editHost(host: any) {
    setHostname(host.hostname);
    setMgmtIp(host.mgmt_ip || '');
    setHostSshPort(String(host.ssh_port || 22));
    setHostVlanId(host.vlan_id || '');
    setHostTagIds((host.tags || []).map((t: any) => t.id));
    setHostFirewallBackend(host.firewall_backend || 'auto');
    setEditingHost(host.id);
  }

  function toggleHostTag(tagId: string) {
    setHostTagIds((prev) => 
      prev.includes(tagId) 
        ? prev.filter(id => id !== tagId)
        : [...prev, tagId]
    );
  }

  // Bulk operations
  function toggleHostSelection(hostId: string) {
    setSelectedHostIds((prev) => {
      const next = new Set(prev);
      if (next.has(hostId)) {
        next.delete(hostId);
      } else {
        next.add(hostId);
      }
      return next;
    });
  }

  function toggleSelectAll() {
    if (selectedHostIds.size === hosts.length) {
      setSelectedHostIds(new Set());
    } else {
      setSelectedHostIds(new Set(hosts.map(h => h.id)));
    }
  }

  async function handleBulkDelete() {
    if (selectedHostIds.size === 0) return;
    if (!confirm(`Are you sure you want to delete ${selectedHostIds.size} host(s)?`)) return;
    try {
      await api.bulkDeleteHosts(Array.from(selectedHostIds));
      setSelectedHostIds(new Set());
      loadHosts();
    } catch (e: any) {
      setError(String(e?.message ?? e));
    }
  }

  async function handleBulkAssignVlan() {
    if (selectedHostIds.size === 0) return;
    try {
      await api.bulkAssignVlan(Array.from(selectedHostIds), bulkVlanId || null);
      setBulkVlanId('');
      setSelectedHostIds(new Set());
      loadHosts();
    } catch (e: any) {
      setError(String(e?.message ?? e));
    }
  }

  async function handleBulkAssignTag() {
    if (selectedHostIds.size === 0 || !bulkTagId) return;
    try {
      await api.bulkAssignTag(Array.from(selectedHostIds), bulkTagId);
      setBulkTagId('');
      setSelectedHostIds(new Set());
      loadHosts();
    } catch (e: any) {
      setError(String(e?.message ?? e));
    }
  }

  async function handleBulkSetEnabled(enabled: boolean) {
    if (selectedHostIds.size === 0) return;
    try {
      await api.bulkSetEnabled(Array.from(selectedHostIds), enabled);
      setSelectedHostIds(new Set());
      loadHosts();
    } catch (e: any) {
      setError(String(e?.message ?? e));
    }
  }

  async function checkHostCompliance(hostId: string) {
    setCheckingCompliance(prev => new Set(prev).add(hostId));
    try {
      const result = await api.checkHostCompliance(hostId);
      setComplianceStatuses(prev => new Map(prev).set(hostId, result));
    } catch (e: any) {
      setError(`Compliance check failed: ${e.message}`);
    } finally {
      setCheckingCompliance(prev => {
        const next = new Set(prev);
        next.delete(hostId);
        return next;
      });
    }
  }

  async function checkHostReadiness(hostId: string) {
    setCheckingReadiness(prev => new Set(prev).add(hostId));
    try {
      const result = await api.checkHostReadiness(hostId);
      setReadinessResults(prev => new Map(prev).set(hostId, result));
      // Reload hosts to get updated firewall_backend if it was auto-detected
      loadHosts();
    } catch (e: any) {
      setError(`Readiness check failed: ${e.message}`);
    } finally {
      setCheckingReadiness(prev => {
        const next = new Set(prev);
        next.delete(hostId);
        return next;
      });
    }
  }

  async function handleBulkComplianceCheck() {
    if (selectedHostIds.size === 0) return;
    const hostIds = Array.from(selectedHostIds);
    setCheckingCompliance(new Set(hostIds));
    try {
      const result = await api.bulkCheckCompliance(hostIds);
      const newStatuses = new Map(complianceStatuses);
      for (const r of result.results) {
        newStatuses.set(r.hostId, r);
      }
      setComplianceStatuses(newStatuses);
    } catch (e: any) {
      setError(`Bulk compliance check failed: ${e.message}`);
    } finally {
      setCheckingCompliance(new Set());
    }
  }

  // Tag functions
  function resetTagForm() {
    setTagName('');
    setTagDescription('');
    setEditingTag(null);
    setError(null);
  }

  async function saveTag() {
    if (!tagName.trim()) {
      setError('Tag name is required');
      return;
    }
    setError(null);
    try {
      if (editingTag) {
        const r = await api.updateTag(editingTag, {
          name: tagName.trim(),
          description: tagDescription.trim() || undefined
        });
        setTags((prev) => prev.map(t => t.id === editingTag ? r.tag : t));
      } else {
        const r = await api.createTag({
          name: tagName.trim(),
          description: tagDescription.trim() || undefined
        });
        setTags((prev) => [...prev, r.tag]);
      }
      resetTagForm();
      loadData(); // Reload to get fresh data from database
    } catch (e: any) {
      setError(String(e?.message ?? e));
    }
  }

  async function deleteTag(id: string) {
    if (!confirm('Are you sure you want to delete this tag?')) return;
    setError(null);
    try {
      await api.deleteTag(id);
      setTags((prev) => prev.filter(t => t.id !== id));
      loadData(); // Reload to get fresh data from database
    } catch (e: any) {
      setError(String(e?.message ?? e));
    }
  }

  function editTag(tag: any) {
    setTagName(tag.name);
    setTagDescription(tag.description || '');
    setEditingTag(tag.id);
  }

  // VLAN functions
  function resetVlanForm() {
    setVlanTag('');
    setVlanName('');
    setVlanDescription('');
    setVlanSubnet('');
    setEditingVlan(null);
    setError(null);
  }

  async function saveVlan() {
    if (!vlanName.trim()) {
      setError('VLAN name is required');
      return;
    }
    const tagNum = parseInt(vlanTag.trim());
    if (isNaN(tagNum) || tagNum < 1 || tagNum > 4094) {
      setError('VLAN tag must be a number between 1 and 4094');
      return;
    }
    setError(null);
    try {
      if (editingVlan) {
        const r = await api.updateVlan(editingVlan, {
          vlanTag: tagNum,
          name: vlanName.trim(),
          description: vlanDescription.trim() || undefined,
          subnet: vlanSubnet.trim() || undefined
        });
        setVlans((prev) => prev.map(v => v.id === editingVlan ? r.vlan : v));
      } else {
        const r = await api.createVlan({
          vlanTag: tagNum,
          name: vlanName.trim(),
          description: vlanDescription.trim() || undefined,
          subnet: vlanSubnet.trim() || undefined
        });
        setVlans((prev) => [...prev, r.vlan]);
      }
      resetVlanForm();
      loadData(); // Reload to get fresh data from database
    } catch (e: any) {
      setError(String(e?.message ?? e));
    }
  }

  async function deleteVlan(id: string) {
    if (!confirm('Are you sure you want to delete this VLAN?')) return;
    setError(null);
    try {
      await api.deleteVlan(id);
      setVlans((prev) => prev.filter(v => v.id !== id));
      loadData(); // Reload to get fresh data from database
    } catch (e: any) {
      setError(String(e?.message ?? e));
    }
  }

  function editVlan(vlan: any) {
    setVlanTag(String(vlan.vlan_tag));
    setVlanName(vlan.name);
    setVlanDescription(vlan.description || '');
    setVlanSubnet(vlan.subnet || '');
    setEditingVlan(vlan.id);
  }

  return (
    <div className="page">
      <div className="page-header">
        <h2>Inventory</h2>
      </div>

      {/* Tabs */}
      <div style={{ display: 'flex', gap: 8, marginBottom: 24, borderBottom: '2px solid #e0e0e0' }}>
        <button
          onClick={() => setActiveTab('hosts')}
          className={activeTab === 'hosts' ? 'btn-primary' : 'btn-secondary'}
          style={{ borderBottom: activeTab === 'hosts' ? '2px solid #646cff' : 'none', borderRadius: 0, marginBottom: -2 }}
        >
          Hosts
        </button>
        <button
          onClick={() => setActiveTab('tags')}
          className={activeTab === 'tags' ? 'btn-primary' : 'btn-secondary'}
          style={{ borderBottom: activeTab === 'tags' ? '2px solid #646cff' : 'none', borderRadius: 0, marginBottom: -2 }}
        >
          Tags
        </button>
        <button
          onClick={() => setActiveTab('vlans')}
          className={activeTab === 'vlans' ? 'btn-primary' : 'btn-secondary'}
          style={{ borderBottom: activeTab === 'vlans' ? '2px solid #646cff' : 'none', borderRadius: 0, marginBottom: -2 }}
        >
          VLANs
        </button>
        <button
          onClick={() => { setActiveTab('tag-rules'); loadTagRules(); }}
          className={activeTab === 'tag-rules' ? 'btn-primary' : 'btn-secondary'}
          style={{ borderBottom: activeTab === 'tag-rules' ? '2px solid #646cff' : 'none', borderRadius: 0, marginBottom: -2 }}
        >
          Tag Rules
        </button>
      </div>

      {error && <div className="error-banner">{error}</div>}

      {/* Add Host Modal */}
      {(showAddHost || editingHost) && (
        <div style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, background: 'rgba(0,0,0,0.5)', zIndex: 1000, display: 'flex', alignItems: 'center', justifyContent: 'center' }}
          onClick={(e) => { if (e.target === e.currentTarget) { resetHostForm(); setShowAddHost(false); } }}>
          <div style={{ background: 'white', borderRadius: 8, padding: 24, width: '90%', maxWidth: 700, maxHeight: '90vh', overflow: 'auto', boxShadow: '0 4px 24px rgba(0,0,0,0.2)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
              <h3 style={{ margin: 0 }}>{editingHost ? 'Edit Host' : 'Add Host'}</h3>
              <button onClick={() => { resetHostForm(); setShowAddHost(false); }} style={{ background: 'none', border: 'none', fontSize: '1.5em', cursor: 'pointer', color: '#666' }}>x</button>
            </div>
            <div className="form-grid">
              <div className="form-group">
                <label>Hostname *</label>
                <input type="text" value={hostname} onChange={(e) => setHostname(e.target.value)} placeholder="e.g., web-server-01" />
              </div>
              <div className="form-group">
                <label>Management IP</label>
                <input type="text" value={mgmtIp} onChange={(e) => setMgmtIp(e.target.value)} placeholder="e.g., 10.0.0.100" />
              </div>
              <div className="form-group">
                <label>SSH Port</label>
                <input type="number" value={hostSshPort} onChange={(e) => setHostSshPort(e.target.value)} placeholder="22" min="1" max="65535" />
                <small>SSH port for deployments (default: 22)</small>
              </div>
              <div className="form-group">
                <label>VLAN</label>
                <select value={hostVlanId} onChange={(e) => setHostVlanId(e.target.value)}>
                  <option value="">None</option>
                  {vlans.map((v) => (
                    <option key={v.id} value={v.id}>{v.name} (VLAN {v.vlan_tag})</option>
                  ))}
                </select>
              </div>
              <div className="form-group">
                <label>Firewall Backend</label>
                <select value={hostFirewallBackend} onChange={(e) => setHostFirewallBackend(e.target.value)}>
                  <option value="auto">Auto (nftables preferred)</option>
                  <option value="nftables">nftables</option>
                  <option value="iptables">iptables</option>
                </select>
                <small>Firewall backend to use for policy compilation. Auto defaults to nftables.</small>
              </div>
            </div>
            <div className="form-group">
              <label>Tags</label>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginTop: 8 }}>
                {tags.map((tag) => (
                  <label key={tag.id} style={{ display: 'flex', alignItems: 'center', cursor: 'pointer' }}>
                    <input type="checkbox" checked={hostTagIds.includes(tag.id)} onChange={() => toggleHostTag(tag.id)} style={{ marginRight: 6 }} />
                    <span>{tag.name}</span>
                  </label>
                ))}
                {tags.length === 0 && (
                  <span style={{ color: '#999', fontStyle: 'italic' }}>No tags available. Create tags in the Tags tab.</span>
                )}
              </div>
            </div>
            <div className="form-actions" style={{ marginTop: 16 }}>
              <button disabled={!hostname.trim()} onClick={async () => { await saveHost(); setShowAddHost(false); }} className="btn-primary">
                {editingHost ? 'Update' : 'Add'} Host
              </button>
              <button onClick={() => { resetHostForm(); setShowAddHost(false); }} className="btn-secondary">Cancel</button>
            </div>
          </div>
        </div>
      )}

      {/* Bulk Import Modal */}
      {showImport && (
        <div style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, background: 'rgba(0,0,0,0.5)', zIndex: 1000, display: 'flex', alignItems: 'center', justifyContent: 'center' }}
          onClick={(e) => { if (e.target === e.currentTarget) { setShowImport(false); setImportResults(null); } }}>
          <div style={{ background: 'white', borderRadius: 8, padding: 24, width: '90%', maxWidth: 700, maxHeight: '90vh', overflow: 'auto', boxShadow: '0 4px 24px rgba(0,0,0,0.2)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
              <h3 style={{ margin: 0 }}>Bulk Import Hosts (CSV)</h3>
              <button onClick={() => { setShowImport(false); setImportResults(null); }} style={{ background: 'none', border: 'none', fontSize: '1.5em', cursor: 'pointer', color: '#666' }}>x</button>
            </div>
            <div style={{ marginBottom: 16, padding: 12, background: '#f5f5f5', borderRadius: 4, fontSize: '0.9em' }}>
              <strong>CSV Format:</strong>
              <pre style={{ marginTop: 8, fontSize: '0.85em', overflow: 'auto' }}>
{`hostname,mgmt_ip,ssh_port,vlan,tags,firewall_backend,enabled
server1,10.0.0.1,22,Management,web-server,nftables,true
server2,10.0.0.2,2222,Production,db-server,auto,true`}
              </pre>
              <div style={{ marginTop: 8 }}>
                <strong>Columns:</strong>
                <ul style={{ marginTop: 4, paddingLeft: 20 }}>
                  <li><strong>hostname</strong> (required) - Host hostname</li>
                  <li><strong>mgmt_ip</strong> (optional) - Management IP address</li>
                  <li><strong>ssh_port</strong> (optional) - SSH port (default: 22)</li>
                  <li><strong>vlan</strong> (optional) - VLAN name or tag number</li>
                  <li><strong>tags</strong> (optional) - Comma-separated tag names</li>
                  <li><strong>firewall_backend</strong> (optional) - auto, nftables, or iptables (default: auto)</li>
                  <li><strong>enabled</strong> (optional) - true/false (default: true)</li>
                </ul>
              </div>
            </div>
            <div className="form-group">
              <label>CSV File</label>
              <input type="file" accept=".csv,text/csv"
                onChange={(e) => { const file = e.target.files?.[0]; setCsvFile(file || null); setImportResults(null); }}
                disabled={importing} />
            </div>
            {csvFile && (
              <div className="form-actions">
                <button onClick={handleBulkImport} className="btn-primary" disabled={importing}>
                  {importing ? 'Importing...' : 'Import Hosts'}
                </button>
                <button onClick={() => { setCsvFile(null); setImportResults(null); }} className="btn-secondary" disabled={importing}>Clear</button>
              </div>
            )}
            {importResults && (
              <div style={{ marginTop: 16, padding: 12, borderRadius: 4, background: importResults.failed === 0 ? '#e8f5e9' : '#fff3cd', border: `1px solid ${importResults.failed === 0 ? '#4CAF50' : '#ffc107'}` }}>
                <div style={{ fontWeight: 'bold', marginBottom: 8 }}>
                  Import Complete: {importResults.imported} imported, {importResults.failed} failed
                </div>
                {importResults.failed > 0 && (
                  <div style={{ marginTop: 8 }}>
                    <strong>Failed imports:</strong>
                    <ul style={{ marginTop: 4, paddingLeft: 20 }}>
                      {importResults.results.filter((r: any) => !r.success).map((r: any, idx: number) => (
                        <li key={idx}>{r.hostname}: {r.error}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Hosts Tab */}
      {activeTab === 'hosts' && (
        <>
          <div className="card">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <h3 style={{ margin: 0 }}>Hosts</h3>
              <div style={{ display: 'flex', gap: 8 }}>
                <button onClick={() => { resetHostForm(); setShowAddHost(true); }} className="btn-primary">+ Add Host</button>
                <button onClick={() => { setShowImport(true); setImportResults(null); }} className="btn-secondary">Bulk Import</button>
              </div>
            </div>
          </div>

          <div className="card">
            
            {/* Filters */}
            <div style={{ marginBottom: 16, padding: 16, background: '#f5f5f5', borderRadius: 8 }}>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 12, marginBottom: 12 }}>
                <div>
                  <label style={{ display: 'block', marginBottom: 4, fontSize: '0.9em', fontWeight: 500 }}>Search</label>
                  <input
                    type="text"
                    value={searchQuery}
                    onChange={(e) => { setSearchQuery(e.target.value); setCurrentPage(1); }}
                    placeholder="Hostname or IP"
                    style={{ width: '100%', padding: '6px 8px', border: '1px solid #ddd', borderRadius: 4 }}
                  />
                </div>
                <div>
                  <label style={{ display: 'block', marginBottom: 4, fontSize: '0.9em', fontWeight: 500 }}>Filter by Tag</label>
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
                  <label style={{ display: 'block', marginBottom: 4, fontSize: '0.9em', fontWeight: 500 }}>Filter by VLAN</label>
                  <select
                    value={filterVlan}
                    onChange={(e) => { setFilterVlan(e.target.value); setCurrentPage(1); }}
                    style={{ width: '100%', padding: '6px 8px', border: '1px solid #ddd', borderRadius: 4 }}
                  >
                    <option value="">All VLANs</option>
                    {vlans.map((v) => (
                      <option key={v.id} value={v.vlan_tag}>{v.name} (VLAN {v.vlan_tag})</option>
                    ))}
                  </select>
                </div>
                <div>
                  <label style={{ display: 'block', marginBottom: 4, fontSize: '0.9em', fontWeight: 500 }}>Status</label>
                  <select
                    value={filterEnabled}
                    onChange={(e) => { setFilterEnabled(e.target.value); setCurrentPage(1); }}
                    style={{ width: '100%', padding: '6px 8px', border: '1px solid #ddd', borderRadius: 4 }}
                  >
                    <option value="all">All</option>
                    <option value="true">Enabled</option>
                    <option value="false">Disabled</option>
                  </select>
                </div>
              </div>
              {pagination && (
                <div style={{ fontSize: '0.9em', color: '#666' }}>
                  Showing {((currentPage - 1) * (pagination.limit || 50)) + 1} to {Math.min(currentPage * (pagination.limit || 50), pagination.total)} of {pagination.total} hosts
                </div>
              )}
            </div>

            {/* Bulk Actions */}
            {selectedHostIds.size > 0 && (
              <div style={{ marginBottom: 16, padding: 12, background: '#e3f2fd', borderRadius: 8, display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
                <strong>{selectedHostIds.size} host(s) selected</strong>
                <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                  <button onClick={handleBulkDelete} className="btn-small btn-danger">Delete</button>
                  <button onClick={handleBulkComplianceCheck} className="btn-small" disabled={checkingCompliance.size > 0}>
                    Check Compliance ({selectedHostIds.size})
                  </button>
                  <div style={{ display: 'flex', gap: 4, alignItems: 'center' }}>
                    <select
                      value={bulkVlanId}
                      onChange={(e) => setBulkVlanId(e.target.value)}
                      style={{ padding: '4px 8px', border: '1px solid #ddd', borderRadius: 4 }}
                    >
                      <option value="">Assign VLAN...</option>
                      <option value="">None</option>
                      {vlans.map((v) => (
                        <option key={v.id} value={v.id}>{v.name} (VLAN {v.vlan_tag})</option>
                      ))}
                    </select>
                    <button onClick={handleBulkAssignVlan} className="btn-small btn-secondary" disabled={!bulkVlanId && bulkVlanId !== ''}>Apply</button>
                  </div>
                  <div style={{ display: 'flex', gap: 4, alignItems: 'center' }}>
                    <select
                      value={bulkTagId}
                      onChange={(e) => setBulkTagId(e.target.value)}
                      style={{ padding: '4px 8px', border: '1px solid #ddd', borderRadius: 4 }}
                    >
                      <option value="">Assign Tag...</option>
                      {tags.map((t) => (
                        <option key={t.id} value={t.id}>{t.name}</option>
                      ))}
                    </select>
                    <button onClick={handleBulkAssignTag} className="btn-small btn-secondary" disabled={!bulkTagId}>Apply</button>
                  </div>
                  <button onClick={() => handleBulkSetEnabled(true)} className="btn-small btn-secondary">Enable</button>
                  <button onClick={() => handleBulkSetEnabled(false)} className="btn-small btn-secondary">Disable</button>
                  <button onClick={() => setSelectedHostIds(new Set())} className="btn-small">Clear Selection</button>
                </div>
              </div>
            )}

            <table className="data-table">
              <thead>
                <tr>
                  <th style={{ width: 40 }}>
                    <input
                      type="checkbox"
                      checked={selectedHostIds.size === hosts.length && hosts.length > 0}
                      onChange={toggleSelectAll}
                    />
                  </th>
                  <th>Hostname</th>
                  <th>Mgmt IP</th>
                  <th>SSH Port</th>
                  <th>VLAN</th>
                  <th>Tags</th>
                  <th>Backend</th>
                  <th>Compliance</th>
                  <th>Enabled</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {hosts.map((h) => (
                  <tr key={h.id}>
                    <td>
                      <input
                        type="checkbox"
                        checked={selectedHostIds.has(h.id)}
                        onChange={() => toggleHostSelection(h.id)}
                      />
                    </td>
                    <td><strong>{h.hostname}</strong></td>
                    <td>{h.mgmt_ip || '-'}</td>
                    <td><code>{h.ssh_port || 22}</code></td>
                    <td>
                      {h.vlan_name ? (
                        <span>{h.vlan_name} <code>({h.vlan_tag})</code></span>
                      ) : (
                        '-'
                      )}
                    </td>
                    <td>
                      {h.tags && h.tags.length > 0 ? (
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                          {h.tags.map((tag: any) => (
                            <span key={tag.id} style={{ background: '#e3f2fd', padding: '2px 8px', borderRadius: 4, fontSize: '0.85em' }}>
                              {tag.name}
                            </span>
                          ))}
                        </div>
                      ) : (
                        '-'
                      )}
                    </td>
                    <td><code>{h.firewall_backend || 'auto'}</code></td>
                    <td>
                      {complianceStatuses.has(h.id) ? (
                        (() => {
                          const status = complianceStatuses.get(h.id);
                          const color = status.status === 'compliant' ? '#4caf50' : status.status === 'drifted' ? '#ff9800' : status.status === 'unknown' ? '#9e9e9e' : '#f44336';
                          const label = status.status === 'compliant' ? 'Compliant' : status.status === 'drifted' ? 'Drifted' : status.status === 'unknown' ? 'Unknown' : 'Error';
                          return (
                            <span style={{ color, fontWeight: 500, fontSize: '0.9em' }}>
                              {label}
                            </span>
                          );
                        })()
                      ) : (
                        <span style={{ color: '#999', fontSize: '0.85em' }}>-</span>
                      )}
                      {checkingCompliance.has(h.id) && (
                        <span style={{ marginLeft: 8, fontSize: '0.8em', color: '#666' }}>Checking...</span>
                      )}
                    </td>
                    <td>{h.enabled ? '✓' : '✗'}</td>
                    <td>
                      <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                        <button onClick={() => editHost(h)} className="btn-small btn-secondary">Edit</button>
                        <div className="tooltip-wrapper">
                          <button 
                            onClick={() => checkHostCompliance(h.id)} 
                            className="btn-small"
                            disabled={checkingCompliance.has(h.id) || !h.enabled}
                          >
                            Check Compliance
                          </button>
                          <div className="tooltip">
                            Compare current firewall rules on this host to the last successfully deployed policy. Detects configuration drift, manual changes, or failed deployments.
                          </div>
                        </div>
                        <div className="tooltip-wrapper">
                          <button 
                            onClick={() => checkHostReadiness(h.id)} 
                            className="btn-small"
                            disabled={checkingReadiness.has(h.id) || !h.enabled}
                          >
                            Check Readiness
                          </button>
                          <div className="tooltip">
                            Verify this host is ready for deployments. Checks for firewall tools (nft/iptables), passwordless sudo access, kernel support, and auto-detects firewall backend.
                          </div>
                        </div>
                        <button 
                          onClick={() => setVisualizationHost({ id: h.id, hostname: h.hostname })} 
                          className="btn-small"
                          disabled={!h.enabled}
                          title="View visual diagram of firewall policies"
                        >
                          View Visualization
                        </button>
                      </div>
                      {readinessResults.has(h.id) && (
                        <div style={{ marginTop: 4, fontSize: '0.85em' }}>
                          {(() => {
                            const result = readinessResults.get(h.id);
                            return (
                              <div style={{ 
                                padding: 8, 
                                background: result.ready ? '#e8f5e9' : '#ffebee', 
                                borderRadius: 4,
                                marginTop: 4
                              }}>
                                <strong>{result.ready ? '✓ Ready' : '✗ Not Ready'}</strong>
                                {result.backend !== 'unknown' && (
                                  <div>Backend: {result.backend}</div>
                                )}
                                {result.errors.length > 0 && (
                                  <div style={{ color: '#d32f2f', marginTop: 4 }}>
                                    {result.errors.map((e: string, i: number) => (
                                      <div key={i}>• {e}</div>
                                    ))}
                                  </div>
                                )}
                                {result.warnings.length > 0 && (
                                  <div style={{ color: '#f57c00', marginTop: 4 }}>
                                    {result.warnings.map((w: string, i: number) => (
                                      <div key={i}>⚠ {w}</div>
                                    ))}
                                  </div>
                                )}
                              </div>
                            );
                          })()}
                        </div>
                      )}
                    </td>
                  </tr>
                ))}
                {hosts.length === 0 && (
                  <tr>
                    <td colSpan={10} className="empty-state">
                      No hosts found. {searchQuery || filterTag || filterVlan || filterEnabled !== 'all' ? 'Try adjusting your filters.' : 'Add a host above.'}
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
        </>
      )}

      {/* Tags Tab */}
      {activeTab === 'tags' && (
        <>
          <div className="card">
            <h3>{editingTag ? 'Edit Tag' : 'Create Tag'}</h3>
            <div className="form-grid">
              <div className="form-group">
                <label>Name *</label>
                <input
                  type="text"
                  value={tagName}
                  onChange={(e) => setTagName(e.target.value)}
                  placeholder="e.g., web-servers"
                />
              </div>
              <div className="form-group">
                <label>Description</label>
                <input
                  type="text"
                  value={tagDescription}
                  onChange={(e) => setTagDescription(e.target.value)}
                  placeholder="Optional description"
                />
              </div>
            </div>
            <div className="form-actions">
              <button
                disabled={!tagName.trim()}
                onClick={saveTag}
                className="btn-primary"
              >
                {editingTag ? 'Update' : 'Create'} Tag
              </button>
              {editingTag && (
                <button onClick={resetTagForm} className="btn-secondary">
                  Cancel
                </button>
              )}
            </div>
          </div>

          <div className="card">
            <h3>Tags</h3>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Description</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {tags.map((t) => (
                  <tr key={t.id}>
                    <td>
                      <strong>{t.name}</strong>
                      {t.is_system && <span style={{ marginLeft: 8, fontSize: '10px', padding: '1px 6px', borderRadius: 4, background: '#f0ebe2', color: '#8b6914', fontWeight: 600, verticalAlign: 'middle' }}>SYSTEM</span>}
                    </td>
                    <td>{t.description || '-'}</td>
                    <td>
                      <button onClick={() => editTag(t)} className="btn-small btn-secondary" style={{ marginRight: 8 }}>Edit</button>
                      {!t.is_system && <button onClick={() => deleteTag(t.id)} className="btn-small btn-danger">Delete</button>}
                      {t.is_system && <span style={{ fontSize: '11px', color: '#97846c' }}>Protected</span>}
                    </td>
                  </tr>
                ))}
                {tags.length === 0 && (
                  <tr>
                    <td colSpan={3} className="empty-state">
                      No tags found. Create a tag above.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </>
      )}

      {/* VLANs Tab */}
      {activeTab === 'vlans' && (
        <>
          <div className="card">
            <h3>{editingVlan ? 'Edit VLAN' : 'Create VLAN'}</h3>
            <div className="form-grid">
              <div className="form-group">
                <label>VLAN Tag *</label>
                <input
                  type="number"
                  value={vlanTag}
                  onChange={(e) => setVlanTag(e.target.value)}
                  placeholder="1-4094"
                  min="1"
                  max="4094"
                />
                <small>VLAN tag number (1-4094)</small>
              </div>
              <div className="form-group">
                <label>Name *</label>
                <input
                  type="text"
                  value={vlanName}
                  onChange={(e) => setVlanName(e.target.value)}
                  placeholder="e.g., Production Network"
                />
              </div>
              <div className="form-group">
                <label>Description</label>
                <input
                  type="text"
                  value={vlanDescription}
                  onChange={(e) => setVlanDescription(e.target.value)}
                  placeholder="Optional description"
                />
              </div>
              <div className="form-group">
                <label>Subnet</label>
                <input
                  type="text"
                  value={vlanSubnet}
                  onChange={(e) => setVlanSubnet(e.target.value)}
                  placeholder="e.g., 192.168.1.0/24"
                />
                <small>VLAN subnet in CIDR notation (e.g., 192.168.1.0/24)</small>
              </div>
            </div>
            <div className="form-actions">
              <button
                disabled={!vlanName.trim() || !vlanTag.trim()}
                onClick={saveVlan}
                className="btn-primary"
              >
                {editingVlan ? 'Update' : 'Create'} VLAN
              </button>
              {editingVlan && (
                <button onClick={resetVlanForm} className="btn-secondary">
                  Cancel
                </button>
              )}
            </div>
          </div>

          <div className="card">
            <h3>VLANs</h3>
            <table className="data-table">
              <thead>
                <tr>
                  <th>VLAN Tag</th>
                  <th>Name</th>
                  <th>Subnet</th>
                  <th>Description</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {vlans.map((v) => (
                  <tr key={v.id}>
                    <td><code>{v.vlan_tag}</code></td>
                    <td><strong>{v.name}</strong></td>
                    <td>{v.subnet ? <code>{v.subnet}</code> : '-'}</td>
                    <td>{v.description || '-'}</td>
                    <td>
                      <button onClick={() => editVlan(v)} className="btn-small btn-secondary" style={{ marginRight: 8 }}>Edit</button>
                      <button onClick={() => deleteVlan(v.id)} className="btn-small btn-danger">Delete</button>
                    </td>
                  </tr>
                ))}
                {vlans.length === 0 && (
                  <tr>
                    <td colSpan={5} className="empty-state">
                      No VLANs found. Create a VLAN above.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </>
      )}
      
      {/* Tag Rules Tab */}
      {activeTab === 'tag-rules' && (
        <>
          <div className="card">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
              <div>
                <h3 style={{ margin: 0 }}>Auto-Tagging Rules</h3>
                <p style={{ color: '#666', fontSize: '0.9em', margin: '4px 0 0' }}>
                  Define rules to automatically assign tags to hosts based on hostname, IP, OS, VLAN, or other attributes.
                  Rules are evaluated every 5 minutes and on-demand. Manual tags are never overwritten.
                </p>
              </div>
              <div style={{ display: 'flex', gap: 8 }}>
                <button onClick={evaluateAllRules} disabled={evaluatingAll} className="btn-secondary">
                  {evaluatingAll ? 'Running...' : 'Run All Rules Now'}
                </button>
                <button onClick={() => { resetTagRuleForm(); setShowTagRuleForm(true); }} className="btn-primary">
                  + Create Tag Rule
                </button>
              </div>
            </div>
          </div>

          {/* Rule Form */}
          {showTagRuleForm && (
            <div className="card" style={{ border: '2px solid #646cff' }}>
              <h3>{editingTagRule ? 'Edit Tag Rule' : 'Create Tag Rule'}</h3>

              <div className="form-grid" style={{ gridTemplateColumns: '1fr 1fr 1fr 1fr' }}>
                <div className="form-group">
                  <label>Rule Name *</label>
                  <input type="text" value={tagRuleForm.name} onChange={e => setTagRuleForm(f => ({ ...f, name: e.target.value }))}
                    placeholder="e.g., Web Servers by Hostname" />
                </div>
                <div className="form-group">
                  <label>Assign Tag *</label>
                  <select value={tagRuleForm.tagId} onChange={e => setTagRuleForm(f => ({ ...f, tagId: e.target.value }))}>
                    <option value="">Select a tag...</option>
                    {tags.map(t => <option key={t.id} value={t.id}>{t.name}</option>)}
                  </select>
                </div>
                <div className="form-group">
                  <label>Priority</label>
                  <input type="number" value={tagRuleForm.priority} onChange={e => setTagRuleForm(f => ({ ...f, priority: parseInt(e.target.value) || 0 }))}
                    placeholder="0" />
                  <small>Higher priority rules evaluate first</small>
                </div>
                <div className="form-group">
                  <label>Status</label>
                  <label style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 8 }}>
                    <input type="checkbox" checked={tagRuleForm.enabled} onChange={e => setTagRuleForm(f => ({ ...f, enabled: e.target.checked }))} />
                    Enabled
                  </label>
                </div>
              </div>

              {/* Conditions */}
              <div style={{ marginTop: 16 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 16, marginBottom: 12 }}>
                  <strong>Conditions</strong>
                  <span style={{ fontSize: '0.9em', color: '#666' }}>Match hosts where</span>
                  <label style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                    <input type="radio" checked={tagRuleForm.logic === 'AND'} onChange={() => setTagRuleForm(f => ({ ...f, logic: 'AND' }))} />
                    ALL conditions match (AND)
                  </label>
                  <label style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                    <input type="radio" checked={tagRuleForm.logic === 'OR'} onChange={() => setTagRuleForm(f => ({ ...f, logic: 'OR' }))} />
                    ANY condition matches (OR)
                  </label>
                </div>

                {tagRuleForm.conditions.map((cond, i) => (
                  <div key={i} style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 8, padding: 8, background: '#f9f9f9', borderRadius: 4 }}>
                    <select value={cond.field} onChange={e => updateCondition(i, 'field', e.target.value)} style={{ width: 180 }}>
                      {FIELD_OPTIONS.map(f => <option key={f.value} value={f.value}>{f.label}</option>)}
                    </select>
                    <select value={cond.operator} onChange={e => updateCondition(i, 'operator', e.target.value)} style={{ width: 180 }}>
                      {(OPERATOR_OPTIONS[cond.field] || []).map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                    </select>
                    <input type="text" value={cond.value} onChange={e => updateCondition(i, 'value', e.target.value)}
                      placeholder={
                        cond.operator === 'matches' ? 'Regex pattern (e.g., ^web.*)' :
                        cond.operator === 'in_cidr' ? 'CIDR range (e.g., 10.0.1.0/24)' :
                        cond.operator === 'contains' ? 'Text to find (e.g., acme.com)' :
                        cond.operator === 'has_tag' ? 'Tag name' :
                        'Value'
                      }
                      style={{ flex: 1 }} />
                    {tagRuleForm.conditions.length > 1 && (
                      <button onClick={() => removeCondition(i)} className="btn-small btn-danger">Remove</button>
                    )}
                  </div>
                ))}
                <button onClick={addCondition} className="btn-small btn-secondary" style={{ marginTop: 4 }}>+ Add Condition</button>
              </div>

              {/* Preview */}
              {previewHosts !== null && (
                <div style={{ marginTop: 16, padding: 12, background: '#E8F5E9', borderRadius: 4 }}>
                  <strong>{previewHosts.length} host(s) would match this rule:</strong>
                  {previewHosts.length > 0 ? (
                    <div style={{ marginTop: 8, display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                      {previewHosts.slice(0, 30).map((h: any) => (
                        <span key={h.id} style={{ padding: '2px 8px', background: 'white', borderRadius: 4, fontSize: '0.85em', border: '1px solid #C8E6C9' }}>
                          {h.hostname} <code style={{ fontSize: '0.8em' }}>({h.mgmt_ip})</code>
                        </span>
                      ))}
                      {previewHosts.length > 30 && <span style={{ fontSize: '0.85em', color: '#666' }}>...and {previewHosts.length - 30} more</span>}
                    </div>
                  ) : (
                    <p style={{ color: '#666', margin: '4px 0 0' }}>No hosts match the current conditions.</p>
                  )}
                </div>
              )}

              {/* Actions */}
              <div className="form-actions" style={{ marginTop: 16 }}>
                <button onClick={previewTagRule} className="btn-secondary">Preview Matches</button>
                <button onClick={saveTagRule} disabled={!tagRuleForm.name.trim() || !tagRuleForm.tagId} className="btn-primary">
                  {editingTagRule ? 'Update Rule' : 'Save Rule'}
                </button>
                <button onClick={resetTagRuleForm} className="btn-secondary">Cancel</button>
              </div>
            </div>
          )}

          {/* Rules Table */}
          <div className="card">
            <h3>Tag Rules</h3>
            {tagRulesLoading ? <p>Loading...</p> : (
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Rule Name</th>
                    <th>Target Tag</th>
                    <th>Conditions</th>
                    <th>Status</th>
                    <th>Matched</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {tagRules.map(rule => {
                    const criteria = typeof rule.criteria === 'string' ? JSON.parse(rule.criteria) : rule.criteria;
                    const conditions = criteria?.conditions || [];
                    return (
                      <tr key={rule.id}>
                        <td><strong>{rule.name}</strong></td>
                        <td><span style={{ padding: '2px 8px', background: '#E3F2FD', borderRadius: 4, fontSize: '0.85em' }}>{rule.tag_name || rule.tag_id}</span></td>
                        <td style={{ fontSize: '0.85em' }}>
                          {conditions.map((c: any, i: number) => (
                            <span key={i}>
                              {i > 0 && <strong style={{ margin: '0 4px', color: '#646cff' }}>{criteria.logic}</strong>}
                              <code>{c.field}</code> {c.operator} <code>{c.value}</code>
                            </span>
                          ))}
                        </td>
                        <td>
                          <span style={{ color: rule.enabled ? '#4CAF50' : '#999', fontWeight: 'bold' }}>
                            {rule.enabled ? 'Enabled' : 'Disabled'}
                          </span>
                        </td>
                        <td>
                          <strong>{rule.matched_count || 0}</strong> hosts
                        </td>
                        <td>
                          <button onClick={() => evaluateSingleRule(rule.id)} className="btn-small btn-secondary" style={{ marginRight: 4 }}>Evaluate</button>
                          <button onClick={() => startEditTagRule(rule)} className="btn-small btn-secondary" style={{ marginRight: 4 }}>Edit</button>
                          <button onClick={() => deleteTagRule(rule.id)} className="btn-small btn-danger">Delete</button>
                        </td>
                      </tr>
                    );
                  })}
                  {tagRules.length === 0 && (
                    <tr>
                      <td colSpan={6} className="empty-state">
                        No tag rules defined. Create a rule to automatically assign tags to hosts based on their attributes.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            )}
          </div>

          {/* Examples / Help */}
          <div className="card" style={{ background: '#FAFAFA' }}>
            <h4 style={{ marginTop: 0 }}>Examples</h4>
            <table style={{ width: '100%', fontSize: '0.9em' }}>
              <thead><tr><th>Goal</th><th>Field</th><th>Operator</th><th>Value</th></tr></thead>
              <tbody>
                <tr><td>Tag all web servers</td><td><code>hostname</code></td><td>matches (regex)</td><td><code>^web-.*</code></td></tr>
                <tr><td>Tag all acme.com hosts</td><td><code>hostname</code></td><td>contains</td><td><code>acme.com</code></td></tr>
                <tr><td>Tag hosts in a subnet</td><td><code>mgmt_ip</code></td><td>in CIDR range</td><td><code>10.0.1.0/24</code></td></tr>
                <tr><td>Tag RedHat servers</td><td><code>os_family</code></td><td>equals</td><td><code>rhel</code></td></tr>
                <tr><td>Tag VLAN 100 hosts</td><td><code>vlan_tag</code></td><td>equals</td><td><code>100</code></td></tr>
                <tr><td>Tag hosts with existing tag</td><td><code>tag</code></td><td>has tag</td><td><code>production</code></td></tr>
              </tbody>
            </table>
            <p style={{ fontSize: '0.85em', color: '#666', marginBottom: 0 }}>
              Multiple conditions can be combined with AND (all must match) or OR (any can match).
              A host can match multiple rules and receive multiple tags.
              Use <strong>"Run All Rules Now"</strong> to retroactively apply rules to existing hosts.
            </p>
          </div>
        </>
      )}

      {visualizationHost && (
        <HostPolicyVisualization
          hostId={visualizationHost.id}
          hostname={visualizationHost.hostname}
          onClose={() => setVisualizationHost(null)}
        />
      )}
    </div>
  );
}
