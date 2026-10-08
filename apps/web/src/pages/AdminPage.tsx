import { useEffect, useState } from 'react';

import { api, errorMessage } from '../lib/api';

type SudoMode = 'NOPASSWD' | 'LOGIN_PASSWORD' | 'SUDO_PASSWORD';

const SUDO_MODE_LABELS: Record<SudoMode, string> = {
  NOPASSWD: 'sudo without password',
  LOGIN_PASSWORD: 'sudo with the login password',
  SUDO_PASSWORD: 'sudo with a separate password'
};

type ScopeType = 'GLOBAL' | 'TAG' | 'VLAN' | 'HOST' | 'NONE';

const SCOPE_OPTIONS: Array<{ value: ScopeType; label: string }> = [
  { value: 'GLOBAL', label: 'All hosts (global)' },
  { value: 'TAG', label: 'Hosts with tag' },
  { value: 'VLAN', label: 'Hosts in VLAN' },
  { value: 'HOST', label: 'A specific host' },
  { value: 'NONE', label: 'Not assigned (manual use)' }
];

/** "Applies to" text for a credential row from GET /ssh-credentials. */
function appliesToLabel(c: any): string {
  const missing = '(deleted)';
  switch (c.scope_type) {
    case 'GLOBAL': return 'All hosts (global)';
    case 'TAG': return `Hosts with tag ${c.scope_name ?? missing}`;
    case 'VLAN': return `Hosts in ${c.scope_name ?? `VLAN ${missing}`}`;
    case 'HOST': return `Host ${c.scope_name ?? missing}`;
    case 'NONE': return 'Not assigned (manual use)';
    default: return c.scope_type;
  }
}

/** "Applies to" select plus the matching tag / VLAN / host picker. */
function ScopePicker(props: {
  scopeType: ScopeType;
  scopeId: string;
  onChange: (scopeType: ScopeType, scopeId: string) => void;
  tags: any[];
  vlans: any[];
  hosts: any[];
}) {
  const { scopeType, scopeId, onChange, tags, vlans, hosts } = props;
  const items: Array<{ id: string; label: string }> =
    scopeType === 'TAG' ? tags.map((t) => ({ id: t.id, label: t.name }))
      : scopeType === 'VLAN' ? vlans.map((v) => ({ id: v.id, label: `VLAN ${v.vlan_tag} (${v.name})` }))
        : scopeType === 'HOST' ? hosts.map((h) => ({ id: h.id, label: `${h.hostname}${h.mgmt_ip ? ` (${h.mgmt_ip})` : ''}` }))
          : [];
  return (
    <>
      <div className="form-group">
        <label>Applies to *</label>
        <select value={scopeType} onChange={(e) => onChange(e.target.value as ScopeType, '')}>
          {SCOPE_OPTIONS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
        </select>
        <small>
          {scopeType === 'GLOBAL' && 'Default for every host that has no more specific credential (the newest global one wins).'}
          {scopeType === 'TAG' && 'Used for hosts carrying this tag (beats VLAN and global credentials).'}
          {scopeType === 'VLAN' && "Used for hosts in this VLAN that have no host- or tag-scoped credential."}
          {scopeType === 'HOST' && 'Used for this host only (beats tag, VLAN and global credentials).'}
          {scopeType === 'NONE' && 'Never chosen automatically: for discovery target sets or explicit assignment to a host (Inventory → edit host).'}
        </small>
      </div>
      {(scopeType === 'TAG' || scopeType === 'VLAN' || scopeType === 'HOST') && (
        <div className="form-group">
          <label>{scopeType === 'TAG' ? 'Tag' : scopeType === 'VLAN' ? 'VLAN' : 'Host'} *</label>
          <select value={scopeId} onChange={(e) => onChange(scopeType, e.target.value)}>
            <option value="">Select…</option>
            {items.map((i) => <option key={i.id} value={i.id}>{i.label}</option>)}
          </select>
        </div>
      )}
    </>
  );
}

export function AdminPage() {
  const [ldap, setLdap] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string>('');
  const [success, setSuccess] = useState<string>('');
  
  // LDAP form state
  const [url, setUrl] = useState('ldaps://ad.example.com:636');
  const [baseDn, setBaseDn] = useState('DC=example,DC=com');
  const [bindDn, setBindDn] = useState('');
  const [bindPassword, setBindPassword] = useState('');
  const [useLdaps, setUseLdaps] = useState(true);
  const [ldapEnabled, setLdapEnabled] = useState(false);
  const [userFilter, setUserFilter] = useState('(sAMAccountName={{username}})');
  const [groupFilter, setGroupFilter] = useState('');

  // AD Group mapping form state
  const [adGroupDn, setAdGroupDn] = useState('');
  const [groupMaps, setGroupMaps] = useState<Array<{ id: string; ad_group_dn: string; role_name: string }>>([]);
  const [confirmDeleteMapId, setConfirmDeleteMapId] = useState<string | null>(null);
  const [roleName, setRoleName] = useState<'viewer' | 'operator' | 'approver' | 'admin'>('admin');

  // SSH Credentials form state
  const [sshName, setSshName] = useState('global');
  const [sshUser, setSshUser] = useState('root');
  const [sshKey, setSshKey] = useState('');
  const [sshAuthMethod, setSshAuthMethod] = useState<'KEY' | 'PASSWORD'>('KEY');
  const [sshPassword, setSshPassword] = useState('');
  const [sshPassphrase, setSshPassphrase] = useState('');
  const [sshSudoMode, setSshSudoMode] = useState<SudoMode>('NOPASSWD');
  const [sshSudoPassword, setSshSudoPassword] = useState('');
  const [sshCreds, setSshCreds] = useState<any[]>([]);
  const [showSshForm, setShowSshForm] = useState(false);
  const [sshScopeType, setSshScopeType] = useState<ScopeType>('GLOBAL');
  const [sshScopeId, setSshScopeId] = useState('');
  const [sshPriority, setSshPriority] = useState('0');
  const [scopeTags, setScopeTags] = useState<any[]>([]);
  const [scopeHosts, setScopeHosts] = useState<any[]>([]);
  // Edit of an existing credential (name / scope / priority; secrets are not re-entered)
  const [editCred, setEditCred] = useState<{ id: string; name: string; scopeType: ScopeType; scopeId: string; priority: string; authMethod: string; password: string } | null>(null);

  // Executor setting
  const [executor, setExecutor] = useState<'ansible' | 'ssh'>('ansible');
  // null = not loaded yet / failed to load; save is disabled until the real value is known
  const [executorLoaded, setExecutorLoaded] = useState(false);
  const [executorError, setExecutorError] = useState<string>('');

  // Management VLAN setting
  const [managementVlan, setManagementVlan] = useState<any>(null);
  const [vlans, setVlans] = useState<any[]>([]);
  const [selectedManagementVlanId, setSelectedManagementVlanId] = useState<string>('');

  // Local users state
  const [users, setUsers] = useState<any[]>([]);
  const [showUserForm, setShowUserForm] = useState(false);
  const [editingUser, setEditingUser] = useState<any>(null);
  const [userForm, setUserForm] = useState({ username: '', displayName: '', email: '', password: '', roles: ['viewer'] as string[], isActive: true });
  const [resetPasswordUserId, setResetPasswordUserId] = useState<string | null>(null);
  const [newPassword, setNewPassword] = useState('');

  useEffect(() => {
    loadData();
  }, []);

  async function loadData() {
    try {
      const [ldapRes, sshRes, executorRes, mgmtVlanRes, vlansRes] = await Promise.all([
        api.ldapSettings().catch(() => ({ ldapSettings: null })),
        api.sshCredentials().catch(() => ({ sshCredentials: [] })),
        api.executorSetting().then(
          (r) => ({ ok: true as const, executor: r.executor }),
          (e: any) => ({ ok: false as const, error: String(e?.message ?? e) })
        ),
        api.managementVlanSetting().catch(() => ({ managementVlan: null })),
        api.vlans().catch(() => ({ vlans: [] }))
      ]);
      
      const ldapSettings = ldapRes.ldapSettings;
      setLdap(ldapSettings);
      api.groupMaps().then((r) => setGroupMaps(r.maps || [])).catch(() => setGroupMaps([]));
      
      if (ldapSettings) {
        setUrl(ldapSettings.url || 'ldaps://ad.example.com:636');
        setBaseDn(ldapSettings.base_dn || 'DC=example,DC=com');
        setBindDn(ldapSettings.bind_dn || '');
        setUseLdaps(ldapSettings.use_ldaps !== false);
        setLdapEnabled(ldapSettings.enabled !== false);
        setUserFilter(ldapSettings.user_filter ?? '');
        setGroupFilter(ldapSettings.group_filter ?? '');
      }
      
      setSshCreds(sshRes.sshCredentials || []);
      // Pickers for the credential "Applies to" scope
      api.tags().then((r) => setScopeTags(r.tags || []), () => setScopeTags([]));
      api.allHosts().then((r: any) => setScopeHosts(r.hosts || []), () => setScopeHosts([]));
      if (executorRes.ok) {
        setExecutor(executorRes.executor === 'ssh' ? 'ssh' : 'ansible');
        setExecutorLoaded(true);
        setExecutorError('');
      } else {
        setExecutorLoaded(false);
        setExecutorError(`Could not load the current executor setting: ${executorRes.error}`);
      }
      
      setManagementVlan(mgmtVlanRes.managementVlan);
      setVlans(vlansRes.vlans || []);
      setSelectedManagementVlanId(mgmtVlanRes.managementVlan?.id || '');

      // Load users
      try {
        const usersRes = await api.users.list();
        setUsers(usersRes.users || []);
      } catch { /* users endpoint may fail for non-admin */ }
    } catch (e: any) {
      setError(String(e?.message ?? e));
    }
  }

  async function saveExecutorSetting() {
    setLoading(true);
    setError('');
    setSuccess('');
    
    try {
      const r = await api.putExecutorSetting({ executor });
      setExecutor(r.executor as 'ansible' | 'ssh');
      setSuccess(`Deployment executor set to ${r.executor.toUpperCase()}`);
      setTimeout(() => setSuccess(''), 3000);
    } catch (e: any) {
      setError(String(e?.message ?? e));
    } finally {
      setLoading(false);
    }
  }

  async function saveManagementVlanSetting() {
    setLoading(true);
    setError('');
    setSuccess('');
    
    try {
      const r = await api.putManagementVlanSetting({ vlanId: selectedManagementVlanId || null });
      setManagementVlan(r.managementVlan);
      if (r.managementVlan) {
        setSuccess(`Management VLAN set to ${r.managementVlan.name} (VLAN ${r.managementVlan.vlan_tag})`);
      } else {
        setSuccess('Management VLAN cleared (baseline SSH access disabled)');
      }
      setTimeout(() => setSuccess(''), 3000);
    } catch (e: any) {
      setError(String(e?.message ?? e));
    } finally {
      setLoading(false);
    }
  }

  async function createUser() {
    if (!userForm.username.trim() || !userForm.displayName.trim() || !userForm.password.trim()) {
      setError('Username, display name, and password are required');
      return;
    }
    if (userForm.password.length < 8) {
      setError('Password must be at least 8 characters');
      return;
    }
    setLoading(true); setError(''); setSuccess('');
    try {
      await api.users.create({
        username: userForm.username.trim(),
        displayName: userForm.displayName.trim(),
        email: userForm.email.trim() || undefined,
        password: userForm.password,
        roles: userForm.roles,
        isActive: userForm.isActive,
      });
      setSuccess(`User "${userForm.username}" created successfully`);
      setShowUserForm(false);
      setUserForm({ username: '', displayName: '', email: '', password: '', roles: ['viewer'], isActive: true });
      loadData();
      setTimeout(() => setSuccess(''), 3000);
    } catch (e: any) { setError(errorMessage(e)); }
    finally { setLoading(false); }
  }

  async function updateUser() {
    if (!editingUser) return;
    setLoading(true); setError(''); setSuccess('');
    try {
      // Only send email when it changed: '' (cleared) -> explicit null, unchanged -> omitted.
      const newEmail = userForm.email.trim();
      const oldEmail = (editingUser.email ?? '').trim();
      const body: any = {
        displayName: userForm.displayName.trim() || undefined,
        roles: userForm.roles,
        isActive: userForm.isActive,
      };
      if (newEmail !== oldEmail) body.email = newEmail === '' ? null : newEmail;
      await api.users.update(editingUser.id, body);
      setSuccess(`User "${editingUser.username}" updated`);
      setEditingUser(null);
      setShowUserForm(false);
      loadData();
      setTimeout(() => setSuccess(''), 3000);
    } catch (e: any) { setError(errorMessage(e)); }
    finally { setLoading(false); }
  }

  async function resetUserPassword() {
    if (!resetPasswordUserId || newPassword.length < 8) {
      setError('Password must be at least 8 characters');
      return;
    }
    setLoading(true); setError(''); setSuccess('');
    try {
      await api.users.resetPassword(resetPasswordUserId, newPassword);
      setSuccess('Password reset successfully');
      setResetPasswordUserId(null);
      setNewPassword('');
      setTimeout(() => setSuccess(''), 3000);
    } catch (e: any) { setError(String(e?.message ?? e)); }
    finally { setLoading(false); }
  }

  async function deleteUser(id: string, username: string) {
    if (!confirm(`Delete user "${username}"? This cannot be undone.`)) return;
    setError(''); setSuccess('');
    try {
      await api.users.delete(id);
      setSuccess(`User "${username}" deleted`);
      loadData();
      setTimeout(() => setSuccess(''), 3000);
    } catch (e: any) { setError(String(e?.message ?? e)); }
  }

  function startEditUser(u: any) {
    setEditingUser(u);
    setUserForm({
      username: u.username,
      displayName: u.display_name || '',
      email: u.email || '',
      password: '',
      roles: u.roles || ['viewer'],
      isActive: u.is_active,
    });
    setShowUserForm(true);
  }

  async function saveLdapSettings() {
    if (!url.trim() || !baseDn.trim()) {
      setError('URL and Base DN are required');
      return;
    }
    
    setLoading(true);
    setError('');
    setSuccess('');
    
    try {
      const body: any = {
        enabled: ldapEnabled,
        url: url.trim(),
        baseDn: baseDn.trim(),
        bindDn: bindDn.trim() || undefined,
        userFilter: userFilter.trim() || undefined,
        groupFilter: groupFilter.trim() || undefined,
        useLdaps: useLdaps
      };
      // Omit bindPassword entirely when blank so the API keeps the existing secret.
      if (bindPassword !== '') body.bindPassword = bindPassword;
      const r = await api.putLdapSettings(body);
      setLdap(r.ldapSettings);
      if (r.ldapSettings) {
        setUserFilter(r.ldapSettings.user_filter ?? userFilter);
        setGroupFilter(r.ldapSettings.group_filter ?? groupFilter);
      }
      setSuccess('LDAP settings saved successfully');
      setBindPassword(''); // Clear password field
      setTimeout(() => setSuccess(''), 3000);
    } catch (e: any) {
      setError(String(e?.message ?? e));
    } finally {
      setLoading(false);
    }
  }

  async function addGroupMap() {
    if (!adGroupDn.trim()) {
      setError('AD Group DN is required');
      return;
    }
    
    setLoading(true);
    setError('');
    setSuccess('');
    
    try {
      await api.addGroupMap({ adGroupDn: adGroupDn.trim(), roleName });
      setSuccess(`AD Group mapping added: ${adGroupDn} → ${roleName}`);
      setAdGroupDn('');
      setGroupMaps((await api.groupMaps()).maps || []);
      setTimeout(() => setSuccess(''), 3000);
    } catch (e: any) {
      setError(String(e?.message ?? e));
    } finally {
      setLoading(false);
    }
  }

  async function deleteGroupMap(id: string) {
    setError('');
    try {
      await api.deleteGroupMap(id);
      setGroupMaps((m) => m.filter((x) => x.id !== id));
      setConfirmDeleteMapId(null);
    } catch (e: any) {
      setError(String(e?.message ?? e));
    }
  }

  function resetSshForm() {
    setSshName('global');
    setSshUser('root');
    setSshKey('');
    setSshPassword('');
    setSshPassphrase('');
    setSshSudoMode('NOPASSWD');
    setSshSudoPassword('');
    setSshAuthMethod('KEY');
    setSshScopeType('GLOBAL');
    setSshScopeId('');
    setSshPriority('0');
  }

  const patchEdit = (patch: Partial<{ name: string; scopeType: ScopeType; scopeId: string; priority: string; password: string }>) =>
    setEditCred((cur) => (cur ? { ...cur, ...patch } : cur));

  const scopeNeedsId = (t: ScopeType) => t === 'TAG' || t === 'VLAN' || t === 'HOST';

  async function saveCredentialEdit() {
    if (!editCred) return;
    if (!editCred.name.trim()) { setError('Name is required'); return; }
    if (scopeNeedsId(editCred.scopeType) && !editCred.scopeId) { setError('Choose what the credential applies to'); return; }
    setLoading(true);
    setError('');
    setSuccess('');
    try {
      await api.updateSshCredential(editCred.id, {
        name: editCred.name.trim(),
        scopeType: editCred.scopeType,
        scopeId: scopeNeedsId(editCred.scopeType) ? editCred.scopeId : null,
        priority: parseInt(editCred.priority, 10) || 0,
        ...(editCred.authMethod === 'PASSWORD' && editCred.password ? { password: editCred.password } : {})
      });
      setEditCred(null);
      setSuccess('SSH credential updated');
      await loadData();
      setTimeout(() => setSuccess(''), 3000);
    } catch (e: any) {
      setError(errorMessage(e));
    } finally {
      setLoading(false);
    }
  }

  async function deleteCredential(c: any) {
    if (!window.confirm(`Delete SSH credential "${c.name}"? Hosts that use it will fall back to the next matching credential.`)) return;
    setError('');
    setSuccess('');
    try {
      await api.deleteSshCredential(c.id);
      setSuccess('SSH credential deleted');
      await loadData();
      setTimeout(() => setSuccess(''), 3000);
    } catch (e: any) {
      setError(errorMessage(e));
    }
  }

  const sshFormIncomplete =
    !sshName.trim() ||
    !sshUser.trim() ||
    (sshAuthMethod === 'KEY' ? !sshKey.trim() : !sshPassword) ||
    (sshSudoMode === 'SUDO_PASSWORD' && !sshSudoPassword) ||
    (scopeNeedsId(sshScopeType) && !sshScopeId);

  async function saveSshCredential() {
    if (sshFormIncomplete) {
      setError(
        sshSudoMode === 'SUDO_PASSWORD' && !sshSudoPassword
          ? 'Enter the sudo password, or choose another privilege escalation option'
          : sshAuthMethod === 'KEY' ? 'Name, username, and private key are required' : 'Name, username, and password are required'
      );
      return;
    }
    
    setLoading(true);
    setError('');
    setSuccess('');
    
    try {
      const sudo = {
        sudoMode: sshSudoMode,
        ...(sshSudoMode === 'SUDO_PASSWORD' ? { sudoPassword: sshSudoPassword } : {}),
        scopeType: sshScopeType,
        ...(scopeNeedsId(sshScopeType) ? { scopeId: sshScopeId } : {}),
        priority: parseInt(sshPriority, 10) || 0
      };
      await api.createSshCredential(
        sshAuthMethod === 'KEY'
          ? {
              name: sshName.trim(), username: sshUser.trim(), authMethod: 'KEY', privateKeyPem: sshKey.trim(),
              ...(sshPassphrase ? { passphrase: sshPassphrase } : {}), ...sudo
            }
          : { name: sshName.trim(), username: sshUser.trim(), authMethod: 'PASSWORD', password: sshPassword, ...sudo }
      );
      setSuccess('SSH credential saved successfully');
      resetSshForm();
      setShowSshForm(false);
      await loadData();
      setTimeout(() => setSuccess(''), 3000);
    } catch (e: any) {
      setError(String(e?.message ?? e));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="page">
      <div className="page-header">
        <h2>Administration</h2>
      </div>

      {error && <div className="error-banner">{error}</div>}
      {success && (
        <div style={{
          background: '#e8f5e9',
          color: '#2e7d32',
          padding: 12,
          borderRadius: 8,
          marginBottom: 20,
          borderLeft: '4px solid #4CAF50'
        }}>
          {success}
        </div>
      )}

      {/* Local Users Management */}
      <div className="card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <h3 style={{ margin: 0 }}>Local Users</h3>
          <button onClick={() => { setEditingUser(null); setUserForm({ username: '', displayName: '', email: '', password: '', roles: ['viewer'], isActive: true }); setShowUserForm(true); }} className="btn-primary">+ Create User</button>
        </div>
      </div>

      {showUserForm && (
        <div className="card" style={{ border: '2px solid #8b6914' }}>
          <h3>{editingUser ? `Edit User: ${editingUser.username}` : 'Create Local User'}</h3>
          <div className="form-grid">
            {!editingUser && (
              <div className="form-group">
                <label>Username *</label>
                <input value={userForm.username} onChange={e => setUserForm(f => ({ ...f, username: e.target.value }))} placeholder="e.g., john.doe" />
              </div>
            )}
            <div className="form-group">
              <label>Display Name *</label>
              <input value={userForm.displayName} onChange={e => setUserForm(f => ({ ...f, displayName: e.target.value }))} placeholder="e.g., John Doe" />
            </div>
            <div className="form-group">
              <label>Email</label>
              <input type="email" value={userForm.email} onChange={e => setUserForm(f => ({ ...f, email: e.target.value }))} placeholder="e.g., john@company.com" />
            </div>
            {!editingUser && (
              <div className="form-group">
                <label>Password *</label>
                <input type="password" value={userForm.password} onChange={e => setUserForm(f => ({ ...f, password: e.target.value }))} placeholder="Minimum 8 characters" />
              </div>
            )}
          </div>
          <div className="form-group" style={{ marginTop: 12 }}>
            <label>Roles *</label>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 12, marginTop: 6 }}>
              {['viewer', 'operator', 'approver', 'admin'].map(role => (
                <label key={role} style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer' }}>
                  <input type="checkbox" checked={userForm.roles.includes(role)}
                    onChange={e => setUserForm(f => ({ ...f, roles: e.target.checked ? [...f.roles, role] : f.roles.filter(r => r !== role) }))} />
                  <span style={{ textTransform: 'capitalize' }}>{role}</span>
                </label>
              ))}
            </div>
          </div>
          <div className="form-group" style={{ marginTop: 8 }}>
            <label style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <input type="checkbox" checked={userForm.isActive} onChange={e => setUserForm(f => ({ ...f, isActive: e.target.checked }))} />
              Account Active
            </label>
          </div>
          <div className="form-actions" style={{ marginTop: 16 }}>
            <button onClick={editingUser ? updateUser : createUser} className="btn-primary" disabled={loading || (!editingUser && (!userForm.username.trim() || !userForm.password.trim())) || !userForm.displayName.trim() || userForm.roles.length === 0}>
              {editingUser ? 'Update User' : 'Create User'}
            </button>
            <button onClick={() => { setShowUserForm(false); setEditingUser(null); }} className="btn-secondary">Cancel</button>
          </div>
        </div>
      )}

      {/* Password Reset Modal */}
      {resetPasswordUserId && (
        <div className="card" style={{ border: '2px solid #c47a1a', background: '#fdf6ec' }}>
          <h3>Reset Password</h3>
          <div className="form-group">
            <label>New Password *</label>
            <input type="password" value={newPassword} onChange={e => setNewPassword(e.target.value)} placeholder="Minimum 8 characters" />
          </div>
          <div className="form-actions" style={{ marginTop: 12 }}>
            <button onClick={resetUserPassword} className="btn-primary" disabled={loading || newPassword.length < 8}>Reset Password</button>
            <button onClick={() => { setResetPasswordUserId(null); setNewPassword(''); }} className="btn-secondary">Cancel</button>
          </div>
        </div>
      )}

      {/* Users Table */}
      <div className="card">
        <h3>All Users</h3>
        {users.length > 0 ? (
          <table className="data-table">
            <thead>
              <tr><th>Username</th><th>Display Name</th><th>Email</th><th>Roles</th><th>Type</th><th>Status</th><th>Last Login</th><th>Actions</th></tr>
            </thead>
            <tbody>
              {users.map(u => (
                <tr key={u.id}>
                  <td><strong>{u.username}</strong></td>
                  <td>{u.display_name || '-'}</td>
                  <td style={{ fontSize: '12.5px' }}>{u.email || '-'}</td>
                  <td>
                    {(u.roles || []).map((r: string) => (
                      <span key={r} style={{ display: 'inline-block', padding: '1px 8px', borderRadius: 4, fontSize: '11.5px', marginRight: 4, background: r === 'admin' ? '#fdf6ec' : '#f0ebe2', color: r === 'admin' ? '#8b6914' : '#5c4633', fontWeight: 500 }}>{r}</span>
                    ))}
                  </td>
                  <td style={{ fontSize: '12.5px' }}>{u.auth_type === 'local' ? 'Local' : 'LDAP'}</td>
                  <td><span style={{ color: u.is_active ? '#5a7a3a' : '#a63d2f', fontWeight: 600, fontSize: '12.5px' }}>{u.is_active ? 'Active' : 'Disabled'}</span></td>
                  <td style={{ fontSize: '12px', color: '#97846c' }}>{u.last_login_at ? new Date(u.last_login_at).toLocaleDateString() : 'Never'}</td>
                  <td>
                    <button onClick={() => startEditUser(u)} className="btn-small btn-secondary" style={{ marginRight: 4 }}>Edit</button>
                    {u.auth_type === 'local' && (
                      <button onClick={() => setResetPasswordUserId(u.id)} className="btn-small btn-secondary" style={{ marginRight: 4 }}>Reset PW</button>
                    )}
                    <button onClick={() => deleteUser(u.id, u.username)} className="btn-small btn-danger">Delete</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p style={{ color: '#97846c', fontStyle: 'italic' }}>No users found. Click "+ Create User" above to add a local user.</p>
        )}
      </div>

      {/* Deployment Executor Setting */}
      <div className="card">
        <h3>Deployment Executor</h3>
        <p style={{ marginBottom: 20, color: '#666', fontSize: '0.9em' }}>
          Choose how firewall rules are deployed to target hosts. SSH Direct is recommended: it adds lockout protection (automatic revert if SSH is lost) and canary/progressive rollouts, and does not need the Docker socket. Ansible runs the same steps through a playbook in the runner container and deploys all hosts in one run.
        </p>
        
        <div className="form-grid">
          <div className="form-group">
            <label>Executor Type *</label>
            {executorError && (
              <div className="error-banner" style={{ marginBottom: 8 }}>
                {executorError} <button type="button" className="btn-small" onClick={() => loadData()}>Retry</button>
              </div>
            )}
            <select
              value={executor}
              onChange={(e) => setExecutor(e.target.value as 'ansible' | 'ssh')}
              disabled={loading || !executorLoaded}
            >
              <option value="ansible">Ansible - runs the playbook in the runner container (needs the Docker socket)</option>
              <option value="ssh">SSH Direct (recommended) - lockout auto-revert, canary/progressive rollout, no Docker socket</option>
            </select>
            <small>
              {executor === 'ansible' 
                ? 'Uses Ansible playbook for deployments. Requires Ansible container.'
                : 'Uses direct SSH/SCP commands. Requires ssh and scp commands on the host.'}
            </small>
          </div>
        </div>
        
        <div className="form-actions">
          <button
            onClick={saveExecutorSetting}
            className="btn-primary"
            disabled={loading || !executorLoaded}
            title={!executorLoaded ? 'Current setting has not been loaded' : undefined}
          >
            {loading ? 'Saving...' : 'Save Executor Setting'}
          </button>
        </div>
      </div>

      {/* Management VLAN Setting */}
      <div className="card">
        <h3>Management VLAN (Baseline SSH Access)</h3>
        <p style={{ marginBottom: 20, color: '#666', fontSize: '0.9em' }}>
          Configure the default VLAN for baseline management SSH access. This allows administrators to SSH into hosts from the management network, regardless of other firewall rules. The VLAN's subnet will be used as the CIDR range for SSH access (port 22).
        </p>
        
        <div className="form-grid">
          <div className="form-group">
            <label>Management VLAN</label>
            <select
              value={selectedManagementVlanId}
              onChange={(e) => setSelectedManagementVlanId(e.target.value)}
              disabled={loading}
            >
              <option value="">None (disable baseline SSH access)</option>
              {vlans.map((v) => (
                <option key={v.id} value={v.id}>
                  {v.name} (VLAN {v.vlan_tag}){v.subnet ? ` - ${v.subnet}` : ''}
                </option>
              ))}
            </select>
            <small>
              {selectedManagementVlanId && managementVlan
                ? `Current: ${managementVlan.name} (VLAN ${managementVlan.vlan_tag})${managementVlan.subnet ? ` - Subnet: ${managementVlan.subnet}` : ' - No subnet configured'}`
                : 'Select a VLAN to enable baseline SSH access from that VLAN\'s subnet.'}
            </small>
            {selectedManagementVlanId && !vlans.find(v => v.id === selectedManagementVlanId)?.subnet && (
              <div style={{ marginTop: 8, padding: 8, background: '#fff3cd', borderRadius: 4, fontSize: '0.85em' }}>
                ⚠️ Warning: Selected VLAN does not have a subnet configured. Please configure the subnet in the Inventory → VLANs section.
              </div>
            )}
          </div>
        </div>
        
        <div className="form-actions">
          <button
            onClick={saveManagementVlanSetting}
            className="btn-primary"
            disabled={loading}
          >
            {loading ? 'Saving...' : 'Save Management VLAN Setting'}
          </button>
        </div>
      </div>

      {/* LDAP Settings */}
      <div className="card">
        <h3>LDAP / Active Directory Settings</h3>
        {ldap && (
          <div style={{
            background: '#f5f5f5',
            padding: 12,
            borderRadius: 8,
            marginBottom: 20,
            fontSize: '0.9em'
          }}>
            <strong>Current Configuration:</strong>
            <div style={{ marginTop: 8 }}>
              <div><strong>Status:</strong> {ldap.enabled ? <span style={{ color: '#4CAF50' }}>✓ Enabled</span> : <span style={{ color: '#999' }}>Disabled</span>}</div>
              <div><strong>URL:</strong> <code>{ldap.url}</code></div>
              <div><strong>Base DN:</strong> <code>{ldap.base_dn}</code></div>
              {ldap.bind_dn && <div><strong>Bind DN:</strong> <code>{ldap.bind_dn}</code></div>}
              {ldap.user_filter && <div><strong>User Filter:</strong> <code>{ldap.user_filter}</code></div>}
              {ldap.group_filter && <div><strong>Group Filter:</strong> <code>{ldap.group_filter}</code></div>}
              <div><strong>LDAPS:</strong> {ldap.use_ldaps ? 'Yes' : 'No'}</div>
              {ldap.created_at && <div><strong>Created:</strong> {new Date(ldap.created_at).toLocaleString()}</div>}
            </div>
          </div>
        )}
        
        <div className="form-grid">
          <div className="form-group">
            <label>Enabled</label>
            <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
              <input
                type="checkbox"
                checked={ldapEnabled}
                onChange={(e) => setLdapEnabled(e.target.checked)}
              />
              <span>Enable LDAP authentication</span>
            </label>
          </div>
          <div className="form-group">
            <label>LDAP URL *</label>
            <input
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="ldaps://ad.example.com:636"
            />
            <small>LDAP server URL (ldap:// or ldaps://)</small>
          </div>
          <div className="form-group">
            <label>Base DN *</label>
            <input
              type="text"
              value={baseDn}
              onChange={(e) => setBaseDn(e.target.value)}
              placeholder="DC=example,DC=com"
            />
            <small>Base distinguished name for user search</small>
          </div>
          <div className="form-group">
            <label>Bind DN</label>
            <input
              type="text"
              value={bindDn}
              onChange={(e) => setBindDn(e.target.value)}
              placeholder="CN=service,OU=Users,DC=example,DC=com"
            />
            <small>Optional: Service account DN for bind operations</small>
          </div>
          <div className="form-group">
            <label>Bind Password {ldap && <span style={{ fontWeight: 'normal', color: '#97846c' }}>(unchanged — leave blank to keep)</span>}</label>
            <input
              type="password"
              value={bindPassword}
              onChange={(e) => setBindPassword(e.target.value)}
              placeholder={ldap ? '(unchanged — leave blank to keep)' : 'Bind password'}
              autoComplete="new-password"
            />
            <small>Password for bind DN (stored encrypted). Leave empty to keep the existing password.</small>
          </div>
          <div className="form-group">
            <label>User Filter</label>
            <input
              type="text"
              value={userFilter}
              onChange={(e) => setUserFilter(e.target.value)}
              placeholder="(sAMAccountName={{username}})"
            />
            <small>LDAP filter used to find the user; {'{{username}}'} is replaced with the login name.</small>
          </div>
          <div className="form-group">
            <label>Group Filter</label>
            <input
              type="text"
              value={groupFilter}
              onChange={(e) => setGroupFilter(e.target.value)}
              placeholder="Optional"
            />
            <small>Optional LDAP filter for group membership lookups.</small>
          </div>
          <div className="form-group">
            <label>Use LDAPS</label>
            <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
              <input
                type="checkbox"
                checked={useLdaps}
                onChange={(e) => setUseLdaps(e.target.checked)}
              />
              <span>Use secure LDAP (LDAPS)</span>
            </label>
          </div>
        </div>
        
        <div className="form-actions">
          <button
            onClick={saveLdapSettings}
            className="btn-primary"
            disabled={loading || !url.trim() || !baseDn.trim()}
          >
            {loading ? 'Saving...' : 'Save LDAP Settings'}
          </button>
        </div>
      </div>

      {/* AD Group Role Mapping */}
      <div className="card">
        <h3>AD Group → Role Mapping</h3>
        <p style={{ marginBottom: 20, color: '#666', fontSize: '0.9em' }}>
          Map Active Directory groups to Segmentra roles. Users in these AD groups will automatically receive the assigned role.
        </p>
        
        <div className="form-grid">
          <div className="form-group">
            <label>AD Group DN *</label>
            <input
              type="text"
              value={adGroupDn}
              onChange={(e) => setAdGroupDn(e.target.value)}
              placeholder="CN=Admins,OU=Groups,DC=example,DC=com"
            />
            <small>Distinguished name of the AD group</small>
          </div>
          <div className="form-group">
            <label>Role *</label>
            <select
              value={roleName}
              onChange={(e) => setRoleName(e.target.value as any)}
            >
              <option value="viewer">Viewer - Read-only access</option>
              <option value="operator">Operator - Can create policies and deployments</option>
              <option value="approver">Approver - Can approve/reject policy versions</option>
              <option value="admin">Admin - Full administrative access</option>
            </select>
            <small>Role to assign to members of this AD group</small>
          </div>
        </div>
        
        <div className="form-actions">
          <button
            onClick={addGroupMap}
            className="btn-primary"
            disabled={loading || !adGroupDn.trim()}
          >
            {loading ? 'Adding...' : 'Add Mapping'}
          </button>
        </div>
        
        <table className="data-table" style={{ marginTop: 20 }}>
          <thead><tr><th>AD Group DN</th><th>Role</th><th>Actions</th></tr></thead>
          <tbody>
            {groupMaps.map((m) => (
              <tr key={m.id}>
                <td><code style={{ fontSize: '12px' }}>{m.ad_group_dn}</code></td>
                <td style={{ textTransform: 'capitalize' }}>{m.role_name}</td>
                <td>
                  {confirmDeleteMapId === m.id ? (
                    <>
                      <button onClick={() => deleteGroupMap(m.id)} className="btn-small" style={{ background: '#a63d2f', color: 'white', marginRight: 4 }}>Confirm delete</button>
                      <button onClick={() => setConfirmDeleteMapId(null)} className="btn-small btn-secondary">Cancel</button>
                    </>
                  ) : (
                    <button onClick={() => setConfirmDeleteMapId(m.id)} className="btn-small btn-secondary">Delete</button>
                  )}
                </td>
              </tr>
            ))}
            {groupMaps.length === 0 && <tr><td colSpan={3} className="empty-state">No group mappings yet.</td></tr>}
          </tbody>
        </table>

        <div style={{ marginTop: 24, paddingTop: 20, borderTop: '2px solid #e0e0e0' }}>
          <p style={{ fontSize: '0.9em', color: '#666', fontStyle: 'italic' }}>
            Note: Mappings are stored immediately. Users will receive the role on their next login. Group DNs are matched without regard to case or spacing.
          </p>
        </div>
      </div>

      {/* SSH Credentials */}
      <div className="card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
          <h3 style={{ margin: 0 }}>SSH Credentials</h3>
          {!showSshForm && (
            <button onClick={() => setShowSshForm(true)} className="btn-primary">
              + Add SSH Credential
            </button>
          )}
        </div>
        
        <p style={{ marginBottom: 20, color: '#666', fontSize: '0.9em' }}>
          SSH credentials used for readiness checks, deployments, compliance checks and firewall learning.
          For each host Segmentra uses, in this order: a credential explicitly assigned to the host (Inventory → edit host),
          a credential scoped to that host, a credential for one of the host's tags, one for the host's VLAN, and finally
          the global default. Within a level the highest priority wins, then the newest. The Inventory host list shows
          which credential each host uses.
        </p>
        
        <div style={{
          background: '#e3f2fd',
          border: '1px solid #2196F3',
          borderRadius: 8,
          padding: 16,
          marginBottom: 20
        }}>
          <strong style={{ color: '#1976D2' }}>⚠️ Important: Sudo Requirements</strong>
          <ul style={{ marginTop: 8, marginBottom: 0, paddingLeft: 20, fontSize: '0.9em', color: '#1565C0' }}>
            <li>Most modern Linux distributions disable root SSH login for security</li>
            <li>Use a <strong>sudo-capable account</strong> (not root) - Segmentra runs its root steps as <code>sudo sh -c ...</code>; no agent is installed on the hosts</li>
            <li>The account needs <strong>full sudo rights</strong> (<code>ALL</code>, i.e. it may run <code>sh</code> as root) - a sudo rule limited to nft/iptables is not enough. A password for sudo is fine: choose it under <em>Privilege escalation</em></li>
            <li>Log in with a private key (optionally passphrase-protected) or a password</li>
            <li>Sudoers must not require a terminal for this account (<code>Defaults requiretty</code>); readiness checks report it if it does</li>
            <li>Example: an account like <code>deploy</code> or <code>admin</code> with normal sudo (password) rights, or a dedicated service account with <code>NOPASSWD: ALL</code></li>
          </ul>
        </div>

        {showSshForm && (
          <div style={{
            background: '#f8f9fa',
            padding: 20,
            borderRadius: 8,
            marginBottom: 20
          }}>
            <h4 style={{ marginTop: 0 }}>New SSH Credential</h4>
            <div className="form-grid">
              <div className="form-group">
                <label>Name *</label>
                <input
                  type="text"
                  value={sshName}
                  onChange={(e) => setSshName(e.target.value)}
                  placeholder="e.g., global-production"
                />
              </div>
              <div className="form-group">
                <label>Username *</label>
                <input
                  type="text"
                  value={sshUser}
                  onChange={(e) => setSshUser(e.target.value)}
                  placeholder="e.g., deploy or admin (not root)"
                />
                <small>Use a sudo-capable account. Root login is often disabled on modern systems.</small>
              </div>
              <div className="form-group">
                <label>Authentication *</label>
                <select
                  value={sshAuthMethod}
                  onChange={(e) => {
                    const v = e.target.value as 'KEY' | 'PASSWORD';
                    setSshAuthMethod(v);
                    if (v === 'KEY' && sshSudoMode === 'LOGIN_PASSWORD') setSshSudoMode('SUDO_PASSWORD');
                  }}
                >
                  <option value="KEY">Private key</option>
                  <option value="PASSWORD">Password</option>
                </select>
              </div>
            </div>
            {sshAuthMethod === 'PASSWORD' && (
              <div className="form-group">
                <label>Password *</label>
                <input
                  type="password"
                  autoComplete="new-password"
                  value={sshPassword}
                  onChange={(e) => setSshPassword(e.target.value)}
                />
                <small>Stored encrypted. Choose "sudo with the login password" below if sudo asks for this password.</small>
              </div>
            )}
            {sshAuthMethod === 'KEY' && (
              <div className="form-group">
                <label>Private Key (PEM) *</label>
                <textarea
                  rows={8}
                  value={sshKey}
                  onChange={(e) => setSshKey(e.target.value)}
                  placeholder="-----BEGIN PRIVATE KEY-----&#10;...&#10;-----END PRIVATE KEY-----"
                  style={{ fontFamily: 'monospace', fontSize: '0.85em' }}
                />
                <small>Paste the full private key (OpenSSH or PEM) including BEGIN/END markers. Stored encrypted.</small>
                <div className="form-group" style={{ marginTop: 12 }}>
                  <label>Key passphrase</label>
                  <input
                    type="password"
                    autoComplete="new-password"
                    value={sshPassphrase}
                    onChange={(e) => setSshPassphrase(e.target.value)}
                    placeholder="Leave empty if the key has no passphrase"
                  />
                  <small>
                    Checked against the key when you save. Stored encrypted; the key stays encrypted on disk while
                    in use and the passphrase is handed to ssh in memory only.
                  </small>
                </div>
              </div>
            )}
            <div className="form-grid">
              <div className="form-group">
                <label>Privilege escalation *</label>
                <select value={sshSudoMode} onChange={(e) => setSshSudoMode(e.target.value as SudoMode)}>
                  <option value="NOPASSWD">sudo without password</option>
                  {sshAuthMethod === 'PASSWORD' && <option value="LOGIN_PASSWORD">sudo with the login password</option>}
                  <option value="SUDO_PASSWORD">sudo with a separate password</option>
                </select>
                <small>
                  {sshSudoMode === 'NOPASSWD' && <>The account has passwordless sudo (<code>NOPASSWD: ALL</code>).</>}
                  {sshSudoMode === 'LOGIN_PASSWORD' && <>sudo asks for the account's login password (typical for a normal admin account).</>}
                  {sshSudoMode === 'SUDO_PASSWORD' && <>sudo asks for a password different from the login (e.g. key login + sudo password).</>}
                  {' '}The sudo password is sent to sudo on stdin, never on a command line.
                </small>
              </div>
              {sshSudoMode === 'SUDO_PASSWORD' && (
                <div className="form-group">
                  <label>Sudo password *</label>
                  <input
                    type="password"
                    autoComplete="new-password"
                    value={sshSudoPassword}
                    onChange={(e) => setSshSudoPassword(e.target.value)}
                  />
                  <small>Stored encrypted.</small>
                </div>
              )}
            </div>
            <div className="form-grid">
              <ScopePicker
                scopeType={sshScopeType}
                scopeId={sshScopeId}
                onChange={(t, id) => { setSshScopeType(t); setSshScopeId(id); }}
                tags={scopeTags}
                vlans={vlans}
                hosts={scopeHosts}
              />
              <div className="form-group">
                <label>Priority</label>
                <input type="number" value={sshPriority} onChange={(e) => setSshPriority(e.target.value)} min={-1000} max={1000} />
                <small>Breaks ties when several credentials match at the same level (e.g. a host with two tags). Higher wins.</small>
              </div>
            </div>
            <div className="form-actions">
              <button
                onClick={saveSshCredential}
                className="btn-primary"
                disabled={loading || sshFormIncomplete}
              >
                {loading ? 'Saving...' : 'Save SSH Credential'}
              </button>
              <button
                onClick={() => {
                  setShowSshForm(false);
                  resetSshForm();
                }}
                className="btn-secondary"
              >
                Cancel
              </button>
            </div>
          </div>
        )}

        {sshCreds.length > 0 ? (
          <table className="data-table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Username</th>
                <th>Authentication</th>
                <th>Privilege escalation</th>
                <th>Applies to</th>
                <th>Priority</th>
                <th>Created</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {sshCreds.map((c) => editCred?.id === c.id ? (
                <tr key={c.id}>
                  <td colSpan={8} style={{ background: '#f8f9fa' }}>
                    <div className="form-grid">
                      <div className="form-group">
                        <label>Name *</label>
                        <input type="text" value={editCred?.name ?? ''} onChange={(e) => patchEdit({ name: e.target.value })} />
                      </div>
                      <ScopePicker
                        scopeType={editCred?.scopeType ?? 'GLOBAL'}
                        scopeId={editCred?.scopeId ?? ''}
                        onChange={(t, id) => patchEdit({ scopeType: t, scopeId: id })}
                        tags={scopeTags}
                        vlans={vlans}
                        hosts={scopeHosts}
                      />
                      <div className="form-group">
                        <label>Priority</label>
                        <input type="number" value={editCred?.priority ?? '0'} onChange={(e) => patchEdit({ priority: e.target.value })} min={-1000} max={1000} />
                      </div>
                      {editCred?.authMethod === 'PASSWORD' && (
                        <div className="form-group">
                          <label>New password</label>
                          <input type="password" autoComplete="new-password" value={editCred.password} placeholder="Leave empty to keep the stored password"
                            onChange={(e) => patchEdit({ password: e.target.value })} />
                        </div>
                      )}
                    </div>
                    <small style={{ color: '#666' }}>
                      Username, private key and privilege escalation are kept. To replace a key, add a new credential and delete this one.
                    </small>
                    <div className="form-actions" style={{ marginTop: 8 }}>
                      <button className="btn-primary" onClick={saveCredentialEdit} disabled={loading}>Save</button>
                      <button className="btn-secondary" onClick={() => setEditCred(null)}>Cancel</button>
                    </div>
                  </td>
                </tr>
              ) : (
                <tr key={c.id}>
                  <td><strong>{c.name}</strong></td>
                  <td><code>{c.username}</code></td>
                  <td>
                    {c.auth_method === 'PASSWORD' ? 'Password' : 'Private key'}
                    {c.has_passphrase && (
                      <span style={{ marginLeft: 6, padding: '1px 6px', borderRadius: 8, background: '#e8eaf6', color: '#3949ab', fontSize: '0.8em' }}>
                        passphrase
                      </span>
                    )}
                  </td>
                  <td style={{ fontSize: '0.9em' }}>{SUDO_MODE_LABELS[(c.sudo_mode as SudoMode) || 'NOPASSWD'] ?? c.sudo_mode}</td>
                  <td style={{ fontSize: '0.9em' }}>
                    {appliesToLabel(c)}
                    {(c.assigned_host_count > 0 || c.discovery_target_count > 0) && (
                      <div style={{ color: '#666', fontSize: '0.85em' }}>
                        {c.assigned_host_count > 0 && <>assigned to {c.assigned_host_count} host(s)</>}
                        {c.assigned_host_count > 0 && c.discovery_target_count > 0 && ', '}
                        {c.discovery_target_count > 0 && <>used by discovery</>}
                      </div>
                    )}
                  </td>
                  <td style={{ fontSize: '0.9em' }}>{c.priority ?? 0}</td>
                  <td style={{ fontSize: '0.9em', color: '#666' }}>
                    {c.created_at ? new Date(c.created_at).toLocaleString() : '-'}
                  </td>
                  <td>
                    <div style={{ display: 'flex', gap: 4 }}>
                      <button
                        className="btn-small btn-secondary"
                        onClick={() => setEditCred({ id: c.id, name: c.name, scopeType: (c.scope_type || 'GLOBAL') as ScopeType, scopeId: c.scope_id || '', priority: String(c.priority ?? 0), authMethod: c.auth_method || 'KEY', password: '' })}
                      >
                        Edit
                      </button>
                      <button className="btn-small btn-danger" onClick={() => deleteCredential(c)}>Delete</button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <div style={{ padding: 40, textAlign: 'center', color: '#999' }}>
            No SSH credentials configured. Add one above to enable deployments.
          </div>
        )}
      </div>
    </div>
  );
}
