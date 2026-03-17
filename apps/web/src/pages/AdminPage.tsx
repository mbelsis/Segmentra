import { useEffect, useState } from 'react';

import { api } from '../lib/api';

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

  // AD Group mapping form state
  const [adGroupDn, setAdGroupDn] = useState('');
  const [roleName, setRoleName] = useState<'viewer' | 'operator' | 'approver' | 'admin'>('admin');

  // SSH Credentials form state
  const [sshName, setSshName] = useState('global');
  const [sshUser, setSshUser] = useState('root');
  const [sshKey, setSshKey] = useState('');
  const [sshCreds, setSshCreds] = useState<any[]>([]);
  const [showSshForm, setShowSshForm] = useState(false);

  // Executor setting
  const [executor, setExecutor] = useState<'ansible' | 'ssh'>('ansible');

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
        api.executorSetting().catch(() => ({ executor: 'ansible' })),
        api.managementVlanSetting().catch(() => ({ managementVlan: null })),
        api.vlans().catch(() => ({ vlans: [] }))
      ]);
      
      const ldapSettings = ldapRes.ldapSettings;
      setLdap(ldapSettings);
      
      if (ldapSettings) {
        setUrl(ldapSettings.url || 'ldaps://ad.example.com:636');
        setBaseDn(ldapSettings.base_dn || 'DC=example,DC=com');
        setBindDn(ldapSettings.bind_dn || '');
        setUseLdaps(ldapSettings.use_ldaps !== false);
        setLdapEnabled(ldapSettings.enabled !== false);
      }
      
      setSshCreds(sshRes.sshCredentials || []);
      setExecutor(executorRes.executor === 'ssh' ? 'ssh' : 'ansible');
      
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
    } catch (e: any) { setError(String(e?.message ?? e)); }
    finally { setLoading(false); }
  }

  async function updateUser() {
    if (!editingUser) return;
    setLoading(true); setError(''); setSuccess('');
    try {
      await api.users.update(editingUser.id, {
        displayName: userForm.displayName.trim() || undefined,
        email: userForm.email.trim() || undefined,
        roles: userForm.roles,
        isActive: userForm.isActive,
      });
      setSuccess(`User "${editingUser.username}" updated`);
      setEditingUser(null);
      setShowUserForm(false);
      loadData();
      setTimeout(() => setSuccess(''), 3000);
    } catch (e: any) { setError(String(e?.message ?? e)); }
    finally { setLoading(false); }
  }

  async function resetUserPassword() {
    if (!resetPasswordUserId || !newPassword.trim()) {
      setError('Password must be at least 6 characters');
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
      const r = await api.putLdapSettings({
        enabled: ldapEnabled,
        url: url.trim(),
        baseDn: baseDn.trim(),
        bindDn: bindDn.trim() || undefined,
        bindPassword: bindPassword.trim() || undefined,
        userFilter: '(sAMAccountName={{username}})',
        useLdaps: useLdaps
      });
      setLdap(r.ldapSettings);
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
      setTimeout(() => setSuccess(''), 3000);
    } catch (e: any) {
      setError(String(e?.message ?? e));
    } finally {
      setLoading(false);
    }
  }

  async function saveSshCredential() {
    if (!sshName.trim() || !sshUser.trim() || !sshKey.trim()) {
      setError('Name, username, and private key are required');
      return;
    }
    
    setLoading(true);
    setError('');
    setSuccess('');
    
    try {
      await api.createSshCredential({
        name: sshName.trim(),
        username: sshUser.trim(),
        privateKeyPem: sshKey.trim(),
        scopeType: 'GLOBAL'
      });
      setSuccess('SSH credential saved successfully');
      setSshName('global');
      setSshUser('root');
      setSshKey('');
      setShowSshForm(false);
      await loadData();
      setTimeout(() => setSuccess(''), 3000);
    } catch (e: any) {
      setError(String(e?.message ?? e));
    } finally {
      setLoading(false);
    }
  }

  function getRoleBadge(role: string) {
    const colors: Record<string, string> = {
      admin: '#F44336',
      approver: '#FF9800',
      operator: '#2196F3',
      viewer: '#4CAF50'
    };
    return (
      <span style={{
        background: colors[role] || '#666',
        color: 'white',
        padding: '2px 8px',
        borderRadius: 4,
        fontSize: '0.85em',
        fontWeight: 'bold'
      }}>
        {role.toUpperCase()}
      </span>
    );
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
                    <button onClick={() => setResetPasswordUserId(u.id)} className="btn-small btn-secondary" style={{ marginRight: 4 }}>Reset PW</button>
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
          Choose how firewall rules are deployed to target hosts. Ansible provides better error handling and rollback, while SSH direct is lighter weight.
        </p>
        
        <div className="form-grid">
          <div className="form-group">
            <label>Executor Type *</label>
            <select
              value={executor}
              onChange={(e) => setExecutor(e.target.value as 'ansible' | 'ssh')}
              disabled={loading}
            >
              <option value="ansible">Ansible (Recommended) - Better error handling, rollback, and parallel execution</option>
              <option value="ssh">SSH Direct - Lightweight direct SSH execution</option>
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
            disabled={loading}
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
            <label>Bind Password</label>
            <input
              type="password"
              value={bindPassword}
              onChange={(e) => setBindPassword(e.target.value)}
              placeholder="Leave empty to keep existing password"
            />
            <small>Password for bind DN (stored encrypted). Leave empty to keep existing.</small>
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
        
        <div style={{ marginTop: 24, paddingTop: 20, borderTop: '2px solid #e0e0e0' }}>
          <p style={{ fontSize: '0.9em', color: '#666', fontStyle: 'italic' }}>
            Note: Mappings are stored immediately. Users will receive the role on their next login.
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
          SSH credentials used for deploying firewall rules to target hosts. Global credentials are used for all deployments.
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
            <li>Use a <strong>sudo-capable account</strong> (not root) - the system will automatically use sudo when needed</li>
            <li>The account must have passwordless sudo access to firewall commands (nft, iptables, iptables-restore)</li>
            <li>Example: Use an account like <code>deploy</code> or <code>admin</code> with sudo privileges</li>
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
            </div>
              <div className="form-group">
                <label>Private Key (PEM) *</label>
                <textarea
                  rows={8}
                  value={sshKey}
                  onChange={(e) => setSshKey(e.target.value)}
                  placeholder="-----BEGIN PRIVATE KEY-----&#10;...&#10;-----END PRIVATE KEY-----"
                  style={{ fontFamily: 'monospace', fontSize: '0.85em' }}
                />
                <small>Paste the full private key including BEGIN/END markers. Stored encrypted.</small>
                <div style={{ marginTop: 8, padding: 8, background: '#fff3cd', borderRadius: 4, fontSize: '0.85em' }}>
                  <strong>Note:</strong> The system will automatically use <code>sudo</code> when applying firewall rules. 
                  Ensure the account has passwordless sudo access to: <code>nft</code>, <code>iptables</code>, <code>iptables-restore</code>, 
                  and file operations in <code>/etc</code> and <code>/var/backups</code>.
                </div>
              </div>
            <div className="form-actions">
              <button
                onClick={saveSshCredential}
                className="btn-primary"
                disabled={loading || !sshName.trim() || !sshUser.trim() || !sshKey.trim()}
              >
                {loading ? 'Saving...' : 'Save SSH Credential'}
              </button>
              <button
                onClick={() => {
                  setShowSshForm(false);
                  setSshName('global');
                  setSshUser('root');
                  setSshKey('');
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
                <th>Scope</th>
                <th>Created</th>
              </tr>
            </thead>
            <tbody>
              {sshCreds.map((c) => (
                <tr key={c.id}>
                  <td><strong>{c.name}</strong></td>
                  <td><code>{c.username}</code></td>
                  <td>{getRoleBadge(c.scope_type || 'GLOBAL')}</td>
                  <td style={{ fontSize: '0.9em', color: '#666' }}>
                    {c.created_at ? new Date(c.created_at).toLocaleString() : '-'}
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
