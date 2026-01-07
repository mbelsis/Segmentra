import { useEffect, useState } from 'react';

import { api } from '../lib/api';

export function AdminPage() {
  const [ldap, setLdap] = useState<any>(null);
  const [url, setUrl] = useState('ldaps://ad.example.com:636');
  const [baseDn, setBaseDn] = useState('DC=example,DC=com');
  const [bindDn, setBindDn] = useState('');
  const [bindPassword, setBindPassword] = useState('');

  const [adGroupDn, setAdGroupDn] = useState('');
  const [roleName, setRoleName] = useState<'viewer' | 'operator' | 'approver' | 'admin'>('admin');

  const [sshName, setSshName] = useState('global');
  const [sshUser, setSshUser] = useState('root');
  const [sshKey, setSshKey] = useState('');
  const [sshCreds, setSshCreds] = useState<any[]>([]);

  useEffect(() => {
    api.ldapSettings().then((r) => setLdap(r.ldapSettings)).catch(() => undefined);
    api.sshCredentials().then((r) => setSshCreds(r.sshCredentials)).catch(() => undefined);
  }, []);

  return (
    <div style={{ display: 'grid', gap: 16 }}>
      <h2>Admin</h2>

      <section style={{ display: 'grid', gap: 8 }}>
        <h3>LDAP Settings</h3>
        <div style={{ opacity: 0.8, fontSize: 12 }}>Current: {ldap ? JSON.stringify(ldap) : 'none'}</div>
        <label>
          URL
          <input value={url} onChange={(e) => setUrl(e.target.value)} />
        </label>
        <label>
          Base DN
          <input value={baseDn} onChange={(e) => setBaseDn(e.target.value)} />
        </label>
        <label>
          Bind DN (optional)
          <input value={bindDn} onChange={(e) => setBindDn(e.target.value)} />
        </label>
        <label>
          Bind password (stored encrypted)
          <input value={bindPassword} onChange={(e) => setBindPassword(e.target.value)} />
        </label>
        <button
          onClick={async () => {
            const r = await api.putLdapSettings({
              enabled: true,
              url,
              baseDn,
              bindDn: bindDn || undefined,
              bindPassword: bindPassword || undefined,
              userFilter: '(sAMAccountName={{username}})',
              useLdaps: true
            });
            setLdap(r.ldapSettings);
          }}
        >
          Save LDAP settings
        </button>
      </section>

      <section style={{ display: 'grid', gap: 8 }}>
        <h3>AD Group → Role map</h3>
        <label>
          AD group DN
          <input value={adGroupDn} onChange={(e) => setAdGroupDn(e.target.value)} />
        </label>
        <label>
          Role
          <select value={roleName} onChange={(e) => setRoleName(e.target.value as any)}>
            <option value="viewer">viewer</option>
            <option value="operator">operator</option>
            <option value="approver">approver</option>
            <option value="admin">admin</option>
          </select>
        </label>
        <button onClick={() => api.addGroupMap({ adGroupDn, roleName })} disabled={!adGroupDn}>
          Add mapping
        </button>
      </section>

      <section style={{ display: 'grid', gap: 8 }}>
        <h3>SSH Credentials</h3>
        <label>
          Name
          <input value={sshName} onChange={(e) => setSshName(e.target.value)} />
        </label>
        <label>
          Username
          <input value={sshUser} onChange={(e) => setSshUser(e.target.value)} />
        </label>
        <label>
          Private key PEM
          <textarea rows={6} value={sshKey} onChange={(e) => setSshKey(e.target.value)} />
        </label>
        <button
          onClick={async () => {
            await api.createSshCredential({ name: sshName, username: sshUser, privateKeyPem: sshKey, scopeType: 'GLOBAL' });
            const r = await api.sshCredentials();
            setSshCreds(r.sshCredentials);
          }}
          disabled={!sshKey}
        >
          Save global SSH credential
        </button>

        <div>
          <div style={{ fontWeight: 600, marginBottom: 6 }}>Existing</div>
          <ul>
            {sshCreds.map((c) => (
              <li key={c.id}>
                {c.name} ({c.username}) <code>{String(c.id).slice(0, 8)}</code>
              </li>
            ))}
            {sshCreds.length === 0 ? <li style={{ opacity: 0.7 }}>None</li> : null}
          </ul>
        </div>
      </section>
    </div>
  );
}


