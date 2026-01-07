import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';

import { api } from '../lib/api';

export function PolicySetsPage() {
  const navigate = useNavigate();
  const [policySets, setPolicySets] = useState<any[]>([]);
  const [name, setName] = useState('');

  useEffect(() => {
    api.policySets().then((r) => setPolicySets(r.policySets)).catch(() => undefined);
  }, []);

  return (
    <div style={{ display: 'grid', gap: 12 }}>
      <h2>Policy Sets</h2>
      <div style={{ display: 'flex', gap: 8, alignItems: 'flex-end' }}>
        <label>
          Name
          <input value={name} onChange={(e) => setName(e.target.value)} />
        </label>
        <button
          onClick={async () => {
            const ps = await api.createPolicySet({ name, scopeType: 'HOST_LIST', hostIds: [] });
            setPolicySets((prev) => [ps.policySet, ...prev]);
            setName('');
          }}
        >
          Create
        </button>
      </div>

      <table>
        <thead>
          <tr>
            <th>Name</th>
            <th>Scope</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {policySets.map((ps) => (
            <PolicySetRow key={ps.id} ps={ps} onOpen={(versionId) => navigate(`/policy-version/${versionId}`)} />
          ))}
          {policySets.length === 0 ? (
            <tr>
              <td colSpan={3} style={{ opacity: 0.7 }}>
                No policy sets yet.
              </td>
            </tr>
          ) : null}
        </tbody>
      </table>
    </div>
  );
}

function PolicySetRow(props: { ps: any; onOpen: (versionId: string) => void }) {
  const [versions, setVersions] = useState<any[] | null>(null);

  return (
    <>
      <tr>
        <td>{props.ps.name}</td>
        <td>{props.ps.scope_type}</td>
        <td style={{ display: 'flex', gap: 8 }}>
          <button
            onClick={async () => {
              const v = await api.createVersion(props.ps.id, { interfaceScopeType: 'INTERFACE_ROLE', interfaceScopeRoles: ['data'] });
              props.onOpen(v.version.id);
            }}
          >
            New version
          </button>
          <button
            onClick={async () => {
              const r = await api.versions(props.ps.id);
              setVersions(r.versions);
            }}
          >
            List versions
          </button>
        </td>
      </tr>
      {versions?.length ? (
        <tr>
          <td colSpan={3}>
            <div style={{ display: 'grid', gap: 6 }}>
              {versions.map((v) => (
                <div key={v.id} style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                  <code>v{v.version_number}</code>
                  <span>{v.status}</span>
                  <button onClick={() => props.onOpen(v.id)}>Open</button>
                </div>
              ))}
            </div>
          </td>
        </tr>
      ) : null}
    </>
  );
}


