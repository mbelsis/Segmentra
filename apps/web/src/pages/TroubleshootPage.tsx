import { useState } from 'react';
import { api } from '../lib/api';

export function TroubleshootPage() {
  const [searchType, setSearchType] = useState<'ip' | 'host' | 'policy'>('ip');
  const [searchValue, setSearchValue] = useState('');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  async function handleSearch() {
    if (!searchValue.trim()) {
      setError('Please enter a search value');
      return;
    }

    setLoading(true);
    setError(null);
    setResults(null);

    try {
      if (searchType === 'ip') {
        const data = await api.troubleshoot.policiesByIp(searchValue.trim());
        setResults(data);
      } else if (searchType === 'host') {
        // Find host by hostname or ID
        const hostsRes = await api.hosts({ hostname: searchValue.trim() });
        if (hostsRes.hosts.length === 0) {
          setError('Host not found');
          setLoading(false);
          return;
        }
        const host = hostsRes.hosts[0];
        const data = await api.troubleshoot.hostPolicies(host.id);
        setResults(data);
      } else if (searchType === 'policy') {
        const data = await api.troubleshoot.policyVersionHosts(searchValue.trim());
        setResults(data);
      }
    } catch (e: any) {
      setError(String(e?.message ?? e));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div style={{ padding: 24 }}>
      <h1>Troubleshooting</h1>
      <p style={{ color: '#666', marginBottom: 24 }}>
        Search for policies by IP address, find policies deployed to a host, or find hosts with a specific policy.
      </p>

      <div className="card" style={{ marginBottom: 24 }}>
        <div style={{ display: 'flex', gap: 16, alignItems: 'flex-end', flexWrap: 'wrap' }}>
          <div style={{ flex: 1, minWidth: 200 }}>
            <label style={{ display: 'block', marginBottom: 8, fontWeight: 500 }}>Search Type</label>
            <select
              value={searchType}
              onChange={(e) => { setSearchType(e.target.value as any); setResults(null); }}
              style={{ width: '100%', padding: '8px', border: '1px solid #ddd', borderRadius: 4 }}
            >
              <option value="ip">Search Policies by IP Address</option>
              <option value="host">Find Policies on Host</option>
              <option value="policy">Find Hosts with Policy</option>
            </select>
          </div>
          <div style={{ flex: 2, minWidth: 200 }}>
            <label style={{ display: 'block', marginBottom: 8, fontWeight: 500 }}>
              {searchType === 'ip' ? 'IP Address' : searchType === 'host' ? 'Hostname' : 'Policy Version ID'}
            </label>
            <input
              type="text"
              value={searchValue}
              onChange={(e) => setSearchValue(e.target.value)}
              onKeyPress={(e) => e.key === 'Enter' && handleSearch()}
              placeholder={searchType === 'ip' ? 'e.g., 10.10.10.1' : searchType === 'host' ? 'e.g., web-server-01' : 'UUID'}
              style={{ width: '100%', padding: '8px', border: '1px solid #ddd', borderRadius: 4 }}
            />
          </div>
          <button onClick={handleSearch} disabled={loading} className="btn-primary">
            {loading ? 'Searching...' : 'Search'}
          </button>
        </div>
      </div>

      {error && (
        <div className="error-banner" style={{ marginBottom: 24 }}>
          {error}
        </div>
      )}

      {results && searchType === 'ip' && (
        <div className="card">
          <h2>Policies Matching IP: {results.ip}</h2>
          {results.results.length === 0 ? (
            <p style={{ color: '#666', fontStyle: 'italic' }}>No policies found matching this IP address.</p>
          ) : (
            results.results.map((result: any, idx: number) => (
              <div key={idx} style={{ marginBottom: 32, padding: 16, background: '#f9f9f9', borderRadius: 8 }}>
                <h3 style={{ marginTop: 0 }}>
                  Policy: {result.policyVersion.policySetName} v{result.policyVersion.versionNumber}
                  <span style={{ marginLeft: 12, fontSize: '0.85em', fontWeight: 'normal', color: '#666' }}>
                    ({result.policyVersion.status})
                  </span>
                </h3>
                <div style={{ marginBottom: 16 }}>
                  <strong>Matching Rule:</strong>
                  <div style={{ marginLeft: 16, marginTop: 8, padding: 12, background: 'white', borderRadius: 4 }}>
                    <div><strong>Action:</strong> {result.rule.action}</div>
                    <div><strong>Protocol:</strong> {result.rule.protocol}</div>
                    {result.rule.ports && <div><strong>Ports:</strong> {result.rule.ports}</div>}
                    <div><strong>Source:</strong> {result.rule.sourceType} = {result.rule.sourceValue}</div>
                    <div><strong>Direction:</strong> {result.rule.direction}</div>
                    {result.rule.comment && <div><strong>Comment:</strong> {result.rule.comment}</div>}
                  </div>
                </div>
                <div>
                  <strong>Deployed to {result.deployedHosts.length} host(s):</strong>
                  {result.deployedHosts.length === 0 ? (
                    <p style={{ color: '#666', fontStyle: 'italic', marginLeft: 16 }}>Not deployed to any hosts</p>
                  ) : (
                    <table className="data-table" style={{ marginTop: 8 }}>
                      <thead>
                        <tr>
                          <th>Hostname</th>
                          <th>Management IP</th>
                          <th>Deployment Status</th>
                          <th>Host Status</th>
                          <th>Deployed At</th>
                        </tr>
                      </thead>
                      <tbody>
                        {result.deployedHosts.map((dh: any, i: number) => (
                          <tr key={i}>
                            <td><strong>{dh.hostname}</strong></td>
                            <td>{dh.mgmtIp || '-'}</td>
                            <td><code>{dh.deploymentStatus}</code></td>
                            <td><code>{dh.hostDeploymentStatus}</code></td>
                            <td>{new Date(dh.deployedAt).toLocaleString()}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </div>
              </div>
            ))
          )}
        </div>
      )}

      {results && searchType === 'host' && (
        <div className="card">
          <h2>Policies on Host: {results.host.hostname}</h2>
          <p><strong>Management IP:</strong> {results.host.mgmtIp || 'N/A'}</p>
          {results.policies.length === 0 ? (
            <p style={{ color: '#666', fontStyle: 'italic' }}>No policies deployed to this host.</p>
          ) : (
            results.policies.map((policy: any, idx: number) => (
              <div key={idx} style={{ marginBottom: 32, padding: 16, background: '#f9f9f9', borderRadius: 8 }}>
                <h3 style={{ marginTop: 0 }}>
                  {policy.policyVersion.policySetName} v{policy.policyVersion.versionNumber}
                  <span style={{ marginLeft: 12, fontSize: '0.85em', fontWeight: 'normal', color: '#666' }}>
                    ({policy.policyVersion.status})
                  </span>
                </h3>
                <div style={{ marginBottom: 16 }}>
                  <div><strong>Deployment Status:</strong> <code>{policy.hostDeploymentStatus}</code></div>
                  {policy.hostDeploymentMessage && <div><strong>Message:</strong> {policy.hostDeploymentMessage}</div>}
                  <div><strong>Deployed:</strong> {new Date(policy.deployment.createdAt).toLocaleString()}</div>
                </div>
                <div>
                  <strong>Rules ({policy.rules.length}):</strong>
                  <table className="data-table" style={{ marginTop: 8 }}>
                    <thead>
                      <tr>
                        <th>Order</th>
                        <th>Action</th>
                        <th>Protocol</th>
                        <th>Ports</th>
                        <th>Source</th>
                        <th>Direction</th>
                        <th>Comment</th>
                      </tr>
                    </thead>
                    <tbody>
                      {policy.rules.map((rule: any) => (
                        <tr key={rule.id}>
                          <td>{rule.orderIndex}</td>
                          <td><code>{rule.action}</code></td>
                          <td><code>{rule.protocol}</code></td>
                          <td>{rule.ports || '-'}</td>
                          <td>{rule.sourceType}: {rule.sourceValue}</td>
                          <td>{rule.direction}</td>
                          <td>{rule.comment || '-'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            ))
          )}
        </div>
      )}

      {results && searchType === 'policy' && (
        <div className="card">
          <h2>Hosts with Policy: {results.policyVersion.policySetName} v{results.policyVersion.versionNumber}</h2>
          <p><strong>Status:</strong> {results.policyVersion.status}</p>
          {results.hosts.length === 0 ? (
            <p style={{ color: '#666', fontStyle: 'italic' }}>This policy is not deployed to any hosts.</p>
          ) : (
            <table className="data-table">
              <thead>
                <tr>
                  <th>Hostname</th>
                  <th>Management IP</th>
                  <th>Deployments</th>
                </tr>
              </thead>
              <tbody>
                {results.hosts.map((h: any, idx: number) => (
                  <tr key={idx}>
                    <td><strong>{h.host.hostname}</strong></td>
                    <td>{h.host.mgmtIp || '-'}</td>
                    <td>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                        {h.deployments.map((dep: any, i: number) => (
                          <div key={i} style={{ fontSize: '0.9em' }}>
                            <code>{dep.hostDeploymentStatus}</code> - {new Date(dep.createdAt).toLocaleString()}
                            {dep.message && <span style={{ color: '#666' }}> ({dep.message})</span>}
                          </div>
                        ))}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  );
}

