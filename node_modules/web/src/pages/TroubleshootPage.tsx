import { useState, useEffect } from 'react';
import { api } from '../lib/api';

export function TroubleshootPage() {
  const [searchType, setSearchType] = useState<'ip' | 'host' | 'policy'>('ip');
  const [searchValue, setSearchValue] = useState('');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  // Simulation state
  const [simSourceIp, setSimSourceIp] = useState('');
  const [simSourcePort, setSimSourcePort] = useState('');
  const [simDestIp, setSimDestIp] = useState('');
  const [simDestPort, setSimDestPort] = useState('');
  const [simProtocol, setSimProtocol] = useState('tcp');
  const [simLoading, setSimLoading] = useState(false);
  const [simResults, setSimResults] = useState<any>(null);
  const [simError, setSimError] = useState<string | null>(null);

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

  async function handleSimulate() {
    if (!simSourceIp.trim() || !simDestIp.trim()) {
      setSimError('Source IP and Destination IP are required');
      return;
    }

    setSimLoading(true);
    setSimError(null);
    setSimResults(null);

    try {
      const data = await api.troubleshoot.simulateCommunication({
        sourceIp: simSourceIp.trim(),
        sourcePort: simSourcePort ? parseInt(simSourcePort, 10) : null,
        destIp: simDestIp.trim(),
        destPort: simDestPort ? parseInt(simDestPort, 10) : null,
        protocol: simProtocol
      });
      setSimResults(data);
    } catch (e: any) {
      setSimError(String(e?.message ?? e));
    } finally {
      setSimLoading(false);
    }
  }

  // Firewall Audit state
  const [auditHosts, setAuditHosts] = useState<string[]>([]);
  const [auditHostInput, setAuditHostInput] = useState('');
  const [auditDuration, setAuditDuration] = useState(60);
  const [auditLoading, setAuditLoading] = useState(false);
  const [auditSessions, setAuditSessions] = useState<any[]>([]);
  const [selectedSessionHost, setSelectedSessionHost] = useState<string | null>(null);
  const [auditError, setAuditError] = useState<string | null>(null);
  const [allHosts, setAllHosts] = useState<any[]>([]);

  // Load all hosts for selection
  useEffect(() => {
    api.hosts({ limit: 1000 }).then((res) => {
      setAllHosts(res.hosts);
    });
  }, []);

  // Load audit sessions
  useEffect(() => {
    loadAuditSessions();
    const interval = setInterval(loadAuditSessions, 30000); // Refresh every 30 seconds
    return () => clearInterval(interval);
  }, []);

  async function loadAuditSessions() {
    try {
      const res = await api.troubleshoot.audit.listSessions();
      setAuditSessions(res.sessions);
    } catch (e) {
      // Ignore errors
    }
  }

  async function handleStartAudit() {
    if (auditHosts.length === 0) {
      setAuditError('Please select at least one host');
      return;
    }
    if (auditDuration < 1 || auditDuration > 1440) {
      setAuditError('Duration must be between 1 and 1440 minutes');
      return;
    }

    setAuditLoading(true);
    setAuditError(null);

    try {
      await api.troubleshoot.audit.start({
        hosts: auditHosts,
        durationMinutes: auditDuration
      });
      setAuditHosts([]);
      setAuditHostInput('');
      await loadAuditSessions();
    } catch (e: any) {
      setAuditError(String(e?.message ?? e));
    } finally {
      setAuditLoading(false);
    }
  }

  function addHostToAudit() {
    const input = auditHostInput.trim();
    if (!input) return;

    // Try to find host by hostname or IP
    const host = allHosts.find(
      (h) => h.hostname.toLowerCase() === input.toLowerCase() || h.mgmt_ip === input || h.id === input
    );

    if (host && !auditHosts.includes(host.id)) {
      setAuditHosts([...auditHosts, host.id]);
      setAuditHostInput('');
    } else if (!host) {
      setAuditError(`Host "${input}" not found`);
    }
  }

  function removeHostFromAudit(hostId: string) {
    setAuditHosts(auditHosts.filter((id) => id !== hostId));
  }

  function formatTimeRemaining(session: any): string {
    if (session.status !== 'RUNNING') return '';
    const now = new Date();
    const restoreAt = new Date(session.scheduled_restore_at);
    const diff = restoreAt.getTime() - now.getTime();
    if (diff <= 0) return 'Restoring...';
    const minutes = Math.floor(diff / 60000);
    const hours = Math.floor(minutes / 60);
    const mins = minutes % 60;
    return `${hours}h ${mins}m`;
  }

  const activeSessions = auditSessions.filter((s) => s.status === 'RUNNING');
  const completedSessions = auditSessions.filter((s) => s.status === 'COMPLETED');

  return (
    <div style={{ padding: 24 }}>
      <h1>Troubleshooting</h1>
      <p style={{ color: '#666', marginBottom: 24 }}>
        Simulate communication between IPs, search for policies by IP address, find policies deployed to a host, or find hosts with a specific policy.
      </p>

      {/* Firewall Audit Section */}
      <div className="card" style={{ marginBottom: 24 }}>
        <h2 style={{ marginTop: 0 }}>Firewall Audit</h2>
        <p style={{ color: '#666', marginBottom: 16 }}>
          Deploy log-only firewall rules to capture all network traffic without blocking. After the specified duration, original rules will be restored and communication flows will be displayed.
        </p>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: 16, marginBottom: 16 }}>
          <div>
            <label style={{ display: 'block', marginBottom: 8, fontWeight: 500 }}>Hostname or IP *</label>
            <div style={{ display: 'flex', gap: 8 }}>
              <input
                type="text"
                value={auditHostInput}
                onChange={(e) => setAuditHostInput(e.target.value)}
                onKeyPress={(e) => e.key === 'Enter' && addHostToAudit()}
                placeholder="e.g., web-server-01 or 192.168.1.10"
                style={{ flex: 1, padding: '8px', border: '1px solid #ddd', borderRadius: 4 }}
              />
              <button onClick={addHostToAudit} className="btn-primary" style={{ whiteSpace: 'nowrap' }}>
                Add
              </button>
            </div>
          </div>
          <div>
            <label style={{ display: 'block', marginBottom: 8, fontWeight: 500 }}>Duration (minutes) *</label>
            <input
              type="number"
              value={auditDuration}
              onChange={(e) => setAuditDuration(parseInt(e.target.value, 10) || 60)}
              min="1"
              max="1440"
              style={{ width: '100%', padding: '8px', border: '1px solid #ddd', borderRadius: 4 }}
            />
          </div>
        </div>

        {auditHosts.length > 0 && (
          <div style={{ marginBottom: 16 }}>
            <strong>Selected Hosts:</strong>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginTop: 8 }}>
              {auditHosts.map((hostId) => {
                const host = allHosts.find((h) => h.id === hostId);
                return (
                  <span
                    key={hostId}
                    style={{
                      padding: '4px 12px',
                      background: '#e3f2fd',
                      borderRadius: 16,
                      display: 'flex',
                      alignItems: 'center',
                      gap: 8
                    }}
                  >
                    {host?.hostname || hostId}
                    <button
                      onClick={() => removeHostFromAudit(hostId)}
                      style={{
                        background: 'none',
                        border: 'none',
                        cursor: 'pointer',
                        fontSize: '18px',
                        color: '#666',
                        padding: 0,
                        width: 20,
                        height: 20
                      }}
                    >
                      ×
                    </button>
                  </span>
                );
              })}
            </div>
          </div>
        )}

        <button onClick={handleStartAudit} disabled={auditLoading || auditHosts.length === 0} className="btn-primary">
          {auditLoading ? 'Starting...' : 'Start Audit'}
        </button>

        {auditError && (
          <div className="error-banner" style={{ marginTop: 16 }}>
            {auditError}
          </div>
        )}
      </div>

      {/* Active Sessions */}
      {activeSessions.length > 0 && (
        <div className="card" style={{ marginBottom: 24 }}>
          <h2 style={{ marginTop: 0 }}>Active Audit Sessions</h2>
          <table className="data-table">
            <thead>
              <tr>
                <th>Hostname</th>
                <th>Duration</th>
                <th>Time Remaining</th>
                <th>Started</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {activeSessions.map((session) => (
                <tr key={session.id}>
                  <td><strong>{session.hostname}</strong></td>
                  <td>{session.duration_minutes} minutes</td>
                  <td>{formatTimeRemaining(session)}</td>
                  <td>{new Date(session.started_at).toLocaleString()}</td>
                  <td>
                    <button
                      onClick={async () => {
                        if (confirm('Cancel this audit session and restore original firewall rules?')) {
                          try {
                            await api.troubleshoot.audit.cancelSession(session.id);
                            await loadAuditSessions();
                          } catch (e: any) {
                            alert(`Error: ${e.message}`);
                          }
                        }
                      }}
                      style={{ padding: '4px 8px', fontSize: '0.9em' }}
                    >
                      Cancel
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Completed Sessions Results */}
      {completedSessions.length > 0 && (
        <div className="card" style={{ marginBottom: 24 }}>
          <h2 style={{ marginTop: 0 }}>Completed Audit Sessions</h2>
          
          <div style={{ marginBottom: 16 }}>
            <label style={{ display: 'block', marginBottom: 8, fontWeight: 500 }}>Select Server:</label>
            <select
              value={selectedSessionHost || ''}
              onChange={(e) => setSelectedSessionHost(e.target.value || null)}
              style={{ width: '100%', maxWidth: 400, padding: '8px', border: '1px solid #ddd', borderRadius: 4 }}
            >
              <option value="">-- Select a server --</option>
              {completedSessions.map((session) => (
                <option key={session.id} value={session.id}>
                  {session.hostname} - {new Date(session.started_at).toLocaleString()}
                </option>
              ))}
            </select>
          </div>

          {selectedSessionHost && (() => {
            const session = completedSessions.find((s) => s.id === selectedSessionHost);
            if (!session || !session.log_data) {
              return <p style={{ color: '#666' }}>No log data available for this session.</p>;
            }

            const logData = session.log_data;
            const flows = logData.flows || [];

            return (
              <div>
                <h3>Communication Flows ({flows.length} unique flows)</h3>
                <p style={{ color: '#666', marginBottom: 16 }}>
                  Total log entries: {logData.entries?.length || 0}
                </p>
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Direction</th>
                      <th>Source IP</th>
                      <th>Destination IP</th>
                      <th>Protocol</th>
                      <th>Source Port</th>
                      <th>Dest Port</th>
                      <th>Count</th>
                      <th>First Seen</th>
                      <th>Last Seen</th>
                    </tr>
                  </thead>
                  <tbody>
                    {flows.map((flow: any, idx: number) => (
                      <tr key={idx}>
                        <td><code>{flow.direction}</code></td>
                        <td>{flow.sourceIp}</td>
                        <td>{flow.destinationIp}</td>
                        <td><code>{flow.protocol}</code></td>
                        <td>{flow.sourcePort || '-'}</td>
                        <td>{flow.destinationPort || '-'}</td>
                        <td><strong>{flow.count}</strong></td>
                        <td>{new Date(flow.firstSeen).toLocaleString()}</td>
                        <td>{new Date(flow.lastSeen).toLocaleString()}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            );
          })()}
        </div>
      )}

      {/* Communication Simulation Section */}
      <div className="card" style={{ marginBottom: 24 }}>
        <h2 style={{ marginTop: 0 }}>Simulate Communication</h2>
        <p style={{ color: '#666', marginBottom: 16 }}>
          Check if communication between two IP addresses would be blocked by deployed firewall policies.
        </p>
        
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 16, marginBottom: 16 }}>
          <div>
            <label style={{ display: 'block', marginBottom: 8, fontWeight: 500 }}>Source IP *</label>
            <input
              type="text"
              value={simSourceIp}
              onChange={(e) => setSimSourceIp(e.target.value)}
              placeholder="e.g., 192.168.1.10"
              style={{ width: '100%', padding: '8px', border: '1px solid #ddd', borderRadius: 4 }}
            />
          </div>
          <div>
            <label style={{ display: 'block', marginBottom: 8, fontWeight: 500 }}>Source Port (optional)</label>
            <input
              type="number"
              value={simSourcePort}
              onChange={(e) => setSimSourcePort(e.target.value)}
              placeholder="e.g., 50000"
              min="1"
              max="65535"
              style={{ width: '100%', padding: '8px', border: '1px solid #ddd', borderRadius: 4 }}
            />
          </div>
          <div>
            <label style={{ display: 'block', marginBottom: 8, fontWeight: 500 }}>Destination IP *</label>
            <input
              type="text"
              value={simDestIp}
              onChange={(e) => setSimDestIp(e.target.value)}
              placeholder="e.g., 192.168.1.20"
              style={{ width: '100%', padding: '8px', border: '1px solid #ddd', borderRadius: 4 }}
            />
          </div>
          <div>
            <label style={{ display: 'block', marginBottom: 8, fontWeight: 500 }}>Destination Port (optional)</label>
            <input
              type="number"
              value={simDestPort}
              onChange={(e) => setSimDestPort(e.target.value)}
              placeholder="e.g., 80"
              min="1"
              max="65535"
              style={{ width: '100%', padding: '8px', border: '1px solid #ddd', borderRadius: 4 }}
            />
          </div>
          <div>
            <label style={{ display: 'block', marginBottom: 8, fontWeight: 500 }}>Protocol</label>
            <select
              value={simProtocol}
              onChange={(e) => setSimProtocol(e.target.value)}
              style={{ width: '100%', padding: '8px', border: '1px solid #ddd', borderRadius: 4 }}
            >
              <option value="tcp">TCP</option>
              <option value="udp">UDP</option>
              <option value="icmp">ICMP</option>
            </select>
          </div>
        </div>
        
        <button onClick={handleSimulate} disabled={simLoading} className="btn-primary">
          {simLoading ? 'Simulating...' : 'Simulate'}
        </button>
      </div>

      {simError && (
        <div className="error-banner" style={{ marginBottom: 24 }}>
          {simError}
        </div>
      )}

      {simResults && (
        <div className="card" style={{ marginBottom: 24 }}>
          <h2 style={{ marginTop: 0 }}>
            Simulation Results: {simResults.sourceIp}
            {simResults.sourcePort && `:${simResults.sourcePort}`} → {simResults.destIp}
            {simResults.destPort && `:${simResults.destPort}`} ({simResults.protocol.toUpperCase()})
          </h2>
          
          <div style={{ marginBottom: 24, padding: 16, background: simResults.wouldBlock ? '#ffebee' : '#e8f5e9', borderRadius: 8, border: `2px solid ${simResults.wouldBlock ? '#f44336' : '#4CAF50'}` }}>
            <div style={{ fontSize: '1.2em', fontWeight: 'bold', color: simResults.wouldBlock ? '#f44336' : '#4CAF50', marginBottom: 8 }}>
              {simResults.wouldBlock ? '❌ Communication Would Be BLOCKED' : '✅ Communication Would Be ALLOWED'}
            </div>
            {simResults.blockingRule && (
              <div style={{ marginTop: 12 }}>
                <strong>Blocked by:</strong> {simResults.blockingRule.policyVersion.policySetName} v{simResults.blockingRule.policyVersion.versionNumber} 
                - Rule #{simResults.blockingRule.rule.orderIndex} ({simResults.blockingRule.rule.action})
                {simResults.blockingRule.host && ` on host ${simResults.blockingRule.host.hostname}`}
              </div>
            )}
            {simResults.allRules.length === 0 && simResults.wouldBlock && (
              <div style={{ marginTop: 12 }}>
                <strong>Reason:</strong> No matching firewall rules found. Default policy is DENY.
              </div>
            )}
          </div>

          <div style={{ marginBottom: 16 }}>
            <h3>Host Information</h3>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 16 }}>
              <div style={{ padding: 12, background: '#f5f5f5', borderRadius: 4 }}>
                <strong>Source Host:</strong>{' '}
                {simResults.sourceHost ? (
                  <span>{simResults.sourceHost.hostname} ({simResults.sourceHost.mgmtIp})</span>
                ) : (
                  <span style={{ color: '#666' }}>Not found in inventory</span>
                )}
              </div>
              <div style={{ padding: 12, background: '#f5f5f5', borderRadius: 4 }}>
                <strong>Destination Host:</strong>{' '}
                {simResults.destHost ? (
                  <span>{simResults.destHost.hostname} ({simResults.destHost.mgmtIp})</span>
                ) : (
                  <span style={{ color: '#666' }}>Not found in inventory</span>
                )}
              </div>
            </div>
          </div>

          {simResults.allRules.length > 0 && (
            <div>
              <h3>Matching Firewall Rules ({simResults.allRules.length})</h3>
              <div style={{ display: 'grid', gap: 16 }}>
                {simResults.allRules.map((ruleInfo: any, idx: number) => (
                  <div
                    key={idx}
                    style={{
                      padding: 16,
                      background: ruleInfo.rule.action === 'DENY' ? '#ffebee' : '#e8f5e9',
                      borderRadius: 8,
                      border: `2px solid ${ruleInfo.rule.action === 'DENY' ? '#f44336' : '#4CAF50'}`
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 8 }}>
                      <div>
                        <strong style={{ color: ruleInfo.rule.action === 'DENY' ? '#f44336' : '#4CAF50' }}>
                          {ruleInfo.rule.action} Rule #{ruleInfo.rule.orderIndex}
                        </strong>
                        <div style={{ fontSize: '0.9em', color: '#666', marginTop: 4 }}>
                          Policy: {ruleInfo.policyVersion.policySetName} v{ruleInfo.policyVersion.versionNumber}
                        </div>
                        <div style={{ fontSize: '0.9em', color: '#666' }}>
                          Host: {ruleInfo.host.hostname} ({ruleInfo.appliesTo === 'source' ? 'Source' : 'Destination'}, {ruleInfo.direction})
                        </div>
                      </div>
                    </div>
                    <div style={{ marginTop: 12, padding: 12, background: 'white', borderRadius: 4 }}>
                      <div><strong>Protocol:</strong> {ruleInfo.rule.protocol}</div>
                      {ruleInfo.rule.ports && <div><strong>Ports:</strong> {ruleInfo.rule.ports}</div>}
                      <div><strong>Source:</strong> {ruleInfo.rule.sourceType} = {ruleInfo.rule.sourceValue}</div>
                      <div><strong>Direction:</strong> {ruleInfo.rule.direction}</div>
                      {ruleInfo.rule.comment && <div><strong>Comment:</strong> {ruleInfo.rule.comment}</div>}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Existing Search Section */}
      <div style={{ borderTop: '2px solid #e0e0e0', paddingTop: 24, marginTop: 24 }}>
        <h2>Search Tools</h2>

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
    </div>
  );
}

