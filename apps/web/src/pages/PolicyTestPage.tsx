import { useState, useEffect } from 'react';
import { api } from '../lib/api';

const STATUS_COLORS: Record<string, string> = {
  PENDING: '#999', DEPLOYING: '#2196F3', RUNNING: '#FF9800', COLLECTING: '#9C27B0',
  ANALYZING: '#673AB7', COMPLETED: '#4CAF50', FAILED: '#f44336',
};

const STATUS_DESCRIPTIONS: Record<string, string> = {
  DEPLOYING: 'Connecting to host via SSH, backing up current rules, deploying log-only policy...',
  RUNNING: 'Log-only policy is active on the host. All traffic is being logged (nothing blocked). Original rules will be restored automatically when the timer expires.',
  COLLECTING: 'Original rules restored. Traffic logs collected. Ready for analysis.',
  COMPLETED: 'Analysis complete. See results below.',
  FAILED: 'Test failed. Check error details.',
};

export function PolicyTestPage() {
  const [sessions, setSessions] = useState<any[]>([]);
  const [selectedSession, setSelectedSession] = useState<any>(null);
  const [hosts, setHosts] = useState<any[]>([]);
  const [policyVersions, setPolicyVersions] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState(false);
  const [error, setError] = useState('');
  const [statusMessage, setStatusMessage] = useState('');
  const [showStart, setShowStart] = useState(false);
  const [startForm, setStartForm] = useState({ policyVersionId: '', hostId: '', durationMinutes: 30 });

  const load = async () => {
    setLoading(true);
    try {
      const [sessRes, hostRes] = await Promise.all([
        api.policyTest.listSessions(),
        api.hosts({ limit: 500 }),
      ]);
      setSessions(sessRes.sessions);
      setHosts(hostRes.hosts);
    } catch (e: any) { setError(e.message); }
    setLoading(false);
  };

  useEffect(() => { load(); }, []);

  // Auto-refresh running sessions every 30 seconds
  useEffect(() => {
    const hasRunning = sessions.some(s => s.status === 'RUNNING' || s.status === 'DEPLOYING');
    if (!hasRunning) return;
    const timer = setInterval(() => { load(); }, 30000);
    return () => clearInterval(timer);
  }, [sessions]);

  const loadPolicyVersions = async () => {
    try {
      const psRes = await api.policySets();
      const allVersions: any[] = [];
      for (const ps of psRes.policySets) {
        const vRes = await api.versions(ps.id);
        for (const v of vRes.versions) {
          allVersions.push({ ...v, policySetName: ps.name });
        }
      }
      setPolicyVersions(allVersions);
    } catch (e: any) { setError(e.message); }
  };

  const startTest = async () => {
    setActionLoading(true);
    setError('');
    setStatusMessage('');
    try {
      const result = await api.policyTest.start({
        policyVersionId: startForm.policyVersionId,
        hostId: startForm.hostId,
        durationMinutes: startForm.durationMinutes,
      });
      setShowStart(false);
      setStartForm({ policyVersionId: '', hostId: '', durationMinutes: 30 });
      setStatusMessage(result.message);
      load();
      selectSession(result.session);
    } catch (e: any) { setError(e.message); }
    setActionLoading(false);
  };

  const selectSession = async (s: any) => {
    try {
      const res = await api.policyTest.getSession(s.id);
      setSelectedSession(res.session);
      setStatusMessage('');
    } catch (e: any) { setError(e.message); }
  };

  const stopSession = async (id: string) => {
    setActionLoading(true);
    setError('');
    setStatusMessage('Restoring original rules and collecting traffic logs...');
    try {
      const result = await api.policyTest.stop(id);
      setStatusMessage(result.message);
      load();
      const res = await api.policyTest.getSession(id);
      setSelectedSession(res.session);
    } catch (e: any) { setError(e.message); setStatusMessage(''); }
    setActionLoading(false);
  };

  const collectLogs = async (id: string) => {
    setActionLoading(true);
    setError('');
    setStatusMessage('Connecting to host to collect current logs...');
    try {
      const result = await api.policyTest.collectLogs(id);
      setStatusMessage(result.message);
      // Refresh session to get updated raw_log_data
      const res = await api.policyTest.getSession(id);
      setSelectedSession(res.session);
    } catch (e: any) { setError(e.message); setStatusMessage(''); }
    setActionLoading(false);
  };

  const analyzeSession = async (id: string) => {
    setActionLoading(true);
    setError('');
    setStatusMessage('Analyzing collected traffic against policy rules...');
    try {
      const result = await api.policyTest.analyze(id);
      setStatusMessage(result.message);
      const res = await api.policyTest.getSession(id);
      setSelectedSession(res.session);
      load();
    } catch (e: any) { setError(e.message); setStatusMessage(''); }
    setActionLoading(false);
  };

  if (loading) return <div>Loading...</div>;

  const analysis = selectedSession?.analysis_results
    ? (typeof selectedSession.analysis_results === 'string' ? JSON.parse(selectedSession.analysis_results) : selectedSession.analysis_results)
    : null;

  const rawLogData = selectedSession?.raw_log_data
    ? (typeof selectedSession.raw_log_data === 'string' ? JSON.parse(selectedSession.raw_log_data) : selectedSession.raw_log_data)
    : null;

  const timeRemaining = selectedSession?.status === 'RUNNING' && selectedSession?.scheduled_end_at
    ? Math.max(0, Math.round((new Date(selectedSession.scheduled_end_at).getTime() - Date.now()) / 60000))
    : null;

  return (
    <div>
      <h2>Policy Impact Analysis</h2>
      <p style={{ color: '#666', marginBottom: 16 }}>
        Test a firewall policy against real traffic <strong>before enforcing it</strong>. The policy is deployed in log-only mode
        (nothing gets blocked), traffic is captured, then analyzed to find gaps.
      </p>

      {error && <div style={{ color: 'red', marginBottom: 8, padding: 8, background: '#FFEBEE', borderRadius: 4 }}>{error} <button onClick={() => setError('')}>dismiss</button></div>}
      {statusMessage && <div style={{ color: '#1565C0', marginBottom: 8, padding: 8, background: '#E3F2FD', borderRadius: 4 }}>{statusMessage}</div>}

      <div style={{ marginBottom: 16 }}>
        <button onClick={() => { setShowStart(true); loadPolicyVersions(); }}>+ Start Policy Test</button>
      </div>

      {showStart && (
        <div style={{ border: '1px solid #ccc', padding: 16, marginBottom: 16, borderRadius: 4, background: '#FAFAFA' }}>
          <h3>Start Policy Test</h3>
          <p style={{ fontSize: '0.9em', color: '#666', marginBottom: 12 }}>
            Select a policy version and a target host. Segmentra will SSH into the host, backup its current firewall rules,
            deploy your policy in <strong>log-only mode</strong> (all traffic logged, nothing blocked), wait for the specified duration
            to capture real traffic, then automatically restore the original rules and let you analyze the results.
          </p>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
            <div>
              <label style={{ fontSize: '0.85em', fontWeight: 'bold' }}>Policy Version</label>
              <select value={startForm.policyVersionId} onChange={e => setStartForm(f => ({ ...f, policyVersionId: e.target.value }))} style={{ width: '100%' }}>
                <option value="">Select policy version...</option>
                {policyVersions.map(v => <option key={v.id} value={v.id}>{v.policySetName} v{v.version_number} ({v.status})</option>)}
              </select>
            </div>
            <div>
              <label style={{ fontSize: '0.85em', fontWeight: 'bold' }}>Target Host</label>
              <select value={startForm.hostId} onChange={e => setStartForm(f => ({ ...f, hostId: e.target.value }))} style={{ width: '100%' }}>
                <option value="">Select host...</option>
                {hosts.map(h => <option key={h.id} value={h.id}>{h.hostname} ({h.mgmt_ip})</option>)}
              </select>
            </div>
            <div>
              <label style={{ fontSize: '0.85em', fontWeight: 'bold' }}>Duration (minutes)</label>
              <input type="number" value={startForm.durationMinutes} onChange={e => setStartForm(f => ({ ...f, durationMinutes: parseInt(e.target.value) || 30 }))} min={1} max={1440} style={{ width: '100%' }} />
            </div>
          </div>
          <div style={{ marginTop: 12 }}>
            <button onClick={startTest} disabled={!startForm.policyVersionId || !startForm.hostId || actionLoading}>
              {actionLoading ? 'Deploying...' : 'Start Test'}
            </button>
            <button onClick={() => setShowStart(false)} style={{ marginLeft: 8 }}>Cancel</button>
          </div>
        </div>
      )}

      {/* Workflow Steps Indicator */}
      {(() => {
        const steps = [
          { num: '1', label: 'Deploy log-only', icon: '>' },
          { num: '2', label: 'Capture traffic', icon: '>' },
          { num: '3', label: 'Restore & collect', icon: '>' },
          { num: '4', label: 'Analyze gaps', icon: '' },
        ];
        // Determine active step from selected session
        const activeStep = !selectedSession ? -1
          : selectedSession.status === 'DEPLOYING' ? 0
          : selectedSession.status === 'RUNNING' ? 1
          : selectedSession.status === 'COLLECTING' ? 2
          : selectedSession.status === 'COMPLETED' || selectedSession.status === 'ANALYZING' ? 3
          : -1;
        return (
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', marginBottom: 20, gap: 0 }}>
            {steps.map((step, i) => (
              <div key={i} style={{ display: 'contents' }}>
                <div style={{
                  display: 'flex', alignItems: 'center', gap: 8,
                  padding: '8px 18px',
                  borderRadius: 20,
                  fontSize: '13px',
                  fontWeight: i === activeStep ? 600 : 400,
                  background: i === activeStep ? '#8b6914' : i < activeStep ? '#f0ebe2' : '#f7f4ef',
                  color: i === activeStep ? '#fdfcf9' : i < activeStep ? '#5c4633' : '#97846c',
                  border: `1px solid ${i === activeStep ? '#8b6914' : i < activeStep ? '#d4c9b8' : '#e8e0d4'}`,
                  whiteSpace: 'nowrap',
                }}>
                  <span style={{
                    display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
                    width: 20, height: 20, borderRadius: '50%', fontSize: '11px', fontWeight: 700,
                    background: i === activeStep ? 'rgba(255,255,255,0.25)' : i < activeStep ? '#d4c9b8' : '#e8e0d4',
                    color: i === activeStep ? '#fdfcf9' : i < activeStep ? '#5c4633' : '#97846c',
                  }}>{step.num}</span>
                  {step.label}
                </div>
                {step.icon && (
                  <svg width="24" height="12" viewBox="0 0 24 12" style={{ flex: '0 0 24px', margin: '0 4px' }}>
                    <path d="M4 6 L16 6 M13 2.5 L17 6 L13 9.5" fill="none" stroke={i < activeStep ? '#b8a890' : '#d4c9b8'} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
                  </svg>
                )}
              </div>
            ))}
          </div>
        );
      })()}

      <div style={{ display: 'flex', gap: 24 }}>
        {/* Sessions list */}
        <div style={{ flex: 1 }}>
          <table style={{ width: '100%' }}>
            <thead><tr><th>Host</th><th>Policy</th><th>Status</th><th>Duration</th><th>Started</th><th>Actions</th></tr></thead>
            <tbody>
              {sessions.map(s => (
                <tr key={s.id} onClick={() => selectSession(s)} style={{ cursor: 'pointer', background: selectedSession?.id === s.id ? '#e8f0fe' : undefined }}>
                  <td>{s.hostname}</td>
                  <td>{s.policy_set_name} v{s.version_number}</td>
                  <td><span style={{ color: STATUS_COLORS[s.status] || '#000', fontWeight: 'bold' }}>{s.status}</span></td>
                  <td>{s.duration_minutes}m</td>
                  <td>{s.started_at ? new Date(s.started_at).toLocaleString() : '-'}</td>
                  <td onClick={e => e.stopPropagation()}>
                    {s.status === 'RUNNING' && (
                      <>
                        <button onClick={() => collectLogs(s.id)} disabled={actionLoading} style={{ fontSize: '0.85em' }}>Peek Logs</button>
                        <button onClick={() => stopSession(s.id)} disabled={actionLoading} style={{ marginLeft: 4, fontSize: '0.85em' }}>Stop & Collect</button>
                      </>
                    )}
                    {s.status === 'COLLECTING' && (
                      <button onClick={() => analyzeSession(s.id)} disabled={actionLoading} style={{ fontSize: '0.85em', background: '#4CAF50', color: 'white', border: 'none', padding: '4px 12px', borderRadius: 4, cursor: 'pointer' }}>
                        Analyze
                      </button>
                    )}
                  </td>
                </tr>
              ))}
              {sessions.length === 0 && <tr><td colSpan={6} style={{ textAlign: 'center', color: '#666' }}>No test sessions. Click "+ Start Policy Test" to begin.</td></tr>}
            </tbody>
          </table>
        </div>

        {/* Session detail panel */}
        {selectedSession && (
          <div style={{ flex: 1, border: '1px solid #ccc', padding: 16, borderRadius: 4 }}>
            <h3>{selectedSession.hostname} — {selectedSession.policy_set_name} v{selectedSession.version_number}</h3>

            {/* Status description */}
            <div style={{ padding: 8, marginBottom: 12, borderRadius: 4, background: selectedSession.status === 'RUNNING' ? '#FFF3E0' : selectedSession.status === 'COMPLETED' ? '#E8F5E9' : selectedSession.status === 'FAILED' ? '#FFEBEE' : '#F3E5F5' }}>
              <strong style={{ color: STATUS_COLORS[selectedSession.status] }}>{selectedSession.status}</strong>
              {timeRemaining !== null && <span style={{ marginLeft: 8 }}>({timeRemaining} min remaining)</span>}
              <div style={{ fontSize: '0.85em', marginTop: 4 }}>{STATUS_DESCRIPTIONS[selectedSession.status] || ''}</div>
            </div>

            {/* Action buttons */}
            <div style={{ marginBottom: 12 }}>
              {selectedSession.status === 'RUNNING' && (
                <>
                  <button onClick={() => collectLogs(selectedSession.id)} disabled={actionLoading} style={{ marginRight: 8 }}>
                    Peek at Logs (while running)
                  </button>
                  <button onClick={() => stopSession(selectedSession.id)} disabled={actionLoading}>
                    Stop Test & Collect Logs
                  </button>
                </>
              )}
              {selectedSession.status === 'COLLECTING' && (
                <button onClick={() => analyzeSession(selectedSession.id)} disabled={actionLoading}
                  style={{ background: '#4CAF50', color: 'white', border: 'none', padding: '8px 20px', borderRadius: 4, cursor: 'pointer', fontSize: '1em' }}>
                  Analyze Traffic vs. Policy Rules
                </button>
              )}
            </div>

            {/* Collected flows summary (before analysis) */}
            {rawLogData && !analysis && (
              <div style={{ marginBottom: 12 }}>
                <h4>Collected Traffic</h4>
                <p style={{ fontSize: '0.9em', color: '#666' }}>
                  {rawLogData.entries?.length || 0} log entries parsed into {rawLogData.flows?.length || 0} unique flows.
                  Click <strong>Analyze</strong> to compare these flows against your policy rules.
                </p>
                {rawLogData.flows?.length > 0 && (
                  <table style={{ width: '100%', fontSize: '0.85em' }}>
                    <thead><tr><th>Dir</th><th>Source</th><th>Dest</th><th>Proto</th><th>Port</th><th>Count</th></tr></thead>
                    <tbody>
                      {rawLogData.flows.slice(0, 10).map((f: any, i: number) => (
                        <tr key={i}>
                          <td>{f.direction}</td><td>{f.sourceIp}</td><td>{f.destinationIp}</td>
                          <td>{f.protocol}</td><td>{f.destinationPort || '*'}</td><td>{f.count}</td>
                        </tr>
                      ))}
                      {rawLogData.flows.length > 10 && <tr><td colSpan={6} style={{ color: '#666' }}>... and {rawLogData.flows.length - 10} more flows</td></tr>}
                    </tbody>
                  </table>
                )}
              </div>
            )}

            {/* Analysis results */}
            {analysis && (
              <>
                <h4>Analysis Results</h4>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 8, marginBottom: 16 }}>
                  <div style={{ textAlign: 'center', padding: 12, background: '#E8F5E9', borderRadius: 4 }}>
                    <div style={{ fontSize: '2em', fontWeight: 'bold', color: '#4CAF50' }}>{analysis.summary.matched}</div>
                    <div style={{ fontSize: '0.85em' }}>Matched Flows</div>
                    <div style={{ fontSize: '0.75em', color: '#666' }}>Traffic covered by ALLOW rules</div>
                  </div>
                  <div style={{ textAlign: 'center', padding: 12, background: '#FFF3E0', borderRadius: 4 }}>
                    <div style={{ fontSize: '2em', fontWeight: 'bold', color: '#FF9800' }}>{analysis.summary.unexpectedAllows}</div>
                    <div style={{ fontSize: '0.85em' }}>Unmatched Flows</div>
                    <div style={{ fontSize: '0.75em', color: '#666' }}>Default-deny would BLOCK these</div>
                  </div>
                  <div style={{ textAlign: 'center', padding: 12, background: '#FFEBEE', borderRadius: 4 }}>
                    <div style={{ fontSize: '2em', fontWeight: 'bold', color: '#f44336' }}>{analysis.summary.unexpectedBlocks}</div>
                    <div style={{ fontSize: '0.85em' }}>DENY Hits</div>
                    <div style={{ fontSize: '0.75em', color: '#666' }}>Active traffic matching DENY rules</div>
                  </div>
                </div>

                <div style={{ marginBottom: 12, padding: 8, background: '#f5f5f5', borderRadius: 4 }}>
                  <strong>Coverage:</strong> {analysis.summary.coveragePercent}% of observed traffic is covered by ALLOW rules |
                  <strong> Total Flows:</strong> {analysis.summary.totalFlows}
                </div>

                {analysis.unexpectedAllows?.length > 0 && (
                  <>
                    <h4 style={{ color: '#FF9800' }}>Unmatched Flows — would be BLOCKED by default-deny</h4>
                    <p style={{ fontSize: '0.85em', color: '#666' }}>These flows have no matching rule. If you enforce this policy, this traffic will be dropped. Add ALLOW rules for any legitimate traffic.</p>
                    <table style={{ width: '100%', fontSize: '0.85em' }}>
                      <thead><tr><th>Dir</th><th>Source IP</th><th>Dest IP</th><th>Proto</th><th>Dest Port</th><th>Packet Count</th></tr></thead>
                      <tbody>
                        {analysis.unexpectedAllows.slice(0, 20).map((u: any, i: number) => (
                          <tr key={i} style={{ background: '#FFF8E1' }}>
                            <td>{u.flow.direction}</td><td>{u.flow.sourceIp}</td><td>{u.flow.destinationIp}</td>
                            <td>{u.flow.protocol}</td><td>{u.flow.destinationPort || '*'}</td><td>{u.flow.count}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                    {analysis.unexpectedAllows.length > 20 && <p style={{ color: '#666', fontSize: '0.85em' }}>Showing first 20 of {analysis.unexpectedAllows.length}</p>}
                  </>
                )}

                {analysis.unexpectedBlocks?.length > 0 && (
                  <>
                    <h4 style={{ color: '#f44336', marginTop: 16 }}>DENY Rule Hits — active traffic that would be blocked</h4>
                    <p style={{ fontSize: '0.85em', color: '#666' }}>These flows match a DENY rule in your policy, but the traffic is actively flowing. Enforcing this policy will break these connections.</p>
                    <table style={{ width: '100%', fontSize: '0.85em' }}>
                      <thead><tr><th>Dir</th><th>Source IP</th><th>Dest IP</th><th>Proto</th><th>Dest Port</th><th>Blocking Rule</th></tr></thead>
                      <tbody>
                        {analysis.unexpectedBlocks.slice(0, 20).map((u: any, i: number) => (
                          <tr key={i} style={{ background: '#FFEBEE' }}>
                            <td>{u.flow.direction}</td><td>{u.flow.sourceIp}</td><td>{u.flow.destinationIp}</td>
                            <td>{u.flow.protocol}</td><td>{u.flow.destinationPort || '*'}</td>
                            <td>{u.blockingRule?.comment || `Rule #${u.blockingRule?.order_index}`}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </>
                )}

                {analysis.matchedFlows?.length > 0 && (
                  <>
                    <h4 style={{ color: '#4CAF50', marginTop: 16 }}>Matched Flows — covered by ALLOW rules</h4>
                    <table style={{ width: '100%', fontSize: '0.85em' }}>
                      <thead><tr><th>Dir</th><th>Source IP</th><th>Dest IP</th><th>Proto</th><th>Port</th><th>Matched Rule</th></tr></thead>
                      <tbody>
                        {analysis.matchedFlows.slice(0, 15).map((m: any, i: number) => (
                          <tr key={i} style={{ background: '#F1F8E9' }}>
                            <td>{m.flow.direction}</td><td>{m.flow.sourceIp}</td><td>{m.flow.destinationIp}</td>
                            <td>{m.flow.protocol}</td><td>{m.flow.destinationPort || '*'}</td>
                            <td>{m.matchedRule?.comment || `Rule #${m.matchedRule?.order_index} (${m.expectedAction})`}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                    {analysis.matchedFlows.length > 15 && <p style={{ color: '#666', fontSize: '0.85em' }}>Showing first 15 of {analysis.matchedFlows.length}</p>}
                  </>
                )}
              </>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
