import { useState, useEffect } from 'react';
import { api } from '../lib/api';

const STATUS_COLORS: Record<string, string> = {
  PENDING: '#999', DEPLOYING: '#2196F3', RUNNING: '#FF9800', COLLECTING: '#9C27B0',
  ANALYZING: '#673AB7', COMPLETED: '#4CAF50', FAILED: '#f44336',
};

export function PolicyTestPage() {
  const [sessions, setSessions] = useState<any[]>([]);
  const [selectedSession, setSelectedSession] = useState<any>(null);
  const [hosts, setHosts] = useState<any[]>([]);
  const [policyVersions, setPolicyVersions] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
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
    try {
      const result = await api.policyTest.start({
        policyVersionId: startForm.policyVersionId,
        hostId: startForm.hostId,
        durationMinutes: startForm.durationMinutes,
      });
      setShowStart(false);
      setStartForm({ policyVersionId: '', hostId: '', durationMinutes: 30 });
      load();
      selectSession(result.session);
    } catch (e: any) { setError(e.message); }
  };

  const selectSession = async (s: any) => {
    try {
      const res = await api.policyTest.getSession(s.id);
      setSelectedSession(res.session);
    } catch (e: any) { setError(e.message); }
  };

  const stopSession = async (id: string) => {
    try {
      await api.policyTest.stop(id);
      load();
      const res = await api.policyTest.getSession(id);
      setSelectedSession(res.session);
    } catch (e: any) { setError(e.message); }
  };

  const analyzeSession = async (id: string) => {
    try {
      await api.policyTest.analyze(id);
      const res = await api.policyTest.getSession(id);
      setSelectedSession(res.session);
      load();
    } catch (e: any) { setError(e.message); }
  };

  if (loading) return <div>Loading...</div>;

  const analysis = selectedSession?.analysis_results ? (typeof selectedSession.analysis_results === 'string' ? JSON.parse(selectedSession.analysis_results) : selectedSession.analysis_results) : null;

  return (
    <div>
      <h2>Policy Testing</h2>
      {error && <div style={{ color: 'red', marginBottom: 8 }}>{error} <button onClick={() => setError('')}>dismiss</button></div>}

      <div style={{ marginBottom: 16 }}>
        <button onClick={() => { setShowStart(true); loadPolicyVersions(); }}>+ Start Policy Test</button>
      </div>

      {showStart && (
        <div style={{ border: '1px solid #ccc', padding: 16, marginBottom: 16, borderRadius: 4 }}>
          <h3>Start Policy Test</h3>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
            <select value={startForm.policyVersionId} onChange={e => setStartForm(f => ({ ...f, policyVersionId: e.target.value }))}>
              <option value="">Select policy version...</option>
              {policyVersions.map(v => <option key={v.id} value={v.id}>{v.policySetName} v{v.version_number} ({v.status})</option>)}
            </select>
            <select value={startForm.hostId} onChange={e => setStartForm(f => ({ ...f, hostId: e.target.value }))}>
              <option value="">Select host...</option>
              {hosts.map(h => <option key={h.id} value={h.id}>{h.hostname} ({h.mgmt_ip})</option>)}
            </select>
            <label>Duration (minutes): <input type="number" value={startForm.durationMinutes} onChange={e => setStartForm(f => ({ ...f, durationMinutes: parseInt(e.target.value) || 30 }))} min={1} max={1440} /></label>
          </div>
          <div style={{ marginTop: 8 }}>
            <button onClick={startTest} disabled={!startForm.policyVersionId || !startForm.hostId}>Start Test</button>
            <button onClick={() => setShowStart(false)} style={{ marginLeft: 8 }}>Cancel</button>
          </div>
        </div>
      )}

      <div style={{ display: 'flex', gap: 24 }}>
        <div style={{ flex: 1 }}>
          <table style={{ width: '100%' }}>
            <thead><tr><th>Host</th><th>Policy</th><th>Status</th><th>Duration</th><th>Started</th><th>Actions</th></tr></thead>
            <tbody>
              {sessions.map(s => (
                <tr key={s.id} onClick={() => selectSession(s)} style={{ cursor: 'pointer', background: selectedSession?.id === s.id ? '#e8f0fe' : undefined }}>
                  <td>{s.hostname}</td>
                  <td>{s.policy_set_name} v{s.version_number}</td>
                  <td><span style={{ color: STATUS_COLORS[s.status] || '#000' }}>{s.status}</span></td>
                  <td>{s.duration_minutes}m</td>
                  <td>{s.started_at ? new Date(s.started_at).toLocaleString() : '-'}</td>
                  <td>
                    {s.status === 'RUNNING' && <button onClick={(e) => { e.stopPropagation(); stopSession(s.id); }}>Stop</button>}
                    {(s.status === 'COLLECTING' || s.status === 'RUNNING') && <button onClick={(e) => { e.stopPropagation(); analyzeSession(s.id); }} style={{ marginLeft: 4 }}>Analyze</button>}
                  </td>
                </tr>
              ))}
              {sessions.length === 0 && <tr><td colSpan={6}>No test sessions</td></tr>}
            </tbody>
          </table>
        </div>

        {selectedSession && analysis && (
          <div style={{ flex: 1, border: '1px solid #ccc', padding: 16, borderRadius: 4 }}>
            <h3>Analysis Results</h3>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 8, marginBottom: 16 }}>
              <div style={{ textAlign: 'center', padding: 8, background: '#E8F5E9', borderRadius: 4 }}>
                <div style={{ fontSize: '1.5em', fontWeight: 'bold', color: '#4CAF50' }}>{analysis.summary.matched}</div>
                <div>Matched Flows</div>
              </div>
              <div style={{ textAlign: 'center', padding: 8, background: '#FFF3E0', borderRadius: 4 }}>
                <div style={{ fontSize: '1.5em', fontWeight: 'bold', color: '#FF9800' }}>{analysis.summary.unexpectedAllows}</div>
                <div>Unmatched (would block)</div>
              </div>
              <div style={{ textAlign: 'center', padding: 8, background: '#FFEBEE', borderRadius: 4 }}>
                <div style={{ fontSize: '1.5em', fontWeight: 'bold', color: '#f44336' }}>{analysis.summary.unexpectedBlocks}</div>
                <div>Unexpected Blocks</div>
              </div>
            </div>
            <div style={{ marginBottom: 8 }}>
              <strong>Coverage:</strong> {analysis.summary.coveragePercent}% | <strong>Total Flows:</strong> {analysis.summary.totalFlows}
            </div>

            {analysis.unexpectedAllows?.length > 0 && (
              <>
                <h4 style={{ color: '#FF9800' }}>Unmatched Flows (would be blocked by default-deny)</h4>
                <table style={{ width: '100%', fontSize: '0.85em' }}>
                  <thead><tr><th>Dir</th><th>Source</th><th>Dest</th><th>Proto</th><th>Port</th><th>Count</th></tr></thead>
                  <tbody>
                    {analysis.unexpectedAllows.slice(0, 20).map((u: any, i: number) => (
                      <tr key={i} style={{ background: '#FFF8E1' }}>
                        <td>{u.flow.direction}</td><td>{u.flow.sourceIp}</td><td>{u.flow.destinationIp}</td>
                        <td>{u.flow.protocol}</td><td>{u.flow.destinationPort || '*'}</td><td>{u.flow.count}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </>
            )}

            {analysis.unexpectedBlocks?.length > 0 && (
              <>
                <h4 style={{ color: '#f44336' }}>Unexpected Blocks (DENY rule matches active traffic)</h4>
                <table style={{ width: '100%', fontSize: '0.85em' }}>
                  <thead><tr><th>Dir</th><th>Source</th><th>Dest</th><th>Proto</th><th>Port</th><th>Blocking Rule</th></tr></thead>
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
          </div>
        )}
      </div>
    </div>
  );
}
