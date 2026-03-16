import { useState } from 'react';
import { api } from '../lib/api';

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#a63d2f',
  high: '#c47a1a',
  medium: '#8b6914',
  low: '#5c4633',
  info: '#78644e',
};
const SEVERITY_BG: Record<string, string> = {
  critical: '#faf0ee',
  high: '#fdf6ec',
  medium: '#f7f4ef',
  low: '#f7f4ef',
  info: '#f7f4ef',
};

export function SecurityAuditPage() {
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [filterSeverity, setFilterSeverity] = useState('');

  const runScan = async () => {
    setLoading(true);
    setError('');
    try {
      const res = await api.securityAudit.scan();
      setResult(res);
    } catch (e: any) { setError(e.message); }
    setLoading(false);
  };

  const filtered = result?.findings?.filter((f: any) => !filterSeverity || f.severity === filterSeverity) || [];

  return (
    <div>
      <h2>Security Posture Audit</h2>
      <p style={{ color: '#78644e', fontSize: '13.5px', marginTop: -4, marginBottom: 16, lineHeight: 1.6 }}>
        Scan all deployed and approved policies for excessive permissions, overly broad rules, sensitive port exposure,
        unmanaged hosts, stale deployments, and duplicate rules. Findings are categorized by severity to help prioritize remediation.
      </p>

      {error && <div style={{ color: '#a63d2f', marginBottom: 12, padding: 10, background: '#faf0ee', borderRadius: 8, borderLeft: '4px solid #a63d2f' }}>{error}</div>}

      <div style={{ marginBottom: 20 }}>
        <button onClick={runScan} disabled={loading} className="btn-primary" style={{ minWidth: 160 }}>
          {loading ? 'Scanning...' : 'Run Security Scan'}
        </button>
      </div>

      {result && (
        <>
          {/* Summary cards */}
          <div style={{ display: 'flex', gap: 12, marginBottom: 24 }}>
            {(['critical', 'high', 'medium', 'low'] as const).map(sev => (
              <div key={sev} onClick={() => setFilterSeverity(filterSeverity === sev ? '' : sev)}
                style={{
                  flex: 1, textAlign: 'center', padding: '16px 12px', borderRadius: 10,
                  background: SEVERITY_BG[sev], border: `2px solid ${filterSeverity === sev ? SEVERITY_COLORS[sev] : 'transparent'}`,
                  cursor: 'pointer', transition: 'border-color 0.15s',
                }}>
                <div style={{ fontSize: '2em', fontWeight: 700, color: SEVERITY_COLORS[sev] }}>{result.summary[sev]}</div>
                <div style={{ fontSize: '12.5px', fontWeight: 600, color: SEVERITY_COLORS[sev], textTransform: 'uppercase', letterSpacing: '0.04em' }}>{sev}</div>
              </div>
            ))}
            <div style={{ flex: 1, textAlign: 'center', padding: '16px 12px', borderRadius: 10, background: '#f7f4ef', border: '2px solid transparent' }}>
              <div style={{ fontSize: '2em', fontWeight: 700, color: '#3d2e1e' }}>{result.summary.total}</div>
              <div style={{ fontSize: '12.5px', fontWeight: 600, color: '#5c4633', textTransform: 'uppercase', letterSpacing: '0.04em' }}>Total</div>
            </div>
          </div>

          {filterSeverity && (
            <div style={{ marginBottom: 12, fontSize: '13px', color: '#78644e' }}>
              Showing <strong>{filterSeverity}</strong> findings only. <button onClick={() => setFilterSeverity('')} className="btn-small btn-secondary">Show All</button>
            </div>
          )}

          {/* Findings list */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {filtered.map((f: any, i: number) => (
              <div key={i} style={{
                padding: '14px 18px', borderRadius: 10, background: '#fdfcf9',
                border: `1px solid #e8e0d4`, borderLeft: `4px solid ${SEVERITY_COLORS[f.severity]}`,
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 4 }}>
                  <div>
                    <span style={{
                      display: 'inline-block', padding: '2px 8px', borderRadius: 4, fontSize: '11px', fontWeight: 600,
                      background: SEVERITY_BG[f.severity], color: SEVERITY_COLORS[f.severity], textTransform: 'uppercase',
                      marginRight: 8,
                    }}>{f.severity}</span>
                    <span style={{
                      display: 'inline-block', padding: '2px 8px', borderRadius: 4, fontSize: '11px',
                      background: '#f0ebe2', color: '#5c4633',
                    }}>{f.category}</span>
                  </div>
                  {f.policySetName && (
                    <span style={{ fontSize: '12px', color: '#97846c' }}>{f.policySetName} v{f.versionNumber}</span>
                  )}
                </div>
                <div style={{ fontWeight: 600, fontSize: '14px', color: '#292018', marginBottom: 4 }}>{f.title}</div>
                <div style={{ fontSize: '13px', color: '#5c4633', lineHeight: 1.5 }}>{f.description}</div>
                {f.hostCount && (
                  <div style={{ marginTop: 6, fontSize: '12.5px', color: '#78644e' }}>
                    Affected: <strong>{f.hostCount} host(s)</strong>
                  </div>
                )}
                {f.details?.hosts && (
                  <div style={{ marginTop: 6, display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                    {f.details.hosts.slice(0, 10).map((h: any, j: number) => (
                      <span key={j} style={{ padding: '2px 8px', background: '#f0ebe2', borderRadius: 4, fontSize: '11.5px', color: '#5c4633' }}>
                        {h.hostname || h.policy} {h.ip ? <code>({h.ip})</code> : ''} {h.daysAgo ? `(${h.daysAgo}d ago)` : ''}
                      </span>
                    ))}
                    {f.details.hosts.length > 10 && <span style={{ fontSize: '11.5px', color: '#97846c' }}>+{f.details.hosts.length - 10} more</span>}
                  </div>
                )}
              </div>
            ))}
            {filtered.length === 0 && result.summary.total === 0 && (
              <div style={{ textAlign: 'center', padding: 40, color: '#5a7a3a', fontSize: '15px' }}>
                No findings. Your security posture looks good.
              </div>
            )}
            {filtered.length === 0 && result.summary.total > 0 && (
              <div style={{ textAlign: 'center', padding: 24, color: '#97846c' }}>
                No findings match the selected filter.
              </div>
            )}
          </div>
        </>
      )}

      {!result && !loading && (
        <div style={{ textAlign: 'center', padding: '48px 24px', background: '#f7f4ef', borderRadius: 10, border: '1px solid #e8e0d4' }}>
          <p style={{ color: '#5c4633', fontSize: '14px', marginBottom: 16 }}>
            Click <strong>Run Security Scan</strong> to analyze all deployed policies for excessive permissions and compliance risks.
          </p>
          <div style={{ fontSize: '13px', color: '#97846c', lineHeight: 1.8 }}>
            The scan checks for:<br />
            Sensitive ports (SSH, RDP, databases) open to 0.0.0.0/0<br />
            Very broad source CIDRs (/0 to /8)<br />
            Any-protocol / any-port rules<br />
            ALL_INTERFACES scope with broad sources<br />
            Duplicate rules across policy sets<br />
            Unmanaged hosts (no policy deployed)<br />
            Stale policies (deployed &gt; 90 days without review)
          </div>
        </div>
      )}
    </div>
  );
}
