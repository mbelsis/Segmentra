import { useCallback, useEffect, useMemo, useState } from 'react';
import { api } from '../lib/api';

type Logs = Awaited<ReturnType<typeof api.hostFirewallLogs>>;
type Filter = 'ALL' | 'ALLOW' | 'DENY';

interface Props {
  hostId: string;
  hostname: string;
  onClose: () => void;
}

function formatTime(at: number | null, raw: string) {
  return at === null ? raw : new Date(at).toLocaleString();
}

export function HostFirewallLogsPanel({ hostId, hostname, onClose }: Props) {
  const [logs, setLogs] = useState<Logs | null>(null);
  const [busy, setBusy] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<Filter>('ALL');

  const load = useCallback(async () => {
    setBusy(true);
    setError(null);
    try {
      setLogs(await api.hostFirewallLogs(hostId));
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not read the firewall logs');
    } finally {
      setBusy(false);
    }
  }, [hostId]);

  useEffect(() => { void load(); }, [load]);

  const entries = useMemo(() => logs?.entries ?? [], [logs]);
  const shown = useMemo(() => (filter === 'ALL' ? entries : entries.filter((e) => e.action === filter)), [entries, filter]);
  const denied = entries.filter((e) => e.action === 'DENY').length;
  const logOnly = logs?.activeSession != null;

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content active-rules-modal" role="dialog" aria-label={`Firewall logs of ${hostname}`} onClick={(e) => e.stopPropagation()}>
        <div className="visualization-header">
          <div>
            <h2>Firewall logs: {hostname}</h2>
            {logs && <div className="active-rules-muted">Read {new Date(logs.readAt).toLocaleTimeString()} from {logs.source}</div>}
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button onClick={() => void load()} className="btn-secondary" disabled={busy}>{busy ? 'Reading...' : 'Refresh'}</button>
            <button onClick={onClose} className="btn-secondary">Close</button>
          </div>
        </div>

        <div className="active-rules-body">
          {error && <p className="error">{error}</p>}
          {logs && !logs.success && <p className="error">{logs.error}</p>}

          {logOnly && (
            <div role="note" className="firewall-logs-note">
              A {logs?.activeSession === 'learning' ? 'firewall learning session' : 'policy test'} is running on this host, so nothing is being
              blocked.
            </div>
          )}

          {logs?.success && logs.source === 'none' && (
            <div role="note" className="firewall-logs-note">
              This host has no kernel log Segmentra can read (no rsyslog, journald, kernel log file or permitted dmesg). Install rsyslog on the
              host. Containers normally cannot read the kernel log.
            </div>
          )}

          {logs?.success && logs.source !== 'none' && (
            <>
              <div className="firewall-logs-filter" role="group" aria-label="Filter by action">
                {(['ALL', 'ALLOW', 'DENY'] as Filter[]).map((f) => (
                  <button key={f} onClick={() => setFilter(f)} className={filter === f ? 'btn-small btn-primary' : 'btn-small btn-secondary'} aria-pressed={filter === f}>
                    {f === 'ALL' ? `All (${entries.length})` : f === 'ALLOW' ? `Accepted (${entries.length - denied})` : `Denied (${denied})`}
                  </button>
                ))}
              </div>

              {shown.length === 0 ? (
                <p className="active-rules-muted">No {filter === 'ALL' ? '' : filter === 'ALLOW' ? 'accepted ' : 'denied '}entries found.</p>
              ) : (
                <table className="firewall-logs-table">
                  <thead>
                    <tr><th>Time</th><th>Action</th><th>Dir</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Rule</th></tr>
                  </thead>
                  <tbody>
                    {shown.map((e, i) => (
                      <tr key={i}>
                        <td>{formatTime(e.at, e.timestamp)}</td>
                        <td className={e.action === 'DENY' ? 'firewall-logs-deny' : 'firewall-logs-allow'}>{e.logOnly ? (e.action === 'DENY' ? 'Would deny' : 'Logged') : e.action === 'DENY' ? 'Denied' : 'Accepted'}</td>
                        <td>{e.direction}</td>
                        <td>{e.sourceIp}{e.sourcePort ? `:${e.sourcePort}` : ''}</td>
                        <td>{e.destinationIp}{e.destinationPort ? `:${e.destinationPort}` : ''}</td>
                        <td>{e.protocol}</td>
                        <td>{e.rule ?? ''}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
              <p className="active-rules-muted firewall-logs-footnote">
                Shows rules with logging turned on, and traffic stopped by the default deny (at most 5 lines per second per rule, so not every packet; hosts need a redeployment after upgrading to log it). Hosts using native firewalld or UFW follow their own logging settings instead. "Logged" and "Would deny" come from log-only tests, where nothing was blocked. Shows up to the newest 200 entries.
              </p>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
