import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { api } from '../lib/api';
import { Pagination } from './Pagination';

type Logs = Awaited<ReturnType<typeof api.hostFirewallLogs>>;
type Entry = Logs['entries'][number];
type ActionFilter = 'ALL' | 'ALLOW' | 'DENY';

/** How many of the newest log lines to read from the host. The page is filtered and paged here, so this is what the filters can search. */
const LINE_COUNTS = [100, 200, 300, 500, 1000];
const DEFAULT_LINES = 200;
const PAGE_SIZES = [25, 50, 100, 250];
const NO_FILTERS = { direction: '', protocol: '', source: '', destination: '' };

const endpoint = (ip: string, port: number | null) => `${ip}${port ? `:${port}` : ''}`;
const includes = (value: string, search: string) => value.toLowerCase().includes(search.trim().toLowerCase());
const uniqueSorted = (values: string[]) => [...new Set(values.filter(Boolean))].sort();

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
  const [action, setAction] = useState<ActionFilter>('ALL');
  const [filters, setFilters] = useState(NO_FILTERS);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(PAGE_SIZES[0]);
  const [lines, setLines] = useState(DEFAULT_LINES);
  const latestRead = useRef(0);

  const load = useCallback(async () => {
    // Changing the line count while a read is running must not let the older, slower answer win.
    const read = ++latestRead.current;
    setBusy(true);
    setError(null);
    try {
      const result = await api.hostFirewallLogs(hostId, lines);
      if (read === latestRead.current) setLogs(result);
    } catch (e) {
      if (read === latestRead.current) setError(e instanceof Error ? e.message : 'Could not read the firewall logs');
    } finally {
      if (read === latestRead.current) setBusy(false);
    }
  }, [hostId, lines]);

  useEffect(() => { void load(); }, [load]);

  const entries = useMemo(() => logs?.entries ?? [], [logs]);
  const directions = useMemo(() => uniqueSorted(entries.map((e) => e.direction)), [entries]);
  const protocols = useMemo(() => uniqueSorted(entries.map((e) => e.protocol)), [entries]);
  // The action buttons count what the other filters leave, so they say what a click will show.
  const matching = useMemo(() => entries.filter((e: Entry) => (
    (!filters.direction || e.direction === filters.direction)
    && (!filters.protocol || e.protocol === filters.protocol)
    && includes(endpoint(e.sourceIp, e.sourcePort), filters.source)
    && includes(endpoint(e.destinationIp, e.destinationPort), filters.destination)
  )), [entries, filters]);
  const shown = useMemo(() => (action === 'ALL' ? matching : matching.filter((e) => e.action === action)), [matching, action]);
  const denied = matching.filter((e) => e.action === 'DENY').length;
  // A refresh or a narrower filter can leave fewer pages than the one being viewed.
  const lastPage = Math.max(1, Math.ceil(shown.length / pageSize));
  const currentPage = Math.min(page, lastPage);
  const pageEntries = shown.slice((currentPage - 1) * pageSize, currentPage * pageSize);
  const filtered = action !== 'ALL' || Object.values(filters).some(Boolean);

  const changeFilter = (name: keyof typeof NO_FILTERS, value: string) => {
    setFilters((current) => ({ ...current, [name]: value }));
    setPage(1);
  };
  const clearFilters = () => {
    setAction('ALL');
    setFilters(NO_FILTERS);
    setPage(1);
  };
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
                {(['ALL', 'ALLOW', 'DENY'] as ActionFilter[]).map((f) => (
                  <button key={f} onClick={() => { setAction(f); setPage(1); }} className={action === f ? 'btn-small btn-primary' : 'btn-small btn-secondary'} aria-pressed={action === f}>
                    {f === 'ALL' ? `All (${matching.length})` : f === 'ALLOW' ? `Accepted (${matching.length - denied})` : `Denied (${denied})`}
                  </button>
                ))}
              </div>
              <div className="firewall-logs-fields">
                <label>
                  Direction
                  <select value={filters.direction} onChange={(e) => changeFilter('direction', e.target.value)}>
                    <option value="">All</option>
                    {directions.map((d) => <option key={d} value={d}>{d}</option>)}
                  </select>
                </label>
                <label>
                  Protocol
                  <select value={filters.protocol} onChange={(e) => changeFilter('protocol', e.target.value)}>
                    <option value="">All</option>
                    {protocols.map((p) => <option key={p} value={p}>{p}</option>)}
                  </select>
                </label>
                <label>
                  Source
                  <input type="search" value={filters.source} onChange={(e) => changeFilter('source', e.target.value)} placeholder="IP or port" />
                </label>
                <label>
                  Destination
                  <input type="search" value={filters.destination} onChange={(e) => changeFilter('destination', e.target.value)} placeholder="IP or port" />
                </label>
                <button type="button" className="btn-small btn-secondary" onClick={clearFilters} disabled={!filtered}>Clear filters</button>
                <label className="firewall-logs-lines">
                  Lines to read
                  <select value={lines} onChange={(e) => { setLines(Number(e.target.value)); setPage(1); }} disabled={busy}>
                    {LINE_COUNTS.map((n) => <option key={n} value={n}>{n}</option>)}
                  </select>
                </label>
              </div>

              {shown.length === 0 ? (
                <p className="active-rules-muted">{entries.length === 0 ? 'No entries found.' : 'No entries match these filters.'}</p>
              ) : (
                <table className="firewall-logs-table">
                  <thead>
                    <tr><th>Time</th><th>Action</th><th>Dir</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Rule</th></tr>
                  </thead>
                  <tbody>
                    {pageEntries.map((e, i) => (
                      <tr key={i}>
                        <td>{formatTime(e.at, e.timestamp)}</td>
                        <td className={e.action === 'DENY' ? 'firewall-logs-deny' : 'firewall-logs-allow'}>{e.logOnly ? (e.action === 'DENY' ? 'Would deny' : 'Logged') : e.action === 'DENY' ? 'Denied' : 'Accepted'}</td>
                        <td>{e.direction}</td>
                        <td>{endpoint(e.sourceIp, e.sourcePort)}</td>
                        <td>{endpoint(e.destinationIp, e.destinationPort)}</td>
                        <td>{e.protocol}</td>
                        <td>{e.rule ?? ''}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
              {shown.length > 0 && (
                <Pagination page={currentPage} pageSize={pageSize} total={shown.length} onPage={setPage} onPageSize={(size) => { setPageSize(size); setPage(1); }} noun="entries" sizes={PAGE_SIZES} />
              )}
              <p className="active-rules-muted firewall-logs-footnote">
                Shows rules with logging turned on, and traffic stopped by the default deny (at most 5 lines per second per rule, so not every packet; hosts need a redeployment after upgrading to log it). Hosts using native firewalld or UFW follow their own logging settings instead. "Logged" and "Would deny" come from log-only tests, where nothing was blocked. Reads the newest {lines} lines of the log, and the filters search those. To search further back, read more lines.
              </p>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
