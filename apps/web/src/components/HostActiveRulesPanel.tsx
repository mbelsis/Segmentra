import { Fragment, useEffect, useMemo, useState } from 'react';

import { api } from '../lib/api';

/**
 * "Active rules" panel for one inventory host: which policy set / version is enforced right now,
 * its access-control rules in readable form, the compliance (drift) status, and - for operators -
 * the live ruleset read from the host next to the ruleset Segmentra expects to be there.
 */

type HostPolicy = {
  deployment: { id: string; status: string; mode: string; createdAt: string; startedAt: string | null; finishedAt: string | null };
  policyVersion: { id: string; versionNumber: number; status: string; policySetName: string };
  hostDeploymentStatus: string;
  hostDeploymentMessage: string | null;
  current?: boolean;
  rules: Array<{
    id: string;
    orderIndex: number;
    action: string;
    protocol: string;
    ports: string | null;
    sourceType: string;
    sourceValue: string;
    destinationType: string | null;
    destinationValue: string | null;
    direction: string;
    comment: string | null;
  }>;
};

type NameMaps = {
  tags: Map<string, string>;
  vlans: Map<string, string>;
  hosts: Map<string, string>;
  assets: Map<string, string>;
};

interface Props {
  hostId: string;
  hostname: string;
  /** operator/admin: may run the SSH-based checks (compliance, live rules, expected ruleset) */
  canOperate: boolean;
  onClose: () => void;
}

function fmtDate(value: string | null | undefined): string {
  if (!value) return '-';
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? String(value) : d.toLocaleString();
}

function shortId(id: string): string {
  return id.length > 8 ? id.slice(0, 8) : id;
}

function describeSelector(type: string | null, value: string | null, maps: NameMaps): string {
  if (!type || !value) return '-';
  switch (type) {
    case 'CIDR':
      return value === '0.0.0.0/0' || value === '::/0' ? `any (${value})` : value;
    case 'TAG':
      return `tag: ${maps.tags.get(value) ?? shortId(value)}`;
    case 'VLAN':
      return `VLAN: ${maps.vlans.get(value) ?? shortId(value)}`;
    case 'HOST':
      return `host: ${maps.hosts.get(value) ?? shortId(value)}`;
    case 'IOT_ASSET':
      return `IoT asset: ${maps.assets.get(value) ?? shortId(value)}`;
    default:
      return `${type}: ${value}`;
  }
}

function directionLabel(direction: string): string {
  switch (direction) {
    case 'IN':
      return 'Inbound';
    case 'OUT':
      return 'Outbound';
    case 'BOTH':
      return 'In + Out';
    case 'FORWARD':
      return 'Forwarded';
    default:
      return direction;
  }
}

function statusColor(status: string): string {
  switch (status) {
    case 'SUCCEEDED':
    case 'compliant':
      return '#2e7d32';
    case 'FAILED':
    case 'error':
      return '#c62828';
    case 'drifted':
    case 'PARTIAL':
      return '#ef6c00';
    default:
      return '#6b5d4d';
  }
}

export function HostActiveRulesPanel({ hostId, hostname, canOperate, onClose }: Props) {
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [host, setHost] = useState<{ id: string; hostname: string; mgmtIp: string | null } | null>(null);
  const [policies, setPolicies] = useState<HostPolicy[]>([]);
  const [maps, setMaps] = useState<NameMaps>({ tags: new Map(), vlans: new Map(), hosts: new Map(), assets: new Map() });
  const [showHistory, setShowHistory] = useState(false);
  const [expandedHistory, setExpandedHistory] = useState<Set<string>>(new Set());

  // Compliance (drift) check
  const [compliance, setCompliance] = useState<any | null>(null);
  const [complianceBusy, setComplianceBusy] = useState(false);
  const [complianceError, setComplianceError] = useState<string | null>(null);

  // Live vs expected rulesets
  const [live, setLive] = useState<any | null>(null);
  const [liveBusy, setLiveBusy] = useState(false);
  const [liveError, setLiveError] = useState<string | null>(null);
  const [expected, setExpected] = useState<{ backend: string; sha256: string; text: string } | null>(null);
  const [expectedBusy, setExpectedBusy] = useState(false);
  const [expectedError, setExpectedError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      setLoading(true);
      setLoadError(null);
      try {
        const [res, tagsRes, vlansRes, hostsRes, assetsRes] = await Promise.all([
          api.troubleshoot.hostPolicies(hostId),
          api.tags().catch(() => ({ tags: [] as any[] })),
          api.vlans().catch(() => ({ vlans: [] as any[] })),
          api.allHosts().catch(() => ({ hosts: [] as any[] })),
          api.iot.assets().catch(() => ({ assets: [] as any[] }))
        ]);
        if (cancelled) return;
        setHost(res.host);
        setPolicies((res.policies || []) as HostPolicy[]);
        setMaps({
          tags: new Map((tagsRes.tags || []).map((t: any) => [t.id, t.name])),
          vlans: new Map((vlansRes.vlans || []).map((v: any) => [v.id, `${v.vlan_tag} ${v.name}`])),
          hosts: new Map((hostsRes.hosts || []).map((h: any) => [h.id, h.hostname])),
          assets: new Map(((assetsRes as any).assets || []).map((a: any) => [a.id, a.name]))
        });
      } catch (e: any) {
        if (!cancelled) setLoadError(e?.message || 'Failed to load host policies');
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    load();
    return () => {
      cancelled = true;
    };
  }, [hostId]);

  const current = useMemo(() => policies.find((p) => p.current) ?? null, [policies]);
  const history = useMemo(() => policies.filter((p) => !p.current), [policies]);

  async function runCompliance() {
    setComplianceBusy(true);
    setComplianceError(null);
    try {
      setCompliance(await api.checkHostCompliance(hostId));
    } catch (e: any) {
      setComplianceError(e?.message || 'Compliance check failed');
    } finally {
      setComplianceBusy(false);
    }
  }

  async function fetchLive() {
    setLiveBusy(true);
    setLiveError(null);
    try {
      setLive(await api.hostLiveRules(hostId));
    } catch (e: any) {
      setLiveError(e?.body?.message || e?.message || 'Could not read live rules');
    } finally {
      setLiveBusy(false);
    }
  }

  async function fetchExpected() {
    if (!current) return;
    setExpectedBusy(true);
    setExpectedError(null);
    try {
      setExpected(await api.render(current.policyVersion.id, hostId));
    } catch (e: any) {
      setExpectedError(e?.body?.message || e?.message || 'Could not compile the expected ruleset');
    } finally {
      setExpectedBusy(false);
    }
  }

  function toggleHistory(id: string) {
    setExpandedHistory((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  const hashesMatch = live?.rulesHash && live?.expectedHash ? live.rulesHash === live.expectedHash : null;

  function renderRulesTable(rules: HostPolicy['rules']) {
    if (rules.length === 0) return <p className="active-rules-muted">This version has no rules; only the baseline (established/related traffic, loopback, management SSH) applies.</p>;
    return (
      <table className="data-table active-rules-table">
        <thead>
          <tr>
            <th>#</th>
            <th>Direction</th>
            <th>Action</th>
            <th>Protocol</th>
            <th>Ports</th>
            <th>Source / peer</th>
            <th>Destination</th>
            <th>Comment</th>
          </tr>
        </thead>
        <tbody>
          {rules.map((r) => (
            <tr key={r.id}>
              <td>{r.orderIndex}</td>
              <td>{directionLabel(r.direction)}</td>
              <td>
                <span className={`active-rules-action ${r.action === 'ALLOW' ? 'allow' : 'deny'}`}>{r.action}</span>
              </td>
              <td><code>{r.protocol}</code></td>
              <td>{r.ports ? <code>{r.ports}</code> : <span className="active-rules-muted">any</span>}</td>
              <td>{describeSelector(r.sourceType, r.sourceValue, maps)}</td>
              <td>{r.direction === 'FORWARD' ? describeSelector(r.destinationType, r.destinationValue, maps) : <span className="active-rules-muted">this host</span>}</td>
              <td>{r.comment || <span className="active-rules-muted">-</span>}</td>
            </tr>
          ))}
        </tbody>
      </table>
    );
  }

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content active-rules-modal" onClick={(e) => e.stopPropagation()}>
        <div className="visualization-header">
          <div>
            <h2>Active rules: {hostname}</h2>
            {host?.mgmtIp && <div className="active-rules-muted">Management IP {host.mgmtIp}</div>}
          </div>
          <button onClick={onClose} className="btn-secondary">Close</button>
        </div>

        <div className="active-rules-body">
          {loading && <p>Loading...</p>}
          {loadError && <p className="error">{loadError}</p>}

          {!loading && !loadError && (
            <>
              <section className="active-rules-section">
                <h3>Active policy</h3>
                {current ? (
                  <>
                    <div className="active-rules-summary">
                      <div><span className="active-rules-label">Policy set</span><strong>{current.policyVersion.policySetName}</strong></div>
                      <div><span className="active-rules-label">Version</span>v{current.policyVersion.versionNumber} <code>{current.policyVersion.status}</code></div>
                      <div><span className="active-rules-label">Deployed</span>{fmtDate(current.deployment.finishedAt ?? current.deployment.startedAt ?? current.deployment.createdAt)}</div>
                      <div><span className="active-rules-label">Deployment</span><code>{shortId(current.deployment.id)}</code> ({current.deployment.mode}, host status <span style={{ color: statusColor(current.hostDeploymentStatus) }}>{current.hostDeploymentStatus}</span>)</div>
                    </div>
                    <p className="active-rules-muted">
                      These are the access-control rules Segmentra last applied successfully to this host. Allowed traffic returns to the
                      system's own chains; everything else in Segmentra's chains is handled by the policy's deny rules and the host baseline.
                    </p>
                    {renderRulesTable(current.rules)}
                  </>
                ) : (
                  <p className="active-rules-muted">
                    No Segmentra policy is currently deployed on this host (no successful deployment recorded, or the last one was removed on expiry).
                    The host runs whatever its own firewall configuration says.
                  </p>
                )}
              </section>

              <section className="active-rules-section">
                <h3>Compliance (drift)</h3>
                {canOperate ? (
                  <>
                    <div className="active-rules-actions">
                      <button className="btn-small btn-action" onClick={runCompliance} disabled={complianceBusy}>
                        {complianceBusy ? 'Checking...' : compliance ? 'Re-check compliance' : 'Check compliance'}
                      </button>
                      <span className="active-rules-muted">Reads the host over SSH and compares its live Segmentra rules with the last deployment.</span>
                    </div>
                    {complianceError && <p className="error">{complianceError}</p>}
                    {compliance && (
                      <div className="active-rules-summary">
                        <div><span className="active-rules-label">Status</span><strong style={{ color: statusColor(compliance.status) }}>{String(compliance.status).toUpperCase()}</strong></div>
                        {compliance.message && <div><span className="active-rules-label">Detail</span>{compliance.message}</div>}
                        {compliance.error && <div><span className="active-rules-label">Error</span>{compliance.error}</div>}
                        {compliance.backend && <div><span className="active-rules-label">Backend</span><code>{compliance.backend}</code></div>}
                        {compliance.persistence && (
                          <div><span className="active-rules-label">Boot persistence</span>{compliance.persistence.status}{compliance.persistence.method ? ` (${compliance.persistence.method})` : ''}{compliance.persistence.state ? `, ${compliance.persistence.state}` : ''}</div>
                        )}
                      </div>
                    )}
                  </>
                ) : (
                  <p className="active-rules-muted">Compliance checks need the operator or admin role.</p>
                )}
              </section>

              <section className="active-rules-section">
                <h3>Live ruleset vs expected</h3>
                {canOperate ? (
                  <>
                    <div className="active-rules-actions">
                      <button className="btn-small btn-action" onClick={fetchLive} disabled={liveBusy}>
                        {liveBusy ? 'Reading...' : live ? 'Re-read live rules' : 'Fetch live rules from host'}
                      </button>
                      <button className="btn-small btn-action" onClick={fetchExpected} disabled={expectedBusy || !current} title={current ? undefined : 'No active policy to compile'}>
                        {expectedBusy ? 'Compiling...' : expected ? 'Re-compile expected' : 'Show expected ruleset'}
                      </button>
                      {hashesMatch !== null && (
                        <span style={{ color: hashesMatch ? '#2e7d32' : '#ef6c00', fontWeight: 600 }}>
                          {hashesMatch ? 'Live rules match the last deployment' : 'Live rules differ from the last deployment'}
                        </span>
                      )}
                    </div>
                    {liveError && <p className="error">{liveError}</p>}
                    {expectedError && <p className="error">{expectedError}</p>}
                    {(live || expected) && (
                      <div className="active-rules-columns">
                        <div>
                          <h4>Live on host {live ? <span className="active-rules-muted">({live.backend}, read {fmtDate(live.readAt)})</span> : null}</h4>
                          {live ? (
                            live.success ? (
                              <>
                                {live.segmentraPresent === false && <p className="error">Segmentra's table/chains are not present on this host.</p>}
                                <pre className="active-rules-pre">{live.rulesText || '(empty)'}</pre>
                              </>
                            ) : (
                              <p className="error">{live.error}</p>
                            )
                          ) : (
                            <p className="active-rules-muted">Not read yet.</p>
                          )}
                        </div>
                        <div>
                          <h4>Expected (compiled from the active version) {expected ? <span className="active-rules-muted">({expected.backend})</span> : null}</h4>
                          {expected ? <pre className="active-rules-pre">{expected.text}</pre> : <p className="active-rules-muted">Not compiled yet.</p>}
                        </div>
                      </div>
                    )}
                  </>
                ) : (
                  <p className="active-rules-muted">Reading the live ruleset needs the operator or admin role.</p>
                )}
              </section>

              <section className="active-rules-section">
                <h3>
                  Deployment history{' '}
                  <button className="btn-small btn-secondary" onClick={() => setShowHistory((v) => !v)} disabled={history.length === 0}>
                    {history.length === 0 ? 'none' : showHistory ? 'Hide' : `Show ${history.length}`}
                  </button>
                </h3>
                {showHistory && history.length > 0 && (
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>When</th>
                        <th>Policy</th>
                        <th>Deployment</th>
                        <th>Host result</th>
                        <th>Rules</th>
                      </tr>
                    </thead>
                    <tbody>
                      {history.map((p) => (
                        <Fragment key={p.deployment.id}>
                          <tr>
                            <td>{fmtDate(p.deployment.finishedAt ?? p.deployment.createdAt)}</td>
                            <td>{p.policyVersion.policySetName} v{p.policyVersion.versionNumber}</td>
                            <td><code>{shortId(p.deployment.id)}</code> {p.deployment.mode} <code>{p.deployment.status}</code></td>
                            <td>
                              <span style={{ color: statusColor(p.hostDeploymentStatus) }}>{p.hostDeploymentStatus}</span>
                              {p.hostDeploymentMessage && <div className="active-rules-muted">{p.hostDeploymentMessage}</div>}
                            </td>
                            <td>
                              <button className="btn-small btn-secondary" onClick={() => toggleHistory(p.deployment.id)}>
                                {expandedHistory.has(p.deployment.id) ? 'Hide' : `Show ${p.rules.length}`}
                              </button>
                            </td>
                          </tr>
                          {expandedHistory.has(p.deployment.id) && (
                            <tr>
                              <td colSpan={5}>{renderRulesTable(p.rules)}</td>
                            </tr>
                          )}
                        </Fragment>
                      ))}
                    </tbody>
                  </table>
                )}
              </section>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
