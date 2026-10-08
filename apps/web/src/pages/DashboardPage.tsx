import { useCallback, useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  Line,
  Area,
  AreaChart
} from 'recharts';

import { api } from '../lib/api';

interface DashboardStats {
  totalDeployments: number;
  runningDeployments: number;
  successRate: number;
  statusBreakdown: Array<{ status: string; count: number }>;
  topDeployers: Array<{ userId: string; username: string; displayName: string | null; deploymentCount: number }>;
  recentDeployments: any[];
  currentDeployments: Array<{
    id: string;
    status: string;
    mode: string;
    targetCount: number;
    createdAt: string;
    startedAt: string | null;
    policySetName: string | null;
    versionNumber: number | null;
    totalHosts: number;
    succeededHosts: number;
    failedHosts: number;
    runningHosts: number;
    progressPercent: number;
  }>;
  deploymentActivity: Array<{
    date: string;
    total: number;
    succeeded: number;
    failed: number;
    running: number;
  }>;
}

function getStatusColor(status: string): string {
  switch (status) {
    case 'SUCCEEDED':
      return '#4CAF50';
    case 'FAILED':
      return '#f44336';
    case 'RUNNING':
      return '#2196F3';
    case 'QUEUED':
      return '#FF9800';
    case 'SCHEDULED':
      return '#7E57C2';
    case 'PAUSED':
    case 'PARTIAL':
      return '#c47a1a';
    default:
      return '#757575';
  }
}

function formatDate(dateStr: string | null): string {
  if (!dateStr) return 'N/A';
  return new Date(dateStr).toLocaleString();
}

export function DashboardPage() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [me, setMe] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string>('');
  const navigate = useNavigate();
  const runningRef = useRef(0);
  const inFlightRef = useRef(false);

  const loadData = useCallback(async () => {
    if (inFlightRef.current) return;
    inFlightRef.current = true;
    try {
      const [meRes, statsRes] = await Promise.all([
        api.me().catch(() => null),
        api.dashboardStats()
      ]);
      if (meRes) setMe(meRes.user);
      // Only replace stats on success; failures keep the last good data.
      setStats(statsRes);
      runningRef.current = statsRes.runningDeployments ?? 0;
      setLoadError('');
    } catch (e: any) {
      setLoadError(String(e?.message ?? e));
    } finally {
      inFlightRef.current = false;
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
    // Stable interval: poll every 5s while deployments are running, otherwise
    // every 30s. A failed poll never stops polling.
    let ticks = 0;
    const interval = setInterval(() => {
      ticks++;
      if (runningRef.current > 0 || ticks % 6 === 0) {
        loadData();
      }
    }, 5000);
    return () => clearInterval(interval);
  }, [loadData]);

  if (loading) {
    return (
      <div style={{ padding: 40, textAlign: 'center' }}>
        <div>Loading dashboard...</div>
      </div>
    );
  }

  if (!stats) {
    return (
      <div style={{ padding: 40, textAlign: 'center' }}>
        <div style={{ color: '#f44336' }}>Failed to load dashboard data{loadError ? `: ${loadError}` : ''}</div>
        <button style={{ marginTop: 12 }} onClick={() => loadData()}>Retry</button>
      </div>
    );
  }

  return (
    <div style={{ display: 'grid', gap: 24 }}>
      {/* Header */}
      <div>
        <h2 style={{ margin: 0, marginBottom: 8 }}>Dashboard</h2>
        <div style={{ opacity: 0.7, fontSize: 14 }}>
          Welcome back, <strong>{me?.username ?? 'unknown'}</strong>
        </div>
        {loadError && (
          <div style={{ marginTop: 8, padding: '6px 10px', background: '#fff3e0', border: '1px solid #ff9800', borderRadius: 6, fontSize: 13, color: '#8a5a00' }}>
            Couldn't refresh dashboard ({loadError}). Showing last loaded data; will retry automatically.
          </div>
        )}
      </div>

      {/* Stats Cards - Row 1: Deployments */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 12, marginBottom: 12 }}>
        <div className="card" style={{ padding: 16 }}>
          <div style={{ fontSize: 11, color: '#97846c', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.04em', fontWeight: 600 }}>Total Deployments</div>
          <div style={{ fontSize: 28, fontWeight: 700, color: '#8b6914' }}>{stats.totalDeployments}</div>
        </div>
        <div className="card" style={{ padding: 16 }}>
          <div style={{ fontSize: 11, color: '#97846c', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.04em', fontWeight: 600 }}>Running</div>
          <div style={{ fontSize: 28, fontWeight: 700, color: stats.runningDeployments > 0 ? '#c47a1a' : '#b8a890' }}>{stats.runningDeployments}</div>
        </div>
        <div className="card" style={{ padding: 16 }}>
          <div style={{ fontSize: 11, color: '#97846c', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.04em', fontWeight: 600 }}>Success Rate</div>
          <div style={{ fontSize: 28, fontWeight: 700, color: stats.successRate >= 90 ? '#5a7a3a' : stats.successRate >= 70 ? '#c47a1a' : '#a63d2f' }}>{stats.successRate}%</div>
        </div>
        <div className="card" style={{ padding: 16 }}>
          <div style={{ fontSize: 11, color: '#97846c', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.04em', fontWeight: 600 }}>Succeeded</div>
          <div style={{ fontSize: 28, fontWeight: 700, color: '#5a7a3a' }}>{stats.statusBreakdown.find((s) => s.status === 'SUCCEEDED')?.count || 0}</div>
        </div>
      </div>

      {/* Stats Cards - Row 2: Infrastructure */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 12, marginBottom: 12 }}>
        <div className="card" style={{ padding: 16 }}>
          <div style={{ fontSize: 11, color: '#97846c', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.04em', fontWeight: 600 }}>Managed Hosts</div>
          <div style={{ fontSize: 28, fontWeight: 700, color: '#5c4633' }}>{(stats as any).enabledHosts ?? '-'}<span style={{ fontSize: 14, fontWeight: 400, color: '#97846c' }}> / {(stats as any).totalHosts ?? '-'}</span></div>
          <div style={{ fontSize: 11, color: '#97846c', marginTop: 2 }}>enabled / total</div>
        </div>
        <div className="card" style={{ padding: 16 }}>
          <div style={{ fontSize: 11, color: '#97846c', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.04em', fontWeight: 600 }}>Policy Sets</div>
          <div style={{ fontSize: 28, fontWeight: 700, color: '#5c4633' }}>{(stats as any).totalPolicySets ?? '-'}</div>
        </div>
        <div className="card" style={{ padding: 16 }}>
          <div style={{ fontSize: 11, color: '#97846c', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.04em', fontWeight: 600 }}>IoT/OT Assets</div>
          <div style={{ fontSize: 28, fontWeight: 700, color: '#5c4633' }}>{(stats as any).totalIotAssets ?? 0}</div>
        </div>
        <div className="card" style={{ padding: 16 }}>
          <div style={{ fontSize: 11, color: '#97846c', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.04em', fontWeight: 600 }}>Pending Approvals</div>
          <div style={{ fontSize: 28, fontWeight: 700, color: (stats as any).pendingApprovals > 0 ? '#c47a1a' : '#5a7a3a' }}>{(stats as any).pendingApprovals ?? 0}</div>
        </div>
      </div>

      {/* Stats Cards - Row 3: Security & Intelligence */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: 12 }}>
        <div className="card" style={{ padding: 16 }}>
          <div style={{ fontSize: 11, color: '#97846c', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.04em', fontWeight: 600 }}>Most Deployed Policy</div>
          {(stats as any).mostDeployedPolicy ? (
            <>
              <div style={{ fontSize: 16, fontWeight: 600, color: '#3d2e1e' }}>{(stats as any).mostDeployedPolicy.name}</div>
              <div style={{ fontSize: 12, color: '#78644e', marginTop: 2 }}>{(stats as any).mostDeployedPolicy.deployCount} successful deployment(s)</div>
            </>
          ) : (
            <div style={{ fontSize: 14, color: '#b8a890' }}>No deployments yet</div>
          )}
        </div>
        <div className="card" style={{ padding: 16 }}>
          <div style={{ fontSize: 11, color: '#97846c', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.04em', fontWeight: 600 }}>Last Security Audit</div>
          {(stats as any).lastSecurityAudit ? (
            <>
              <div style={{ fontSize: 13, color: '#3d2e1e' }}>{new Date((stats as any).lastSecurityAudit.timestamp).toLocaleString()}</div>
              {(stats as any).lastSecurityAudit.summary && (
                <div style={{ display: 'flex', gap: 8, marginTop: 6 }}>
                  {(stats as any).lastSecurityAudit.summary.critical > 0 && <span style={{ padding: '2px 8px', borderRadius: 4, fontSize: 11, fontWeight: 600, background: '#faf0ee', color: '#a63d2f' }}>{(stats as any).lastSecurityAudit.summary.critical} critical</span>}
                  {(stats as any).lastSecurityAudit.summary.high > 0 && <span style={{ padding: '2px 8px', borderRadius: 4, fontSize: 11, fontWeight: 600, background: '#fdf6ec', color: '#c47a1a' }}>{(stats as any).lastSecurityAudit.summary.high} high</span>}
                  {(stats as any).lastSecurityAudit.summary.medium > 0 && <span style={{ padding: '2px 8px', borderRadius: 4, fontSize: 11, fontWeight: 600, background: '#f7f4ef', color: '#8b6914' }}>{(stats as any).lastSecurityAudit.summary.medium} medium</span>}
                  {(stats as any).lastSecurityAudit.summary.critical === 0 && (stats as any).lastSecurityAudit.summary.high === 0 && <span style={{ padding: '2px 8px', borderRadius: 4, fontSize: 11, fontWeight: 600, background: '#eef4e8', color: '#5a7a3a' }}>Clean</span>}
                </div>
              )}
            </>
          ) : (
            <div style={{ fontSize: 14, color: '#b8a890' }}>No audit run yet</div>
          )}
        </div>
        <div className="card" style={{ padding: 16 }}>
          <div style={{ fontSize: 11, color: '#97846c', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.04em', fontWeight: 600 }}>Expiring Deployments</div>
          <div style={{ fontSize: 28, fontWeight: 700, color: (stats as any).expiringDeployments > 0 ? '#c47a1a' : '#5a7a3a' }}>{(stats as any).expiringDeployments ?? 0}</div>
          <div style={{ fontSize: 11, color: '#97846c', marginTop: 2 }}>within 7 days</div>
        </div>
      </div>

      {/* Current Deployments Progress */}
      {stats.currentDeployments.length > 0 && (
        <div className="card">
          <h3 style={{ marginTop: 0 }}>Current Deployments</h3>
          <div style={{ display: 'grid', gap: 16 }}>
            {stats.currentDeployments.map((dep) => (
              <div
                key={dep.id}
                style={{
                  border: '1px solid #e0e0e0',
                  borderRadius: 8,
                  padding: 16,
                  background: '#fafafa'
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 12 }}>
                  <div>
                    <div style={{ fontWeight: 'bold', marginBottom: 4 }}>
                      {dep.policySetName || 'Unknown Policy'} (v{dep.versionNumber || '?'})
                    </div>
                    <div style={{ fontSize: 12, color: '#666' }}>
                      Mode: {dep.mode} • Started: {formatDate(dep.startedAt)}
                    </div>
                  </div>
                  <span
                    style={{
                      background: getStatusColor(dep.status),
                      color: 'white',
                      padding: '4px 12px',
                      borderRadius: 12,
                      fontSize: 12,
                      fontWeight: 'bold'
                    }}
                  >
                    {dep.status}
                  </span>
                </div>

                {/* Progress Bar */}
                <div style={{ marginBottom: 8 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginBottom: 4 }}>
                    <span>Progress: {dep.progressPercent}%</span>
                    <span>
                      {dep.succeededHosts + dep.failedHosts} / {dep.totalHosts} hosts
                    </span>
                  </div>
                  <div
                    style={{
                      width: '100%',
                      height: 24,
                      background: '#e0e0e0',
                      borderRadius: 12,
                      overflow: 'hidden',
                      display: 'flex'
                    }}
                  >
                    <div
                      style={{
                        width: `${dep.progressPercent}%`,
                        background: dep.failedHosts > 0 ? '#f44336' : '#4CAF50',
                        transition: 'width 0.3s ease'
                      }}
                    />
                  </div>
                </div>

                {/* Host Status Breakdown */}
                <div style={{ display: 'flex', gap: 16, fontSize: 12 }}>
                  <span style={{ color: '#4CAF50' }}>✓ {dep.succeededHosts} succeeded</span>
                  {dep.failedHosts > 0 && <span style={{ color: '#f44336' }}>✗ {dep.failedHosts} failed</span>}
                  {dep.runningHosts > 0 && <span style={{ color: '#2196F3' }}>⟳ {dep.runningHosts} running</span>}
                </div>

                <div style={{ marginTop: 12 }}>
                  <button
                    className="btn-secondary"
                    onClick={() => navigate(`/deployments`)}
                    style={{ fontSize: 12, padding: '6px 12px' }}
                  >
                    View Details
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}


      {/* Charts Section */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(400px, 1fr))',
          gap: 24
        }}
      >
        {/* Deployment Status Pie Chart */}
        {stats.statusBreakdown.length > 0 && (
          <div className="card">
            <h3 style={{ marginTop: 0 }}>Deployment Status Breakdown</h3>
            <ResponsiveContainer width="100%" height={300}>
              <PieChart>
                <Pie
                  data={stats.statusBreakdown}
                  cx="50%"
                  cy="50%"
                  labelLine={false}
                  label={(entry: any) => {
                    const status = entry.status || '';
                    const count = entry.count || 0;
                    const percent = entry.percent || 0;
                    return `${status.replace('_', ' ')}: ${count} (${(percent * 100).toFixed(0)}%)`;
                  }}
                  outerRadius={80}
                  fill="#8884d8"
                  dataKey="count"
                >
                  {stats.statusBreakdown.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={getStatusColor(entry.status)} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </div>
        )}

        {/* Top Deployers Bar Chart */}
        {stats.topDeployers.length > 0 && (
          <div className="card">
            <h3 style={{ marginTop: 0 }}>Most Active Deployers</h3>
            <ResponsiveContainer width="100%" height={300}>
              <BarChart
                data={stats.topDeployers.map((d) => ({
                  name: d.displayName || d.username,
                  deployments: d.deploymentCount
                }))}
                margin={{ top: 20, right: 30, left: 20, bottom: 60 }}
              >
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis
                  dataKey="name"
                  angle={-45}
                  textAnchor="end"
                  height={80}
                  interval={0}
                  style={{ fontSize: '12px' }}
                />
                <YAxis />
                <Tooltip />
                <Bar dataKey="deployments" fill="#2196F3" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}
      </div>

      {/* Deployment Activity Over Time */}
      {stats.deploymentActivity && stats.deploymentActivity.length > 0 && (
        <div className="card">
          <h3 style={{ marginTop: 0 }}>Deployment Activity (Last 30 Days)</h3>
          <ResponsiveContainer width="100%" height={350}>
            <AreaChart
              data={stats.deploymentActivity.map((d) => ({
                date: new Date(d.date).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
                succeeded: d.succeeded,
                failed: d.failed,
                running: d.running,
                total: d.total
              }))}
              margin={{ top: 10, right: 30, left: 0, bottom: 0 }}
            >
              <defs>
                <linearGradient id="colorSucceeded" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#4CAF50" stopOpacity={0.8} />
                  <stop offset="95%" stopColor="#4CAF50" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="colorFailed" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#f44336" stopOpacity={0.8} />
                  <stop offset="95%" stopColor="#f44336" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="date" />
              <YAxis />
              <Tooltip />
              <Legend />
              <Area
                type="monotone"
                dataKey="succeeded"
                stackId="1"
                stroke="#4CAF50"
                fillOpacity={1}
                fill="url(#colorSucceeded)"
                name="Succeeded"
              />
              <Area
                type="monotone"
                dataKey="failed"
                stackId="1"
                stroke="#f44336"
                fillOpacity={1}
                fill="url(#colorFailed)"
                name="Failed"
              />
              <Line type="monotone" dataKey="total" stroke="#2196F3" strokeWidth={2} name="Total" />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      )}

      {/* Recent Deployments */}
      <div className="card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
          <h3 style={{ marginTop: 0 }}>Recent Deployments</h3>
          <button className="btn-secondary" onClick={() => navigate('/deployments')} style={{ fontSize: 12 }}>
            View All
          </button>
        </div>
        {stats.recentDeployments.length === 0 ? (
          <div style={{ padding: 40, textAlign: 'center', color: '#666' }}>No deployments yet</div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr style={{ borderBottom: '2px solid #e0e0e0' }}>
                  <th style={{ textAlign: 'left', padding: 12, fontSize: 12, fontWeight: 'bold', color: '#666' }}>
                    Policy Set
                  </th>
                  <th style={{ textAlign: 'left', padding: 12, fontSize: 12, fontWeight: 'bold', color: '#666' }}>
                    Status
                  </th>
                  <th style={{ textAlign: 'left', padding: 12, fontSize: 12, fontWeight: 'bold', color: '#666' }}>
                    Mode
                  </th>
                  <th style={{ textAlign: 'left', padding: 12, fontSize: 12, fontWeight: 'bold', color: '#666' }}>
                    Created
                  </th>
                  <th style={{ textAlign: 'left', padding: 12, fontSize: 12, fontWeight: 'bold', color: '#666' }}>
                    By
                  </th>
                </tr>
              </thead>
              <tbody>
                {stats.recentDeployments.map((d: any) => (
                  <tr
                    key={d.id}
                    style={{
                      borderBottom: '1px solid #f0f0f0',
                      cursor: 'pointer'
                    }}
                    onClick={() => navigate('/deployments')}
                  >
                    <td style={{ padding: 12 }}>
                      <div style={{ fontWeight: 'bold' }}>{d.policy_set_name || 'Unknown'}</div>
                      <div style={{ fontSize: 11, color: '#666' }}>v{d.version_number || '?'}</div>
                    </td>
                    <td style={{ padding: 12 }}>
                      <span
                        style={{
                          background: getStatusColor(d.status),
                          color: 'white',
                          padding: '4px 8px',
                          borderRadius: 4,
                          fontSize: 11,
                          fontWeight: 'bold'
                        }}
                      >
                        {d.status}
                      </span>
                    </td>
                    <td style={{ padding: 12, fontSize: 13 }}>{d.mode}</td>
                    <td style={{ padding: 12, fontSize: 12, color: '#666' }}>{formatDate(d.created_at)}</td>
                    <td style={{ padding: 12, fontSize: 12, color: '#666' }}>{d.created_by_username || 'N/A'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
