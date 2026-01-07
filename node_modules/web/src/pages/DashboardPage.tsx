import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';

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
  const navigate = useNavigate();

  useEffect(() => {
    loadData();
    // Refresh every 5 seconds if there are running deployments
    const interval = setInterval(() => {
      if (stats?.runningDeployments && stats.runningDeployments > 0) {
        loadData();
      }
    }, 5000);
    return () => clearInterval(interval);
  }, [stats?.runningDeployments]);

  async function loadData() {
    try {
      const [meRes, statsRes] = await Promise.all([
        api.me().catch(() => ({ user: null })),
        api.dashboardStats().catch(() => null)
      ]);
      setMe(meRes.user);
      setStats(statsRes);
    } catch (e) {
      console.error('Failed to load dashboard data', e);
    } finally {
      setLoading(false);
    }
  }

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
        <div style={{ color: '#f44336' }}>Failed to load dashboard data</div>
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
      </div>

      {/* Stats Cards */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
          gap: 16
        }}
      >
        <div className="card" style={{ padding: 20 }}>
          <div style={{ fontSize: 12, color: '#666', marginBottom: 8, textTransform: 'uppercase', letterSpacing: 0.5 }}>
            Total Deployments
          </div>
          <div style={{ fontSize: 32, fontWeight: 'bold', color: '#2196F3' }}>{stats.totalDeployments}</div>
        </div>

        <div className="card" style={{ padding: 20 }}>
          <div style={{ fontSize: 12, color: '#666', marginBottom: 8, textTransform: 'uppercase', letterSpacing: 0.5 }}>
            Running
          </div>
          <div style={{ fontSize: 32, fontWeight: 'bold', color: stats.runningDeployments > 0 ? '#FF9800' : '#757575' }}>
            {stats.runningDeployments}
          </div>
        </div>

        <div className="card" style={{ padding: 20 }}>
          <div style={{ fontSize: 12, color: '#666', marginBottom: 8, textTransform: 'uppercase', letterSpacing: 0.5 }}>
            Success Rate
          </div>
          <div style={{ fontSize: 32, fontWeight: 'bold', color: stats.successRate >= 90 ? '#4CAF50' : stats.successRate >= 70 ? '#FF9800' : '#f44336' }}>
            {stats.successRate}%
          </div>
        </div>

        <div className="card" style={{ padding: 20 }}>
          <div style={{ fontSize: 12, color: '#666', marginBottom: 8, textTransform: 'uppercase', letterSpacing: 0.5 }}>
            Finished
          </div>
          <div style={{ fontSize: 32, fontWeight: 'bold', color: '#757575' }}>
            {stats.statusBreakdown.find((s) => s.status === 'SUCCEEDED')?.count || 0}
          </div>
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

      {/* Top Deployers */}
      {stats.topDeployers.length > 0 && (
        <div className="card">
          <h3 style={{ marginTop: 0 }}>Most Active Deployers</h3>
          <div style={{ display: 'grid', gap: 12 }}>
            {stats.topDeployers.map((deployer, idx) => (
              <div
                key={deployer.userId}
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  padding: 12,
                  background: idx < 3 ? '#f5f5f5' : 'transparent',
                  borderRadius: 8
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                  <div
                    style={{
                      width: 32,
                      height: 32,
                      borderRadius: '50%',
                      background: idx === 0 ? '#FFD700' : idx === 1 ? '#C0C0C0' : idx === 2 ? '#CD7F32' : '#e0e0e0',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      fontWeight: 'bold',
                      color: idx < 3 ? 'white' : '#666',
                      fontSize: 14
                    }}
                  >
                    {idx + 1}
                  </div>
                  <div>
                    <div style={{ fontWeight: 'bold' }}>{deployer.displayName || deployer.username}</div>
                    <div style={{ fontSize: 12, color: '#666' }}>@{deployer.username}</div>
                  </div>
                </div>
                <div style={{ fontSize: 18, fontWeight: 'bold', color: '#2196F3' }}>{deployer.deploymentCount}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Status Breakdown */}
      {stats.statusBreakdown.length > 0 && (
        <div className="card">
          <h3 style={{ marginTop: 0 }}>Deployment Status Breakdown</h3>
          <div style={{ display: 'grid', gap: 8 }}>
            {stats.statusBreakdown.map((s) => (
              <div key={s.status} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <div
                    style={{
                      width: 12,
                      height: 12,
                      borderRadius: '50%',
                      background: getStatusColor(s.status)
                    }}
                  />
                  <span style={{ textTransform: 'capitalize' }}>{s.status.toLowerCase().replace('_', ' ')}</span>
                </div>
                <span style={{ fontWeight: 'bold' }}>{s.count}</span>
              </div>
            ))}
          </div>
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
