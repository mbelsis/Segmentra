import { useEffect, useState } from 'react';
import { api } from '../lib/api';

interface HostPolicyVisualizationProps {
  hostId: string;
  hostname: string;
  onClose: () => void;
}

interface SourceConnection {
  sourceType: 'CIDR' | 'TAG' | 'VLAN' | 'HOST';
  sourceValue: string;
  sourceDisplayName: string;
  action: 'ALLOW' | 'DENY';
  ports: string | null;
  protocol: string;
  direction: 'IN' | 'OUT' | 'BOTH';
}

interface PositionedSource extends SourceConnection {
  x: number;
  y: number;
  angle: number;
}

export function HostPolicyVisualization({ hostId, hostname, onClose }: HostPolicyVisualizationProps) {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [policies, setPolicies] = useState<any[]>([]);
  const [tags, setTags] = useState<Map<string, string>>(new Map());
  const [vlans, setVlans] = useState<Map<string, string>>(new Map());
  const [hosts, setHosts] = useState<Map<string, string>>(new Map());
  const [direction, setDirection] = useState<'IN' | 'OUT' | 'BOTH'>('IN');
  const [showDenied, setShowDenied] = useState(false);

  useEffect(() => {
    loadData();
  }, [hostId]);

  async function loadData() {
    setLoading(true);
    setError(null);
    try {
      // Load policies for the host
      const policiesRes = await api.troubleshoot.hostPolicies(hostId);
      setPolicies(policiesRes.policies || []);

      // Load tags, VLANs, and hosts for resolution
      const [tagsRes, vlansRes, hostsRes] = await Promise.all([
        api.tags().catch(() => ({ tags: [] })),
        api.vlans().catch(() => ({ vlans: [] })),
        api.allHosts().catch(() => ({ hosts: [] as any[] }))
      ]);

      // Build maps for quick lookup
      const tagsMap = new Map<string, string>();
      tagsRes.tags.forEach((tag: any) => tagsMap.set(tag.id, tag.name));
      setTags(tagsMap);

      const vlansMap = new Map<string, string>();
      vlansRes.vlans.forEach((vlan: any) => vlansMap.set(vlan.id, vlan.name));
      setVlans(vlansMap);

      const hostsMap = new Map<string, string>();
      hostsRes.hosts.forEach((host: any) => hostsMap.set(host.id, host.hostname));
      setHosts(hostsMap);
    } catch (e: any) {
      setError(e.message || 'Failed to load policy data');
    } finally {
      setLoading(false);
    }
  }

  function resolveSourceName(sourceType: string, sourceValue: string): string {
    switch (sourceType) {
      case 'CIDR':
        return sourceValue;
      case 'TAG':
        return tags.get(sourceValue) || `Tag: ${sourceValue.substring(0, 8)}...`;
      case 'VLAN':
        return vlans.get(sourceValue) || `VLAN: ${sourceValue.substring(0, 8)}...`;
      case 'HOST':
        return hosts.get(sourceValue) || `Host: ${sourceValue.substring(0, 8)}...`;
      default:
        return sourceValue;
    }
  }

  function processRules(): PositionedSource[] {
    if (policies.length === 0) return [];

    // Collect all rules from all policies
    const allRules: SourceConnection[] = [];
    for (const policy of policies) {
      if (policy.hostDeploymentStatus !== 'SUCCEEDED') continue;
      
      for (const rule of policy.rules || []) {
        // Filter by direction
        if (direction === 'IN') {
          if (rule.direction !== 'IN' && rule.direction !== 'BOTH') continue;
        } else if (direction === 'OUT') {
          if (rule.direction !== 'OUT' && rule.direction !== 'BOTH') continue;
        }
        // For BOTH mode, include all directions (no filtering)

        // Filter by action if needed
        if (!showDenied && rule.action === 'DENY') continue;

        const sourceDisplayName = resolveSourceName(rule.sourceType, rule.sourceValue);
        
        // Check if we already have this source
        const existing = allRules.find(
          r => r.sourceType === rule.sourceType && r.sourceValue === rule.sourceValue
        );

        if (existing) {
          // Merge ports if different
          if (rule.ports && existing.ports) {
            const existingPorts = existing.ports.split(',').map((p: string) => p.trim());
            const newPorts = rule.ports.split(',').map((p: string) => p.trim());
            const combined = [...new Set([...existingPorts, ...newPorts])].join(', ');
            existing.ports = combined;
          } else if (rule.ports) {
            existing.ports = rule.ports;
          }
          // Update action if we have both ALLOW and DENY (prefer ALLOW for display)
          if (rule.action === 'ALLOW') {
            existing.action = 'ALLOW';
          }
        } else {
          allRules.push({
            sourceType: rule.sourceType,
            sourceValue: rule.sourceValue,
            sourceDisplayName,
            action: rule.action,
            ports: rule.ports,
            protocol: rule.protocol,
            direction: rule.direction
          });
        }
      }
    }

    // Position sources in a circle
    const centerX = 400;
    const centerY = 300;
    const radius = Math.min(200, Math.max(150, allRules.length * 15));
    
    return allRules.map((source, index) => {
      const angle = (2 * Math.PI / allRules.length) * index - Math.PI / 2; // Start from top
      return {
        ...source,
        x: centerX + radius * Math.cos(angle),
        y: centerY + radius * Math.sin(angle),
        angle
      };
    });
  }

  const positionedSources = processRules();

  function formatPorts(ports: string | null): string {
    if (!ports) return 'any';
    // Simplify port ranges
    if (ports.includes('-')) {
      return ports;
    }
    // Limit display length
    if (ports.length > 20) {
      return ports.substring(0, 17) + '...';
    }
    return ports;
  }

  function getSourceIcon(sourceType: string): string {
    switch (sourceType) {
      case 'CIDR':
        return '🌐';
      case 'TAG':
        return '🏷️';
      case 'VLAN':
        return '🔌';
      case 'HOST':
        return '🖥️';
      default:
        return '📡';
    }
  }

  function getProtocolBadge(protocol: string): string {
    switch (protocol.toUpperCase()) {
      case 'TCP':
        return 'T';
      case 'UDP':
        return 'U';
      case 'ICMP':
        return 'I';
      default:
        return '?';
    }
  }

  if (loading) {
    return (
      <div className="modal-overlay" onClick={onClose}>
        <div className="modal-content visualization-modal" onClick={(e) => e.stopPropagation()}>
          <div style={{ padding: 40, textAlign: 'center' }}>Loading policy data...</div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="modal-overlay" onClick={onClose}>
        <div className="modal-content visualization-modal" onClick={(e) => e.stopPropagation()}>
          <div style={{ padding: 40, textAlign: 'center', color: '#d32f2f' }}>
            Error: {error}
          </div>
          <button onClick={onClose} className="btn-primary" style={{ marginTop: 20 }}>Close</button>
        </div>
      </div>
    );
  }

  if (policies.length === 0) {
    return (
      <div className="modal-overlay" onClick={onClose}>
        <div className="modal-content visualization-modal" onClick={(e) => e.stopPropagation()}>
          <div style={{ padding: 40, textAlign: 'center', color: '#666' }}>
            No policies deployed to this host
          </div>
          <button onClick={onClose} className="btn-primary" style={{ marginTop: 20 }}>Close</button>
        </div>
      </div>
    );
  }

  if (positionedSources.length === 0) {
    return (
      <div className="modal-overlay" onClick={onClose}>
        <div className="modal-content visualization-modal" onClick={(e) => e.stopPropagation()}>
          <div style={{ padding: 40, textAlign: 'center', color: '#666' }}>
            No rules match the selected direction and filters
          </div>
          <button onClick={onClose} className="btn-primary" style={{ marginTop: 20 }}>Close</button>
        </div>
      </div>
    );
  }

  const centerX = 400;
  const centerY = 300;

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content visualization-modal" onClick={(e) => e.stopPropagation()}>
        <div className="visualization-header">
          <h2>Policy Visualization: {hostname}</h2>
          <button onClick={onClose} className="btn-secondary">Close</button>
        </div>

        <div className="visualization-controls">
          <div className="control-group">
            <label>Direction:</label>
            <select value={direction} onChange={(e) => setDirection(e.target.value as any)}>
              <option value="IN">IN (Incoming)</option>
              <option value="OUT">OUT (Outgoing)</option>
              <option value="BOTH">BOTH</option>
            </select>
          </div>
          <div className="control-group">
            <label>
              <input
                type="checkbox"
                checked={showDenied}
                onChange={(e) => setShowDenied(e.target.checked)}
              />
              Show Denied Connections
            </label>
          </div>
        </div>

        <div className="visualization-container">
          <svg width="800" height="600" viewBox="0 0 800 600" style={{ border: '1px solid #e0e0e0', borderRadius: 8 }}>
            {/* Arrow marker definitions */}
            <defs>
              <marker
                id="arrowhead-allow"
                markerWidth="10"
                markerHeight="10"
                refX="9"
                refY="3"
                orient="auto"
              >
                <polygon points="0 0, 10 3, 0 6" fill="#4CAF50" />
              </marker>
              <marker
                id="arrowhead-deny"
                markerWidth="10"
                markerHeight="10"
                refX="9"
                refY="3"
                orient="auto"
              >
                <polygon points="0 0, 10 3, 0 6" fill="#F44336" />
              </marker>
            </defs>

            {/* Draw arrows from sources to host */}
            {positionedSources.map((source, idx) => {
              const arrowColor = source.action === 'ALLOW' ? '#4CAF50' : '#F44336';
              const markerId = source.action === 'ALLOW' ? 'arrowhead-allow' : 'arrowhead-deny';
              const dx = centerX - source.x;
              const dy = centerY - source.y;
              const distance = Math.sqrt(dx * dx + dy * dy);
              const arrowLength = distance - 60; // Account for icon size
              const angle = Math.atan2(dy, dx);
              
              // Arrow path
              const endX = source.x + Math.cos(angle) * arrowLength;
              const endY = source.y + Math.sin(angle) * arrowLength;
              
              return (
                <g key={`arrow-${idx}`}>
                  {/* Arrow line */}
                  <line
                    x1={source.x}
                    y1={source.y}
                    x2={endX}
                    y2={endY}
                    stroke={arrowColor}
                    strokeWidth={2}
                    markerEnd={`url(#${markerId})`}
                  />
                  {/* Port label */}
                  {source.ports && (
                    <text
                      x={(source.x + endX) / 2}
                      y={(source.y + endY) / 2 - 8}
                      fill={arrowColor}
                      fontSize="11"
                      fontWeight="bold"
                      textAnchor="middle"
                      style={{ pointerEvents: 'none' }}
                    >
                      {formatPorts(source.ports)}
                    </text>
                  )}
                  {/* Protocol badge */}
                  <circle
                    cx={(source.x + endX) / 2 + 15}
                    cy={(source.y + endY) / 2 - 8}
                    r="8"
                    fill={arrowColor}
                    opacity="0.8"
                  />
                  <text
                    x={(source.x + endX) / 2 + 15}
                    y={(source.y + endY) / 2 - 4}
                    fill="white"
                    fontSize="8"
                    fontWeight="bold"
                    textAnchor="middle"
                    style={{ pointerEvents: 'none' }}
                  >
                    {getProtocolBadge(source.protocol)}
                  </text>
                </g>
              );
            })}

            {/* Source icons and labels */}
            {positionedSources.map((source, idx) => (
              <g key={`source-${idx}`}>
                {/* Source icon circle */}
                <circle
                  cx={source.x}
                  cy={source.y}
                  r="25"
                  fill="white"
                  stroke={source.action === 'ALLOW' ? '#4CAF50' : '#F44336'}
                  strokeWidth={2}
                />
                {/* Source icon */}
                <text
                  x={source.x}
                  y={source.y + 8}
                  fontSize="24"
                  textAnchor="middle"
                  style={{ pointerEvents: 'none' }}
                >
                  {getSourceIcon(source.sourceType)}
                </text>
                {/* Source label */}
                <text
                  x={source.x}
                  y={source.y + 45}
                  fontSize="11"
                  textAnchor="middle"
                  fill="#333"
                  style={{ pointerEvents: 'none' }}
                >
                  {source.sourceDisplayName.length > 20
                    ? source.sourceDisplayName.substring(0, 17) + '...'
                    : source.sourceDisplayName}
                </text>
                {/* Source type badge */}
                <rect
                  x={source.x - 20}
                  y={source.y - 35}
                  width="40"
                  height="14"
                  fill={source.action === 'ALLOW' ? '#4CAF50' : '#F44336'}
                  rx="3"
                />
                <text
                  x={source.x}
                  y={source.y - 26}
                  fontSize="9"
                  fill="white"
                  textAnchor="middle"
                  fontWeight="bold"
                  style={{ pointerEvents: 'none' }}
                >
                  {source.action}
                </text>
              </g>
            ))}

            {/* Host icon in center */}
            <g>
              <circle
                cx={centerX}
                cy={centerY}
                r="40"
                fill="#2196F3"
                stroke="#1976D2"
                strokeWidth={3}
              />
              <text
                x={centerX}
                y={centerY + 10}
                fontSize="32"
                textAnchor="middle"
                style={{ pointerEvents: 'none' }}
              >
                🖥️
              </text>
              <text
                x={centerX}
                y={centerY + 60}
                fontSize="14"
                fontWeight="bold"
                textAnchor="middle"
                fill="#333"
                style={{ pointerEvents: 'none' }}
              >
                {hostname}
              </text>
            </g>
          </svg>
        </div>

        <div className="visualization-legend">
          <div className="legend-item">
            <div className="legend-color" style={{ backgroundColor: '#4CAF50' }}></div>
            <span>Allowed Connection</span>
          </div>
          <div className="legend-item">
            <div className="legend-color" style={{ backgroundColor: '#F44336' }}></div>
            <span>Denied Connection</span>
          </div>
          <div className="legend-item">
            <span>🌐 CIDR</span>
            <span>🏷️ TAG</span>
            <span>🔌 VLAN</span>
            <span>🖥️ HOST</span>
          </div>
        </div>
      </div>
    </div>
  );
}
