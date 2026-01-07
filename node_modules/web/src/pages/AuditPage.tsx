import { useEffect, useState } from 'react';

import { api } from '../lib/api';

export function AuditPage() {
  const [events, setEvents] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  
  // Filters
  const [filterActor, setFilterActor] = useState('');
  const [filterAction, setFilterAction] = useState('');
  const [filterEntityType, setFilterEntityType] = useState('');
  const [filterFrom, setFilterFrom] = useState('');
  const [filterTo, setFilterTo] = useState('');
  
  // Get unique values for dropdowns
  const [allActors, setAllActors] = useState<string[]>([]);
  const [allActions, setAllActions] = useState<string[]>([]);
  const [allEntityTypes, setAllEntityTypes] = useState<string[]>([]);

  useEffect(() => {
    loadData();
  }, []);

  useEffect(() => {
    loadData();
  }, [filterActor, filterAction, filterEntityType, filterFrom, filterTo]);

  async function loadData() {
    setLoading(true);
    try {
      const params: any = {};
      if (filterActor) params.actor = filterActor;
      if (filterAction) params.action = filterAction;
      if (filterEntityType) params.entityType = filterEntityType;
      if (filterFrom) params.from = filterFrom;
      if (filterTo) params.to = filterTo;
      
      const res = await api.audit(params);
      setEvents(res.events || []);
      
      // Extract unique values for filters
      const actors = new Set<string>();
      const actions = new Set<string>();
      const entityTypes = new Set<string>();
      
      res.events.forEach((e: any) => {
        if (e.actor_username) actors.add(e.actor_username);
        if (e.action) actions.add(e.action);
        if (e.entity_type) entityTypes.add(e.entity_type);
      });
      
      setAllActors(Array.from(actors).sort());
      setAllActions(Array.from(actions).sort());
      setAllEntityTypes(Array.from(entityTypes).sort());
    } catch (e: any) {
      console.error('Failed to load audit events:', e);
    } finally {
      setLoading(false);
    }
  }

  function clearFilters() {
    setFilterActor('');
    setFilterAction('');
    setFilterEntityType('');
    setFilterFrom('');
    setFilterTo('');
  }

  function formatTimestamp(ts: string) {
    try {
      const date = new Date(ts);
      return date.toLocaleString();
    } catch {
      return ts;
    }
  }

  function formatAction(action: string) {
    return action
      .split('_')
      .map(word => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
      .join(' ');
  }

  function formatEntityType(type: string) {
    return type
      .split('_')
      .map(word => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
      .join(' ');
  }

  function getActionColor(action: string) {
    if (action.includes('APPROVE') || action.includes('CREATE')) return '#4CAF50';
    if (action.includes('REJECT') || action.includes('DELETE')) return '#F44336';
    if (action.includes('SUBMIT') || action.includes('START')) return '#2196F3';
    if (action.includes('UPDATE') || action.includes('EDIT')) return '#FF9800';
    return '#666';
  }

  const hasFilters = filterActor || filterAction || filterEntityType || filterFrom || filterTo;

  return (
    <div className="page">
      <div className="page-header">
        <h2>Audit Log</h2>
        {hasFilters && (
          <button onClick={clearFilters} className="btn-secondary">
            Clear Filters
          </button>
        )}
      </div>

      {/* Filters */}
      <div className="card">
        <h3>Filters</h3>
        <div className="form-grid">
          <div className="form-group">
            <label>Actor (User)</label>
            <select
              value={filterActor}
              onChange={(e) => setFilterActor(e.target.value)}
            >
              <option value="">All Users</option>
              {allActors.map((actor) => (
                <option key={actor} value={actor}>
                  {actor}
                </option>
              ))}
            </select>
          </div>
          <div className="form-group">
            <label>Action</label>
            <select
              value={filterAction}
              onChange={(e) => setFilterAction(e.target.value)}
            >
              <option value="">All Actions</option>
              {allActions.map((action) => (
                <option key={action} value={action}>
                  {formatAction(action)}
                </option>
              ))}
            </select>
          </div>
          <div className="form-group">
            <label>Entity Type</label>
            <select
              value={filterEntityType}
              onChange={(e) => setFilterEntityType(e.target.value)}
            >
              <option value="">All Types</option>
              {allEntityTypes.map((type) => (
                <option key={type} value={type}>
                  {formatEntityType(type)}
                </option>
              ))}
            </select>
          </div>
          <div className="form-group">
            <label>From Date</label>
            <input
              type="datetime-local"
              value={filterFrom}
              onChange={(e) => setFilterFrom(e.target.value)}
            />
          </div>
          <div className="form-group">
            <label>To Date</label>
            <input
              type="datetime-local"
              value={filterTo}
              onChange={(e) => setFilterTo(e.target.value)}
            />
          </div>
        </div>
      </div>

      {/* Results */}
      <div className="card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
          <h3 style={{ margin: 0 }}>Events</h3>
          <div style={{ color: '#666', fontSize: '0.9em' }}>
            {loading ? 'Loading...' : `${events.length} event${events.length !== 1 ? 's' : ''}`}
          </div>
        </div>
        
        {loading && events.length === 0 ? (
          <div style={{ padding: 40, textAlign: 'center', color: '#666' }}>Loading audit events...</div>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Actor</th>
                <th>Action</th>
                <th>Entity Type</th>
                <th>Entity ID</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {events.map((e) => (
                <tr key={e.id}>
                  <td style={{ whiteSpace: 'nowrap', fontSize: '0.9em' }}>
                    {formatTimestamp(e.timestamp)}
                  </td>
                  <td>
                    <strong>{e.actor_username || '(system)'}</strong>
                  </td>
                  <td>
                    <span style={{ color: getActionColor(e.action), fontWeight: 'bold' }}>
                      {formatAction(e.action)}
                    </span>
                  </td>
                  <td>
                    <code style={{ fontSize: '0.85em' }}>{formatEntityType(e.entity_type)}</code>
                  </td>
                  <td>
                    <code style={{ fontSize: '0.85em', color: '#666' }}>
                      {String(e.entity_id).slice(0, 8)}...
                    </code>
                  </td>
                  <td>
                    {e.metadata && typeof e.metadata === 'object' ? (
                      <details style={{ fontSize: '0.85em' }}>
                        <summary style={{ cursor: 'pointer', color: '#646cff' }}>View</summary>
                        <pre style={{ 
                          marginTop: 8, 
                          padding: 8, 
                          background: '#f5f5f5', 
                          borderRadius: 4,
                          fontSize: '0.8em',
                          overflow: 'auto',
                          maxWidth: '400px'
                        }}>
                          {JSON.stringify(e.metadata, null, 2)}
                        </pre>
                      </details>
                    ) : (
                      <span style={{ color: '#999' }}>-</span>
                    )}
                  </td>
                </tr>
              ))}
              {events.length === 0 && !loading && (
                <tr>
                  <td colSpan={6} className="empty-state">
                    {hasFilters 
                      ? 'No events match the selected filters.' 
                      : 'No audit events found.'}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
