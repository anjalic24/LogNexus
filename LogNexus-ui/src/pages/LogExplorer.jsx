import React, { useState, useEffect } from 'react';
import { Search, Filter, Calendar, Activity, Database, Download, RefreshCw, AlertTriangle, AlertCircle } from 'lucide-react';
import { listBundles } from '../api/correlationApi';
import axios from 'axios';
import '../index.css';
import { useActiveBundle } from '../contexts/ActiveBundleContext.jsx';

// The correlation service exposes events via proxy at /api/correlation
const eventsApi = axios.create({
  baseURL: '/api/correlation',
  timeout: 30000,
  headers: { 'Content-Type': 'application/json' }
});

export default function LogExplorer() {
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [bundles, setBundles] = useState([]);
  const [selectedBundle, setSelectedBundle] = useState('');
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const { activeBundleId, setActiveBundleId } = useActiveBundle();

  // Fetch available bundles on mount
  useEffect(() => {
    listBundles()
      .then(r => setBundles(r.data || []))
      .catch(() => {});
  }, []);

  useEffect(() => {
    if (!selectedBundle && activeBundleId) {
      setSelectedBundle(activeBundleId);
      fetchEvents(activeBundleId);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeBundleId]);

  // Fetch events when a bundle is selected
  const fetchEvents = (bundleId) => {
    if (!bundleId) return;
    setLoading(true);
    setError('');
    eventsApi.get(`/events/${bundleId}`)
      .then(r => {
        setLogs(Array.isArray(r.data) ? r.data : []);
      })
      .catch(err => {
        console.error('Failed to fetch events:', err);
        setError('Failed to load events. Make sure the Correlation Service is running and the bundle has processed events.');
        setLogs([]);
      })
      .finally(() => setLoading(false));
  };

  const handleBundleChange = (bundleId) => {
    setSelectedBundle(bundleId);
    setActiveBundleId(bundleId);
    if (bundleId) fetchEvents(bundleId);
    else setLogs([]);
  };

  const getSeverityLabel = (severity) => {
    if (severity >= 9) return 'CRITICAL';
    if (severity >= 7) return 'HIGH';
    if (severity >= 4) return 'MEDIUM';
    if (severity >= 1) return 'LOW';
    return 'INFO';
  };

  const getSeverityStyle = (sev) => {
    const label = typeof sev === 'string' ? sev : getSeverityLabel(sev);
    switch(label) {
      case 'CRITICAL': return { bg: 'rgba(255, 51, 102, 0.1)', color: 'var(--sev-critical)' };
      case 'HIGH': return { bg: 'rgba(255, 107, 53, 0.1)', color: 'var(--sev-high)' };
      case 'MEDIUM': return { bg: 'rgba(255, 193, 7, 0.1)', color: 'var(--sev-medium)' };
      case 'LOW': return { bg: 'rgba(34, 197, 94, 0.1)', color: 'var(--sev-low)' };
      default: return { bg: 'rgba(56, 189, 248, 0.1)', color: 'var(--sev-info)' };
    }
  };

  const filteredLogs = logs.filter(log => {
    const logAction = log.action || log.eventType || '';
    const logSource = log.sourceHost || log.sourceIp || '';
    const matchesSearch = logAction.toLowerCase().includes(searchTerm.toLowerCase()) ||
                          logSource.toLowerCase().includes(searchTerm.toLowerCase());
    
    const logSev = typeof log.severity === 'number' ? getSeverityLabel(log.severity) : (log.severity || 'INFO');
    const matchesSev = severityFilter === 'ALL' || logSev === severityFilter;
    return matchesSearch && matchesSev;
  });

  const handleExportCSV = () => {
    if (filteredLogs.length === 0) return;
    const headers = ['Timestamp', 'Severity', 'Source', 'Target', 'Action', 'Rule'];
    const rows = filteredLogs.map(log => [
      log.tsUtc || log.timestamp || '',
      typeof log.severity === 'number' ? getSeverityLabel(log.severity) : (log.severity || ''),
      log.eventType || log.logSource || '',
      log.sourceHost || log.sourceIp || '',
      log.action || log.eventType || '',
      log.ruleId || log.attckTtp || ''
    ]);
    const csv = [headers.join(','), ...rows.map(r => r.map(c => `"${c}"`).join(','))].join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `events_${selectedBundle || 'all'}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div
      className="dashboard-container"
      style={{ padding: '32px', height: '100%', display: 'flex', flexDirection: 'column', color: 'var(--text-primary)' }}
    >
      
      {/* Header Block */}
      <div style={{ marginBottom: '24px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h1 style={{ fontSize: '28px', fontWeight: 700, marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '12px' }}>
            <Database color="var(--accent)" size={28} />
            Data Lake Explorer
          </h1>
          <p style={{ color: 'var(--text-muted)' }}>Query and analyze raw events across all ingested log bundles.</p>
        </div>
        
        <div style={{ display: 'flex', gap: '12px' }}>
          <button 
            onClick={() => selectedBundle && fetchEvents(selectedBundle)}
            style={{ 
              background: 'var(--bg-surface)', border: '1px solid var(--border)', padding: '10px 16px',
              borderRadius: 'var(--radius-sm)', color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '8px', cursor: 'pointer', transition: '0.2s'
            }}>
            <RefreshCw size={16} /> Refresh Data
          </button>
          <button 
            onClick={handleExportCSV}
            disabled={filteredLogs.length === 0}
            style={{ 
              background: filteredLogs.length > 0 ? 'linear-gradient(135deg, var(--accent), var(--accent-purple))' : 'var(--bg-surface)',
              border: 'none', padding: '10px 16px',
              borderRadius: 'var(--radius-sm)', color: filteredLogs.length > 0 ? '#fff' : 'var(--text-muted)',
              display: 'flex', alignItems: 'center', gap: '8px', cursor: filteredLogs.length > 0 ? 'pointer' : 'not-allowed', fontWeight: 600
            }}>
            <Download size={16} /> Export CSV
          </button>
        </div>
      </div>

      {error && (
        <div style={{ marginBottom: '16px', padding: '12px', background: 'var(--status-danger-bg)', color: 'var(--status-danger)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--status-danger-border)', fontSize: '13px', display: 'flex', alignItems: 'center', gap: '8px' }}>
          <AlertCircle size={16} /> {error}
        </div>
      )}

      {/* Advanced Filters Block */}
      <div style={{ 
        background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 'var(--radius-md)', 
        padding: '16px', marginBottom: '24px', display: 'flex', gap: '16px', alignItems: 'center', flexWrap: 'wrap'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--text-secondary)', fontWeight: 600, fontSize: '14px', marginRight: '8px' }}>
          <Filter size={18} /> Filters:
        </div>

        {/* Bundle Selector */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', background: 'var(--bg-input)', border: '1px solid var(--border)', padding: '6px', borderRadius: 'var(--radius-sm)' }}>
          <Database size={16} color="var(--text-muted)" style={{ marginLeft: '8px' }} />
          <select 
            value={selectedBundle} 
            onChange={(e) => handleBundleChange(e.target.value)}
            style={{ background: 'transparent', border: 'none', color: 'var(--text-primary)', padding: '4px', outline: 'none', minWidth: '200px' }}
          >
            <option value="">Select a bundle...</option>
            {bundles.map((b, i) => (
              <option key={i} value={b.bundleId}>{b.bundleId} ({b.eventCount} events)</option>
            ))}
          </select>
        </div>

        {/* Search */}
        <div style={{ position: 'relative', flex: 1, minWidth: '200px' }}>
          <Search size={16} style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
          <input 
            type="text" 
            placeholder="Search action, source..." 
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            style={{
              background: 'var(--bg-input)', border: '1px solid var(--border)', padding: '10px 16px 10px 36px',
              borderRadius: 'var(--radius-sm)', color: 'var(--text-primary)', width: '100%'
            }}
          />
        </div>

        {/* Severity Filter */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', background: 'var(--bg-input)', border: '1px solid var(--border)', padding: '6px', borderRadius: 'var(--radius-sm)' }}>
          <AlertTriangle size={16} color="var(--text-muted)" style={{ marginLeft: '8px' }}/>
          <select 
            value={severityFilter} 
            onChange={(e) => setSeverityFilter(e.target.value)}
            style={{ background: 'transparent', border: 'none', color: 'var(--text-primary)', padding: '4px', outline: 'none' }}
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical Only</option>
            <option value="HIGH">High &amp; Above</option>
            <option value="MEDIUM">Medium &amp; Above</option>
            <option value="LOW">Low &amp; Above</option>
          </select>
        </div>
      </div>

      {/* Loading */}
      {loading && (
        <div className="loading-container"><div className="loading-spinner" /><p>Loading events...</p></div>
      )}

      {/* Empty state — no bundle selected */}
      {!loading && !selectedBundle && (
        <div className="empty-state">
          <Database size={48} style={{ opacity: 0.3, marginBottom: 16 }} />
          <h3>Select a bundle</h3>
          <p>Choose a bundle from the filter bar to explore its events.</p>
        </div>
      )}

      {/* Main Data Grid */}
      {!loading && selectedBundle && (
        <>
          <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', flex: 1, overflow: 'auto', color: 'var(--text-primary)' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', minWidth: '800px' }}>
              <thead style={{ background: 'var(--bg-surface)', position: 'sticky', top: 0, zIndex: 10 }}>
                <tr>
                  <th style={{ padding: '16px 20px', color: 'var(--text-secondary)', fontWeight: 600, fontSize: '12px', textTransform: 'uppercase', borderBottom: '1px solid var(--border)' }}>Time (UTC)</th>
                  <th style={{ padding: '16px 20px', color: 'var(--text-secondary)', fontWeight: 600, fontSize: '12px', textTransform: 'uppercase', borderBottom: '1px solid var(--border)' }}>Severity</th>
                  <th style={{ padding: '16px 20px', color: 'var(--text-secondary)', fontWeight: 600, fontSize: '12px', textTransform: 'uppercase', borderBottom: '1px solid var(--border)' }}>Log Source</th>
                  <th style={{ padding: '16px 20px', color: 'var(--text-secondary)', fontWeight: 600, fontSize: '12px', textTransform: 'uppercase', borderBottom: '1px solid var(--border)' }}>Target Host/IP</th>
                  <th style={{ padding: '16px 20px', color: 'var(--text-secondary)', fontWeight: 600, fontSize: '12px', textTransform: 'uppercase', borderBottom: '1px solid var(--border)' }}>Action</th>
                  <th style={{ padding: '16px 20px', color: 'var(--text-secondary)', fontWeight: 600, fontSize: '12px', textTransform: 'uppercase', borderBottom: '1px solid var(--border)' }}>TTP / Rule</th>
                </tr>
              </thead>
              <tbody>
                {filteredLogs.map((log, idx) => {
                  const sevLabel = typeof log.severity === 'number' ? getSeverityLabel(log.severity) : (log.severity || 'INFO');
                  const sevCfg = getSeverityStyle(sevLabel);
                  return (
                    <tr key={log.id || idx} style={{ borderBottom: '1px solid rgba(56, 189, 248, 0.05)' }}>
                      <td style={{ padding: '12px 20px', color: 'var(--text-muted)', fontSize: '13px', whiteSpace: 'nowrap' }}>
                        {log.tsUtc || log.timestamp || '—'}
                      </td>
                      <td style={{ padding: '12px 20px' }}>
                        <span style={{ 
                          display: 'inline-block', background: sevCfg.bg, color: sevCfg.color, 
                          padding: '4px 10px', borderRadius: '4px', fontSize: '11px', fontWeight: 700 
                        }}>
                          {sevLabel}
                        </span>
                      </td>
                      <td style={{ padding: '12px 20px', color: 'var(--text-secondary)', fontSize: '13px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <Activity size={14} color="var(--text-muted)" />
                        {log.eventType || log.logSource || '—'}
                      </td>
                      <td style={{ padding: '12px 20px', color: 'var(--text-primary)', fontWeight: 500, fontSize: '13px' }}>
                        {log.sourceHost || log.sourceIp || '—'}
                      </td>
                      <td style={{ padding: '12px 20px', color: 'var(--text-primary)', fontSize: '13px' }}>
                        {log.action || '—'}
                      </td>
                      <td style={{ padding: '12px 20px', color: 'var(--text-muted)', fontFamily: 'monospace', fontSize: '12px' }}>
                        {log.attckTtp || log.ruleId || '—'}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
            
            {filteredLogs.length === 0 && (
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '64px', color: 'var(--text-muted)' }}>
                <Filter size={48} style={{ opacity: 0.2, marginBottom: '16px' }} />
                <p>{logs.length === 0 ? 'No events found in this bundle.' : 'No logs match your filter criteria.'}</p>
              </div>
            )}
          </div>

          {/* Footer */}
          <div style={{ marginTop: '16px', display: 'flex', justifyContent: 'space-between', color: 'var(--text-muted)', fontSize: '13px' }}>
            <span>Showing {filteredLogs.length} of {logs.length} events</span>
          </div>
        </>
      )}
    </div>
  );
}
