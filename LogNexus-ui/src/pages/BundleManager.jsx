import React, { useState, useEffect } from 'react';
import { Database, Trash2, CheckCircle2, Clock, FileJson, Search, Filter, RefreshCw, AlertCircle } from 'lucide-react';
import { listBundles, deleteAllBundles, deleteBundle } from '../api/correlationApi';
import '../index.css';

export default function BundleManager() {
  const [search, setSearch] = useState('');
  const [bundles, setBundles] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [deleting, setDeleting] = useState(false);

  const fetchBundles = () => {
    setLoading(true);
    setError('');
    listBundles()
      .then(r => {
        setBundles(r.data || []);
      })
      .catch(err => {
        console.error('Failed to fetch bundles:', err);
        setError('Failed to load bundles. Make sure the Correlation Service is running.');
        setBundles([]);
      })
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchBundles();
  }, []);

  const handleDeleteAll = () => {
    if (!window.confirm(`Are you sure you want to delete ALL ${bundles.length} bundles? This action cannot be undone.`)) return;
    setDeleting(true);
    setError('');
    deleteAllBundles()
      .then(() => {
        setBundles([]);
      })
      .catch(err => {
        console.error('Failed to delete bundles:', err);
        setError('Failed to delete bundles. The backend may not support this operation yet.');
      })
      .finally(() => setDeleting(false));
  };

  const handleDeleteBundle = (bundleId) => {
    if (!window.confirm(`Delete bundle ${bundleId}?`)) return;
    deleteBundle(bundleId)
      .then(() => {
        setBundles(prev => prev.filter(b => b.bundleId !== bundleId));
      })
      .catch(err => {
        console.error('Failed to delete bundle:', err);
        setError(`Failed to delete bundle ${bundleId}.`);
      });
  };

  const getStatusConfig = (bundle) => {
    // Derive status from bundle data
    const eventCount = bundle.eventCount || 0;
    if (eventCount > 0) {
      return { status: 'Completed', color: 'var(--accent-green)', icon: CheckCircle2, bg: 'rgba(34, 197, 94, 0.1)' };
    }
    return { status: 'Processing', color: 'var(--accent)', icon: Clock, bg: 'rgba(0, 212, 255, 0.1)' };
  };

  const filteredBundles = bundles.filter(b =>
    (b.bundleId || '').toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="dashboard-container" style={{ padding: '32px', height: '100%', display: 'flex', flexDirection: 'column' }}>
      
      <div style={{ marginBottom: '24px', display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end' }}>
        <div>
          <h1 style={{ fontSize: '28px', fontWeight: 700, marginBottom: '8px' }}>Bundle Manager</h1>
          <p style={{ color: 'var(--text-muted)' }}>Audit and manage all raw logs uploaded through the Ingestion Hub.</p>
        </div>
        
        <div style={{ display: 'flex', gap: '12px' }}>
          <div style={{ position: 'relative' }}>
            <Search size={16} style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
            <input 
              type="text" 
              placeholder="Search bundle ID..." 
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              style={{
                background: 'var(--bg-input)', border: '1px solid var(--border)', padding: '10px 16px 10px 36px',
                borderRadius: 'var(--radius-sm)', color: 'var(--text-primary)', width: '250px'
              }}
            />
          </div>
          <button 
            onClick={fetchBundles}
            style={{ 
              background: 'var(--bg-surface)', border: '1px solid var(--border)', padding: '0 16px',
              borderRadius: 'var(--radius-sm)', color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '8px', cursor: 'pointer'
            }}>
            <RefreshCw size={16} /> Refresh
          </button>
          {bundles.length > 0 && (
            <button 
              onClick={handleDeleteAll}
              disabled={deleting}
              style={{ 
                background: 'var(--status-danger-bg)', border: '1px solid var(--status-danger-border)', padding: '0 16px',
                borderRadius: 'var(--radius-sm)', color: 'var(--status-danger)', display: 'flex', alignItems: 'center', gap: '8px',
                cursor: deleting ? 'not-allowed' : 'pointer', fontWeight: 600, opacity: deleting ? 0.6 : 1
              }}>
              <Trash2 size={16} /> {deleting ? 'Deleting...' : 'Clear All'}
            </button>
          )}
        </div>
      </div>

      {error && (
        <div style={{ marginBottom: '16px', padding: '12px', background: 'var(--status-danger-bg)', color: 'var(--status-danger)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--status-danger-border)', fontSize: '13px', display: 'flex', alignItems: 'center', gap: '8px' }}>
          <AlertCircle size={16} /> {error}
        </div>
      )}

      {loading ? (
        <div className="loading-container"><div className="loading-spinner" /><p>Loading bundles...</p></div>
      ) : (
        <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', flex: 1, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
            <thead style={{ background: 'var(--bg-surface)', borderBottom: '1px solid var(--border)' }}>
              <tr>
                <th style={{ padding: '16px 24px', color: 'var(--text-secondary)', fontWeight: 600, fontSize: '13px' }}>Bundle ID</th>
                <th style={{ padding: '16px 24px', color: 'var(--text-secondary)', fontWeight: 600, fontSize: '13px' }}>Events</th>
                <th style={{ padding: '16px 24px', color: 'var(--text-secondary)', fontWeight: 600, fontSize: '13px' }}>Max Severity</th>
                <th style={{ padding: '16px 24px', color: 'var(--text-secondary)', fontWeight: 600, fontSize: '13px' }}>First Event</th>
                <th style={{ padding: '16px 24px', color: 'var(--text-secondary)', fontWeight: 600, fontSize: '13px' }}>Last Event</th>
                <th style={{ padding: '16px 24px', color: 'var(--text-secondary)', fontWeight: 600, fontSize: '13px' }}>Status</th>
                <th style={{ padding: '16px 24px', color: 'var(--text-secondary)', fontWeight: 600, fontSize: '13px', textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredBundles.map((bundle, idx) => {
                const statusCfg = getStatusConfig(bundle);
                const StatusIcon = statusCfg.icon;
                return (
                  <tr key={bundle.bundleId || idx} style={{ borderBottom: '1px solid var(--border)' }}>
                    <td style={{ padding: '16px 24px', fontWeight: 500, display: 'flex', alignItems: 'center', gap: '12px' }}>
                      <div style={{ background: 'var(--bg-surface)', padding: '8px', borderRadius: '8px' }}>
                        <Database size={16} color="var(--accent-purple)" />
                      </div>
                      <span style={{ fontFamily: 'monospace', fontSize: '12px', color: 'var(--accent)' }}>{bundle.bundleId}</span>
                    </td>
                    <td style={{ padding: '16px 24px', color: 'var(--text-primary)' }}>{bundle.eventCount || 0}</td>
                    <td style={{ padding: '16px 24px', color: 'var(--text-primary)', fontWeight: 600 }}>{bundle.maxSeverity?.toFixed(1) || '—'}</td>
                    <td style={{ padding: '16px 24px', color: 'var(--text-muted)', fontSize: '13px' }}>
                      {bundle.firstEvent ? new Date(bundle.firstEvent).toLocaleString() : '—'}
                    </td>
                    <td style={{ padding: '16px 24px', color: 'var(--text-muted)', fontSize: '13px' }}>
                      {bundle.lastEvent ? new Date(bundle.lastEvent).toLocaleString() : '—'}
                    </td>
                    <td style={{ padding: '16px 24px' }}>
                      <span style={{ 
                        display: 'inline-flex', alignItems: 'center', gap: '6px', 
                        background: statusCfg.bg, color: statusCfg.color, 
                        padding: '4px 10px', borderRadius: '12px', fontSize: '12px', fontWeight: 600 
                      }}>
                        <StatusIcon size={12} /> {statusCfg.status}
                      </span>
                    </td>
                    <td style={{ padding: '16px 24px', textAlign: 'right' }}>
                      <button
                        onClick={() => handleDeleteBundle(bundle.bundleId)}
                        title="Delete this bundle"
                        style={{ background: 'transparent', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', padding: '6px', borderRadius: '4px', transition: '0.2s' }}
                      >
                        <Trash2 size={16} />
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          
          {filteredBundles.length === 0 && !loading && (
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', flex: 1, color: 'var(--text-muted)', padding: '64px' }}>
              <Database size={48} style={{ opacity: 0.2, marginBottom: '16px' }} />
              <p>{search ? 'No bundles match your search.' : 'No log bundles have been ingested yet.'}</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
