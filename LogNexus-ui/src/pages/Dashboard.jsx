import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Activity, ShieldAlert, Network, Server, Clock, AlertTriangle } from 'lucide-react';
import { getStatus, listBundles } from '../api/correlationApi';
import { getSeverityClass, formatTimestamp } from '../utils/helpers';

export default function Dashboard() {
  const [status, setStatus] = useState(null);
  const [bundles, setBundles] = useState([]);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    Promise.allSettled([
      getStatus().then(r => setStatus(r.data)),
      listBundles().then(r => setBundles(r.data || []))
    ]).finally(() => setLoading(false));
  }, []);

  const totalEvents = bundles.reduce((sum, b) => sum + (b.eventCount || 0), 0);
  const criticalBundles = bundles.filter(b => b.maxSeverity >= 9).length;
  const highBundles = bundles.filter(b => b.maxSeverity >= 7 && b.maxSeverity < 9).length;

  if (loading) {
    return <div className="loading-container"><div className="loading-spinner" /><p>Loading dashboard...</p></div>;
  }

  return (
    <div className="animate-in">
      <div className="page-header">
        <h2>Dashboard</h2>
        <p>Correlation Engine</p>
      </div>


      <div className="card-grid card-grid-4" style={{ marginBottom: 24 }}>
        <div className="card">
          <div className="stat-card">
            <div className="stat-icon blue"><Activity size={22} /></div>
            <div className="stat-info">
              <h3 style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span className={`status-dot ${status?.status === 'UP' ? 'online' : 'offline'}`} />
                {status?.status || 'OFFLINE'}
              </h3>
              <p>Service Status</p>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="stat-card">
            <div className="stat-icon purple"><ShieldAlert size={22} /></div>
            <div className="stat-info">
              <h3>{bundles.length}</h3>
              <p>Total Bundles</p>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="stat-card">
            <div className="stat-icon green"><Network size={22} /></div>
            <div className="stat-info">
              <h3>{totalEvents}</h3>
              <p>Events Processed</p>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="stat-card">
            <div className="stat-icon red"><AlertTriangle size={22} /></div>
            <div className="stat-info">
              <h3>{criticalBundles}</h3>
              <p>Critical Bundles</p>
            </div>
          </div>
        </div>
      </div>


      <div className="card">
        <h3 style={{ marginBottom: 16, fontSize: 16, fontWeight: 600 }}>Recent Bundles</h3>
        {bundles.length === 0 ? (
          <div className="empty-state">
            <Server size={40} style={{ marginBottom: 12, opacity: 0.3 }} />
            <h3>No bundles yet</h3>
            <p>Upload logs via the Ingestion page to get started.</p>
          </div>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Bundle ID</th>
                <th>Events</th>
                <th>Max Severity</th>
                <th>First Event</th>
                <th>Last Event</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {bundles.map((b, i) => (
                <tr key={i} className="bundle-row" onClick={() => navigate(`/sessions/${b.bundleId}`)}>
                  <td style={{ fontFamily: 'monospace', fontSize: 12, color: 'var(--accent)' }}>
                    {b.bundleId}
                  </td>
                  <td>{b.eventCount}</td>
                  <td>
                    <span className={`badge ${getSeverityClass(
                      b.maxSeverity >= 9 ? 'CRITICAL' : b.maxSeverity >= 7 ? 'HIGH' : b.maxSeverity >= 4 ? 'MEDIUM' : 'LOW'
                    )}`}>
                      {b.maxSeverity?.toFixed(1)}
                    </span>
                  </td>
                  <td style={{ fontSize: 12 }}>{formatTimestamp(b.firstEvent)}</td>
                  <td style={{ fontSize: 12 }}>{formatTimestamp(b.lastEvent)}</td>
                  <td>
                    <div style={{ display: 'flex', gap: 6 }}>
                      <button className="btn btn-ghost" style={{ padding: '4px 10px', fontSize: 12 }}
                        onClick={e => { e.stopPropagation(); navigate(`/sessions/${b.bundleId}`); }}>
                        Sessions
                      </button>
                      <button className="btn btn-ghost" style={{ padding: '4px 10px', fontSize: 12 }}
                        onClick={e => { e.stopPropagation(); navigate(`/graph/${b.bundleId}`); }}>
                        Graph
                      </button>
                      <button className="btn btn-ghost" style={{ padding: '4px 10px', fontSize: 12 }}
                        onClick={e => { e.stopPropagation(); navigate(`/rca/${b.bundleId}`); }}>
                        RCA
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
