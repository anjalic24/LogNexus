import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { ShieldAlert, Users, Wifi, Server, Clock, ChevronRight, Target } from 'lucide-react';
import { getAttackSessions, listBundles } from '../api/correlationApi';
import { getSeverityClass, formatTimestamp, KILL_CHAIN_ORDER } from '../utils/helpers';
import { useActiveBundle } from '../contexts/ActiveBundleContext.jsx';

export default function Sessions() {
  const { bundleId } = useParams();
  const [sessions, setSessions] = useState([]);
  const [bundles, setBundles] = useState([]);
  const [selectedBundle, setSelectedBundle] = useState(bundleId || '');
  const [loading, setLoading] = useState(false);
  const [severityFilter, setSeverityFilter] = useState('');
  const navigate = useNavigate();
  const { activeBundleId, setActiveBundleId } = useActiveBundle();

  useEffect(() => {
    listBundles().then(r => setBundles(r.data || [])).catch(() => {});
  }, []);

  useEffect(() => {
    if (selectedBundle) {
      setLoading(true);
      getAttackSessions(selectedBundle)
        .then(r => setSessions(r.data || []))
        .catch(() => setSessions([]))
        .finally(() => setLoading(false));
    }
  }, [selectedBundle]);

  useEffect(() => {
    if (bundleId) setSelectedBundle(bundleId);
  }, [bundleId]);

  useEffect(() => {
    if (!bundleId && activeBundleId) {
      setSelectedBundle(activeBundleId);
    }
  }, [bundleId, activeBundleId]);

  const filteredSessions = sessions.filter(s => {
    if (!severityFilter) return true;
    // Sessions returned by the backend don't include per-event arrays; use overall_severity/max_risk_score.
    const sevLabel = (s.overall_severity || '').toString().toUpperCase();
    return sevLabel === severityFilter;
  });

  return (
    <div className="animate-in">
      <div className="page-header">
        <h2>Attack Sessions</h2>
        <p>Correlated attack narratives from the Directed Event Graph</p>
      </div>

      {/* Filters */}
      <div className="filter-bar">
        <div className="form-group">
          <label className="form-label">Bundle</label>
          <select className="form-select" value={selectedBundle}
            onChange={e => {
              const v = e.target.value;
              setSelectedBundle(v);
              setActiveBundleId(v);
              navigate(v ? `/sessions/${v}` : `/sessions`);
            }}
            style={{ minWidth: 220 }}>
            <option value="">Select a bundle...</option>
            {bundles.map((b, i) => (
              <option key={i} value={b.bundleId}>{b.bundleId} ({b.eventCount} events)</option>
            ))}
          </select>
        </div>
        <div className="form-group">
          <label className="form-label">Severity Filter</label>
          <select className="form-select" value={severityFilter} onChange={e => setSeverityFilter(e.target.value)}>
            <option value="">All</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
        </div>
      </div>

      {loading && <div className="loading-container"><div className="loading-spinner" /><p>Analyzing attack sessions...</p></div>}

      {!loading && !selectedBundle && (
        <div className="empty-state">
          <ShieldAlert size={48} style={{ opacity: 0.3, marginBottom: 16 }} />
          <h3>Select a bundle</h3>
          <p>Choose a bundle from the dropdown to view its attack sessions.</p>
        </div>
      )}

      {!loading && selectedBundle && sessions.length === 0 && (
        <div className="empty-state">
          <ShieldAlert size={48} style={{ opacity: 0.3, marginBottom: 16 }} />
          <h3>No attack sessions</h3>
          <p>No correlated attack sessions were found in this bundle.</p>
        </div>
      )}

      {/* Session Cards */}
      {filteredSessions.map((session, idx) => {
        const eventsCount = session.event_count || 0;
        const avgSev = session.avg_severity || 0;
        const sevLabel = session.overall_severity || 'LOW';
        const users = session.involved_users || [];
        const ips = session.involved_ips || [];
        const hosts = session.involved_hosts || [];
        const stages = session.kill_chain_stages || [];
        const ttps = session.mitre_ttps || [];

        return (
          <div key={idx} className="card session-card" style={{ marginBottom: 16 }}>
            <div className="session-header">
              <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                <ShieldAlert size={20} style={{ color: 'var(--accent)' }} />
                <span style={{ fontSize: 16, fontWeight: 700 }}>Attack Session #{idx + 1}</span>
                <span className={`badge ${getSeverityClass(sevLabel)}`}>{sevLabel}</span>
              </div>
              <span style={{ fontSize: 13, color: 'var(--text-secondary)' }}>{eventsCount} events</span>
            </div>

            {/* Meta */}
            <div className="session-meta">
              {users.length > 0 && (
                <div className="session-meta-item">
                  <Users size={14} />
                  <span className="value">{users.join(', ')}</span>
                </div>
              )}
              {ips.length > 0 && (
                <div className="session-meta-item">
                  <Wifi size={14} />
                  <span className="value">{ips.slice(0, 3).join(', ')}{ips.length > 3 ? ` +${ips.length - 3}` : ''}</span>
                </div>
              )}
              {hosts.length > 0 && (
                <div className="session-meta-item">
                  <Server size={14} />
                  <span className="value">{hosts.slice(0, 2).join(', ')}</span>
                </div>
              )}
              {ttps.length > 0 && (
                <div className="session-meta-item">
                  <Target size={14} />
                  <span className="value">{ttps.join(', ')}</span>
                </div>
              )}
            </div>

            {/* Kill Chain Pipeline */}
            {stages.length > 0 && (
              <div className="kill-chain" style={{ marginBottom: 16 }}>
                {KILL_CHAIN_ORDER.map((stage, i) => (
                  <span key={stage}>
                    {i > 0 && <span className="kill-chain-arrow" style={{ margin: '0 2px' }}>→</span>}
                    <span className={`kill-chain-stage ${stages.includes(stage) ? 'active' : ''}`}>
                      {stage.replace(/_/g, ' ')}
                    </span>
                  </span>
                ))}
              </div>
            )}

            {/* Narrative */}
            {session.narrative && (
              <div style={{ marginTop: 8, padding: '12px', background: 'var(--bg-surface)', borderRadius: '6px', borderLeft: `3px solid var(--accent)`, fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                 {session.narrative}
              </div>
            )}

            {/* Actions */}
            <div style={{ marginTop: 12, display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
              <button className="btn btn-ghost" style={{ fontSize: 12, padding: '6px 12px' }}
                onClick={() => navigate(`/graph/${selectedBundle}`)}>
                View Graph
              </button>
              <button className="btn btn-ghost" style={{ fontSize: 12, padding: '6px 12px' }}
                onClick={() => navigate(`/rca/${selectedBundle}`)}>
                RCA Report
              </button>
            </div>
          </div>
        );
      })}
    </div>
  );
}
