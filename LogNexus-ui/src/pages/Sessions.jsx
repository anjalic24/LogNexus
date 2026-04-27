import React, { useState, useEffect } from 'react';
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

    const sevLabel = (s.overall_severity || '').toString().toUpperCase();
    return sevLabel === severityFilter;
  });

  return (
    <div className="animate-in">
      <div className="page-header">
        <h2>Attack Sessions</h2>
        <p>Correlated attack narratives from the Directed Event Graph</p>
      </div>


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
          <div key={idx} 
            style={{ 
              marginBottom: 24, 
              padding: 24,
              background: 'var(--bg-card)',
              backdropFilter: 'blur(10px)',
              border: '1px solid var(--border)',
              borderLeft: `4px solid ${sevLabel === 'CRITICAL' ? 'var(--status-danger)' : sevLabel === 'HIGH' ? 'var(--status-warning)' : sevLabel === 'MEDIUM' ? 'var(--status-info)' : 'var(--accent)'}`,
              borderRadius: '12px',
              transition: 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)',
              boxShadow: 'var(--shadow-card)'
            }}
            onMouseEnter={e => {
              e.currentTarget.style.transform = 'translateY(-2px)';
              e.currentTarget.style.border = '1px solid var(--border-hover)';
              e.currentTarget.style.borderLeft = `4px solid ${sevLabel === 'CRITICAL' ? 'var(--status-danger)' : sevLabel === 'HIGH' ? 'var(--status-warning)' : sevLabel === 'MEDIUM' ? 'var(--status-info)' : 'var(--accent)'}`;
              e.currentTarget.style.boxShadow = 'var(--shadow-card), var(--shadow-glow)';
            }}
            onMouseLeave={e => {
              e.currentTarget.style.transform = 'translateY(0)';
              e.currentTarget.style.border = '1px solid var(--border)';
              e.currentTarget.style.borderLeft = `4px solid ${sevLabel === 'CRITICAL' ? 'var(--status-danger)' : sevLabel === 'HIGH' ? 'var(--status-warning)' : sevLabel === 'MEDIUM' ? 'var(--status-info)' : 'var(--accent)'}`;
              e.currentTarget.style.boxShadow = 'var(--shadow-card)';
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 20 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
                <div style={{ 
                  background: 'var(--bg-hover-subtle)', 
                  padding: 10, 
                  borderRadius: 10,
                  display: 'flex', alignItems: 'center', justifyContent: 'center'
                }}>
                  <ShieldAlert size={22} style={{ color: sevLabel === 'CRITICAL' ? 'var(--status-danger)' : sevLabel === 'HIGH' ? 'var(--status-warning)' : sevLabel === 'MEDIUM' ? 'var(--status-info)' : 'var(--accent)' }} />
                </div>
                <div>
                  <h3 style={{ margin: 0, fontSize: 18, fontWeight: 700, letterSpacing: '-0.3px', color: 'var(--text-primary)' }}>
                    Attack Session #{idx + 1}
                  </h3>
                  <span style={{ fontSize: 13, color: 'var(--text-muted)', fontWeight: 500 }}>
                    {eventsCount} correlated events
                  </span>
                </div>
              </div>
              <span className={`badge ${getSeverityClass(sevLabel)}`} style={{ padding: '6px 12px', fontSize: 11, fontWeight: 800, letterSpacing: '0.5px' }}>
                {sevLabel}
              </span>
            </div>


            <div style={{ 
              display: 'flex', flexWrap: 'wrap', gap: 12, marginBottom: 20,
              background: 'var(--bg-surface)', padding: 16, borderRadius: 8, border: '1px solid var(--border)'
            }}>
              {users.length > 0 && (
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: 'var(--text-secondary)', fontSize: 13, minWidth: 150 }}>
                  <Users size={15} style={{ color: 'var(--accent-purple)' }}/>
                  <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{users.join(', ')}</span>
                </div>
              )}
              {ips.length > 0 && (
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: 'var(--text-secondary)', fontSize: 13, minWidth: 150 }}>
                  <Wifi size={15} style={{ color: 'var(--accent-green)' }}/>
                  <span style={{ fontWeight: 600, color: 'var(--text-primary)', fontFamily: 'monospace' }}>
                    {ips.slice(0, 3).join(', ')}{ips.length > 3 ? ` +${ips.length - 3}` : ''}
                  </span>
                </div>
              )}
              {hosts.length > 0 && (
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: 'var(--text-secondary)', fontSize: 13, minWidth: 150 }}>
                  <Server size={15} style={{ color: 'var(--accent)' }}/>
                  <span style={{ fontWeight: 600, color: 'var(--text-primary)', fontFamily: 'monospace' }}>
                    {hosts.slice(0, 2).join(', ')}
                  </span>
                </div>
              )}
              {ttps.length > 0 && (
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: 'var(--text-secondary)', fontSize: 13, minWidth: 150 }}>
                  <Target size={15} style={{ color: 'var(--status-danger)' }}/>
                  <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{ttps.join(', ')}</span>
                </div>
              )}
            </div>


            {stages.length > 0 && (
              <div style={{ 
                display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 6, marginBottom: 20,
                background: 'var(--bg-hover-subtle)', padding: '12px 16px', borderRadius: 8, border: '1px solid var(--border)'
              }}>
                {KILL_CHAIN_ORDER.map((stage, i) => {
                  const isActive = stages.includes(stage);
                  return (
                    <React.Fragment key={stage}>
                      {i > 0 && <ChevronRight size={14} color={isActive ? 'var(--text-secondary)' : 'var(--text-muted)'} style={{ opacity: 0.5 }} />}
                      <span style={{
                        padding: '4px 10px', borderRadius: 4, fontSize: 11, fontWeight: 700, letterSpacing: '0.3px', textTransform: 'uppercase',
                        background: isActive ? 'var(--accent-glow)' : 'transparent',
                        color: isActive ? 'var(--accent)' : 'var(--text-muted)',
                        border: isActive ? '1px solid var(--border-active)' : '1px solid transparent',
                        transition: 'all 0.2s',
                        boxShadow: isActive ? 'var(--shadow-glow)' : 'none'
                      }}>
                        {stage.replace(/_/g, ' ')}
                      </span>
                    </React.Fragment>
                  );
                })}
              </div>
            )}


            {session.narrative && (
              <div style={{ 
                marginTop: 8, padding: 16, background: 'var(--bg-surface)', borderRadius: 8, 
                borderLeft: `3px solid var(--border-active)`, fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.6, fontWeight: 400 
              }}>
                <div style={{ marginBottom: 6, display: 'flex', alignItems: 'center', gap: 6, color: 'var(--text-primary)', fontWeight: 600, fontSize: 12, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                  <ShieldAlert size={14} /> Automated Attack Narrative
                </div>
                 {session.narrative}
              </div>
            )}


            <div style={{ marginTop: 20, paddingTop: 16, borderTop: '1px solid var(--border)', display: 'flex', gap: 12, justifyContent: 'flex-end' }}>
              <button 
                onClick={() => navigate(`/graph/${selectedBundle}`)}
                style={{ 
                  background: 'var(--bg-hover-subtle)', border: '1px solid var(--border)', color: 'var(--text-primary)',
                  padding: '8px 16px', borderRadius: 6, fontSize: 13, fontWeight: 600, cursor: 'pointer', transition: 'all 0.2s'
                }}
                onMouseEnter={e => { e.currentTarget.style.background = 'var(--bg-surface)'; e.currentTarget.style.border = '1px solid var(--border-hover)'; }}
                onMouseLeave={e => { e.currentTarget.style.background = 'var(--bg-hover-subtle)'; e.currentTarget.style.border = '1px solid var(--border)'; }}
              >
                Explore on Threat Graph
              </button>
              <button 
                onClick={() => navigate(`/rca/${selectedBundle}`)}
                style={{ 
                  background: 'linear-gradient(135deg, var(--accent-purple), var(--accent))', border: 'none', color: '#ffffff',
                  padding: '8px 16px', borderRadius: 6, fontSize: 13, fontWeight: 600, cursor: 'pointer', transition: 'all 0.2s'
                }}
                onMouseEnter={e => { e.currentTarget.style.opacity = '0.9'; }}
                onMouseLeave={e => { e.currentTarget.style.opacity = '1'; }}
              >
                Generate RCA
              </button>
            </div>
          </div>
        );
      })}
    </div>
  );
}
