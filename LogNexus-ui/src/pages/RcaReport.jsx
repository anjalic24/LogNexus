import { useState, useEffect, useRef } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { FileText, Download, Printer, ShieldAlert, Cpu, Users, Wifi } from 'lucide-react';
import { getRcaReport, listBundles } from '../api/correlationApi';
import { formatTimestamp, getSeverityClass, getSeverityColor } from '../utils/helpers';
import { useActiveBundle } from '../contexts/ActiveBundleContext.jsx';

export default function RcaReport() {
  const { bundleId: paramBundle } = useParams();
  const [selectedBundle, setSelectedBundle] = useState(paramBundle || '');
  const [bundles, setBundles] = useState([]);
  const [reportData, setReportData] = useState(null);
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();
  const { activeBundleId, setActiveBundleId } = useActiveBundle();

  useEffect(() => {
    listBundles().then(r => setBundles(r.data || [])).catch(() => {});
  }, []);

  useEffect(() => {
    if (paramBundle) setSelectedBundle(paramBundle);
  }, [paramBundle]);

  useEffect(() => {
    if (!paramBundle && activeBundleId) {
      setSelectedBundle(activeBundleId);
    }
  }, [paramBundle, activeBundleId]);

  useEffect(() => {
    if (selectedBundle) {
      setLoading(true);
      getRcaReport(selectedBundle)
        .then(r => setReportData(r.data))
        .catch(() => setReportData(null))
        .finally(() => setLoading(false));
    }
  }, [selectedBundle]);

  const handlePrint = () => {
    window.print();
  };

  const exportTimelineCsv = () => {
    if (!reportData?.timeline || reportData.timeline.length === 0) return;

    const esc = (v) => {
      const val = (v === null || v === undefined || v === '') ? 'NA' : String(v);
      return `"${val.replaceAll('"', '""')}"`;
    };
    const headers = [
      'bundleId',
      'eventId',
      'tsUtc',
      'severity',
      'severityLabel',
      'sourceType',
      'user',
      'srcIp',
      'dstIp',
      'host',
      'action',
      'attckTtp',
      'killChainStage',
      'message',
    ];

    const rows = reportData.timeline.map(e => ([
      reportData.bundleId,
      e.eventId,
      e.tsUtc,
      e.severity,
      e.severityLabel,
      e.sourceType,
      e.user,
      e.srcIp,
      e.dstIp,
      e.host,
      e.action,
      e.attckTtp,
      e.killChainStage,
      e.message,
    ]));

    const csv = [
      headers.join(','),
      ...rows.map(r => r.map(esc).join(',')),
    ].join('\n');

    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `rca_timeline_${reportData.bundleId || 'bundle'}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="animate-in">
      <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <h2>Root Cause Analysis Report</h2>
          <p>Automated RCA generated from correlated graph data</p>
        </div>
        {reportData && (
          <div style={{ display: 'flex', gap: 10 }}>
            <button className="btn btn-secondary" onClick={exportTimelineCsv} title="Export timeline as CSV">
              <Download size={16} /> Export CSV
            </button>
            <button className="btn btn-primary" onClick={handlePrint} title="Export as PDF via Print dialog">
              <Printer size={16} /> Export PDF
            </button>
          </div>
        )}
      </div>

      <div className="filter-bar" style={{ marginBottom: 24 }}>
        <div className="form-group">
          <label className="form-label">Bundle</label>
          <select className="form-select" value={selectedBundle}
            onChange={e => {
              const v = e.target.value;
              setSelectedBundle(v);
              setActiveBundleId(v);
              navigate(v ? `/rca/${v}` : `/rca`);
            }}
            style={{ minWidth: 220 }}>
            <option value="">Select a bundle...</option>
            {bundles.map((b, i) => (
              <option key={i} value={b.bundleId}>{b.bundleId} ({b.eventCount} events)</option>
            ))}
          </select>
        </div>
      </div>

      {loading && <div className="loading-container"><div className="loading-spinner" /><p>Generating RCA report...</p></div>}

      {!loading && !selectedBundle && (
        <div className="empty-state">
          <FileText size={48} style={{ opacity: 0.3, marginBottom: 16 }} />
          <h3>Select a bundle</h3>
          <p>Choose a bundle to generate an automated RCA report.</p>
        </div>
      )}

      {!loading && selectedBundle && !reportData && (
        <div className="empty-state">
          <ShieldAlert size={48} style={{ opacity: 0.3, marginBottom: 16 }} />
          <h3>Failed to load report</h3>
        </div>
      )}

      {/* Actual Report Content */}
      {!loading && reportData && (
        <div className="card" style={{ padding: '40px 48px', maxWidth: 1000, margin: '0 auto', background: 'var(--bg-primary)' }}>
          
          <div style={{ textAlign: 'center', marginBottom: 40, paddingBottom: 24, borderBottom: '1px solid var(--border)' }}>
            <h1 style={{ fontSize: 24, fontWeight: 800, marginBottom: 8, letterSpacing: '-0.5px' }}>Automated Root Cause Analysis</h1>
            <div style={{ color: 'var(--text-secondary)', fontSize: 13, marginBottom: 4 }}>
              Bundle Reference: <span style={{ fontFamily: 'monospace', color: 'var(--accent)' }}>{reportData.bundleId}</span>
            </div>
            <div style={{ color: 'var(--text-secondary)', fontSize: 13 }}>
              Generated: {formatTimestamp(reportData.generatedAt)}
            </div>
          </div>

          {/* Exec Summary */}
          <section className="rca-section">
            <h3>Executive Summary</h3>
            <p style={{ color: 'var(--text-primary)', lineHeight: 1.6, fontSize: 14 }}>
              The Vulnuris Correlation Engine analyzed <strong>{reportData.totalEvents}</strong> events and identified 
              <strong> {reportData.totalSessions}</strong> correlated attack sessions. 
              The most critical identified path involves {reportData.causalChain?.length || 0} high-confidence causal links.
              Immediate review of the affected assets is recommended.
            </p>
          </section>

          {/* Affected Assets */}
          <section className="rca-section">
            <h3>Affected Assets</h3>
            <div className="card-grid card-grid-3">
              
              {/* Users */}
              <div className="card" style={{ padding: 16 }}>
                <div style={{ display: 'flex', gap: 8, color: 'var(--text-secondary)', marginBottom: 12, alignItems: 'center' }}>
                  <Users size={16} /> <span style={{ fontWeight: 600 }}>Compromised Users</span>
                </div>
                {reportData.affectedUsers?.length > 0 ? (
                  <ul style={{ listStyle: 'none', padding: 0 }}>
                    {reportData.affectedUsers.map((u, i) => (
                      <li key={i} style={{ display: 'flex', justifyContent: 'space-between', padding: '4px 0', borderBottom: '1px solid var(--border)', fontSize: 13 }}>
                        <span>{u.userId}</span>
                        <span style={{ color: getSeverityColor(u.riskScore * 10) }}>{(u.riskScore * 10).toFixed(1)}</span>
                      </li>
                    ))}
                  </ul>
                ) : <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>None identified</div>}
              </div>

              {/* Hosts */}
              <div className="card" style={{ padding: 16 }}>
                <div style={{ display: 'flex', gap: 8, color: 'var(--text-secondary)', marginBottom: 12, alignItems: 'center' }}>
                  <Cpu size={16} /> <span style={{ fontWeight: 600 }}>Affected Hosts</span>
                </div>
                {reportData.affectedHosts?.length > 0 ? (
                  <ul style={{ listStyle: 'none', padding: 0 }}>
                    {reportData.affectedHosts.map((h, i) => (
                      <li key={i} style={{ display: 'flex', justifyContent: 'space-between', padding: '4px 0', borderBottom: '1px solid var(--border)', fontSize: 13 }}>
                        <span style={{ fontFamily: 'monospace' }}>{h.hostname}</span>
                        <span style={{ color: getSeverityColor(h.riskScore * 10) }}>{(h.riskScore * 10).toFixed(1)}</span>
                      </li>
                    ))}
                  </ul>
                ) : <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>None identified</div>}
              </div>

              {/* IPs */}
              <div className="card" style={{ padding: 16 }}>
                <div style={{ display: 'flex', gap: 8, color: 'var(--text-secondary)', marginBottom: 12, alignItems: 'center' }}>
                  <Wifi size={16} /> <span style={{ fontWeight: 600 }}>External Actor IPs</span>
                </div>
                {reportData.affectedIps?.length > 0 ? (
                  <ul style={{ listStyle: 'none', padding: 0 }}>
                    {reportData.affectedIps.map((ip, i) => (
                      <li key={i} style={{ display: 'flex', justifyContent: 'space-between', padding: '4px 0', borderBottom: '1px solid var(--border)', fontSize: 13 }}>
                        <span style={{ fontFamily: 'monospace' }}>{ip.ipAddress}</span>
                        <span style={{ color: 'var(--text-muted)', fontSize: 11 }}>{ip.country}</span>
                      </li>
                    ))}
                  </ul>
                ) : <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>None identified</div>}
              </div>

            </div>
          </section>

          {/* Timeline */}
          <section className="rca-section">
            <h3>Chronological Incident Timeline</h3>
            {reportData.timelineTruncated && (
              <div style={{ marginBottom: 12, fontSize: 13, color: 'var(--text-muted)' }}>
                Showing the first {reportData.timelineLimit} events for PDF performance. Use Log Explorer to view/export the full dataset.
              </div>
            )}
            <div style={{ paddingLeft: 10 }}>
              {reportData.timeline?.map((evt, i) => (
                <div key={i} className="rca-timeline-item">
                  <div className="rca-timeline-dot" style={{ background: getSeverityColor(evt.severity) }} />
                  <div style={{ flex: 1 }}>
                    <div style={{ display: 'flex', gap: 12, alignItems: 'center', marginBottom: 4 }}>
                      <span style={{ color: 'var(--text-secondary)', fontSize: 13, minWidth: 140 }}>
                        {formatTimestamp(evt.tsUtc)}
                      </span>
                      <span className={`badge ${getSeverityClass(evt.severityLabel)}`}>
                        {evt.severityLabel}
                      </span>
                      <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{evt.action}</span>
                      {evt.attckTtp && (
                        <span style={{ background: 'var(--bg-surface)', padding: '2px 6px', borderRadius: 4, fontSize: 10, color: 'var(--accent)' }}>
                          {evt.attckTtp}
                        </span>
                      )}
                    </div>
                    <div style={{ color: 'var(--text-secondary)', fontSize: 13, paddingLeft: 152 }}>
                      {evt.message}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </section>

          {/* IOCs list if present */}
          {reportData.iocs?.length > 0 && (
            <section className="rca-section">
              <h3>Identified Indicators of Compromise (IOCs)</h3>
              <table className="data-table" style={{ border: '1px solid var(--border)', borderRadius: 'var(--radius-md)' }}>
                <thead><tr><th>Indicator</th><th>Type</th></tr></thead>
                <tbody>
                  {reportData.iocs.map((ioc, i) => (
                    <tr key={i}>
                      <td style={{ fontFamily: 'monospace', color: 'var(--sev-critical)' }}>{ioc.iocValue}</td>
                      <td style={{ color: 'var(--text-secondary)' }}>{ioc.iocValue.startsWith('CVE') ? 'Vulnerability' : 'Other'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </section>
          )}

          {/* Suggested Actions */}
          <section className="rca-section" style={{ borderTop: '1px solid var(--border)', paddingTop: 32 }}>
            <h3>Recommended Mitigation Actions</h3>
            <ul style={{ color: 'var(--text-primary)', fontSize: 14, lineHeight: 1.8, paddingLeft: 20 }}>
              <li>Isolate affected hosts: {reportData.affectedHosts?.map(h => h.hostname).join(', ') || 'N/A'}.</li>
              <li>Force password resets for compromised users: {reportData.affectedUsers?.map(u => u.userId).join(', ') || 'N/A'}.</li>
              <li>Block external attacker IPs at the perimeter firewall: {reportData.affectedIps?.map(ip => ip.ipAddress).join(', ') || 'N/A'}.</li>
              {reportData.iocs?.length > 0 && (
                <li>Patch immediately against identified CVEs: {reportData.iocs.map(i => i.iocValue).join(', ')}.</li>
              )}
            </ul>
          </section>

        </div>
      )}
    </div>
  );
}
