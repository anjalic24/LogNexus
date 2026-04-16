import { Routes, Route, NavLink, Link, useLocation } from 'react-router-dom';
import { LayoutDashboard, Upload, Network, ShieldAlert, FileText, Moon, Sun, Database, ListOrdered } from 'lucide-react';
import Dashboard from './pages/Dashboard.jsx';
import Ingest from './pages/Ingest.jsx';
import Sessions from './pages/Sessions.jsx';
import GraphExplorer from './pages/GraphExplorer.jsx';
import RcaReport from './pages/RcaReport.jsx';
import BundleManager from './pages/BundleManager.jsx';
import LogExplorer from './pages/LogExplorer.jsx';
import { useTheme } from './contexts/ThemeContext.jsx';

export default function App() {
  const location = useLocation();
  const { isDark, toggleTheme } = useTheme();

  const navigation = [
    {
      category: 'Overview',
      items: [
        { path: '/', icon: LayoutDashboard, label: 'Dashboard' },
      ],
    },
    {
      category: 'Ingestion Hub',
      items: [
        { path: '/ingest', icon: Upload, label: 'Log Upload' },
        { path: '/bundles', icon: ListOrdered, label: 'Bundle Manager' },
      ],
    },
    {
      category: 'Data Lake (Event Service)',
      items: [
        { path: '/explorer', icon: Database, label: 'Log Explorer' },
      ],
    },
    {
      category: 'Threat Intelligence (Correlation)',
      items: [
        { path: '/sessions', icon: ShieldAlert, label: 'Attack Sessions' },
        { path: '/graph', icon: Network, label: 'Threat Graph' },
        { path: '/rca', icon: FileText, label: 'RCA Reports' },
      ],
    }
  ];

  return (
    <div className="app-layout">
      {/* Sidebar */}
      <aside className="sidebar">
        <div className="sidebar-logo" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <Link
            to="/"
            style={{ display: 'flex', alignItems: 'center', gap: 12, textDecoration: 'none', color: 'inherit' }}
            title="Go to Dashboard"
          >
            <div className="logo-dot" style={{ background: 'var(--accent)' }} />
            <h1 style={{ fontSize: '22px', fontWeight: 800, letterSpacing: '-0.5px' }}>LogNexus</h1>
          </Link>
          <button
            onClick={toggleTheme}
            className="theme-toggle-btn"
            title={`Switch to ${isDark ? 'Light' : 'Dark'} Mode`}
            style={{ padding: '6px 10px' }}
          >
            {isDark ? <Sun size={16} /> : <Moon size={16} />}
          </button>
        </div>
        
        <nav className="sidebar-nav" style={{ padding: '20px 0', flex: 1, overflowY: 'auto' }}>
          {navigation.map((group) => (
            <div key={group.category} style={{ marginBottom: '24px' }}>
              <div style={{ 
                padding: '0 20px', 
                fontSize: '11px', 
                textTransform: 'uppercase', 
                color: 'var(--text-muted)', 
                fontWeight: 600,
                letterSpacing: '0.5px',
                marginBottom: '8px'
              }}>
                {group.category}
              </div>
              {group.items.map(({ path, icon: Icon, label }) => (
                <NavLink
                  key={path}
                  to={path}
                  className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}
                  end={path === '/'}
                  style={{ borderRadius: '0', borderLeft: '3px solid transparent' }}
                >
                  <Icon size={18} />
                  {label}
                </NavLink>
              ))}
            </div>
          ))}
        </nav>
        
        <div className="sidebar-footer">
          <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Vulnuris Security Solutions</div>
        </div>
      </aside>

      {/* Main content */}
      <main className="main-content">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/ingest" element={<Ingest />} />
          <Route path="/bundles" element={<BundleManager />} />
          <Route path="/explorer" element={<LogExplorer />} />
          <Route path="/sessions" element={<Sessions />} />
          <Route path="/sessions/:bundleId" element={<Sessions />} />
          <Route path="/graph" element={<GraphExplorer />} />
          <Route path="/graph/:bundleId" element={<GraphExplorer />} />
          <Route path="/rca" element={<RcaReport />} />
          <Route path="/rca/:bundleId" element={<RcaReport />} />
        </Routes>
      </main>
    </div>
  );
}
