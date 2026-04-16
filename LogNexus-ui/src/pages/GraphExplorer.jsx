import { useState, useEffect, useCallback, useRef } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { Network, X, Eye, EyeOff } from 'lucide-react';
import { getGraphData, listBundles } from '../api/correlationApi';
import { getNodeColor, getSeverityColor, formatTimestamp } from '../utils/helpers';
import { useActiveBundle } from '../contexts/ActiveBundleContext.jsx';

export default function GraphExplorer() {
  const { bundleId: paramBundle } = useParams();
  const [selectedBundle, setSelectedBundle] = useState(paramBundle || '');
  const [bundles, setBundles] = useState([]);
  const [graphData, setGraphData] = useState(null);
  const [viewMode, setViewMode] = useState('STORY'); // STORY | FULL | ENTITY
  const [layoutSpread, setLayoutSpread] = useState(2.6); // 0.8 .. 3.5
  const [loading, setLoading] = useState(false);
  const [selectedNode, setSelectedNode] = useState(null);
  const [showEntityEdges, setShowEntityEdges] = useState(false);
  const [minConfidence, setMinConfidence] = useState(0.6);
  const canvasRef = useRef(null);
  const nodesRef = useRef([]);
  const animRef = useRef(null);
  const dragRef = useRef({ dragging: false, nodeId: null });
  const worldRef = useRef({ w: 800, h: 600, cx: 400, cy: 300, margin: 40 });
  const edgesRef = useRef([]);
  const viewRef = useRef({ scale: 1, panX: 0, panY: 0 }); // screen-space pan (px)
  const panRef = useRef({ panning: false, startX: 0, startY: 0, startPanX: 0, startPanY: 0 });
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
      setSelectedNode(null);
      getGraphData(selectedBundle)
        .then(r => {
          setGraphData(r.data);
        })
        .catch(() => setGraphData(null))
        .finally(() => setLoading(false));
    }
  }, [selectedBundle]);

  const buildView = useCallback((data) => {
    if (!data) return null;

    const rawNodes = Array.isArray(data.nodes) ? data.nodes : [];
    const rawEdges = Array.isArray(data.edges) ? data.edges : [];

    let edges = rawEdges;
    if (viewMode === 'STORY') {
      edges = rawEdges.filter(e => e.type === 'LINKED' && (e.confidence || 0) >= minConfidence);
    } else if (viewMode === 'ENTITY') {
      edges = rawEdges.filter(e => e.type !== 'LINKED');
    } else {
      // FULL: include everything. (Confidence slider affects Story view primarily.)
      edges = rawEdges;
    }

    // Only allow hiding entity edges in FULL mode.
    // In STORY mode we already only show LINKED edges, and in ENTITY mode entity edges are the whole point.
    if (viewMode === 'FULL' && !showEntityEdges) {
      edges = edges.filter(e => e.type === 'LINKED');
    }

    // Node filtering based on mode/edges.
    // In FULL mode, keep all nodes (so even sparse edge sets still show context).
    let nodes = rawNodes;
    if (viewMode !== 'FULL') {
      const used = new Set();
      edges.forEach(e => {
        used.add(e.source);
        used.add(e.target);
      });
      nodes = rawNodes.filter(n => used.has(n.id));
    }
    if (viewMode === 'ENTITY') {
      nodes = nodes.filter(n => n.type !== 'Event');
      // Also drop any edges that still reference Event nodes (defensive)
      const entityIds = new Set(nodes.map(n => n.id));
      edges = edges.filter(e => entityIds.has(e.source) && entityIds.has(e.target));
    }

    return {
      bundleId: data.bundleId,
      nodes,
      edges,
    };
  }, [minConfidence, showEntityEdges, viewMode]);

  useEffect(() => {
    if (!graphData) return;
    const view = buildView(graphData);
    if (!view) return;
    setSelectedNode(null);
    initializePositions(view);
  }, [graphData, buildView]);

  const initializePositions = (data) => {
    if (!data) return;
    edgesRef.current = data.edges || [];
    const nodeCount = data.nodes.length || 1;
    // Expand the "world" as node count grows to avoid clamping piles at the edges.
    const baseW = 1200;
    const baseH = 900;
    const scale = Math.min(3.0, 1.0 + Math.log10(Math.max(10, nodeCount)) * 0.9) * layoutSpread;
    const worldW = Math.round(baseW * scale);
    const worldH = Math.round(baseH * scale);
    worldRef.current = {
      w: worldW,
      h: worldH,
      cx: worldW / 2,
      cy: worldH / 2,
      margin: 90,
    };

    const nodes = data.nodes.map((n, i) => {
      const angle = (i / data.nodes.length) * Math.PI * 2;
      const radius = (n.type === 'Event' ? 220 : 380) * layoutSpread;
      const { cx, cy } = worldRef.current;
      return {
        ...n,
        x: cx + Math.cos(angle) * radius + (Math.random() - 0.5) * 120,
        y: cy + Math.sin(angle) * radius + (Math.random() - 0.5) * 120,
        vx: 0, vy: 0,
        radius: n.type === 'Event' ? 16 : 12,
      };
    });
    nodesRef.current = nodes;
    runSimulation(nodes, data.edges);
  };

  const runSimulation = (nodes, edges) => {
    if (animRef.current) cancelAnimationFrame(animRef.current);
    let iterations = 0;
    const maxIter = 450;

    const modeFactor = (viewMode === 'FULL' || viewMode === 'ENTITY') ? 1.8 : 1.0;
    const repulsionBase = 1800 * modeFactor * layoutSpread * layoutSpread;
    const linkedIdeal = 180 * modeFactor * layoutSpread;
    const entityIdeal = 140 * modeFactor * layoutSpread;

    const tick = () => {
      // Don't "freeze" mid-drag. If user is dragging, keep simulating.
      if (iterations >= maxIter && !dragRef.current.dragging) {
        drawGraph(nodes, edges);
        return;
      }
      iterations++;

      // Repulsion
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const dx = nodes[j].x - nodes[i].x;
          const dy = nodes[j].y - nodes[i].y;
          const dist = Math.max(Math.sqrt(dx * dx + dy * dy), 1);
          const force = repulsionBase / (dist * dist);
          const fx = (dx / dist) * force;
          const fy = (dy / dist) * force;
          nodes[i].vx -= fx; nodes[i].vy -= fy;
          nodes[j].vx += fx; nodes[j].vy += fy;

          // Collision avoidance (prevents stacking)
          const minDist = (nodes[i].radius || 12) + (nodes[j].radius || 12) + (viewMode === 'STORY' ? 24 : 38);
          if (dist < minDist) {
            const push = (minDist - dist) * 0.12;
            const px = (dx / dist) * push;
            const py = (dy / dist) * push;
            nodes[i].vx -= px; nodes[i].vy -= py;
            nodes[j].vx += px; nodes[j].vy += py;
          }
        }
      }

      // Attraction along edges
      edges.forEach(edge => {
        const s = nodes.find(n => n.id === edge.source);
        const t = nodes.find(n => n.id === edge.target);
        if (!s || !t) return;
        const dx = t.x - s.x;
        const dy = t.y - s.y;
        const dist = Math.max(Math.sqrt(dx * dx + dy * dy), 1);
        const idealDist = edge.type === 'LINKED' ? linkedIdeal : entityIdeal;
        const force = (dist - idealDist) * 0.01;
        const fx = (dx / dist) * force;
        const fy = (dy / dist) * force;
        s.vx += fx; s.vy += fy;
        t.vx -= fx; t.vy -= fy;
      });

      // Center gravity
      const gravity = 0.0008 / layoutSpread;
      const { cx, cy, w: worldW, h: worldH, margin } = worldRef.current;
      nodes.forEach(n => {
        n.vx += (cx - n.x) * gravity;
        n.vy += (cy - n.y) * gravity;
        n.vx *= 0.85; n.vy *= 0.85;
        n.x += n.vx; n.y += n.vy;
        // Clamp within expanded world bounds (prevents everything piling into a tiny 800x600 box)
        n.x = Math.max(margin, Math.min(worldW - margin, n.x));
        n.y = Math.max(margin, Math.min(worldH - margin, n.y));
      });

      drawGraph(nodes, edges);
      animRef.current = requestAnimationFrame(tick);
    };
    tick();
  };

  const drawGraph = useCallback((nodes, edges) => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const w = canvas.width = canvas.offsetWidth;
    const h = canvas.height = canvas.offsetHeight;
    const world = worldRef.current;
    const { scale, panX, panY } = viewRef.current;
    const sx = (w / world.w) * scale;
    const sy = (h / world.h) * scale;

    ctx.clearRect(0, 0, w, h);

    // Draw edges
    edges.forEach(edge => {
      const s = nodes.find(n => n.id === edge.source);
      const t = nodes.find(n => n.id === edge.target);
      if (!s || !t) return;

      ctx.beginPath();
      ctx.moveTo(s.x * sx + panX, s.y * sy + panY);
      ctx.lineTo(t.x * sx + panX, t.y * sy + panY);

      if (edge.type === 'LINKED') {
        const conf = edge.confidence || 0.5;
        ctx.strokeStyle = conf >= 0.65
          ? `rgba(0, 212, 255, ${0.3 + conf * 0.5})`
          : `rgba(148, 163, 184, ${0.2 + conf * 0.3})`;
        ctx.lineWidth = 1 + conf * 3;
      } else {
        // Entity edges: keep them visually lighter than LINKED, but still visible in both themes.
        ctx.strokeStyle = 'rgba(100, 116, 139, 0.35)';
        ctx.lineWidth = 1.1;
        ctx.setLineDash([5, 4]);
      }
      ctx.stroke();
      ctx.setLineDash([]);
    });

    // Draw nodes
    nodes.forEach(n => {
      const x = n.x * sx + panX;
      const y = n.y * sy + panY;
      const r = n.radius || 12;
      const color = n.type === 'Event' ? getSeverityColor(n.severity || 0) : getNodeColor(n.type);

      // Glow
      ctx.beginPath();
      const gradient = ctx.createRadialGradient(x, y, 0, x, y, r * 2.5);
      gradient.addColorStop(0, color + '30');
      gradient.addColorStop(1, 'transparent');
      ctx.fillStyle = gradient;
      ctx.arc(x, y, r * 2.5, 0, Math.PI * 2);
      ctx.fill();

      // Node body
      ctx.beginPath();
      ctx.arc(x, y, r, 0, Math.PI * 2);
      ctx.fillStyle = color;
      ctx.fill();
      ctx.strokeStyle = color + '80';
      ctx.lineWidth = 2;
      ctx.stroke();

      // Label (Dynamic Theme Text)
      const computed = getComputedStyle(document.documentElement);
      const textPrimary = computed.getPropertyValue('--text-primary').trim() || '#e2e8f0';
      
      ctx.fillStyle = textPrimary;
      ctx.font = `${n.type === 'Event' ? 9 : 10}px Inter, sans-serif`;
      ctx.textAlign = 'center';
      const label = n.label || n.id || '';
      ctx.fillText(label.length > 18 ? label.slice(0, 16) + '..' : label, x, y + r + 14);
    });
  }, []);

  useEffect(() => {
    if (graphData && nodesRef.current.length > 0) {
      drawGraph(nodesRef.current, graphData.edges);
    }
  }, [showEntityEdges, minConfidence, drawGraph, graphData]);

  const handleCanvasClick = (e) => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    const mx = e.clientX - rect.left;
    const my = e.clientY - rect.top;
    const sx = canvas.width / worldRef.current.w;
    const sy = canvas.height / worldRef.current.h;

    const clicked = nodesRef.current.find(n => {
      const { scale, panX, panY } = viewRef.current;
      const dx = n.x * sx * scale + panX - mx;
      const dy = n.y * sy * scale + panY - my;
      return Math.sqrt(dx * dx + dy * dy) < (n.radius || 12) + 4;
    });
    setSelectedNode(clicked || null);
  };

  const canvasToGraph = (canvas, mx, my) => {
    // mx/my are canvas pixels; convert into graph coords (0..world.w / 0..world.h)
    const { scale, panX, panY } = viewRef.current;
    const sx = (canvas.width / worldRef.current.w) * scale;
    const sy = (canvas.height / worldRef.current.h) * scale;
    return { gx: (mx - panX) / sx, gy: (my - panY) / sy, sx, sy };
  };

  const pickNodeAt = (mx, my) => {
    const canvas = canvasRef.current;
    if (!canvas) return null;
    const rect = canvas.getBoundingClientRect();
    const cx = mx - rect.left;
    const cy = my - rect.top;
    const { sx, sy } = canvasToGraph(canvas, cx, cy);
    return nodesRef.current.find(n => {
      const dx = n.x * sx - cx;
      const dy = n.y * sy - cy;
      return Math.sqrt(dx * dx + dy * dy) < (n.radius || 12) + 6;
    }) || null;
  };

  const handlePointerDown = (e) => {
    // Pan if user clicks empty space; drag node if click hits node.
    const node = pickNodeAt(e.clientX, e.clientY);
    if (node) {
      // Ensure simulation is running so connected nodes respond while dragging.
      if (!animRef.current) {
        runSimulation(nodesRef.current, edgesRef.current);
      }
      dragRef.current = { dragging: true, nodeId: node.id };
      node.vx = 0;
      node.vy = 0;
    } else {
      panRef.current = {
        panning: true,
        startX: e.clientX,
        startY: e.clientY,
        startPanX: viewRef.current.panX,
        startPanY: viewRef.current.panY,
      };
    }
    e.currentTarget.setPointerCapture?.(e.pointerId);
  };

  const handlePointerMove = (e) => {
    if (panRef.current.panning) {
      const dx = e.clientX - panRef.current.startX;
      const dy = e.clientY - panRef.current.startY;
      viewRef.current.panX = panRef.current.startPanX + dx;
      viewRef.current.panY = panRef.current.startPanY + dy;
      if (graphData) drawGraph(nodesRef.current, edgesRef.current);
      return;
    }
    if (!dragRef.current.dragging) return;
    const canvas = canvasRef.current;
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    const cx = e.clientX - rect.left;
    const cy = e.clientY - rect.top;
    const { gx, gy } = canvasToGraph(canvas, cx, cy);
    const node = nodesRef.current.find(n => n.id === dragRef.current.nodeId);
    if (!node) return;
    const { w: worldW, h: worldH, margin } = worldRef.current;
    node.x = Math.max(margin, Math.min(worldW - margin, gx));
    node.y = Math.max(margin, Math.min(worldH - margin, gy));
    node.vx = 0;
    node.vy = 0;
    // draw is handled by the simulation loop while dragging
  };

  const handlePointerUp = (e) => {
    panRef.current.panning = false;
    dragRef.current = { dragging: false, nodeId: null };
    e.currentTarget.releasePointerCapture?.(e.pointerId);
  };

  const handleWheel = (e) => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    e.preventDefault();
    const rect = canvas.getBoundingClientRect();
    const mx = e.clientX - rect.left;
    const my = e.clientY - rect.top;

    const prev = viewRef.current.scale;
    const delta = e.deltaY;
    const next = Math.max(0.6, Math.min(4.0, prev * (delta > 0 ? 0.92 : 1.08)));

    // Zoom around cursor: keep graph point under cursor stable.
    const { panX, panY } = viewRef.current;
    const world = worldRef.current;
    const baseSx = canvas.width / world.w;
    const baseSy = canvas.height / world.h;

    const prevSx = baseSx * prev;
    const prevSy = baseSy * prev;
    const gx = (mx - panX) / prevSx;
    const gy = (my - panY) / prevSy;

    const nextSx = baseSx * next;
    const nextSy = baseSy * next;
    viewRef.current.scale = next;
    viewRef.current.panX = mx - gx * nextSx;
    viewRef.current.panY = my - gy * nextSy;

    if (graphData) drawGraph(nodesRef.current, edgesRef.current);
  };

  return (
    <div className="animate-in">
      <div className="page-header">
        <h2>Graph Explorer</h2>
        <p>Interactive Directed Event Graph visualization</p>
      </div>

      <div className="filter-bar" style={{ marginBottom: 16 }}>
        <div className="form-group">
          <label className="form-label">Bundle</label>
          <select className="form-select" value={selectedBundle}
            onChange={e => {
              const v = e.target.value;
              setSelectedBundle(v);
              setActiveBundleId(v);
              navigate(v ? `/graph/${v}` : `/graph`);
            }} style={{ minWidth: 220 }}>
            <option value="">Select a bundle...</option>
            {bundles.map((b, i) => (
              <option key={i} value={b.bundleId}>{b.bundleId} ({b.eventCount} events)</option>
            ))}
          </select>
        </div>
        <div className="form-group">
          <label className="form-label">View</label>
          <select
            className="form-select"
            value={viewMode}
            onChange={e => setViewMode(e.target.value)}
            style={{ minWidth: 160 }}
          >
            <option value="STORY">Story</option>
            <option value="FULL">Full</option>
            <option value="ENTITY">Entity</option>
          </select>
        </div>
        <div className="form-group">
          <label className="form-label">Min Confidence</label>
          <input type="range" min="0" max="1" step="0.05" value={minConfidence}
            onChange={e => setMinConfidence(parseFloat(e.target.value))}
            style={{ width: 120, accentColor: 'var(--accent)' }} />
          <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{minConfidence.toFixed(2)}</span>
        </div>
        <div className="form-group">
          <label className="form-label">Layout Spread</label>
          <input
            type="range"
            min="0.8"
            max="3.5"
            step="0.1"
            value={layoutSpread}
            onChange={e => setLayoutSpread(parseFloat(e.target.value))}
            style={{ width: 120, accentColor: 'var(--accent)' }}
          />
          <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{layoutSpread.toFixed(1)}x</span>
        </div>
        <button
          className="btn btn-secondary"
          onClick={() => graphData && initializePositions(buildView(graphData))}
          style={{ fontSize: 12 }}
          title="Re-run layout with current settings"
          disabled={!graphData}
        >
          Re-layout
        </button>
        <button
          className={`btn ${showEntityEdges ? 'btn-secondary' : 'btn-ghost'}`}
          onClick={() => setShowEntityEdges(!showEntityEdges)}
          style={{ fontSize: 12 }}
          disabled={viewMode === 'STORY' || viewMode === 'ENTITY'}
          title={viewMode === 'FULL' ? 'Show/hide entity relationship edges' : 'Entity edges are not shown in this view'}
        >
          {showEntityEdges ? <Eye size={14} /> : <EyeOff size={14} />} Entity Edges
        </button>
      </div>

      {loading && <div className="loading-container"><div className="loading-spinner" /><p>Loading graph...</p></div>}

      {!loading && !selectedBundle && (
        <div className="empty-state">
          <Network size={48} style={{ opacity: 0.3, marginBottom: 16 }} />
          <h3>Select a bundle</h3>
          <p>Choose a bundle from the dropdown to visualize its correlation graph.</p>
        </div>
      )}

      {/* Legend + Stats (above graph box) */}
      {!loading && graphData && (
        <div style={{ display: 'flex', justifyContent: 'space-between', gap: 16, marginBottom: 12, alignItems: 'center' }}>
          <div className="graph-legend" style={{ position: 'static' }}>
            {['Event', 'User', 'IP', 'Host', 'IOC'].map(type => (
              <div key={type} className="legend-item">
                <div className="legend-dot" style={{ background: getNodeColor(type) }} />
                {type}
              </div>
            ))}
          </div>
          <div className="card" style={{ padding: 10, fontSize: 12, opacity: 0.9, minWidth: 140 }}>
            <div style={{ color: 'var(--text-secondary)' }}>Graph</div>
            <div style={{ marginTop: 4 }}>{graphData.nodes.length} nodes</div>
            <div>{graphData.edges.length} edges</div>
          </div>
        </div>
      )}

      {!loading && graphData && (
        <div className="graph-container">
          <canvas
            ref={canvasRef}
            onClick={handleCanvasClick}
            onWheel={handleWheel}
            onPointerDown={handlePointerDown}
            onPointerMove={handlePointerMove}
            onPointerUp={handlePointerUp}
            style={{ width: '100%', height: '100%', cursor: dragRef.current.dragging ? 'grabbing' : 'grab' }}
          />

          {/* Inspector */}
          {selectedNode && (
            <div className="inspector-panel">
              <h3>
                <span style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <div style={{ width: 12, height: 12, borderRadius: '50%',
                    background: selectedNode.type === 'Event' ? getSeverityColor(selectedNode.severity) : getNodeColor(selectedNode.type) }} />
                  {selectedNode.type}
                </span>
                <button className="btn btn-ghost" onClick={() => setSelectedNode(null)} style={{ padding: 4 }}>
                  <X size={16} />
                </button>
              </h3>
              {Object.entries(selectedNode).filter(([k]) =>
                !['x', 'y', 'vx', 'vy', 'radius'].includes(k) && selectedNode[k] != null
              ).map(([k, v]) => (
                <div key={k} className="inspector-row">
                  <span className="label">{k}</span>
                  <span className="value">{typeof v === 'number' ? v.toFixed(3) : String(v)}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
