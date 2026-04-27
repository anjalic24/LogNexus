import { useState, useEffect, useRef, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { Clock, X, ChevronDown, ChevronUp, Search } from 'lucide-react';
import { getRcaReport, listBundles } from '../api/correlationApi';
import { getSeverityColor, formatTimestamp } from '../utils/helpers';
import { useActiveBundle } from '../contexts/ActiveBundleContext.jsx';


const ROW_H        = 52;    // px per actor row
const ROW_PAD      = 14;    // padding inside each row
const LEFT_W       = 180;   // px reserved for actor labels
const TOP_H        = 48;    // px reserved for time axis
const DOT_MIN_R    = 5;
const DOT_MAX_R    = 11;
const TICK_INTERVAL_PX = 110;


const severityToRadius = sev => DOT_MIN_R + Math.round(((sev || 0) / 10) * (DOT_MAX_R - DOT_MIN_R));

const formatTick = (ms) => {
  const d = new Date(ms);
  const hh = String(d.getUTCHours()).padStart(2, '0');
  const mm = String(d.getUTCMinutes()).padStart(2, '0');
  const ss = String(d.getUTCSeconds()).padStart(2, '0');
  return `${hh}:${mm}:${ss}`;
};


export default function TimelineView() {
  const { bundleId: paramBundle } = useParams();
  const navigate                  = useNavigate();
  const { activeBundleId, setActiveBundleId } = useActiveBundle();

  const [bundles,        setBundles]        = useState([]);
  const [selectedBundle, setSelectedBundle] = useState(paramBundle || '');
  const [rcaData,        setRcaData]        = useState(null);
  const [loading,        setLoading]        = useState(false);
  const [error,          setError]          = useState('');
  const [selectedEvents, setSelectedEvents] = useState([]);
  const [selectedIndex,  setSelectedIndex]  = useState(0);
  const [minConfidence,  setMinConfidence]  = useState(0.5);
  const [actorSearch,    setActorSearch]    = useState('');
  const [collapsedRows,  setCollapsedRows]  = useState(new Set());

  const canvasRef  = useRef(null);
  const stateRef   = useRef({ actors: [], events: [], edges: [] });
  const viewRef    = useRef({ min: 0, max: 1, baseMin: 0, baseMax: 1, baseRange: 1 });
  const dragRef    = useRef({ isDragging: false, lastX: 0, hasMoved: false });
  const hoverRef   = useRef(null);


  useEffect(() => {
    listBundles().then(r => setBundles(r.data || [])).catch(() => {});
  }, []);


  useEffect(() => { if (paramBundle) setSelectedBundle(paramBundle); }, [paramBundle]);
  useEffect(() => {
    if (!paramBundle && activeBundleId) setSelectedBundle(activeBundleId);
  }, [paramBundle, activeBundleId]);


  useEffect(() => {
    if (!selectedBundle) return;
    setLoading(true);
    setError('');
    setSelectedEvents([]);
    setSelectedIndex(0);
    getRcaReport(selectedBundle)
      .then(r => setRcaData(r.data))
      .catch(() => setError('Failed to load timeline data. Ensure the bundle has been correlated.'))
      .finally(() => setLoading(false));
  }, [selectedBundle]);


  const buildState = useCallback(() => {
    if (!rcaData) return;

    const rawTimeline = Array.isArray(rcaData.timeline) ? rcaData.timeline : [];
    const rawEdges    = Array.isArray(rcaData.causalChain) ? rcaData.causalChain : [];


    const events = rawTimeline
      .map(e => ({ ...e, _ms: e.tsUtc ? new Date(e.tsUtc).getTime() : null }))
      .filter(e => e._ms && !isNaN(e._ms));

    if (events.length === 0) return;


    const timeMin   = Math.min(...events.map(e => e._ms));
    const timeMax   = Math.max(...events.map(e => e._ms));
    const timeRange = Math.max(timeMax - timeMin, 1000); // avoid /0

    viewRef.current = {
      min: timeMin,
      max: timeMax,
      baseMin: timeMin,
      baseMax: timeMax,
      baseRange: timeRange
    };


    const actorMap = new Map(); // key → { type, id, events[] }
    const addActor = (type, id, event) => {
      if (!id) return;
      const key = `${type}:${id}`;
      if (!actorMap.has(key)) actorMap.set(key, { type, id, key, events: [] });
      actorMap.get(key).events.push(event);
    };

    events.forEach(e => {
      addActor('User', e.user,   e);
      addActor('IP',   e.srcIp,  e);
      addActor('Host', e.host,   e);
    });


    const typePriority = { User: 0, IP: 1, Host: 2 };
    const actors = [...actorMap.values()].sort((a, b) => {
      const tp = typePriority[a.type] - typePriority[b.type];
      if (tp !== 0) return tp;
      return Math.min(...a.events.map(e => e._ms)) - Math.min(...b.events.map(e => e._ms));
    });

    stateRef.current = { actors, events, edges: rawEdges };
  }, [rcaData]);

  useEffect(() => { buildState(); }, [buildState]);


  const draw = useCallback(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx   = canvas.getContext('2d');
    const { actors, events, edges } = stateRef.current;
    if (actors.length === 0) return;
    
    const { min: timeMin, max: timeMax } = viewRef.current;
    const timeRange = Math.max(timeMax - timeMin, 1);

    const computed = getComputedStyle(document.documentElement);
    const clrBg      = computed.getPropertyValue('--bg-surface').trim()   || '#0f172a';
    const clrCard    = computed.getPropertyValue('--bg-card').trim()      || '#1e293b';
    const clrBorder  = computed.getPropertyValue('--border').trim()       || '#334155';
    const clrText    = computed.getPropertyValue('--text-primary').trim() || '#e2e8f0';
    const clrMuted   = computed.getPropertyValue('--text-muted').trim()   || '#64748b';
    const clrAccent  = computed.getPropertyValue('--accent').trim()       || '#00d4ff';


    const visibleActors = actors.filter(a =>
      !actorSearch || a.id.toLowerCase().includes(actorSearch.toLowerCase())
    );
    const totalRows = visibleActors.length;
    const canvasH   = TOP_H + totalRows * ROW_H + 16;
    const canvasW   = canvas.offsetWidth;
    canvas.width    = canvasW;
    canvas.height   = canvasH;

    const contentW = canvasW - LEFT_W - 16; // drawable X width


    const msToX = ms => LEFT_W + ((ms - timeMin) / timeRange) * contentW;


    ctx.fillStyle = clrBg;
    ctx.fillRect(0, 0, canvasW, canvasH);


    visibleActors.forEach((actor, rowIdx) => {
      const rowY = TOP_H + rowIdx * ROW_H;
      ctx.fillStyle = rowIdx % 2 === 0 ? clrCard : clrBg;
      ctx.fillRect(0, rowY, canvasW, ROW_H);
    });


    ctx.fillStyle = clrBg;
    ctx.fillRect(0, 0, LEFT_W, canvasH);


    const tickCount = Math.floor(contentW / TICK_INTERVAL_PX);
    const tickMs    = timeRange / Math.max(tickCount, 1);
    ctx.strokeStyle = clrBorder + '60';
    ctx.lineWidth   = 1;
    for (let i = 0; i <= tickCount; i++) {
      const x = LEFT_W + i * TICK_INTERVAL_PX;
      ctx.beginPath();
      ctx.moveTo(x, TOP_H);
      ctx.lineTo(x, canvasH);
      ctx.stroke();
    }


    ctx.fillStyle = clrCard;
    ctx.fillRect(LEFT_W, 0, contentW, TOP_H);
    ctx.font      = '11px Inter, sans-serif';
    ctx.fillStyle = clrMuted;
    ctx.textAlign = 'center';
    for (let i = 0; i <= tickCount; i++) {
      const ms = timeMin + i * tickMs;
      const x  = LEFT_W + i * TICK_INTERVAL_PX;
      ctx.fillText(formatTick(ms), x, TOP_H / 2 + 4);
    }


    ctx.strokeStyle = clrBorder + '50';
    ctx.lineWidth   = 1;
    visibleActors.forEach((_, idx) => {
      const y = TOP_H + idx * ROW_H;
      ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(canvasW, y); ctx.stroke();
    });


    const typeColors = { User: '#818cf8', IP: '#f59e0b', Host: '#34d399' };
    ctx.textAlign = 'left';
    visibleActors.forEach((actor, idx) => {
      const y = TOP_H + idx * ROW_H + ROW_H / 2;

      ctx.font      = '10px Inter, sans-serif';
      ctx.fillStyle = typeColors[actor.type] || clrAccent;
      ctx.fillRect(12, y - 8, 38, 16);
      ctx.fillStyle = '#000';
      ctx.textAlign = 'center';
      ctx.fillText(actor.type, 31, y + 4);

      ctx.textAlign  = 'left';
      ctx.fillStyle  = clrText;
      ctx.font       = '11px Inter, sans-serif';
      const maxLbl   = 20;
      const lbl      = actor.id.length > maxLbl ? actor.id.slice(0, maxLbl - 1) + '…' : actor.id;
      ctx.fillText(lbl, 58, y + 4);
    });


    const rowIndex = new Map(visibleActors.map((a, i) => [a.key, i]));
    const eventPos = new Map(); // eventId → { x, y }


    edges.forEach(edge => {
      if ((edge.confidence || 0) < minConfidence) return;


      const srcEvt  = events.find(e => e.eventId === edge.sourceId);
      const tgtEvt  = events.find(e => e.eventId === edge.targetId);
      if (!srcEvt || !tgtEvt) return;


      const getActorKey = e => {
        if (e.user)  return `User:${e.user}`;
        if (e.srcIp) return `IP:${e.srcIp}`;
        if (e.host)  return `Host:${e.host}`;
        return null;
      };
      const srcKey = getActorKey(srcEvt);
      const tgtKey = getActorKey(tgtEvt);
      const srcRow = rowIndex.get(srcKey);
      const tgtRow = rowIndex.get(tgtKey);
      if (srcRow === undefined || tgtRow === undefined) return;

      const sx = msToX(srcEvt._ms);
      const sy = TOP_H + srcRow * ROW_H + ROW_H / 2;
      const tx = msToX(tgtEvt._ms);
      const ty = TOP_H + tgtRow * ROW_H + ROW_H / 2;

      const conf    = edge.confidence || 0;
      const alpha   = 0.25 + conf * 0.55;
      
      ctx.save();
      ctx.beginPath();
      ctx.setLineDash([4, 4]);
      ctx.strokeStyle = conf >= 0.7 ? clrAccent : clrMuted;
      ctx.globalAlpha = alpha;
      ctx.lineWidth = 1 + conf * 2;


      const mx = (sx + tx) / 2;
      if (srcRow === tgtRow) {
        ctx.moveTo(sx, sy);
        ctx.lineTo(tx, ty);
      } else {
        ctx.moveTo(sx, sy);
        ctx.bezierCurveTo(mx, sy, mx, ty, tx, ty);
      }
      ctx.stroke();
      ctx.setLineDash([]);
      

      ctx.font      = '10px Inter, sans-serif';
      ctx.fillStyle = conf >= 0.7 ? clrAccent : clrMuted;
      ctx.globalAlpha = alpha + 0.3;
      ctx.textAlign = 'center';
      ctx.fillText(conf.toFixed(2), mx, (sy + ty) / 2 - 4);
      ctx.restore();
    });


    events.forEach(evt => {
      const getActorKey = e => {
        if (e.user)  return `User:${e.user}`;
        if (e.srcIp) return `IP:${e.srcIp}`;
        if (e.host)  return `Host:${e.host}`;
        return null;
      };
      const key = getActorKey(evt);
      const row = rowIndex.get(key);
      if (row === undefined) return;

      const x = msToX(evt._ms);
      const y = TOP_H + row * ROW_H + ROW_H / 2;
      const r = severityToRadius(evt.severity || 0);

      eventPos.set(evt.eventId, { x, y, r, evt });

      const color  = getSeverityColor(evt.severity || 0);
      const isHov  = hoverRef.current?.eventId === evt.eventId;
      const activeEvent = selectedEvents[selectedIndex];
      const isSel  = activeEvent?.eventId === evt.eventId;


      ctx.beginPath();
      ctx.arc(x, y, r, 0, Math.PI * 2);
      ctx.fillStyle  = color;
      ctx.fill();
      

      if (isHov || isSel) {
        ctx.beginPath();
        ctx.arc(x, y, r + 3, 0, Math.PI * 2);
        ctx.strokeStyle = color;
        ctx.lineWidth = 2;
        ctx.stroke();
        
        ctx.beginPath();
        ctx.arc(x, y, r, 0, Math.PI * 2);
        ctx.strokeStyle = clrBg;
        ctx.lineWidth = 1.5;
        ctx.stroke();
      }
    });

    stateRef.current._eventPos = eventPos;
  }, [minConfidence, actorSearch, selectedEvents, selectedIndex]);


  useEffect(() => { draw(); }, [draw, rcaData]);


  useEffect(() => {
    const obs = new ResizeObserver(() => draw());
    if (canvasRef.current) obs.observe(canvasRef.current);
    return () => obs.disconnect();
  }, [draw]);


  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const handleWheel = e => {

      if (!e.ctrlKey) return;

      e.preventDefault();
      const rect = canvas.getBoundingClientRect();
      const mx = e.clientX - rect.left;
      if (mx < LEFT_W) return;

      const view = viewRef.current;
      const contentW = canvas.offsetWidth - LEFT_W - 16;
      const timeRange = view.max - view.min;
      const timeAtCursor = view.min + ((mx - LEFT_W) / contentW) * timeRange;


      const zoomFactor = e.deltaY < 0 ? (1 / 1.15) : 1.15;
      let newRange = timeRange * zoomFactor;

      const MIN_RANGE = 100;
      const MAX_RANGE = view.baseRange;
      if (newRange < MIN_RANGE) newRange = MIN_RANGE;
      if (newRange > MAX_RANGE) newRange = MAX_RANGE;

      let newMin = timeAtCursor - ((mx - LEFT_W) / contentW) * newRange;
      let newMax = newMin + newRange;

      if (newMax > view.baseMax + (MAX_RANGE * 0.05)) {
         newMax = view.baseMax + (MAX_RANGE * 0.05);
         newMin = newMax - newRange;
      }
      if (newMin < view.baseMin - (MAX_RANGE * 0.05)) {
         newMin = view.baseMin - (MAX_RANGE * 0.05);
         newMax = newMin + newRange;
      }

      view.min = newMin;
      view.max = newMax;
      draw();
    };

    canvas.addEventListener('wheel', handleWheel, { passive: false });
    return () => canvas.removeEventListener('wheel', handleWheel);
  }, [draw]);


  const pickEvents = useCallback((clientX, clientY) => {
    const canvas = canvasRef.current;
    if (!canvas) return [];
    const rect   = canvas.getBoundingClientRect();
    const mx     = clientX - rect.left;
    const my     = clientY - rect.top;
    const posMap = stateRef.current._eventPos;
    if (!posMap) return [];

    const hits = [];
    for (const [, { x, y, r, evt }] of posMap) {
      const dx = mx - x, dy = my - y;
      if (dx * dx + dy * dy <= (r + 5) * (r + 5)) hits.push(evt);
    }
    return hits;
  }, []);

  const handlePointerDown = useCallback(e => {
    if (!canvasRef.current) return;
    const rect = canvasRef.current.getBoundingClientRect();
    const mx = e.clientX - rect.left;
    if (mx < LEFT_W) return; 
    
    dragRef.current = { isDragging: true, lastX: e.clientX, hasMoved: false };
    canvasRef.current.style.cursor = 'grabbing';
  }, []);

  const handlePointerMove = useCallback(e => {
    if (dragRef.current.isDragging) {
      const dx = e.clientX - dragRef.current.lastX;
      if (Math.abs(dx) > 3) dragRef.current.hasMoved = true;
      
      const canvas = canvasRef.current;
      const contentW = canvas.offsetWidth - LEFT_W - 16;
      const view = viewRef.current;
      const timeRange = view.max - view.min;
      
      const timeShift = -(dx / contentW) * timeRange;
      view.min += timeShift;
      view.max += timeShift;
      
      dragRef.current.lastX = e.clientX;
      draw();
      return;
    }


    const hits = pickEvents(e.clientX, e.clientY);
    const topHit = hits.length > 0 ? hits[0] : null;
    if (topHit?.eventId !== hoverRef.current?.eventId) {
      hoverRef.current = topHit;
      canvasRef.current.style.cursor = topHit ? 'pointer' : 'default';
      draw();
    }
  }, [pickEvents, draw]);

  const handlePointerUp = useCallback(e => {
    const wasDragging = dragRef.current.isDragging;
    const hasMoved = dragRef.current.hasMoved;
    dragRef.current.isDragging = false;
    
    if (canvasRef.current) canvasRef.current.style.cursor = 'default';

    if (wasDragging && hasMoved) return;
    

    const hits = pickEvents(e.clientX, e.clientY);
    setSelectedEvents(hits);
    setSelectedIndex(0);
  }, [pickEvents]);

  const handlePointerLeave = useCallback(() => {
    dragRef.current.isDragging = false;
    hoverRef.current = null;
    draw();
  }, [draw]);


  const handleBundleChange = (id) => {
    setSelectedBundle(id);
    setActiveBundleId(id);
    navigate(id ? `/timeline/${id}` : '/timeline');
  };


  const severityLegend = [
    { label: 'INFO',     sev: 1 },
    { label: 'LOW',      sev: 3 },
    { label: 'MEDIUM',   sev: 5 },
    { label: 'HIGH',     sev: 8 },
    { label: 'CRITICAL', sev: 10 },
  ];


  return (
    <div className="animate-in" style={{ height: '100%', display: 'flex', flexDirection: 'column', overflowY: 'auto' }}>


      <div className="page-header">
        <h2>Attack Timeline</h2>
        <p>Swimlane view — actors (Users · IPs · Hosts) vs. time, coloured by severity</p>
      </div>


      <div className="filter-bar" style={{ marginBottom: 16, flexWrap: 'wrap', gap: 12 }}>

        <div className="form-group">
          <label className="form-label">Bundle</label>
          <select className="form-select" style={{ minWidth: 220 }}
            value={selectedBundle} onChange={e => handleBundleChange(e.target.value)}>
            <option value="">Select a bundle...</option>
            {bundles.map((b, i) => (
              <option key={i} value={b.bundleId}>{b.bundleId} ({b.eventCount} events)</option>
            ))}
          </select>
        </div>


        <div className="form-group">
          <label className="form-label">Min Edge Confidence</label>
          <input type="range" min="0" max="1" step="0.05" value={minConfidence}
            onChange={e => setMinConfidence(parseFloat(e.target.value))}
            style={{ width: 110, accentColor: 'var(--accent)' }} />
          <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{minConfidence.toFixed(2)}</span>
        </div>


        <div className="form-group" style={{ position: 'relative' }}>
          <label className="form-label">Highlight Actor</label>
          <div style={{ position: 'relative' }}>
            <Search size={13} style={{ position: 'absolute', left: 9, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
            <input type="text" placeholder="user / IP / host…" value={actorSearch}
              onChange={e => setActorSearch(e.target.value)}
              style={{ background: 'var(--bg-input)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', color: 'var(--text-primary)', padding: '6px 10px 6px 28px', width: 170 }} />
          </div>
        </div>


        <div className="form-group" style={{ marginLeft: 'auto', display: 'flex', alignItems: 'flex-end' }}>
          <button 
            className="btn btn-secondary" 
            style={{ padding: '6px 16px', fontSize: 13, height: 38 }}
            onClick={() => {
              viewRef.current.min = viewRef.current.baseMin;
              viewRef.current.max = viewRef.current.baseMax;
              draw();
            }}>
             Reset Zoom
          </button>
        </div>
      </div>


      {rcaData && (
        <div style={{ display: 'flex', gap: 16, marginBottom: 12, alignItems: 'center', flexWrap: 'wrap' }}>
          <span style={{ fontSize: 12, color: 'var(--text-muted)', fontWeight: 600 }}>Severity:</span>
          {severityLegend.map(s => (
            <div key={s.label} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <div style={{
                width: severityToRadius(s.sev) * 2, height: severityToRadius(s.sev) * 2,
                borderRadius: '50%', background: getSeverityColor(s.sev), flexShrink: 0
              }} />
              <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>{s.label}</span>
            </div>
          ))}
          <span style={{ marginLeft: 12, fontSize: 12, color: 'var(--text-muted)', fontWeight: 600 }}>Actors:</span>
          {[['User', '#818cf8'], ['IP', '#f59e0b'], ['Host', '#34d399']].map(([t, c]) => (
            <div key={t} style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
              <div style={{ width: 28, height: 14, background: c, borderRadius: 3 }} />
              <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>{t}</span>
            </div>
          ))}
        </div>
      )}


      {loading && (
        <div className="loading-container">
          <div className="loading-spinner" />
          <p>Building timeline…</p>
        </div>
      )}
      {error && (
        <div style={{ padding: '12px 16px', background: 'var(--status-danger-bg)', color: 'var(--status-danger)', border: '1px solid var(--status-danger-border)', borderRadius: 'var(--radius-sm)', fontSize: 13, marginBottom: 16 }}>
          {error}
        </div>
      )}
      {!loading && !selectedBundle && (
        <div className="empty-state">
          <Clock size={48} style={{ opacity: 0.3, marginBottom: 16 }} />
          <h3>Select a bundle</h3>
          <p>Choose a bundle to render the attack timeline.</p>
        </div>
      )}


      {!loading && rcaData && (
        <div style={{ display: 'flex', gap: 16, flex: 1, minHeight: 0 }}>


          <div style={{
            flex: 1, background: 'var(--bg-surface)', border: '1px solid var(--border)',
            borderRadius: 'var(--radius-lg)', overflow: 'auto', position: 'relative'
          }}>
            <canvas
              ref={canvasRef}
              onPointerDown={handlePointerDown}
              onPointerMove={handlePointerMove}
              onPointerUp={handlePointerUp}
              onPointerLeave={handlePointerLeave}
              style={{ display: 'block', width: '100%', touchAction: 'none' }}
            />
          </div>


          {selectedEvents.length > 0 && (() => {
            const selectedEvent = selectedEvents[selectedIndex];
            return (
            <div style={{ 
              minWidth: 260, maxWidth: 300,
              background: 'var(--bg-card)',
              backdropFilter: 'blur(12px)',
              border: '1px solid var(--border)',
              borderLeft: `4px solid ${getSeverityColor(selectedEvent.severity || 0)}`,
              borderRadius: '12px',
              padding: '16px',
              color: 'var(--text-primary)',
              boxShadow: 'var(--shadow-card)',
              display: 'flex', flexDirection: 'column'
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border)', paddingBottom: 12, marginBottom: 16 }}>
                <h3 style={{ margin: 0, fontSize: 16, fontWeight: 700, display: 'flex', alignItems: 'center', gap: 8 }}>
                  <div style={{ width: 8, height: 8, borderRadius: '50%', background: getSeverityColor(selectedEvent.severity || 0) }} />
                  Event Detail
                </h3>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  {selectedEvents.length > 1 && (
                    <div style={{ display: 'flex', alignItems: 'center', gap: 4, background: 'var(--bg-hover-subtle)', borderRadius: 16, padding: '2px 8px', fontSize: 12, color: 'var(--text-secondary)' }}>
                      <button onClick={() => setSelectedIndex(Math.max(0, selectedIndex - 1))} disabled={selectedIndex === 0} style={{ background: 'none', border: 'none', color: selectedIndex > 0 ? 'var(--text-primary)' : 'var(--text-muted)', cursor: selectedIndex > 0 ? 'pointer' : 'default', padding: 0 }}>&lt;</button>
                      <span style={{ fontWeight: 600 }}>{selectedIndex + 1} of {selectedEvents.length}</span>
                      <button onClick={() => setSelectedIndex(Math.min(selectedEvents.length - 1, selectedIndex + 1))} disabled={selectedIndex === selectedEvents.length - 1} style={{ background: 'none', border: 'none', color: selectedIndex < selectedEvents.length - 1 ? 'var(--text-primary)' : 'var(--text-muted)', cursor: selectedIndex < selectedEvents.length - 1 ? 'pointer' : 'default', padding: 0 }}>&gt;</button>
                    </div>
                  )}
                  <button 
                    style={{ background: 'transparent', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', padding: 4, borderRadius: 4, display: 'flex' }} 
                    onMouseEnter={e => e.currentTarget.style.background = 'var(--bg-hover-subtle)'}
                    onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                    onClick={() => { setSelectedEvents([]); setSelectedIndex(0); }}
                  >
                    <X size={16} />
                  </button>
                </div>
              </div>
              
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10, overflowY: 'auto', paddingRight: 4 }}>
              {[
                ['Event ID',   selectedEvent.eventId],
                ['Time (UTC)', selectedEvent.tsUtc],
                ['Action',     selectedEvent.action],
                ['Severity',   selectedEvent.severityLabel || selectedEvent.severity],
                ['User',       selectedEvent.user],
                ['Src IP',     selectedEvent.srcIp],
                ['Host',       selectedEvent.host],
                ['MITRE TTP',  selectedEvent.attckTtp],
                ['Kill Chain', selectedEvent.killChainStage],
                ['Country',    selectedEvent.geoCountry],
                ['Node Risk',  typeof selectedEvent.nodeRisk === 'number'
                                 ? selectedEvent.nodeRisk.toFixed(3) : null],
                ['Message',    selectedEvent.message],
              ]
                .filter(([, v]) => v != null && v !== '')
                .map(([k, v]) => {
                  const isMsg = k === 'Message';
                  return (
                    <div key={k} style={{ 
                      display: 'flex', 
                      flexDirection: isMsg ? 'column' : 'row', 
                      justifyContent: 'space-between', 
                      alignItems: isMsg ? 'flex-start' : 'flex-start',
                      fontSize: 13, borderBottom: '1px solid var(--border)', paddingBottom: 6 
                    }}>
                      <span style={{ color: 'var(--text-muted)', fontWeight: 500, minWidth: 80, marginBottom: isMsg ? 4 : 0 }}>{k}</span>
                      <span style={{ 
                        color: 'var(--text-primary)', fontWeight: 600, textAlign: isMsg ? 'left' : 'right', 
                        maxWidth: isMsg ? '100%' : '65%', wordBreak: 'break-word', lineHeight: 1.4 
                      }} title={String(v)}>
                        {isMsg ? String(v) : (String(v).length > 50 ? String(v).slice(0, 48) + '…' : String(v))}
                      </span>
                    </div>
                  );
                })
              }
              </div>
            </div>
            );
          })()}
        </div>
      )}
    </div>
  );
}
