import React, { useEffect, useMemo, useRef, useState } from 'react';
import { UploadCloud, CheckCircle2, Server, Layers, Trash2, RefreshCw, AlertCircle, FileText, XCircle, Filter, ShieldOff } from 'lucide-react';
import axios from 'axios';

const BACKEND_URL = 'http://localhost:8081';
const PERSIST_KEY = 'lognexus.ingest.lastRun';

export default function Ingest() {
  const [files, setFiles] = useState([]);
  const [uploadedFiles, setUploadedFiles] = useState([]);
  const [uploading, setUploading] = useState(false);
  const [overallProgress, setOverallProgress] = useState(0);
  const [currentFileIndex, setCurrentFileIndex] = useState(-1);
  const [currentFileProgress, setCurrentFileProgress] = useState(0);
  const [dragOver, setDragOver] = useState(false);
  const [result, setResult] = useState(null);
  const [errorMsg, setErrorMsg] = useState('');
  const [fileStatuses, setFileStatuses] = useState({});
  const [trace, setTrace] = useState([]);
  const [streamState, setStreamState] = useState('idle');
  const [corrState, setCorrState] = useState({ phase: 'idle', eventCount: 0, lastEvent: null });

  const [excludedSources, setExcludedSources] = useState(new Set());
  const fileRef = useRef(null);
  const abortControllerRef = useRef(null);
  const sseRef = useRef(null);
  const corrPollRef = useRef(null);


  const SOURCE_TYPE_OPTIONS = [
    { id: 'AWS',       label: 'AWS CloudTrail',     desc: 'CloudTrail API activity and management events' },
    { id: 'O365',      label: 'O365 Audit',         desc: 'Office 365 Unified Audit Log events' },
    { id: 'PaloAlto',  label: 'Palo Alto',          desc: 'Palo Alto Networks firewall traffic/threat logs' },
    { id: 'syslog',    label: 'Syslog',             desc: 'RFC 5424 syslog messages (Linux, network devices)' },
    { id: 'WEB',       label: 'Webserver Access',   desc: 'Apache / Nginx / IIS access logs (Combined Log Format)' },
    { id: 'WINDOWS',   label: 'Windows Security',   desc: 'Windows Security Event Log (4624, 4625, 4688, etc.)' },
  ];

  const toggleExclude = (id) => {
    setExcludedSources(prev => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  };

  const bundleId = result?.bundleId || '';

  const correlationApi = useMemo(() => axios.create({ baseURL: '/api/correlation' }), []);
  const ingestionApi = useMemo(() => axios.create({ baseURL: BACKEND_URL }), []);

  const getFileIdentifier = (f) => `${f.name}-${f.size}-${f.lastModified}`;

  const appendTrace = (msg) => {
    const line = { ts: new Date().toISOString(), msg: String(msg ?? '') };
    setTrace(prev => [...prev.slice(-249), line]);
  };


  useEffect(() => {
    try {
      const raw = localStorage.getItem(PERSIST_KEY);
      if (!raw) return;
      const saved = JSON.parse(raw);
      if (!saved?.bundleId) return;

      setResult({ status: 'SUCCESS', bundleId: saved.bundleId });
      if (Array.isArray(saved.trace)) setTrace(saved.trace.slice(-250));
      if (saved.corrState && typeof saved.corrState === 'object') {
        setCorrState({
          phase: saved.corrState.phase || 'idle',
          eventCount: Number(saved.corrState.eventCount || 0),
          lastEvent: saved.corrState.lastEvent || null,
        });
      }
      if (saved.errorMsg) setErrorMsg(String(saved.errorMsg));
    } catch {
      // ignore corrupted saved state
    }
    // run only once on mount
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);


  useEffect(() => {
    try {
      if (!bundleId) return;
      const payload = {
        bundleId,
        trace: trace.slice(-250),
        corrState,
        errorMsg,
        savedAt: new Date().toISOString(),
      };
      localStorage.setItem(PERSIST_KEY, JSON.stringify(payload));
    } catch {
      // ignore storage errors
    }
  }, [bundleId, trace, corrState, errorMsg]);


  useEffect(() => {
    if (!bundleId) return;


    if (sseRef.current) {
      try { sseRef.current.close(); } catch {}
      sseRef.current = null;
    }
    if (corrPollRef.current) {
      clearInterval(corrPollRef.current);
      corrPollRef.current = null;
    }

    setTrace([]);
    setStreamState('connecting');
    setCorrState({ phase: 'waiting', eventCount: 0, lastEvent: null });
    appendTrace(`Connecting to ingestion trace for bundle ${bundleId}...`);

    const streamUrl = `${BACKEND_URL}/logs/stream/${bundleId}`;
    const es = new EventSource(streamUrl);
    sseRef.current = es;

    const noUpdateTimer = setTimeout(() => {
      appendTrace('Still waiting for ingestion updates... (if this persists, ensure the ingestion service is running and reachable)');
    }, 6000);

    es.onopen = () => {
      setStreamState('connected');
      appendTrace('Connected. Waiting for parsing and Kafka publish...');
    };

    es.onmessage = (e) => {
      clearTimeout(noUpdateTimer);
      appendTrace(e.data);
    };

    es.onerror = () => {
      setStreamState('disconnected');
      appendTrace('Trace stream disconnected. If ingestion is still running, refresh the page or re-open the bundle.');
      try { es.close(); } catch {}
    };


    corrPollRef.current = setInterval(async () => {
      try {
        const r = await correlationApi.get(`/bundles/${bundleId}/status`);
        const phase = r.data?.phase || 'WAITING';
        setCorrState({
          phase,
          eventCount: Number(r.data?.eventCount || 0),
          lastEvent: r.data?.lastEvent || null,
        });
        if (phase === 'PERSISTED') {
          appendTrace(`✅ Correlation persisted ${Number(r.data?.eventCount || 0)} events. Bundle is now visible across the app.`);
          clearInterval(corrPollRef.current);
          corrPollRef.current = null;
        }
      } catch {
      }
    }, 2000);

    return () => {
      clearTimeout(noUpdateTimer);
      if (corrPollRef.current) {
        clearInterval(corrPollRef.current);
        corrPollRef.current = null;
      }
      if (sseRef.current) {
        try { sseRef.current.close(); } catch {}
        sseRef.current = null;
      }
    };
  }, [bundleId, correlationApi]);

  const stopBundle = async () => {
    if (!bundleId) return;
    appendTrace('🛑 Sending cancel request...');
    try {
      await ingestionApi.post(`/logs/cancel/${bundleId}`);
      appendTrace('🛑 Cancel requested. You can start a new bundle anytime.');
      setCorrState(prev => ({ ...prev, phase: 'CANCELLED' }));
      if (corrPollRef.current) {
        clearInterval(corrPollRef.current);
        corrPollRef.current = null;
      }
      if (sseRef.current) {
        try { sseRef.current.close(); } catch {}
        sseRef.current = null;
      }
      setStreamState('disconnected');
    } catch (e) {
      appendTrace(`❌ Cancel failed: ${e?.message || 'unknown error'}`);
    }
  };

  const processIncomingFiles = (incomingFiles) => {
    setErrorMsg('');
    const newFiles = Array.from(incomingFiles);

    const existingIds = new Set(files.map(getFileIdentifier));
    const uploadedIds = new Set(uploadedFiles.map(getFileIdentifier));

    const uniqueFiles = newFiles.filter(f => {
      const id = getFileIdentifier(f);
      if (uploadedIds.has(id)) {
        console.warn(`File already uploaded in this session: ${f.name}`);
        return false;
      }
      if (existingIds.has(id)) {
        return false;
      }
      return true;
    });

    if (uniqueFiles.length < newFiles.length) {
      setErrorMsg('Some files were ignored because they are already staged or were previously uploaded.');
    }

    setFiles(prev => [...prev, ...uniqueFiles]);
  };

  const handleFileSelect = (e) => {
    if (e.target.files) {
      processIncomingFiles(e.target.files);
      e.target.value = '';
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setDragOver(false);
    if (e.dataTransfer.files) {
      processIncomingFiles(e.dataTransfer.files);
    }
  };

  const removeFile = (index) => {
    setFiles(prev => prev.filter((_, i) => i !== index));
  };

  const startNewBundle = () => {
    setFiles([]);
    setUploadedFiles([]);
    setResult(null);
    setTrace([]);
    setStreamState('idle');
    setCorrState({ phase: 'idle', eventCount: 0, lastEvent: null });
    setOverallProgress(0);
    setCurrentFileIndex(-1);
    setCurrentFileProgress(0);
    setErrorMsg('');
    setFileStatuses({});
    try { localStorage.removeItem(PERSIST_KEY); } catch {}
  };

  const cancelUpload = () => {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
      abortControllerRef.current = null;
    }
  };

  const handleSubmit = async () => {
    if (files.length === 0) return;
    setUploading(true);
    setOverallProgress(0);
    setCurrentFileIndex(0);
    setCurrentFileProgress(0);
    setResult(null);
    setTrace([]);
    setStreamState('idle');
    setCorrState({ phase: 'idle', eventCount: 0, lastEvent: null });
    setErrorMsg('');


    const totalSize = files.reduce((sum, f) => sum + f.size, 0);
    let uploadedSize = 0;


    const initialStatuses = {};
    files.forEach((f, i) => { initialStatuses[i] = 'pending'; });
    setFileStatuses(initialStatuses);


    const controller = new AbortController();
    abortControllerRef.current = controller;


    const formData = new FormData();
    files.forEach(file => {
      formData.append('files', file);
    });


    if (excludedSources.size > 0) {
      const exclusionList = [...excludedSources].join(',');
      formData.append('excludeSources', exclusionList);
      appendTrace(`🚫 Excluding source types: ${exclusionList}`);
    }

    try {

      const uploadingStatuses = {};
      files.forEach((_, i) => { uploadingStatuses[i] = 'uploading'; });
      setFileStatuses(uploadingStatuses);
      setCurrentFileIndex(0);

      const res = await axios.post(`${BACKEND_URL}/logs/upload`, formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
        signal: controller.signal,

        timeout: 300000,
        onUploadProgress: (progressEvent) => {
          const loaded = progressEvent.loaded || 0;
          const total = progressEvent.total || totalSize;


          let accumulated = 0;
          let activeIndex = 0;
          for (let i = 0; i < files.length; i++) {
            if (loaded >= accumulated + files[i].size) {
              accumulated += files[i].size;
              activeIndex = i + 1;
            } else {
              activeIndex = i;
              break;
            }
          }

          activeIndex = Math.min(activeIndex, files.length - 1);
          setCurrentFileIndex(activeIndex);


          const fileLoaded = Math.max(0, loaded - accumulated);
          const fileTotal = files[activeIndex]?.size || 1;
          setCurrentFileProgress(Math.min(100, Math.round((fileLoaded * 100) / fileTotal)));


          setFileStatuses(prev => {
            const next = { ...prev };
            for (let i = 0; i < files.length; i++) {
              if (i < activeIndex) next[i] = 'done';
              else if (i === activeIndex) next[i] = 'uploading';
              else next[i] = 'pending';
            }
            return next;
          });


          const percent = Math.min(100, Math.round((loaded * 100) / total));
          setOverallProgress(percent);
        },
      });


      const doneStatuses = {};
      files.forEach((_, i) => { doneStatuses[i] = 'done'; });
      setFileStatuses(doneStatuses);
      setOverallProgress(100);
      setCurrentFileProgress(100);

      setResult(res.data);

      setUploadedFiles(prev => [...prev, ...files]);
      setFiles([]);
    } catch (err) {
      if (axios.isCancel(err)) {
        setErrorMsg('Upload cancelled.');
        return;
      }
      console.error('Upload Error:', err);


      let errMsgString;
      if (err.code === 'ERR_NETWORK' || err.message === 'Network Error') {
        errMsgString = `Cannot connect to the Ingestion Service at ${BACKEND_URL}. Make sure the backend is running on port 8081.`;
      } else if (err.code === 'ECONNABORTED') {
        errMsgString = 'Upload timed out. The file may be too large or the server is unresponsive.';
      } else {
        const backendError = err.response?.data?.message || err.response?.data || err.message || 'Upload failed due to a network or server error.';
        errMsgString = typeof backendError === 'string' ? backendError : JSON.stringify(backendError);
      }


      setFileStatuses(prev => {
        const next = { ...prev };
        for (let i = 0; i < files.length; i++) {
          if (next[i] !== 'done') next[i] = 'error';
        }
        return next;
      });

      setResult({ status: 'ERROR', message: errMsgString });
      setErrorMsg(errMsgString);
    } finally {
      setUploading(false);
      abortControllerRef.current = null;
    }
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'done': return <CheckCircle2 size={14} color="var(--accent-green, #22c55e)" />;
      case 'uploading': return <RefreshCw size={14} color="var(--accent, #818cf8)" style={{ animation: 'spin 1s linear infinite' }} />;
      case 'error': return <AlertCircle size={14} color="var(--status-danger)" />;
      default: return <FileText size={14} color="var(--text-muted)" />;
    }
  };

  return (
    <div style={{ padding: '32px', height: '100%', display: 'flex', flexDirection: 'column' }}>



      <div style={{ marginBottom: '32px', display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <h1 style={{ fontSize: '28px', fontWeight: 700, marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '12px' }}>
            <Server color="var(--accent-purple)" size={28} />
            Ingestion Hub
          </h1>
          <p style={{ color: 'var(--text-muted)' }}>Upload raw security logs to cluster into a unified correlation bundle.</p>
        </div>
        {uploadedFiles.length > 0 && (
          <button
            onClick={startNewBundle}
            style={{ display: 'flex', alignItems: 'center', gap: '8px', background: 'var(--bg-surface)', border: '1px solid var(--border)', padding: '8px 16px', borderRadius: 'var(--radius-sm)', color: 'var(--text-primary)', cursor: 'pointer' }}>
            <RefreshCw size={16} /> New Bundle
          </button>
        )}
      </div>

      {errorMsg && (
        <div style={{ marginBottom: '16px', padding: '12px', background: 'var(--status-danger-bg)', color: 'var(--status-danger)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--status-danger-border)', fontSize: '13px', display: 'flex', alignItems: 'flex-start', gap: '8px' }}>
          <AlertCircle size={16} style={{ flexShrink: 0, marginTop: '1px' }} />
          <span>{errorMsg}</span>
        </div>
      )}


      <div
        onClick={() => !uploading && fileRef.current?.click()}
        onDragOver={e => { e.preventDefault(); setDragOver(true); }}
        onDragLeave={() => setDragOver(false)}
        onDrop={handleDrop}
        style={{
          border: `2px dashed ${dragOver ? 'var(--accent)' : 'var(--border)'}`,
          background: dragOver ? 'var(--accent-glow)' : 'var(--bg-card)',
          borderRadius: 'var(--radius-lg)',
          padding: '48px',
          textAlign: 'center',
          cursor: uploading ? 'not-allowed' : 'pointer',
          transition: 'all 0.2s',
          marginBottom: '24px',
          opacity: uploading ? 0.6 : 1,
        }}
      >
        <UploadCloud size={48} style={{ marginBottom: 16, color: 'var(--accent)', opacity: 0.8 }} />
        <h3 style={{ fontSize: '18px', fontWeight: 600, marginBottom: '8px' }}>Drag & drop log files here</h3>
        <p style={{ color: 'var(--text-muted)', fontSize: '14px' }}>Supports raw JSON arrays, CSV, or Syslog</p>
        <input
          ref={fileRef}
          type="file"
          multiple
          style={{ display: 'none' }}
          onChange={handleFileSelect}
        />
      </div>


      <div style={{
        background: 'var(--bg-card)', border: '1px solid var(--border)',
        borderRadius: 'var(--radius-md)', padding: '20px 24px', marginBottom: '24px'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <Filter size={16} color="var(--accent)" />
            <span style={{ fontWeight: 600, fontSize: 14 }}>Source Exclusion Filters</span>
            {excludedSources.size > 0 && (
              <span style={{
                background: 'var(--status-danger-bg)', color: 'var(--status-danger)',
                border: '1px solid var(--status-danger-border)', borderRadius: 20,
                padding: '1px 10px', fontSize: 11, fontWeight: 700
              }}>
                {excludedSources.size} excluded
              </span>
            )}
          </div>
          {excludedSources.size > 0 && (
            <button
              onClick={() => setExcludedSources(new Set())}
              style={{ background: 'none', border: 'none', color: 'var(--text-muted)', fontSize: 12, cursor: 'pointer' }}
            >
              Clear all
            </button>
          )}
        </div>
        <p style={{ color: 'var(--text-muted)', fontSize: 12, marginBottom: 14 }}>
          Toggle source types to exclude from ingestion. Excluded events are dropped at parse time — never sent to Kafka.
        </p>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
          {SOURCE_TYPE_OPTIONS.map(opt => {
            const isExcluded = excludedSources.has(opt.id);
            return (
              <button
                key={opt.id}
                onClick={() => toggleExclude(opt.id)}
                disabled={uploading}
                title={opt.desc}
                style={{
                  display: 'flex', alignItems: 'center', gap: 6,
                  padding: '6px 14px', borderRadius: 20, fontSize: 12, fontWeight: 600,
                  cursor: uploading ? 'not-allowed' : 'pointer', transition: 'all 0.18s',
                  background: isExcluded ? 'var(--status-danger-bg)' : 'var(--bg-surface)',
                  color:      isExcluded ? 'var(--status-danger)'    : 'var(--text-secondary)',
                  border:     isExcluded
                    ? '1px solid var(--status-danger-border)'
                    : '1px solid var(--border)',
                  opacity: uploading ? 0.5 : 1,
                }}
              >
                {isExcluded && <ShieldOff size={11} />}
                {opt.label}
              </button>
            );
          })}
        </div>
      </div>


      {files.length > 0 && (
        <div style={{ background: 'var(--bg-surface)', borderRadius: 'var(--radius-md)', padding: '24px', marginBottom: '24px', border: '1px solid var(--border)' }}>
          <h4 style={{ marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px', fontWeight: 600 }}>
            <Layers size={18} /> Staged for Upload ({files.length} file{files.length !== 1 ? 's' : ''})
          </h4>
          <ul style={{ listStyle: 'none', padding: 0, marginBottom: '20px', maxHeight: '200px', overflowY: 'auto' }}>
            {files.map((f, index) => (
              <li key={index} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '10px 0', borderBottom: '1px solid var(--border)', fontSize: '13px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  {uploading ? getStatusIcon(fileStatuses[index]) : <FileText size={14} color="var(--text-muted)" />}
                  <div style={{ display: 'flex', flexDirection: 'column' }}>
                    <span style={{ color: 'var(--text-primary)', fontWeight: 500 }}>{f.name}</span>
                    <span style={{ color: 'var(--text-muted)', fontSize: '12px' }}>{(f.size / 1024 / 1024).toFixed(2)} MB</span>
                  </div>
                </div>
                {!uploading && (
                  <button
                    onClick={(e) => { e.stopPropagation(); removeFile(index); }}
                    style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}>
                    <Trash2 size={16} />
                  </button>
                )}
              </li>
            ))}
          </ul>

          {uploading && (
            <div style={{ marginBottom: '16px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px', marginBottom: '4px', color: 'var(--text-secondary)' }}>
                <span>
                  Uploading{currentFileIndex >= 0 && files[currentFileIndex]
                    ? ` — ${files[currentFileIndex].name}`
                    : '...'}
                </span>
                <span>{overallProgress}%</span>
              </div>
              <div style={{ width: '100%', height: '6px', background: 'var(--bg-input)', borderRadius: '3px', overflow: 'hidden' }}>
                <div style={{ width: `${overallProgress}%`, height: '100%', background: 'linear-gradient(90deg, var(--accent-purple), var(--accent))', transition: 'width 0.3s ease' }} />
              </div>
              <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>
                {files.filter((_, i) => fileStatuses[i] === 'done').length} / {files.length} files transferred
              </div>
            </div>
          )}

          <div style={{ display: 'flex', gap: '10px' }}>
            <button
              onClick={handleSubmit}
              disabled={uploading}
              style={{
                flex: 1, padding: '12px', background: 'linear-gradient(135deg, var(--accent-purple), var(--accent))',
                border: 'none', borderRadius: 'var(--radius-sm)', color: '#fff', fontWeight: 600, fontSize: '14px',
                cursor: uploading ? 'not-allowed' : 'pointer', opacity: uploading ? 0.7 : 1
              }}
            >
              {uploading ? 'Processing...' : 'Commence Ingestion Sequence'}
            </button>
            {uploading && (
              <button
                onClick={cancelUpload}
                style={{
                  padding: '12px 20px', background: 'var(--status-danger-bg)',
                  border: '1px solid var(--status-danger-border)', borderRadius: 'var(--radius-sm)',
                  color: 'var(--status-danger)', fontWeight: 600, fontSize: '14px',
                  cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '6px'
                }}
              >
                <XCircle size={16} /> Cancel
              </button>
            )}
          </div>
        </div>
      )}


      {result && result.status === 'SUCCESS' && (
        <div style={{ background: 'rgba(34, 197, 94, 0.1)', border: '1px solid var(--border-active)', padding: '24px', borderRadius: 'var(--radius-md)', display: 'flex', flexDirection: 'column', gap: '12px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', color: 'var(--text-primary)', fontWeight: 600, fontSize: '16px' }}>
            <CheckCircle2 color="var(--accent-green)" size={24} />
            Ingestion Dispatched Successfully
          </div>
          <div style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
            The files have been transferred to the ingestion engines. Correlation will automatically trigger once the files are parsed into the Kafka stream.
          </div>
          {result.bundleId && (
            <div style={{ padding: '12px', background: 'var(--bg-input)', borderRadius: 'var(--radius-sm)', fontFamily: 'monospace', color: 'var(--accent)', marginTop: '8px' }}>
              Bundle ID: {result.bundleId}
            </div>
          )}


          {result.bundleId && (
            <div style={{ marginTop: '14px', background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius-md)', padding: '16px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
                <div style={{ fontWeight: 700, fontSize: 13 }}>Live processing trace</div>
                <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                  Trace: {streamState} • Correlation: {corrState.phase}{corrState.eventCount ? ` (${corrState.eventCount} events)` : ''}
                </div>
              </div>
              <div style={{ display: 'flex', gap: 10, marginBottom: 10 }}>
                <button
                  onClick={stopBundle}
                  disabled={corrState.phase === 'PERSISTED' || corrState.phase === 'CANCELLED'}
                  style={{
                    padding: '8px 12px',
                    borderRadius: 'var(--radius-sm)',
                    border: '1px solid var(--status-danger-border)',
                    background: 'var(--status-danger-bg)',
                    color: 'var(--status-danger)',
                    fontWeight: 700,
                    cursor: (corrState.phase === 'PERSISTED' || corrState.phase === 'CANCELLED') ? 'not-allowed' : 'pointer'
                  }}
                  title="Cancel ingestion for this bundle"
                >
                  Cancel bundle
                </button>
                <div style={{ fontSize: 12, color: 'var(--text-muted)', alignSelf: 'center' }}>
                  Use this if you uploaded the wrong files or need to stop processing.
                </div>
              </div>
              <div style={{
                fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace',
                fontSize: 12,
                color: 'var(--text-secondary)',
                background: 'var(--bg-input)',
                border: '1px solid var(--border)',
                borderRadius: 'var(--radius-sm)',
                padding: 12,
                maxHeight: 220,
                overflowY: 'auto',
                whiteSpace: 'pre-wrap',
              }}>
                {trace.length === 0 ? 'Waiting for ingestion trace...' : trace.map((t, i) => `${t.ts}  ${t.msg}`).join('\n')}
              </div>
              {corrState.phase !== 'PERSISTED' && (
                <div style={{ marginTop: 10, fontSize: 12, color: 'var(--text-muted)' }}>
                  If this stays on “WAITING” for too long, the correlation service may be down, Kafka may be unreachable, or the uploaded file format wasn’t parsed.
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
