export const getSeverityClass = (label) => {
  if (!label) return 'badge-info';
  switch (label.toUpperCase()) {
    case 'CRITICAL': return 'badge-critical';
    case 'HIGH': return 'badge-high';
    case 'MEDIUM': return 'badge-medium';
    case 'LOW': return 'badge-low';
    default: return 'badge-info';
  }
};

export const getSeverityColor = (severity) => {
  const root = document?.documentElement;
  const style = root ? getComputedStyle(root) : null;
  const fallback = (hex) => hex;
  if (!style) {
    if (severity >= 9) return fallback('#ff3366');
    if (severity >= 7) return fallback('#ff6b35');
    if (severity >= 4) return fallback('#ffc107');
    return fallback('#22c55e');
  }
  if (severity >= 9) return style.getPropertyValue('--sev-critical').trim() || fallback('#ff3366');
  if (severity >= 7) return style.getPropertyValue('--sev-high').trim() || fallback('#ff6b35');
  if (severity >= 4) return style.getPropertyValue('--sev-medium').trim() || fallback('#ffc107');
  return style.getPropertyValue('--sev-low').trim() || fallback('#22c55e');
};

export const getNodeColor = (type) => {
  const root = document?.documentElement;
  const style = root ? getComputedStyle(root) : null;
  const getVar = (v, fallback) => (style?.getPropertyValue(v)?.trim() || fallback);
  switch (type) {
    case 'Event': return getVar('--node-event', '#38bdf8');
    case 'User': return getVar('--node-user', '#a855f7');
    case 'IP': return getVar('--node-ip', '#f97316');
    case 'Host': return getVar('--node-host', '#22c55e');
    case 'IOC': return getVar('--node-ioc', '#ef4444');
    default: return getVar('--text-muted', '#64748b');
  }
};

export const formatTimestamp = (ts) => {
  if (!ts) return '—';
  try {
    return new Date(ts).toLocaleString();
  } catch {
    return ts;
  }
};

export const truncate = (str, len = 40) => {
  if (!str) return '—';
  return str.length > len ? str.slice(0, len) + '...' : str;
};

export const KILL_CHAIN_ORDER = [
  'RECONNAISSANCE', 'WEAPONIZATION', 'DELIVERY',
  'EXPLOITATION', 'INSTALLATION', 'COMMAND_AND_CONTROL',
  'LATERAL_MOVEMENT', 'ACTIONS_ON_OBJECTIVES'
];
