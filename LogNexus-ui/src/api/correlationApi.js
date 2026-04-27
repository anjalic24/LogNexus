import axios from 'axios';

const api = axios.create({
  baseURL: '/api/correlation',
  timeout: 120000,
  headers: { 'Content-Type': 'application/json' }
});

const heavyApi = axios.create({
  baseURL: '/api/correlation',
  timeout: 180000,
  headers: { 'Content-Type': 'application/json' }
});

export const getStatus          = ()           => api.get('/status');
export const listBundles        = ()           => api.get('/bundles');
export const getBundleStatus    = (bundleId)   => api.get(`/bundles/${bundleId}/status`);
export const manualIngest       = (events)     => api.post('/manual-ingest', events);
export const filteredIngest     = (payload)    => api.post('/filtered-ingest', payload);
export const deleteAllBundles   = ()           => api.delete('/bundles');
export const deleteBundle       = (bundleId)   => api.delete(`/bundles/${bundleId}`);

export const getEvents = (bundleId, page = 0, size = 200) =>
  api.get(`/events/${bundleId}`, { params: { page, size } });

export const getAttackSessions  = (bundleId)   => heavyApi.get(`/attack-sessions/${bundleId}`);
export const getRcaReport       = (bundleId)   => heavyApi.get(`/rca/${bundleId}`);
export const getGraphData       = (bundleId)   => heavyApi.get(`/graph/${bundleId}`);

export default api;
