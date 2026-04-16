import axios from 'axios';

const api = axios.create({
  baseURL: '/api/correlation',
  timeout: 30000,
  headers: { 'Content-Type': 'application/json' }
});

export const getStatus = () => api.get('/status');
export const listBundles = () => api.get('/bundles');
export const manualIngest = (events) => api.post('/manual-ingest', events);
export const filteredIngest = (payload) => api.post('/filtered-ingest', payload);
export const getAttackSessions = (bundleId) => api.get(`/attack-sessions/${bundleId}`);
export const getGraphData = (bundleId) => api.get(`/graph/${bundleId}`);
export const getRcaReport = (bundleId) => api.get(`/rca/${bundleId}`);
export const deleteAllBundles = () => api.delete('/bundles');
export const deleteBundle = (bundleId) => api.delete(`/bundles/${bundleId}`);

export default api;
