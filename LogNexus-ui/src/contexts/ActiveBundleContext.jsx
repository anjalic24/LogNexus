import { createContext, useContext, useEffect, useMemo, useState } from 'react';

const ActiveBundleContext = createContext(null);
const STORAGE_KEY = 'lognexus.activeBundleId';

export function ActiveBundleProvider({ children }) {
  const initial = useMemo(() => {
    try {
      return localStorage.getItem(STORAGE_KEY) || '';
    } catch {
      return '';
    }
  }, []);

  const [activeBundleId, setActiveBundleId] = useState(initial);

  useEffect(() => {
    try {
      if (activeBundleId) localStorage.setItem(STORAGE_KEY, activeBundleId);
      else localStorage.removeItem(STORAGE_KEY);
    } catch {
      // ignore
    }
  }, [activeBundleId]);

  return (
    <ActiveBundleContext.Provider value={{ activeBundleId, setActiveBundleId }}>
      {children}
    </ActiveBundleContext.Provider>
  );
}

export function useActiveBundle() {
  const ctx = useContext(ActiveBundleContext);
  if (!ctx) throw new Error('useActiveBundle must be used within ActiveBundleProvider');
  return ctx;
}

