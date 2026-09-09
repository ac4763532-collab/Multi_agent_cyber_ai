import { useState, useCallback } from 'react';

export interface AppState {
  activeDomain: string;
  isSidebarOpen: boolean;
  selectedIncidentId: string | null;
}

export function useAppStore() {
  const [state, setState] = useState<AppState>({
    activeDomain: 'ALL',
    isSidebarOpen: true,
    selectedIncidentId: null,
  });

  const setActiveDomain = useCallback((domain: string) => {
    setState((prev) => ({ ...prev, activeDomain: domain }));
  }, []);

  const toggleSidebar = useCallback(() => {
    setState((prev) => ({ ...prev, isSidebarOpen: !prev.isSidebarOpen }));
  }, []);

  const setSelectedIncidentId = useCallback((id: string | null) => {
    setState((prev) => ({ ...prev, selectedIncidentId: id }));
  }, []);

  return {
    ...state,
    setActiveDomain,
    toggleSidebar,
    setSelectedIncidentId,
  };
}
