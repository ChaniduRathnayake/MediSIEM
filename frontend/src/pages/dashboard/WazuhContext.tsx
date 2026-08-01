// Shares one live useWazuh() connection across the Wazuh SIEM tab and the
// Devices tab, so both read the same agents/status and the same 30s poll —
// instead of each tab reconnecting from scratch whenever it mounts.
import React, { createContext, useContext } from 'react';
import { useWazuh, UseWazuhReturn } from './useWazuh';

const WazuhContext = createContext<UseWazuhReturn | undefined>(undefined);

export const WazuhProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const wazuh = useWazuh();
  return <WazuhContext.Provider value={wazuh}>{children}</WazuhContext.Provider>;
};

export const useWazuhContext = (): UseWazuhReturn => {
  const ctx = useContext(WazuhContext);
  if (!ctx) throw new Error('useWazuhContext must be used inside <WazuhProvider>');
  return ctx;
};
