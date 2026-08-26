// Playbooks tab — hosts the ported life-critical-orchestration SOC console
// (see soc-console/SocConsole.tsx) verbatim, wired to MediSIEM's own
// authenticated proxy instead of hitting the engine/sim ports directly.
import React from 'react';
import SocConsole from './soc-console/SocConsole';

const PlaybooksPanel: React.FC<{ token: string | null }> = ({ token }) => {
  if (!token) return null;
  return (
    <div className="p-5">
      <SocConsole token={token} />
    </div>
  );
};

export default PlaybooksPanel;
