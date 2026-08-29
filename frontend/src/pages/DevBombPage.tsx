// Bare, unauthenticated dev utility — one click wipes the entire alert backlog (live
// buffer + AlertLog/Assignment/Closure/Snooze/Note) AND the Playbooks backlog (SoarAction
// mirror + the life-critical-orchestration engine's audit log/recent-alerts cache + the
// Shuffle sim's action log) so a demo can restart from a fully empty dashboard. Mirrors
// backend/routes/dev.js, which hard-disables itself outside dev.
import React, { useState } from 'react';
import { Skull } from 'lucide-react';
import { BASE_URL } from '../services/api';

type Status = { kind: 'idle' } | { kind: 'working' } | { kind: 'done'; message: string } | { kind: 'error'; message: string };

interface ServiceResult {
  ok: boolean;
  error?: string;
}

const DevBombPage: React.FC = () => {
  const [status, setStatus] = useState<Status>({ kind: 'idle' });

  const handleDelete = async () => {
    if (!window.confirm('This permanently deletes the entire alert backlog and playbook history. Continue?')) return;
    setStatus({ kind: 'working' });
    try {
      const [alertsRes, playbooksRes] = await Promise.all([
        fetch(`${BASE_URL}/dev/wipe-alerts`, { method: 'POST' }),
        fetch(`${BASE_URL}/dev/wipe-playbooks`, { method: 'POST' }),
      ]);
      const [alertsJson, playbooksJson] = await Promise.all([
        alertsRes.json().catch(() => ({})),
        playbooksRes.json().catch(() => ({})),
      ]);
      if (!alertsRes.ok) throw new Error(alertsJson.error || `Alerts wipe failed (HTTP ${alertsRes.status}).`);
      if (!playbooksRes.ok) throw new Error(playbooksJson.error || `Playbooks wipe failed (HTTP ${playbooksRes.status}).`);

      // The engine/Shuffle sim are separate optional Python processes — the route
      // reports each one's reachability rather than failing the whole request.
      const engine: ServiceResult | undefined = playbooksJson.engine;
      const shuffleSim: ServiceResult | undefined = playbooksJson.shuffleSim;
      const unreachable = [
        engine && !engine.ok ? `engine (${engine.error})` : null,
        shuffleSim && !shuffleSim.ok ? `Shuffle sim (${shuffleSim.error})` : null,
      ].filter((v): v is string => Boolean(v));

      setStatus({
        kind: 'done',
        message: unreachable.length
          ? `Alerts and playbook records wiped. Unreachable, so unaffected: ${unreachable.join(', ')}.`
          : 'Alerts and playbook backlog wiped.',
      });
    } catch (err) {
      setStatus({ kind: 'error', message: err instanceof Error ? err.message : 'Failed to wipe backlog.' });
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 flex flex-col items-center justify-center gap-6 px-4">
      <div className="flex items-center gap-2 text-slate-500">
        <Skull className="w-5 h-5" />
        <span className="text-xs uppercase tracking-widest">Dev utility — /devbomb</span>
      </div>

      <button
        onClick={handleDelete}
        disabled={status.kind === 'working'}
        className="px-10 py-6 rounded-2xl bg-red-600 hover:bg-red-500 active:bg-red-700 disabled:opacity-60 disabled:cursor-not-allowed text-white text-2xl font-bold uppercase tracking-wide shadow-2xl shadow-red-900/40 border-2 border-red-400/30 transition-colors"
      >
        {status.kind === 'working' ? 'Deleting…' : 'Delete'}
      </button>

      <p className="text-slate-500 text-sm max-w-md text-center">
        Wipes the live alert queue, every stored alert record (log, assignments, closures, snoozes, notes), and the Playbooks backlog (SOAR history, engine audit log, Shuffle sim actions) so the dashboard comes back empty.
      </p>

      {status.kind === 'done' && (
        <p className="text-emerald-400 text-sm font-medium">{status.message}</p>
      )}
      {status.kind === 'error' && (
        <p className="text-red-400 text-sm font-medium">{status.message}</p>
      )}
    </div>
  );
};

export default DevBombPage;
