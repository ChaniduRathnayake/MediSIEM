// Chrome-free, full-screen SOC wallboard for an actual monitor in the room —
// no sidebar, nothing to click, composed from existing admin-console data
// hooks/components. Always dark regardless of the app theme toggle, scoped
// via a `dark` class wrapper rather than ThemeContext so it can't affect the
// admin's own light/dark preference elsewhere.
import React, { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { Shield, Wifi, WifiOff, ArrowLeft, AlertTriangle, Server, TrendingUp, Users } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { useLiveAlerts } from '../../hooks/useLiveAlerts';
import { usePresenceSummary } from './PresenceWidget';
import { WazuhProvider, useWazuhContext } from './WazuhContext';
import { normalizeAgentStatus } from './wazuhApi';
import StatCard from '../../components/StatCard';
import ChartCard from '../../components/charts/ChartCard';
import AlertsTimelineChart from '../../components/charts/AlertsTimelineChart';
import SeverityDonutChart from '../../components/charts/SeverityDonutChart';
import TopBarChart from '../../components/charts/TopBarChart';
import SoundToggle from '../../components/SoundToggle';
import { casToSeverity, bucketAlertsByHour, latestTimestamp, SEVERITY_ORDER, SEVERITY_COLORS } from '../../utils/chartData';
import { LifeCriticalBadge, MitreBadge, isLifeCriticalDevice } from '../../components/AlertBadges';

const SEVERITY_ROW_CLASS: Record<string, string> = {
  CRITICAL: 'border-red-500/30 bg-red-500/5',
  HIGH: 'border-orange-500/20 bg-orange-500/5',
  MEDIUM: 'border-amber-500/20 bg-amber-500/5',
  LOW: 'border-blue-500/20 bg-blue-500/5',
};

const WallboardContent: React.FC = () => {
  const { user, token } = useAuth();
  const { alerts: liveAlerts, connected: alertsConnected, severityTotals } = useLiveAlerts(token);
  const { summary: presenceSummary } = usePresenceSummary(token);
  const { agents, connected: wazuhConnected } = useWazuhContext();
  const [now, setNow] = useState(() => new Date());

  useEffect(() => {
    const timer = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

  const criticalCount = severityTotals.CRITICAL;
  const alertsAnchor = latestTimestamp(liveAlerts, (a) => a.timestamp);
  const last24h = liveAlerts.filter((a) => alertsAnchor - new Date(a.timestamp).getTime() <= 24 * 60 * 60 * 1000).length;
  const activeDevices = agents.filter((a) => normalizeAgentStatus(a.status) === 'active').length;

  const timeline = useMemo(
    () => bucketAlertsByHour(liveAlerts, (a) => a.timestamp, (a) => casToSeverity(a.CAS), 24),
    [liveAlerts]
  );
  const severityDist = useMemo(
    () => SEVERITY_ORDER.map((name) => ({ name, value: severityTotals[name], color: SEVERITY_COLORS[name] })),
    [severityTotals]
  );

  // Raw CAS histogram (width-2 buckets) — a finer-grained view of the same
  // underlying score than the 4-bucket Severity mix donut above, since a
  // sea of alerts sitting at CAS 7.9 vs. spread evenly across "HIGH" reads
  // very differently on a wallboard even though both count as one severity bucket.
  const casDistribution = useMemo(() => {
    const buckets = [
      { label: '0–2', min: 0, max: 2 },
      { label: '2–4', min: 2, max: 4 },
      { label: '4–6', min: 4, max: 6 },
      { label: '6–8', min: 6, max: 8 },
      { label: '8–10', min: 8, max: 10.01 },
    ];
    return buckets.map((b) => ({ label: b.label, value: liveAlerts.filter((a) => a.CAS >= b.min && a.CAS < b.max).length }));
  }, [liveAlerts]);
  const casBucketColor = (label: string) => {
    if (label === '8–10') return '#ef4444';
    if (label === '6–8') return '#f97316';
    if (label === '4–6') return '#f59e0b';
    return '#3b82f6';
  };

  const recentCritical = useMemo(
    () => liveAlerts.filter((a) => casToSeverity(a.CAS) === 'CRITICAL' || casToSeverity(a.CAS) === 'HIGH').slice(0, 25),
    [liveAlerts]
  );

  return (
    <div className="dark h-screen w-screen overflow-hidden bg-slate-950 text-white flex flex-col">
      {/* Header */}
      <header className="flex items-center justify-between px-6 py-4 border-b border-slate-800 flex-shrink-0">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 bg-gradient-to-br from-cyan-500 to-blue-600 rounded-lg flex items-center justify-center">
            <Shield className="w-5 h-5 text-white" strokeWidth={2.5} />
          </div>
          <div>
            <h1 className="text-base font-bold">
              Medi<span className="text-cyan-400">SIEM</span> · SOC Wallboard
            </h1>
            <p className="text-xs text-slate-500">R26-CS-008 · Live security operations feed</p>
          </div>
        </div>
        <div className="flex items-center gap-5">
          <div className="flex items-center gap-2 text-xs font-medium">
            {alertsConnected ? (
              <><Wifi className="w-3.5 h-3.5 text-emerald-400" /> <span className="text-emerald-400">Live</span></>
            ) : (
              <><WifiOff className="w-3.5 h-3.5 text-red-400" /> <span className="text-red-400">Reconnecting…</span></>
            )}
          </div>
          <SoundToggle className="!text-slate-400 hover:!text-white hover:!bg-slate-800" />
          <div className="text-right">
            <p className="text-lg font-mono font-bold tabular-nums leading-none">{now.toLocaleTimeString()}</p>
            <p className="text-[11px] text-slate-500 mt-0.5">{now.toLocaleDateString(undefined, { weekday: 'long', month: 'long', day: 'numeric' })}</p>
          </div>
          <Link
            to={user?.role === 'admin' ? '/admin' : '/dashboard'}
            className="opacity-0 hover:opacity-100 focus:opacity-100 transition-opacity flex items-center gap-1.5 text-xs text-slate-400 hover:text-white px-2.5 py-1.5 rounded-lg hover:bg-slate-800"
          >
            <ArrowLeft className="w-3.5 h-3.5" /> Back to dashboard
          </Link>
        </div>
      </header>

      {/* Body */}
      <div className="flex-1 min-h-0 grid grid-cols-4 gap-4 p-5">
        {/* Left: KPIs + charts */}
        <div className="col-span-3 flex flex-col gap-4 min-h-0">
          <div className="grid grid-cols-4 gap-4 flex-shrink-0">
            <StatCard icon={<AlertTriangle className="w-5 h-5" />} label="Critical Alerts" value={String(criticalCount)} sub="CAS ≥ 8 · all-time" color="red" />
            <StatCard icon={<TrendingUp className="w-5 h-5" />} label="Alerts (24h)" value={String(last24h)} sub="In current buffer" color="emerald" />
            <StatCard
              icon={<Server className="w-5 h-5" />}
              label="Devices Online"
              value={wazuhConnected ? String(activeDevices) : '—'}
              sub={wazuhConnected ? `of ${agents.length} monitored` : 'Wazuh not connected'}
              color="cyan"
            />
            <StatCard
              icon={<Users className="w-5 h-5" />}
              label="Analysts Online"
              value={presenceSummary ? String(presenceSummary.admins.online + presenceSummary.analysts.online) : '—'}
              sub="Currently signed in"
              color="violet"
            />
          </div>

          <div className="grid grid-cols-4 gap-4 flex-1 min-h-0">
            <ChartCard title="Alert volume (24h)" subtitle="Stacked by severity" height={380} empty={liveAlerts.length === 0} className="col-span-2">
              <AlertsTimelineChart data={timeline} />
            </ChartCard>
            <ChartCard title="Severity mix" subtitle="All-time" height={380} empty={liveAlerts.length === 0}>
              <SeverityDonutChart data={severityDist} />
            </ChartCard>
            <ChartCard title="CAS distribution" subtitle="Current buffer" height={380} empty={liveAlerts.length === 0}>
              <TopBarChart data={casDistribution} colorOf={(entry) => casBucketColor(entry.label)} />
            </ChartCard>
          </div>
        </div>

        {/* Right: persistent critical/high feed */}
        <div className="col-span-1 min-h-0 flex flex-col rounded-xl bg-slate-900 border border-slate-800 overflow-hidden">
          <div className="px-4 py-3 border-b border-slate-800 flex-shrink-0">
            <h2 className="text-sm font-semibold flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-red-400" />
              Priority feed
            </h2>
            <p className="text-[11px] text-slate-500 mt-0.5">Critical &amp; high severity, newest first</p>
          </div>
          <div className="flex-1 overflow-y-auto p-2.5 space-y-1.5">
            {recentCritical.length === 0 && (
              <p className="text-xs text-slate-500 text-center py-10">No critical or high severity alerts in the current buffer.</p>
            )}
            {recentCritical.map((a) => {
              const sev = casToSeverity(a.CAS);
              return (
                <div key={a.id} className={`rounded-lg border px-3 py-2 ${SEVERITY_ROW_CLASS[sev]}`}>
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-[10px] font-bold uppercase tracking-wide text-slate-300">{sev}</span>
                    <span className="text-[10px] text-slate-500 font-mono">CAS {a.CAS.toFixed(1)}</span>
                  </div>
                  <p className="text-xs font-medium text-white mt-1 truncate">
                    {a.label !== 'Unclassified' ? a.label : a.ruleDescription}
                  </p>
                  <div className="flex items-center justify-between mt-1">
                    <span className="text-[11px] text-slate-400 truncate">{a.agent}</span>
                    <span className="text-[10px] text-slate-500 flex-shrink-0 ml-2">{new Date(a.timestamp).toLocaleTimeString()}</span>
                  </div>
                  {(isLifeCriticalDevice(a) || a.mitre?.id?.length) && (
                    <div className="flex items-center gap-1.5 flex-wrap mt-1.5">
                      {isLifeCriticalDevice(a) && <LifeCriticalBadge />}
                      <MitreBadge mitre={a.mitre} />
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      </div>

      <footer className="flex-shrink-0 px-6 py-2.5 border-t border-slate-800 text-center text-[11px] text-slate-600">
        MediSIEM SOC Wallboard · {user?.name} · Auto-updating via live socket feed
      </footer>
    </div>
  );
};

const Wallboard: React.FC = () => (
  <WazuhProvider>
    <WallboardContent />
  </WazuhProvider>
);

export default Wallboard;
