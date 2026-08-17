import React, { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Shield,
  FileText,
  Bell,
  ChevronRight,
  ChevronDown,
  User,
  CheckCircle2,
  AlertCircle,
  AlertTriangle,
  Info,
  X,
  Globe,
  Menu,
  Server,
  Bug,
  Radio,
  Activity,
  ShieldCheck,
  ShieldAlert,
  ClipboardCheck,
  Tv,
  Inbox,
  Database,
  Wrench,
  TrendingUp,
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { useTheme } from '../../context/ThemeContext';
import AccountMenu from '../../components/AccountMenu';
import ThemeToggle from '../../components/ThemeToggle';
import SoundToggle from '../../components/SoundToggle';
import BrowserNotifToggle from '../../components/BrowserNotifToggle';
import NotificationCenterBell from '../../components/NotificationCenterBell';
import CommandPalette from '../../components/CommandPalette';
import type { CommandPaletteItem } from '../../components/CommandPalette';
import StatCard from '../../components/StatCard';
import SeverityBadge from '../../components/SeverityBadge';
import ChartCard from '../../components/charts/ChartCard';
import AlertsTimelineChart from '../../components/charts/AlertsTimelineChart';
import SeverityDonutChart from '../../components/charts/SeverityDonutChart';
import { WazuhProvider } from './WazuhContext';
import DevicesReadOnlyPanel from './DevicesReadOnlyPanel';
import MedicalDeviceInventoryPanel from './MedicalDeviceInventoryPanel';
import VulnerabilitiesPanel from './VulnerabilitiesPanel';
import AlertsBrowser from './AlertsBrowser';
import AlertsPanel from './AlertsPanel';
import MyAlertsPanel from './MyAlertsPanel';
import CompliancePanel from './CompliancePanel';
import type { FrameworkTab } from './CompliancePanel';
import AuditLogPanel from './AuditLogPanel';
import PresenceWidget, { usePresenceSummary } from './PresenceWidget';
import MyStatsWidget from './MyStatsWidget';
import ReportsPanel from './ReportsPanel';
import { apiGetTrendingDevices } from '../../services/reportsApi';
import type { TrendingDevice } from '../../services/reportsApi';
import { useDeviceMeta } from './useDeviceMeta';
import { useLiveAlerts } from '../../hooks/useLiveAlerts';
import { casToSeverity, severityCounts, bucketAlertsByHour, SEVERITY_ORDER, SEVERITY_COLORS } from '../../utils/chartData';
import type { Severity } from '../../utils/chartData';

// ─── Types ─────────────────────────────────────────────────────────────────────
type Tab = 'overview' | 'alerts' | 'my-alerts' | 'reports' | 'devices' | 'vulnerabilities' | 'live-alerts' | 'audit-log' | 'hipaa' | 'gdpr' | 'cis';

interface Notification {
  id: string;
  message: string;
  type: 'info' | 'warning' | 'success';
  time: string;
}

// ─── Helpers ───────────────────────────────────────────────────────────────────
const sevDot: Record<Severity, string> = {
  CRITICAL: 'bg-red-500',
  HIGH: 'bg-orange-500',
  MEDIUM: 'bg-amber-500',
  LOW: 'bg-blue-500',
};

// Quiet climbers within the last hour that haven't crossed CRITICAL yet — see
// TREND_WINDOW_MS in backend/routes/reports.js. Data-only, no AI involved.
const TrendingDevicesCard: React.FC<{ token: string | null }> = ({ token }) => {
  const [devices, setDevices] = useState<TrendingDevice[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!token) { setLoading(false); return; }
    apiGetTrendingDevices(token)
      .then((data) => setDevices(data.devices))
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [token]);

  if (!loading && devices.length === 0) return null;

  return (
    <div className="p-5 rounded-xl bg-white dark:bg-slate-900/80 border border-slate-200 dark:border-slate-800">
      <div className="flex items-center gap-2 mb-3">
        <TrendingUp className="w-4 h-4 text-amber-500 dark:text-amber-400" />
        <h2 className="text-base font-semibold text-slate-900 dark:text-white">Trending Devices</h2>
        <span className="text-xs text-slate-400 dark:text-slate-500">rising CAS in the last hour, not yet critical</span>
      </div>
      {loading ? (
        <p className="text-sm text-slate-400 dark:text-slate-500 text-center py-4">Loading…</p>
      ) : (
        <div className="space-y-2">
          {devices.slice(0, 5).map((d) => (
            <div key={d.agent} className="flex items-center gap-3 px-3 py-2 rounded-lg bg-amber-500/5 border border-amber-500/20">
              <div className="flex-1 min-w-0">
                <p className="text-sm text-slate-900 dark:text-white font-medium truncate">{d.agent}</p>
                <p className="text-xs text-slate-500 dark:text-slate-400">{d.department ?? 'Unknown dept'} · {d.alertCount} alerts</p>
              </div>
              <span className="text-xs font-mono text-slate-500 dark:text-slate-400 flex-shrink-0">{d.earlierAvgCas.toFixed(1)} → {d.recentAvgCas.toFixed(1)}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

// ─── UserDashboard ─────────────────────────────────────────────────────────────
const UserDashboard: React.FC = () => {
  const { user, token, logout } = useAuth();
  const { toggleTheme } = useTheme();
  const navigate = useNavigate();
  // Shared by every non-admin role — AdminRoute only special-cases role === 'admin'.
  const role = user?.role ?? 'user';
  const isBiomed = role === 'biomed';
  const isAuditor = role === 'auditor';
  const roleLabel = isBiomed ? 'Biomedical Engineer' : isAuditor ? 'Auditor' : 'SOC Analyst';
  const [activeTab, setActiveTab] = useState<Tab>('overview');
  const [dismissedIds, setDismissedIds] = useState<Set<string>>(new Set());
  const [showNotifications, setShowNotifications] = useState(false);
  const [showAccountMenu, setShowAccountMenu] = useState(false);
  const [accountMenuView, setAccountMenuView] = useState<'menu' | 'mfa'>('menu');
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [complianceOpen, setComplianceOpen] = useState(false);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const { summary: presenceSummary, loading: presenceLoading, error: presenceError } = usePresenceSummary(token);
  // Only rendered for 'biomed' — called unconditionally since hooks can't be conditional.
  const { groups: deviceGroups, createGroup } = useDeviceMeta(token);
  const {
    alerts: liveAlerts,
    connected: alertsConnected,
    loading: alertsLoading,
    error: alertsError,
    totalCount: alertsTotalCount,
    severityTotals: alertsSeverityTotals,
  } = useLiveAlerts(token, user?.id);

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  // Global — works from any tab, unlike useKeyboardShortcuts (scoped to
  // whichever panel calls it, e.g. AlertsPanel's j/k/Enter/x).
  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setPaletteOpen((v) => !v);
      }
    };
    document.addEventListener('keydown', onKeyDown);
    return () => document.removeEventListener('keydown', onKeyDown);
  }, []);

  const notifications: Notification[] = useMemo(
    () =>
      liveAlerts
        .filter((a) => a.action === 'Immediate' && !dismissedIds.has(a.id))
        .slice(0, 5)
        .map((a) => ({
          id: a.id,
          message: `${a.label !== 'Unclassified' ? a.label : a.ruleDescription} — ${a.agent}`,
          type: 'warning' as const,
          time: new Date(a.timestamp).toLocaleTimeString(),
        })),
    [liveAlerts, dismissedIds]
  );
  const dismissNotification = (id: string) => setDismissedIds((prev) => new Set(prev).add(id));

  const openCount = liveAlerts.filter((a) => a.action === 'Immediate').length;
  const myOpenCount = liveAlerts.filter((a) => a.assignedTo?.id === user?.id && !a.closure).length;
  const criticalCount = alertsSeverityTotals?.CRITICAL ?? liveAlerts.filter((a) => casToSeverity(a.CAS) === 'CRITICAL').length;
  const investigatingCount = liveAlerts.filter((a) => a.action === 'Investigate').length;
  const monitorCount = liveAlerts.filter((a) => a.action === 'Monitor').length;

  const timeline = useMemo(
    () => bucketAlertsByHour(liveAlerts, (a) => a.timestamp, (a) => casToSeverity(a.CAS), 24),
    [liveAlerts]
  );
  const severityDist = useMemo(() => {
    if (alertsSeverityTotals) {
      return SEVERITY_ORDER.map((name) => ({ name, value: alertsSeverityTotals[name], color: SEVERITY_COLORS[name] }));
    }
    return severityCounts(liveAlerts, (a) => casToSeverity(a.CAS));
  }, [liveAlerts, alertsSeverityTotals]);
  const recentAlerts = useMemo(() => [...liveAlerts].sort((a, b) => b.CAS - a.CAS).slice(0, 5), [liveAlerts]);

  const tabs: { id: Tab; label: string; icon: React.ReactNode }[] = isBiomed
    ? [
        { id: 'overview', label: 'Overview', icon: <Shield className="w-4 h-4" /> },
        { id: 'devices', label: 'Devices', icon: <Server className="w-4 h-4" /> },
        { id: 'vulnerabilities', label: 'Vulnerabilities', icon: <Bug className="w-4 h-4" /> },
      ]
    : isAuditor
    ? [
        { id: 'overview', label: 'Overview', icon: <Shield className="w-4 h-4" /> },
        { id: 'audit-log', label: 'Audit Log', icon: <Database className="w-4 h-4" /> },
      ]
    : [
        { id: 'overview', label: 'Overview', icon: <Shield className="w-4 h-4" /> },
        { id: 'alerts', label: 'SOC Alerts', icon: <Activity className="w-4 h-4" /> },
        { id: 'my-alerts', label: 'My Alerts', icon: <Inbox className="w-4 h-4" /> },
        { id: 'live-alerts', label: 'Live Alerts', icon: <Radio className="w-4 h-4" /> },
        { id: 'devices', label: 'Devices', icon: <Server className="w-4 h-4" /> },
        { id: 'vulnerabilities', label: 'Vulnerabilities', icon: <Bug className="w-4 h-4" /> },
        { id: 'reports', label: 'Reports', icon: <FileText className="w-4 h-4" /> },
      ];

  const complianceSubItems: { id: Tab; label: string; icon: React.ReactNode; framework: FrameworkTab }[] = [
    { id: 'hipaa', label: 'HIPAA', icon: <ShieldCheck className="w-3.5 h-3.5" />, framework: 'hipaa' },
    { id: 'gdpr', label: 'GDPR', icon: <Globe className="w-3.5 h-3.5" />, framework: 'gdpr' },
    { id: 'cis', label: 'CIS', icon: <ClipboardCheck className="w-3.5 h-3.5" />, framework: 'cis' },
  ];
  const isComplianceActive = complianceSubItems.some((s) => s.id === activeTab);

  const paletteItems: CommandPaletteItem[] = useMemo(() => [
    ...tabs.map((t) => ({ id: `tab-${t.id}`, label: t.label, hint: 'Go to tab', icon: t.icon, run: () => setActiveTab(t.id) })),
    ...complianceSubItems.map((c) => ({ id: `tab-${c.id}`, label: c.label, hint: 'Compliance', icon: c.icon, run: () => setActiveTab(c.id) })),
    { id: 'action-theme', label: 'Toggle light/dark theme', icon: <Menu className="w-4 h-4" />, run: toggleTheme },
    { id: 'action-wallboard', label: 'Open SOC wallboard', hint: 'New tab', icon: <Tv className="w-4 h-4" />, run: () => window.open('/wallboard', '_blank', 'noopener,noreferrer') },
    { id: 'action-logout', label: 'Sign out', icon: <User className="w-4 h-4" />, run: handleLogout },
    // eslint-disable-next-line react-hooks/exhaustive-deps
  ], [tabs, complianceSubItems, toggleTheme]);

  return (
    <WazuhProvider>
    <div className="h-screen overflow-hidden bg-white dark:bg-slate-950 text-slate-900 dark:text-white flex flex-col">
      {/* Background */}
      <div className="fixed inset-0 dark:bg-[linear-gradient(rgba(6,182,212,0.02)_1px,transparent_1px),linear-gradient(90deg,rgba(6,182,212,0.02)_1px,transparent_1px)] bg-[size:48px_48px] pointer-events-none" />

      <div className="flex flex-1 min-h-0">
        {/* ── Sidebar ── */}
        <aside
          className={`no-print fixed inset-y-0 left-0 z-40 flex flex-col w-64 bg-white dark:bg-slate-900 border-r border-slate-200 dark:border-slate-800 transition-transform duration-300 ${
            sidebarOpen ? 'translate-x-0' : '-translate-x-full'
          } lg:translate-x-0 lg:static lg:z-auto`}
        >
          {/* Logo */}
          <div className="flex items-center justify-between px-5 py-4 border-b border-slate-200 dark:border-slate-800">
            <div className="flex items-center gap-2.5">
              <div className="w-7 h-7 bg-slate-900 dark:bg-white rounded-md flex items-center justify-center">
                <Shield className="w-4 h-4 text-cyan-400 dark:text-slate-900" strokeWidth={2.5} />
              </div>
              <span className="font-bold text-[15px] text-slate-900 dark:text-white tracking-tight">
                MediSIEM
              </span>
            </div>
            <button onClick={() => setSidebarOpen(false)} aria-label="Close sidebar" className="lg:hidden text-slate-400 dark:text-slate-500 hover:text-slate-900 dark:hover:text-white">
              <X className="w-4 h-4" />
            </button>
          </div>

          {/* Role Badge */}
          <div className="flex items-center gap-1.5 px-5 py-2.5 border-b border-slate-200 dark:border-slate-800">
            {isBiomed ? <Wrench className="w-3 h-3 text-cyan-500 dark:text-cyan-400 flex-shrink-0" /> : <span className="w-1.5 h-1.5 rounded-full bg-cyan-500 flex-shrink-0" />}
            <span className="text-[11px] font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">{roleLabel}</span>
          </div>

          {/* Nav */}
          <nav className="flex-1 px-3 py-4 space-y-0.5 overflow-y-auto">
            {tabs.map((t) => (
              <button
                key={t.id}
                onClick={() => { setActiveTab(t.id); setSidebarOpen(false); }}
                className={`relative w-full flex items-center gap-3 pl-3.5 pr-3 py-2 rounded-md text-[13px] font-medium transition-colors text-left ${
                  activeTab === t.id
                    ? 'bg-slate-100 dark:bg-slate-800/80 text-slate-900 dark:text-white before:absolute before:left-0 before:top-1.5 before:bottom-1.5 before:w-[3px] before:rounded-full before:bg-cyan-500'
                    : 'text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-slate-50 dark:hover:bg-slate-800/40'
                }`}
              >
                {t.icon}
                {t.label}
                {t.id === 'alerts' && openCount > 0 && (
                  <span className="ml-auto flex items-center justify-center min-w-4 h-4 px-1 text-[10px] font-bold bg-red-600 text-white rounded-full">
                    {openCount}
                  </span>
                )}
                {t.id === 'my-alerts' && myOpenCount > 0 && (
                  <span className="ml-auto flex items-center justify-center min-w-4 h-4 px-1 text-[10px] font-bold bg-cyan-600 text-white rounded-full">
                    {myOpenCount}
                  </span>
                )}
              </button>
            ))}

            {/* Compliances — expandable, holds HIPAA / GDPR / CIS (read-only) */}
            <button
              onClick={() => {
                const next = !complianceOpen;
                setComplianceOpen(next);
                if (next && !isComplianceActive) setActiveTab('hipaa');
              }}
              className={`relative w-full flex items-center gap-3 pl-3.5 pr-3 py-2 rounded-md text-[13px] font-medium transition-colors text-left ${
                isComplianceActive
                  ? 'bg-slate-100 dark:bg-slate-800/80 text-slate-900 dark:text-white before:absolute before:left-0 before:top-1.5 before:bottom-1.5 before:w-[3px] before:rounded-full before:bg-cyan-500'
                  : 'text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-slate-50 dark:hover:bg-slate-800/40'
              }`}
            >
              <ShieldCheck className="w-4 h-4" />
              Compliances
              <ChevronDown className={`w-3.5 h-3.5 ml-auto transition-transform ${complianceOpen || isComplianceActive ? 'rotate-180' : ''}`} />
            </button>

            {(complianceOpen || isComplianceActive) && (
              <div className="ml-3 pl-3 border-l border-slate-200 dark:border-slate-800 space-y-0.5">
                {complianceSubItems.map((item) => (
                  <button
                    key={item.id}
                    onClick={() => { setActiveTab(item.id); setSidebarOpen(false); }}
                    className={`w-full flex items-center gap-2.5 px-3 py-1.5 rounded-md text-[13px] font-medium transition-colors text-left ${
                      activeTab === item.id
                        ? 'text-cyan-600 dark:text-cyan-400'
                        : 'text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                    }`}
                  >
                    {item.icon}
                    {item.label}
                  </button>
                ))}
              </div>
            )}
          </nav>

          {/* User */}
          <div className="px-4 py-3.5 border-t border-slate-200 dark:border-slate-800">
            <div className="flex items-center gap-2.5">
              <div className="w-7 h-7 rounded-full bg-slate-800 dark:bg-slate-700 flex items-center justify-center text-[11px] font-bold text-white flex-shrink-0">
                {user?.name?.[0]?.toUpperCase()}
              </div>
              <div className="min-w-0">
                <div className="text-[13px] font-medium text-slate-900 dark:text-white truncate">{user?.name}</div>
                <div className="text-xs text-slate-500 dark:text-slate-400 dark:text-slate-500 truncate">{user?.email}</div>
              </div>
            </div>
          </div>
        </aside>

        {sidebarOpen && (
          <div className="fixed inset-0 z-30 bg-black/50 lg:hidden" onClick={() => setSidebarOpen(false)} />
        )}

        {/* ── Content column ── */}
        <div className="flex-1 flex flex-col min-w-0">
          {/* Top bar */}
          <header className="no-print sticky top-0 z-20 flex items-center justify-between px-5 py-3.5 bg-white/90 dark:bg-slate-950/90 backdrop-blur border-b border-slate-200 dark:border-slate-800">
            <div className="flex items-center gap-3">
              <button onClick={() => setSidebarOpen(true)} className="lg:hidden p-1.5 text-slate-400 dark:text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-900 dark:text-white rounded-lg hover:bg-slate-100 dark:hover:bg-slate-100 dark:bg-slate-800 transition-colors">
                <Menu className="w-5 h-5" />
              </button>
              <div>
                <h1 className="text-[13px] font-semibold text-slate-900 dark:text-white">
                  {isBiomed ? 'Medical Device Inventory' : isAuditor ? 'Compliance & Audit' : 'Security Dashboard — SOC'}
                </h1>
                <p className="text-[11px] text-slate-400 dark:text-slate-500 hidden sm:block">
                  {isBiomed
                    ? 'Device onboarding, criticality tagging, and vulnerability visibility'
                    : isAuditor
                    ? 'Read-only compliance mapping and admin activity log'
                    : 'Real-time threat monitoring'}
                  {' · '}Last updated: {new Date().toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' })}
                </p>
              </div>
            </div>

            <div className="flex items-center gap-4">
              <button
                onClick={() => window.open('/wallboard', '_blank', 'noopener,noreferrer')}
                title="Open SOC wallboard in a new tab"
                className="hidden sm:flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-slate-800 text-[12px] font-medium transition-colors"
              >
                <Tv className="w-3.5 h-3.5" /> Wallboard
              </button>
              <div className="flex items-center gap-1">
                <SoundToggle />
                <BrowserNotifToggle />
                <ThemeToggle />
                <NotificationCenterBell />
              </div>

              {/* Notifications */}
              <div className="relative">
                <button
                  onClick={() => setShowNotifications(!showNotifications)}
                  aria-label={`Immediate-action alerts${notifications.length > 0 ? ` — ${notifications.length} unread` : ''}`}
                  className="relative p-2 rounded-lg text-slate-400 dark:text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-900 dark:text-white hover:bg-slate-100 dark:hover:bg-slate-100 dark:bg-slate-800 transition-colors"
                >
                  <Bell className="w-5 h-5" />
                  {notifications.length > 0 && (
                    <span className="absolute top-1.5 right-1.5 w-2 h-2 bg-red-500 rounded-full" />
                  )}
                </button>

                {showNotifications && (
                  <div className="absolute right-0 top-12 w-80 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-xl shadow-2xl overflow-hidden z-50">
                    <div className="px-4 py-3 border-b border-slate-200 dark:border-slate-800">
                      <p className="text-sm font-semibold text-slate-900 dark:text-white">Notifications</p>
                    </div>
                    {notifications.length === 0 ? (
                      <p className="text-sm text-slate-400 dark:text-slate-500 text-center py-6">All caught up!</p>
                    ) : (
                      <div className="divide-y divide-slate-200 dark:divide-slate-800">
                        {notifications.map((n) => (
                          <div key={n.id} className="flex items-start gap-3 px-4 py-3 hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors">
                            <span className="mt-0.5 flex-shrink-0">
                              {n.type === 'warning' && <AlertCircle className="w-4 h-4 text-amber-400" />}
                              {n.type === 'success' && <CheckCircle2 className="w-4 h-4 text-emerald-400" />}
                              {n.type === 'info' && <Info className="w-4 h-4 text-cyan-400" />}
                            </span>
                            <div className="flex-1 min-w-0">
                              <p className="text-xs text-slate-700 dark:text-slate-300 leading-relaxed">{n.message}</p>
                              <p className="text-xs text-slate-500 dark:text-slate-400 dark:text-slate-600 mt-1">{n.time}</p>
                            </div>
                            <button
                              onClick={() => dismissNotification(n.id)}
                              aria-label="Dismiss notification"
                              className="text-slate-500 dark:text-slate-400 dark:text-slate-600 hover:text-slate-400 dark:text-slate-600 dark:hover:text-slate-500 dark:text-slate-400 transition-colors flex-shrink-0"
                            >
                              <X className="w-3.5 h-3.5" />
                            </button>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </div>

              {/* User pill */}
              <div className="relative pl-4 border-l border-slate-200 dark:border-slate-800">
                <button
                  onClick={() => { setAccountMenuView('menu'); setShowAccountMenu(!showAccountMenu); }}
                  className="flex items-center gap-2"
                >
                  <div className="w-7 h-7 rounded-full bg-slate-800 dark:bg-slate-700 flex items-center justify-center">
                    <User className="w-3.5 h-3.5 text-white" />
                  </div>
                  <span className="text-[13px] text-slate-700 dark:text-slate-300 hidden sm:block">{user?.name}</span>
                  <ChevronDown className={`w-3.5 h-3.5 text-slate-400 dark:text-slate-500 transition-transform ${showAccountMenu ? 'rotate-180' : ''}`} />
                </button>

                {showAccountMenu && (
                  <AccountMenu
                    token={token}
                    userId={user?.id}
                    onClose={() => setShowAccountMenu(false)}
                    onLogout={handleLogout}
                    initialView={accountMenuView}
                  />
                )}
              </div>
            </div>
          </header>

          {/* An admin required 2FA for this account (Users tab → 2FA) and it
              hasn't been set up yet — see routes/auth.js's isMfaSetupRequired().
              Persistent (not dismissible) since it reflects an actual
              requirement, not a tip. */}
          {user?.mfaSetupRequired && (
            <div className="no-print flex items-center justify-between gap-3 px-5 py-2 bg-amber-500/10 border-b border-amber-500/20 text-amber-700 dark:text-amber-400 text-xs">
              <span className="flex items-center gap-2">
                <ShieldAlert className="w-3.5 h-3.5 flex-shrink-0" />
                Your administrator requires two-factor authentication on this account.
              </span>
              <button
                onClick={() => { setAccountMenuView('mfa'); setShowAccountMenu(true); }}
                className="flex-shrink-0 px-2.5 py-1 rounded-md bg-amber-500/20 hover:bg-amber-500/30 font-semibold transition-colors"
              >
                Set up now
              </button>
            </div>
          )}

          {/* ── Main ── */}
          <main className="flex-1 overflow-y-auto p-5 space-y-6">
        {/* ── OVERVIEW TAB ── */}
        {activeTab === 'overview' && (
          <div className="space-y-6">
            {/* Stat cards */}
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
              <StatCard icon={<AlertTriangle className="w-5 h-5" />} label="Total Alerts" value={String(alertsTotalCount ?? liveAlerts.length)} sub={alertsTotalCount !== undefined ? 'All-time' : 'Current buffer'} color="slate" />
              <StatCard icon={<AlertCircle className="w-5 h-5" />} label="Critical" value={String(criticalCount)} sub="CAS ≥ 8" color="red" />
              <StatCard icon={<Activity className="w-5 h-5" />} label="Investigating" value={String(investigatingCount)} sub="In progress" color="amber" />
              <StatCard icon={<CheckCircle2 className="w-5 h-5" />} label="Monitor" value={String(monitorCount)} sub="Low-priority / auto-tracked" color="emerald" />
            </div>

            {/* Team Presence */}
            <PresenceWidget summary={presenceSummary} loading={presenceLoading} error={presenceError} />

            {/* Your stats — closed-case verdict breakdown, SOC analyst only
                (biomed/auditor never close cases, see routes/alerts.js's
                assignment restriction to role 'user') */}
            {!isBiomed && !isAuditor && <MyStatsWidget token={token} />}

            {/* GET /api/reports/trending-devices is allowRoles('admin', 'user') server-side — same restriction as MyStatsWidget above */}
            {!isBiomed && !isAuditor && <TrendingDevicesCard token={token} />}

            {/* Alert volume + severity mix */}
            <div className="grid lg:grid-cols-3 gap-5">
              <ChartCard title="Alert volume (24h)" subtitle="Stacked by severity, current buffer" height={200} empty={liveAlerts.length === 0} className="lg:col-span-2">
                <AlertsTimelineChart data={timeline} />
              </ChartCard>
              <ChartCard title="Severity mix" subtitle="Current buffer" height={200} empty={liveAlerts.length === 0}>
                <SeverityDonutChart data={severityDist} />
              </ChartCard>
            </div>

            {/* Recent Alerts */}
            <div className="p-5 rounded-xl bg-white dark:bg-slate-900/80 border border-slate-200 dark:border-slate-800">
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-base font-semibold text-slate-900 dark:text-white">Recent Alerts</h2>
                <button
                  onClick={() => setActiveTab('alerts')}
                  className="text-xs text-cyan-500 dark:text-cyan-400 hover:text-cyan-600 dark:hover:text-cyan-300 flex items-center gap-1"
                >
                  View all <ChevronRight className="w-3.5 h-3.5" />
                </button>
              </div>
              <div className="space-y-2">
                {alertsLoading ? (
                  <p className="text-sm text-slate-400 dark:text-slate-500 text-center py-6">Loading alerts…</p>
                ) : recentAlerts.length === 0 ? (
                  <p className="text-sm text-slate-400 dark:text-slate-500 text-center py-6">No alerts yet — waiting for the pipeline to index the first one.</p>
                ) : (
                  recentAlerts.map((a) => {
                    const severity = casToSeverity(a.CAS);
                    return (
                      <div key={a.id} className="flex items-center gap-3 px-3 py-2.5 rounded-xl hover:bg-slate-100 dark:hover:bg-slate-800/50 transition-colors">
                        <span className={`w-2 h-2 rounded-full flex-shrink-0 ${sevDot[severity]}`} />
                        <div className="flex-1 min-w-0">
                          <p className="text-sm text-slate-900 dark:text-white font-medium truncate">
                            {a.label !== 'Unclassified' ? a.label : a.ruleDescription}
                          </p>
                          <p className="text-xs text-slate-500 dark:text-slate-400 dark:text-slate-500">{a.agent} · {new Date(a.timestamp).toLocaleString()}</p>
                        </div>
                        <SeverityBadge severity={severity} className="flex-shrink-0" />
                      </div>
                    );
                  })
                )}
              </div>
            </div>

            {/* Reports teaser */}
            <div className="p-5 rounded-xl bg-white dark:bg-slate-900/80 border border-slate-200 dark:border-slate-800 flex items-center justify-between gap-3">
              <div>
                <h2 className="text-base font-semibold text-slate-900 dark:text-white flex items-center gap-2"><FileText className="w-4 h-4 text-cyan-500 dark:text-cyan-400" /> Reports</h2>
                <p className="text-xs text-slate-400 dark:text-slate-500 mt-0.5">Case history, detection accuracy, off-hours activity, device risk, and more — generated from your real case data.</p>
              </div>
              <button onClick={() => setActiveTab('reports')} className="flex-shrink-0 text-xs text-cyan-500 dark:text-cyan-400 hover:text-cyan-600 dark:hover:text-cyan-300 flex items-center gap-1">
                Open <ChevronRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        )}

        {/* ── ALERTS TAB (real CAS-ranked live feed) ── */}
        {activeTab === 'alerts' && (
          <AlertsPanel
            alerts={liveAlerts}
            connected={alertsConnected}
            loading={alertsLoading}
            error={alertsError}
            token={token}
            canAssign={false}
            currentUserId={user?.id}
            totalCount={alertsTotalCount}
            severityTotals={alertsSeverityTotals}
          />
        )}

        {/* ── MY ALERTS TAB (assigned-to-me queue, close-with-evidence) ── */}
        {activeTab === 'my-alerts' && (
          <MyAlertsPanel
            alerts={liveAlerts}
            loading={alertsLoading}
            error={alertsError}
            token={token}
            userId={user?.id}
          />
        )}

        {/* ── REPORTS TAB ── */}
        {activeTab === 'reports' && <ReportsPanel token={token} />}

        {/* ── LIVE ALERTS (real Wazuh, read-only) ── */}
        {activeTab === 'live-alerts' && <AlertsBrowser />}

        {/* ── DEVICES — full onboard/edit for biomed (real backend write access), read-only for everyone else ── */}
        {activeTab === 'devices' && (
          isBiomed
            ? <MedicalDeviceInventoryPanel groups={deviceGroups} createGroup={createGroup} />
            : <DevicesReadOnlyPanel token={token} />
        )}

        {/* ── VULNERABILITIES (read-only) ── */}
        {activeTab === 'vulnerabilities' && <VulnerabilitiesPanel />}

        {/* ── AUDIT LOG (auditor role only — read-only) ── */}
        {activeTab === 'audit-log' && <AuditLogPanel token={token} />}

        {/* ── COMPLIANCES (read-only) ── */}
        {activeTab === 'hipaa' && <CompliancePanel framework="hipaa" />}
        {activeTab === 'gdpr' && <CompliancePanel framework="gdpr" />}
        {activeTab === 'cis' && <CompliancePanel framework="cis" />}
          </main>
        </div>
      </div>
      <CommandPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} items={paletteItems} />
    </div>
    </WazuhProvider>
  );
};

export default UserDashboard;
