import React, { useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Shield,
  FileText,
  Bell,
  ChevronRight,
  ChevronDown,
  Clock,
  User,
  Download,
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
  ClipboardCheck,
  Tv,
  Inbox,
  Database,
  Wrench,
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import AccountMenu from '../../components/AccountMenu';
import ThemeToggle from '../../components/ThemeToggle';
import SoundToggle from '../../components/SoundToggle';
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
import { useDeviceMeta } from './useDeviceMeta';
import { useLiveAlerts } from '../../hooks/useLiveAlerts';
import { casToSeverity, severityCounts, bucketAlertsByHour, SEVERITY_ORDER, SEVERITY_COLORS } from '../../utils/chartData';
import type { Severity } from '../../utils/chartData';

// ─── Types ─────────────────────────────────────────────────────────────────────
type Tab = 'overview' | 'alerts' | 'my-alerts' | 'reports' | 'devices' | 'vulnerabilities' | 'live-alerts' | 'audit-log' | 'hipaa' | 'gdpr' | 'cis';

type ReportCategory =
  | 'Threat Intelligence'
  | 'Incident'
  | 'Access Control'
  | 'Network'
  | 'Compliance'
  | 'Vulnerability';

interface Report {
  id: string;
  title: string;
  description: string;
  date: string;
  category: ReportCategory;
  status: 'ready' | 'pending';
}

interface Notification {
  id: string;
  message: string;
  type: 'info' | 'warning' | 'success';
  time: string;
}

// ─── Mock Data ─────────────────────────────────────────────────────────────────
// Reports have no backing API yet (only audit log / alerts / compliance /
// devices do) — kept as sample UI rather than half-wiring a feature that
// doesn't exist on the backend.
const REPORTS: Report[] = [
  {
    id: 'r1',
    title: 'Weekly Threat Intelligence Digest',
    description: 'Summary of IOCs, threat actor TTPs, and threat landscape shifts for the week ending Apr 12.',
    date: '2025-04-12',
    category: 'Threat Intelligence',
    status: 'ready',
  },
  {
    id: 'r2',
    title: 'Brute Force Incident Report — Apr 12',
    description: 'Forensic timeline of the brute force campaign targeting the EHR portal from IP 185.220.101.47.',
    date: '2025-04-12',
    category: 'Incident',
    status: 'ready',
  },
  {
    id: 'r3',
    title: 'Ransomware Exposure Analysis',
    description: 'Full forensic analysis of the YARA-matched ransomware dropper on the radiology workstation.',
    date: '2025-04-11',
    category: 'Incident',
    status: 'pending',
  },
  {
    id: 'r4',
    title: 'Privileged Access Review — Q1 2025',
    description: 'Audit of all privileged account activity, role assignments, and policy exceptions in Q1.',
    date: '2025-04-10',
    category: 'Access Control',
    status: 'ready',
  },
  {
    id: 'r5',
    title: 'Failed Authentication Summary',
    description: 'Breakdown of 1,240 failed login events across all systems in the past 7 days.',
    date: '2025-04-09',
    category: 'Access Control',
    status: 'ready',
  },
  {
    id: 'r6',
    title: 'Off-Hours Access Report',
    description: 'Flagged access events occurring outside business hours (22:00–06:00) in the past 30 days.',
    date: '2025-04-08',
    category: 'Access Control',
    status: 'ready',
  },
  {
    id: 'r7',
    title: 'Network Anomaly Report',
    description: 'Analysis of abnormal traffic patterns including the 2.3 GB exfiltration attempt detected Apr 11.',
    date: '2025-04-11',
    category: 'Network',
    status: 'ready',
  },
  {
    id: 'r8',
    title: 'Firewall Policy Audit',
    description: 'Review of all inbound/outbound firewall rules against the current security baseline.',
    date: '2025-04-07',
    category: 'Network',
    status: 'pending',
  },
  {
    id: 'r9',
    title: 'HIPAA Audit Trail — Q1 2025',
    description: 'Full audit log of patient data access events for regulatory compliance review.',
    date: '2025-04-05',
    category: 'Compliance',
    status: 'ready',
  },
  {
    id: 'r10',
    title: 'Security Policy Violations',
    description: 'Report on policy deviations including unencrypted data transfers and disabled endpoint agents.',
    date: '2025-04-03',
    category: 'Compliance',
    status: 'ready',
  },
  {
    id: 'r11',
    title: 'CVE Exposure Assessment',
    description: 'Mapping of active CVEs against the hospital asset inventory and current patch status.',
    date: '2025-04-06',
    category: 'Vulnerability',
    status: 'pending',
  },
  {
    id: 'r12',
    title: 'Endpoint Patch Status',
    description: 'Patch compliance across 412 managed endpoints; 23 devices with critical unpatched CVEs.',
    date: '2025-04-04',
    category: 'Vulnerability',
    status: 'ready',
  },
];

// ─── Helpers ───────────────────────────────────────────────────────────────────
const reportCategoryConfig: Record<ReportCategory, { badge: string; dot: string }> = {
  'Threat Intelligence': { badge: 'bg-purple-500/15 text-purple-400 border-purple-500/30', dot: 'bg-purple-500' },
  'Incident':            { badge: 'bg-red-500/15 text-red-400 border-red-500/30',           dot: 'bg-red-500'    },
  'Access Control':      { badge: 'bg-amber-500/15 text-amber-400 border-amber-500/30',     dot: 'bg-amber-500'  },
  'Network':             { badge: 'bg-cyan-500/15 text-cyan-400 border-cyan-500/30',         dot: 'bg-cyan-500'   },
  'Compliance':          { badge: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30', dot: 'bg-emerald-500' },
  'Vulnerability':       { badge: 'bg-orange-500/15 text-orange-400 border-orange-500/30',   dot: 'bg-orange-500' },
};

const sevDot: Record<Severity, string> = {
  CRITICAL: 'bg-red-500',
  HIGH: 'bg-orange-500',
  MEDIUM: 'bg-amber-500',
  LOW: 'bg-blue-500',
};

// ─── UserDashboard ─────────────────────────────────────────────────────────────
const UserDashboard: React.FC = () => {
  const { user, token, logout } = useAuth();
  const navigate = useNavigate();
  // This dashboard is shared by every non-admin role (SOC analyst 'user',
  // 'biomed', 'auditor') — AdminRoute in App.tsx only special-cases
  // role === 'admin', everyone else lands here. What each role actually
  // gets — nav tabs, the role badge, the Devices panel variant — branches
  // on role below rather than assuming 'user' like this file originally did.
  const role = user?.role ?? 'user';
  const isBiomed = role === 'biomed';
  const isAuditor = role === 'auditor';
  const roleLabel = isBiomed ? 'Biomedical Engineer' : isAuditor ? 'Auditor' : 'SOC Analyst';
  const [activeTab, setActiveTab] = useState<Tab>('overview');
  const [reportCategory, setReportCategory] = useState<ReportCategory | 'all'>('all');
  const [dismissedIds, setDismissedIds] = useState<Set<string>>(new Set());
  const [showNotifications, setShowNotifications] = useState(false);
  const [showAccountMenu, setShowAccountMenu] = useState(false);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [complianceOpen, setComplianceOpen] = useState(false);
  const { summary: presenceSummary, loading: presenceLoading, error: presenceError } = usePresenceSummary(token);
  // Only actually rendered for the 'biomed' role (see the Devices tab below)
  // — called unconditionally because hooks can't be conditional, but GET
  // /api/device-groups and /api/devices/meta are both any-authenticated-user
  // reads, so calling this for analyst/auditor accounts too is harmless.
  const { groups: deviceGroups, createGroup } = useDeviceMeta(token);
  const {
    alerts: liveAlerts,
    connected: alertsConnected,
    loading: alertsLoading,
    error: alertsError,
    totalCount: alertsTotalCount,
    severityTotals: alertsSeverityTotals,
  } = useLiveAlerts(token);

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

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

  // SOC case-triage tabs (SOC Alerts / My Alerts / Live Alerts / Reports)
  // only make sense for the 'user' (SOC analyst) role — a biomed engineer
  // isn't triaging alerts and can't be assigned one (backend restricts
  // assignment to role 'user'); an auditor gets Audit Log instead, which
  // no other role in this app can currently reach at all.
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

  // Read-only insight views mirroring what's built for Admin — same live
  // Wazuh data, no edit/manage actions anywhere in these.
  const complianceSubItems: { id: Tab; label: string; icon: React.ReactNode; framework: FrameworkTab }[] = [
    { id: 'hipaa', label: 'HIPAA', icon: <ShieldCheck className="w-3.5 h-3.5" />, framework: 'hipaa' },
    { id: 'gdpr', label: 'GDPR', icon: <Globe className="w-3.5 h-3.5" />, framework: 'gdpr' },
    { id: 'cis', label: 'CIS', icon: <ClipboardCheck className="w-3.5 h-3.5" />, framework: 'cis' },
  ];
  const isComplianceActive = complianceSubItems.some((s) => s.id === activeTab);

  return (
    <WazuhProvider>
    <div className="h-screen overflow-hidden bg-white dark:bg-slate-950 text-slate-900 dark:text-white flex flex-col">
      {/* Background */}
      <div className="fixed inset-0 dark:bg-[linear-gradient(rgba(6,182,212,0.02)_1px,transparent_1px),linear-gradient(90deg,rgba(6,182,212,0.02)_1px,transparent_1px)] bg-[size:48px_48px] pointer-events-none" />

      <div className="flex flex-1 min-h-0">
        {/* ── Sidebar ── */}
        <aside
          className={`fixed inset-y-0 left-0 z-40 flex flex-col w-64 bg-white dark:bg-slate-900 border-r border-slate-200 dark:border-slate-800 transition-transform duration-300 ${
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
            <button onClick={() => setSidebarOpen(false)} className="lg:hidden text-slate-400 dark:text-slate-500 hover:text-slate-900 dark:hover:text-white">
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
          <header className="sticky top-0 z-20 flex items-center justify-between px-5 py-3.5 bg-white/90 dark:bg-slate-950/90 backdrop-blur border-b border-slate-200 dark:border-slate-800">
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
                <ThemeToggle />
              </div>

              {/* Notifications */}
              <div className="relative">
                <button
                  onClick={() => setShowNotifications(!showNotifications)}
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
                  onClick={() => setShowAccountMenu(!showAccountMenu)}
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
                  />
                )}
              </div>
            </div>
          </header>

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

            {/* Recent Reports */}
            <div className="p-5 rounded-xl bg-white dark:bg-slate-900/80 border border-slate-200 dark:border-slate-800">
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-base font-semibold text-slate-900 dark:text-white">Recent Reports</h2>
                <button onClick={() => setActiveTab('reports')} className="text-xs text-cyan-500 dark:text-cyan-400 hover:text-cyan-600 dark:hover:text-cyan-300 flex items-center gap-1">
                  All <ChevronRight className="w-3.5 h-3.5" />
                </button>
              </div>
              <div className="space-y-3">
                {REPORTS.slice(0, 3).map((r) => (
                  <ReportRow key={r.id} report={r} />
                ))}
              </div>
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
        {activeTab === 'reports' && (
          <div className="space-y-5">
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-semibold text-slate-900 dark:text-white">SOC Reports</h2>
              <span className="text-xs text-slate-400 dark:text-slate-500">
                {REPORTS.filter((r) => r.status === 'ready').length} of {REPORTS.length} ready to download
              </span>
            </div>

            {/* Category filter */}
            <div className="flex items-center gap-2 flex-wrap">
              {(['all', 'Threat Intelligence', 'Incident', 'Access Control', 'Network', 'Compliance', 'Vulnerability'] as const).map((cat) => {
                const count = cat === 'all' ? REPORTS.length : REPORTS.filter((r) => r.category === cat).length;
                const active = reportCategory === cat;
                const cfg = cat !== 'all' ? reportCategoryConfig[cat] : null;
                return (
                  <button
                    key={cat}
                    onClick={() => setReportCategory(cat)}
                    className={`flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-medium border transition-all ${
                      active
                        ? cat === 'all'
                          ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40'
                          : cfg!.badge + ' border-opacity-60'
                        : 'bg-slate-100 dark:bg-slate-800/60 text-slate-400 dark:text-slate-500 dark:text-slate-400 border-slate-300 dark:border-slate-700 hover:border-slate-400 dark:hover:border-slate-600'
                    }`}
                  >
                    {cfg && <span className={`w-1.5 h-1.5 rounded-full ${cfg.dot}`} />}
                    <span>{cat === 'all' ? 'All' : cat}</span>
                    <span className="opacity-60">({count})</span>
                  </button>
                );
              })}
            </div>

            {/* Report cards */}
            <div className="space-y-3">
              {REPORTS.filter((r) => reportCategory === 'all' || r.category === reportCategory).map((r) => (
                <ReportCard key={r.id} report={r} />
              ))}
            </div>
          </div>
        )}

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
    </div>
    </WazuhProvider>
  );
};

// ─── Sub-components ────────────────────────────────────────────────────────────

const ReportRow: React.FC<{ report: Report }> = ({ report }) => (
  <div className="flex items-center gap-3 px-1">
    <span className={`w-2 h-2 rounded-full flex-shrink-0 ${reportCategoryConfig[report.category].dot}`} />
    <div className="flex-1 min-w-0">
      <p className="text-sm text-slate-900 dark:text-white font-medium truncate">{report.title}</p>
      <p className="text-xs text-slate-500 dark:text-slate-400 dark:text-slate-500">{report.category} · {report.date}</p>
    </div>
    <span className={`text-xs px-2 py-0.5 rounded-full border flex-shrink-0 ${
      report.status === 'ready'
        ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
        : 'bg-slate-200 dark:bg-slate-700/50 text-slate-400 dark:text-slate-500 dark:text-slate-400 border-slate-300 dark:border-slate-700'
    }`}>
      {report.status}
    </span>
  </div>
);

const ReportCard: React.FC<{ report: Report }> = ({ report }) => {
  const cfg = reportCategoryConfig[report.category];
  return (
    <div className="p-4 rounded-xl bg-white dark:bg-slate-900/80 border border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-300 dark:border-slate-700 transition-colors">
      <div className="flex items-start gap-4">
        <div className="w-10 h-10 rounded-xl bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 flex items-center justify-center flex-shrink-0">
          <FileText className="w-5 h-5 text-slate-500 dark:text-slate-400" />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-start justify-between gap-3 mb-1">
            <p className="text-sm font-semibold text-slate-900 dark:text-white leading-snug">{report.title}</p>
            <span className={`text-xs px-2 py-0.5 rounded-full border flex-shrink-0 ${cfg.badge}`}>
              {report.category}
            </span>
          </div>
          <p className="text-xs text-slate-400 dark:text-slate-500 dark:text-slate-400 leading-relaxed mb-3">{report.description}</p>
          <div className="flex items-center justify-between">
            <span className="text-xs text-slate-500 dark:text-slate-400 dark:text-slate-600 flex items-center gap-1">
              <Clock className="w-3 h-3" /> {report.date}
            </span>
            {report.status === 'ready' ? (
              <button className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-500 dark:text-cyan-400 hover:bg-cyan-500/20 transition-colors text-xs font-medium">
                <Download className="w-3.5 h-3.5" /> Download
              </button>
            ) : (
              <span className="flex items-center gap-1.5 text-xs text-slate-400 dark:text-slate-500 px-3 py-1.5 rounded-xl border border-slate-200 dark:border-slate-800">
                <Clock className="w-3.5 h-3.5" /> Generating…
              </span>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default UserDashboard;
