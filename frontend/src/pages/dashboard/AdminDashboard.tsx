import React, { useState } from 'react';
import WazuhDashboard from './WazuhDashboard';
import {
  Shield, Activity, AlertTriangle, Users, Server, Bell,
  LogOut, Settings, ChevronDown, Menu, X, BarChart3,
  TrendingUp, Network, Zap, CheckCircle,
  Clock, AlertCircle, Database
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { useNavigate } from 'react-router-dom';

// ─── Stat Card ────────────────────────────────────────────────────────────────
const StatCard: React.FC<{
  icon: React.ReactNode;
  label: string;
  value: string;
  sub: string;
  color: string;
  trend?: string;
}> = ({ icon, label, value, sub, color, trend }) => (
  <div className={`p-5 rounded-2xl bg-slate-900 border border-slate-800 hover:border-${color}-500/30 transition-all`}>
    <div className="flex items-start justify-between mb-3">
      <div className={`w-10 h-10 rounded-xl bg-${color}-500/10 flex items-center justify-center`}>{icon}</div>
      {trend && (
        <span className={`text-xs px-2 py-0.5 rounded-full ${trend.startsWith('+') ? 'bg-emerald-500/10 text-emerald-400' : 'bg-red-500/10 text-red-400'}`}>
          {trend}
        </span>
      )}
    </div>
    <div className="text-2xl font-black text-white mb-0.5">{value}</div>
    <div className="text-xs font-medium text-slate-300">{label}</div>
    <div className="text-xs text-slate-500 mt-0.5">{sub}</div>
  </div>
);

// ─── Alert Row ────────────────────────────────────────────────────────────────
const AlertRow: React.FC<{
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  device: string;
  event: string;
  cas: number;
  time: string;
  status: 'Open' | 'Investigating' | 'Resolved';
}> = ({ severity, device, event, cas, time, status }) => {
  const sevColor: Record<string, string> = {
    CRITICAL: 'text-red-400 bg-red-500/10 border-red-500/30',
    HIGH: 'text-orange-400 bg-orange-500/10 border-orange-500/30',
    MEDIUM: 'text-amber-400 bg-amber-500/10 border-amber-500/30',
    LOW: 'text-blue-400 bg-blue-500/10 border-blue-500/30',
  };
  const statusColor: Record<string, string> = {
    Open: 'text-red-400',
    Investigating: 'text-amber-400',
    Resolved: 'text-emerald-400',
  };
  return (
    <tr className="border-b border-slate-800/60 hover:bg-slate-800/30 transition-colors">
      <td className="py-3 px-4">
        <span className={`text-xs font-bold px-2 py-0.5 rounded border ${sevColor[severity]}`}>{severity}</span>
      </td>
      <td className="py-3 px-4 text-sm text-slate-300 font-mono">{device}</td>
      <td className="py-3 px-4 text-sm text-slate-400 max-w-xs truncate">{event}</td>
      <td className="py-3 px-4">
        <div className="flex items-center gap-2">
          <div className="flex-1 bg-slate-700 rounded-full h-1.5 w-16">
            <div
              className={`h-1.5 rounded-full ${cas >= 8 ? 'bg-red-500' : cas >= 6 ? 'bg-orange-500' : cas >= 4 ? 'bg-amber-500' : 'bg-blue-500'}`}
              style={{ width: `${(cas / 10) * 100}%` }}
            />
          </div>
          <span className="text-xs font-mono text-slate-400">{cas.toFixed(1)}</span>
        </div>
      </td>
      <td className="py-3 px-4 text-xs text-slate-500">{time}</td>
      <td className="py-3 px-4">
        <span className={`text-xs font-medium ${statusColor[status]}`}>{status}</span>
      </td>
    </tr>
  );
};

const MOCK_ALERTS = [
  { severity: 'CRITICAL' as const, device: 'ICU-VENT-04', event: 'Unauthorised firmware modification detected', cas: 9.6, time: '2 min ago', status: 'Open' as const },
  { severity: 'HIGH' as const, device: 'INF-PUMP-12', event: 'Anomalous network traffic to external IP', cas: 7.8, time: '8 min ago', status: 'Investigating' as const },
  { severity: 'HIGH' as const, device: 'CARDIAC-MON-7', event: 'Failed authentication — brute force pattern', cas: 7.2, time: '15 min ago', status: 'Investigating' as const },
  { severity: 'MEDIUM' as const, device: 'WORKSTATION-ER', event: 'Unusual process execution via PowerShell', cas: 5.4, time: '31 min ago', status: 'Open' as const },
  { severity: 'LOW' as const, device: 'NURSE-STATION-3', event: 'Port scan from internal subnet', cas: 2.1, time: '1 hr ago', status: 'Resolved' as const },
];

const AdminDashboard: React.FC = () => {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [activeNav, setActiveNav] = useState('Overview');

  const handleLogout = () => {
    logout();
    navigate('/');
  };

  const navItems = [
    { label: 'Overview', icon: <BarChart3 className="w-4 h-4" /> },
    { label: 'Alerts', icon: <Bell className="w-4 h-4" /> },
    { label: 'Devices', icon: <Server className="w-4 h-4" /> },
    { label: 'Users', icon: <Users className="w-4 h-4" /> },
    { label: 'IP Reputation', icon: <Network className="w-4 h-4" /> },
    { label: 'Wazuh SIEM', icon: <Shield className="w-4 h-4 text-cyan-400" /> },
    { label: 'Playbooks', icon: <Zap className="w-4 h-4" /> },
    { label: 'Audit Log', icon: <Database className="w-4 h-4" /> },
    { label: 'Settings', icon: <Settings className="w-4 h-4" /> },
  ];

  return (
    <div className="min-h-screen bg-slate-950 text-white flex flex-col">

      {/* ── Below-banner layout: sidebar + main ── */}
      <div className="flex flex-1 min-h-0">

        {/* Sidebar */}
        <aside
          className={`fixed inset-y-0 left-0 z-40 flex flex-col w-64 bg-slate-900 border-r border-slate-800 transition-transform duration-300 ${
            sidebarOpen ? 'translate-x-0' : '-translate-x-full'
          } lg:translate-x-0 lg:static lg:z-auto`}
        >
          {/* Logo */}
          <div className="flex items-center justify-between px-5 py-4 border-b border-slate-800">
            <div className="flex items-center gap-2.5">
              <div className="w-8 h-8 bg-gradient-to-br from-cyan-500 to-blue-600 rounded-lg flex items-center justify-center shadow-lg shadow-cyan-500/30">
                <Shield className="w-4 h-4 text-white" strokeWidth={2.5} />
              </div>
              <span className="font-bold text-sm text-white">
                Medi<span className="text-cyan-400">SIEM</span>
              </span>
            </div>
            <button onClick={() => setSidebarOpen(false)} className="lg:hidden text-slate-400 hover:text-white">
              <X className="w-4 h-4" />
            </button>
          </div>

          {/* Role Badge */}
          <div className="px-5 py-3 border-b border-slate-800">
            <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-red-500/10 border border-red-500/20">
              <Shield className="w-3.5 h-3.5 text-red-400" />
              <span className="text-xs font-bold text-red-400 uppercase tracking-wider">Admin Console</span>
            </div>
          </div>

          {/* Nav */}
          <nav className="flex-1 px-3 py-4 space-y-0.5 overflow-y-auto">
            {navItems.map((item) => (
              <button
                key={item.label}
                onClick={() => setActiveNav(item.label)}
                className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all text-left ${
                  activeNav === item.label
                    ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20'
                    : 'text-slate-400 hover:text-white hover:bg-slate-800'
                }`}
              >
                {item.icon}
                {item.label}
              </button>
            ))}
          </nav>

          {/* User */}
          <div className="px-4 py-4 border-t border-slate-800">
            <div className="flex items-center gap-3 mb-3">
              <div className="w-8 h-8 rounded-full bg-gradient-to-br from-red-400 to-orange-500 flex items-center justify-center text-xs font-bold text-white flex-shrink-0">
                {user?.name?.[0]?.toUpperCase()}
              </div>
              <div className="min-w-0">
                <div className="text-sm font-medium text-white truncate">{user?.name}</div>
                <div className="text-xs text-slate-500 truncate">{user?.email}</div>
              </div>
            </div>
            <button
              onClick={handleLogout}
              className="w-full flex items-center gap-2 px-3 py-2 text-sm text-slate-400 hover:text-red-400 hover:bg-red-500/10 rounded-lg transition-all"
            >
              <LogOut className="w-4 h-4" />
              Sign Out
            </button>
          </div>
        </aside>

        {/* Overlay for mobile */}
        {sidebarOpen && (
          <div className="fixed inset-0 z-30 bg-black/50 lg:hidden" onClick={() => setSidebarOpen(false)} />
        )}

        {/* Main */}
        <div className="flex-1 flex flex-col min-w-0">
          {/* Top bar */}
          <header className="sticky top-0 z-20 flex items-center justify-between px-5 py-3.5 bg-slate-950/90 backdrop-blur border-b border-slate-800">
            <div className="flex items-center gap-3">
              <button onClick={() => setSidebarOpen(true)} className="lg:hidden p-1.5 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition-colors">
                <Menu className="w-5 h-5" />
              </button>
              <div>
                <h1 className="text-sm font-bold text-white">Admin Dashboard</h1>
                <p className="text-xs text-slate-500 hidden sm:block">R26-CS-008 · MediSIEM Platform</p>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-500/10 border border-emerald-500/20">
                <span className="w-1.5 h-1.5 bg-emerald-400 rounded-full animate-pulse" />
                <span className="text-xs text-emerald-400 font-medium hidden sm:block">System Active</span>
              </div>
              <button className="relative p-2 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition-colors">
                <Bell className="w-4 h-4" />
                <span className="absolute top-1 right-1 w-1.5 h-1.5 bg-red-500 rounded-full" />
              </button>
              <div className="flex items-center gap-2 pl-3 border-l border-slate-800">
                <div className="w-7 h-7 rounded-full bg-gradient-to-br from-red-400 to-orange-500 flex items-center justify-center text-xs font-bold text-white">
                  {user?.name?.[0]?.toUpperCase()}
                </div>
                <ChevronDown className="w-3.5 h-3.5 text-slate-500" />
              </div>
            </div>
          </header>

          {/* Content */}
          <main className="flex-1 overflow-y-auto">
            {activeNav === 'Wazuh SIEM' && <WazuhDashboard />}
            {activeNav !== 'Wazuh SIEM' && <div className="p-5 space-y-6">
            {/* Stats */}
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
              <StatCard icon={<AlertTriangle className="w-5 h-5 text-red-400" />} label="Critical Alerts" value="3" sub="Requires immediate action" color="red" trend="+2" />
              <StatCard icon={<Activity className="w-5 h-5 text-cyan-400" />} label="Monitored Devices" value="47" sub="IoMT assets online" color="cyan" trend="+3" />
              <StatCard icon={<Users className="w-5 h-5 text-violet-400" />} label="Active Users" value="12" sub="SOC analysts online" color="violet" />
              <StatCard icon={<TrendingUp className="w-5 h-5 text-emerald-400" />} label="Alert Reduction" value="76%" sub="vs. last 30 days" color="emerald" trend="+12%" />
            </div>

            {/* CAS Overview + IP Reputation */}
            <div className="grid lg:grid-cols-3 gap-5">
              {/* CAS Distribution */}
              <div className="lg:col-span-2 p-5 rounded-2xl bg-slate-900 border border-slate-800">
                <div className="flex items-center justify-between mb-5">
                  <div>
                    <h2 className="font-semibold text-white">Clinical Alert Score (CAS) Distribution</h2>
                    <p className="text-xs text-slate-500 mt-0.5">TR × CC × TS — last 24 hours</p>
                  </div>
                  <span className="text-xs px-2.5 py-1 rounded-full bg-slate-800 border border-slate-700 text-slate-400">Live</span>
                </div>
                <div className="space-y-3">
                  {[
                    { label: 'Critical (8–10)', count: 3, pct: 6, color: 'bg-red-500' },
                    { label: 'High (6–8)', count: 9, pct: 18, color: 'bg-orange-500' },
                    { label: 'Medium (4–6)', count: 16, pct: 32, color: 'bg-amber-500' },
                    { label: 'Low (0–4)', count: 22, pct: 44, color: 'bg-blue-500' },
                  ].map((row) => (
                    <div key={row.label} className="flex items-center gap-3">
                      <div className="w-28 text-xs text-slate-400 flex-shrink-0">{row.label}</div>
                      <div className="flex-1 bg-slate-800 rounded-full h-2">
                        <div className={`${row.color} h-2 rounded-full transition-all`} style={{ width: `${row.pct}%` }} />
                      </div>
                      <div className="text-xs font-mono text-slate-400 w-10 text-right">{row.count}</div>
                    </div>
                  ))}
                </div>
              </div>

              {/* IP Reputation */}
              <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800">
                <h2 className="font-semibold text-white mb-1">IP Reputation</h2>
                <p className="text-xs text-slate-500 mb-5">Top suspicious sources</p>
                <div className="space-y-3">
                  {[
                    { ip: '185.220.101.x', score: 9.2, label: 'Malicious', color: 'text-red-400 bg-red-500/10' },
                    { ip: '92.118.160.x', score: 7.4, label: 'Suspicious', color: 'text-orange-400 bg-orange-500/10' },
                    { ip: '45.142.212.x', score: 6.1, label: 'Suspicious', color: 'text-amber-400 bg-amber-500/10' },
                    { ip: '10.0.14.22', score: 2.3, label: 'Internal', color: 'text-blue-400 bg-blue-500/10' },
                  ].map((ip) => (
                    <div key={ip.ip} className="flex items-center justify-between py-2 border-b border-slate-800/60 last:border-0">
                      <div>
                        <div className="text-sm font-mono text-slate-300">{ip.ip}</div>
                        <div className={`text-xs px-1.5 py-0.5 rounded mt-0.5 inline-block ${ip.color}`}>{ip.label}</div>
                      </div>
                      <div className="text-sm font-bold text-white">{ip.score}</div>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Alerts Table */}
            <div className="rounded-2xl bg-slate-900 border border-slate-800 overflow-hidden">
              <div className="flex items-center justify-between px-5 py-4 border-b border-slate-800">
                <div>
                  <h2 className="font-semibold text-white">Active Security Alerts</h2>
                  <p className="text-xs text-slate-500 mt-0.5">Sorted by Clinical Alert Score (CAS)</p>
                </div>
                <button className="px-3 py-1.5 text-xs rounded-lg bg-slate-800 border border-slate-700 text-slate-400 hover:text-white transition-colors">
                  View All
                </button>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr className="text-xs text-slate-500 uppercase tracking-wider border-b border-slate-800">
                      <th className="py-2.5 px-4 text-left">Severity</th>
                      <th className="py-2.5 px-4 text-left">Device</th>
                      <th className="py-2.5 px-4 text-left">Event</th>
                      <th className="py-2.5 px-4 text-left">CAS Score</th>
                      <th className="py-2.5 px-4 text-left">Time</th>
                      <th className="py-2.5 px-4 text-left">Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {MOCK_ALERTS.map((a) => (
                      <AlertRow key={a.device + a.time} {...a} />
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Life-Critical Status */}
            <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-4">
              {[
                { label: 'ICU Ventilators', status: 'Protected', icon: <CheckCircle className="w-4 h-4" />, color: 'emerald' },
                { label: 'Infusion Pumps', status: 'Protected', icon: <CheckCircle className="w-4 h-4" />, color: 'emerald' },
                { label: 'Cardiac Monitors', status: 'Monitoring', icon: <Clock className="w-4 h-4" />, color: 'amber' },
                { label: 'CT/MRI Systems', status: 'Alert Active', icon: <AlertCircle className="w-4 h-4" />, color: 'red' },
              ].map((item) => (
                <div key={item.label} className={`flex items-center gap-3 p-4 rounded-xl bg-${item.color}-500/5 border border-${item.color}-500/20`}>
                  <span className={`text-${item.color}-400`}>{item.icon}</span>
                  <div>
                    <div className="text-sm font-medium text-white">{item.label}</div>
                    <div className={`text-xs text-${item.color}-400`}>{item.status}</div>
                  </div>
                </div>
              ))}
            </div>

            {/* Footer */}
            <div className="text-center py-4 text-xs text-slate-700">
              MediSIEM Admin Console · R26-CS-008 · SLIIT 2026 · Logged in as {user?.name}
            </div>
            </div>}
          </main>
        </div>
      </div>
    </div>
  );
};

export default AdminDashboard;
