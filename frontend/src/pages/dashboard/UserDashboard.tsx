import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Shield,
  Heart,
  Calendar,
  FileText,
  Bell,
  LogOut,
  Activity,
  Thermometer,
  Droplets,
  Wind,
  TrendingUp,
  TrendingDown,
  Minus,
  ChevronRight,
  Clock,
  User,
  Download,
  CheckCircle2,
  AlertCircle,
  Info,
  X,
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';

// ─── Types ─────────────────────────────────────────────────────────────────────
type Tab = 'overview' | 'vitals' | 'appointments' | 'reports';

interface Vital {
  label: string;
  value: string;
  unit: string;
  status: 'normal' | 'warning' | 'critical';
  trend: 'up' | 'down' | 'stable';
  icon: React.ReactNode;
  color: string;
  history: number[];
}

interface Appointment {
  id: string;
  doctor: string;
  specialty: string;
  date: string;
  time: string;
  type: 'in-person' | 'virtual';
  status: 'upcoming' | 'completed' | 'cancelled';
}

interface Report {
  id: string;
  title: string;
  date: string;
  type: string;
  status: 'ready' | 'pending';
}

interface Notification {
  id: string;
  message: string;
  type: 'info' | 'warning' | 'success';
  time: string;
}

// ─── Mock Data ─────────────────────────────────────────────────────────────────
const VITALS: Vital[] = [
  {
    label: 'Heart Rate',
    value: '72',
    unit: 'bpm',
    status: 'normal',
    trend: 'stable',
    icon: <Heart className="w-5 h-5" />,
    color: 'rose',
    history: [68, 74, 70, 73, 71, 75, 72],
  },
  {
    label: 'Blood Pressure',
    value: '118/76',
    unit: 'mmHg',
    status: 'normal',
    trend: 'down',
    icon: <Activity className="w-5 h-5" />,
    color: 'cyan',
    history: [125, 122, 120, 119, 121, 118, 118],
  },
  {
    label: 'Temperature',
    value: '36.8',
    unit: '°C',
    status: 'normal',
    trend: 'stable',
    icon: <Thermometer className="w-5 h-5" />,
    color: 'orange',
    history: [36.5, 36.7, 36.9, 36.8, 36.6, 36.8, 36.8],
  },
  {
    label: 'Oxygen Sat.',
    value: '98',
    unit: '%',
    status: 'normal',
    trend: 'up',
    icon: <Droplets className="w-5 h-5" />,
    color: 'blue',
    history: [96, 97, 97, 98, 97, 98, 98],
  },
  {
    label: 'Resp. Rate',
    value: '16',
    unit: '/min',
    status: 'normal',
    trend: 'stable',
    icon: <Wind className="w-5 h-5" />,
    color: 'violet',
    history: [15, 16, 17, 16, 15, 16, 16],
  },
  {
    label: 'Blood Glucose',
    value: '104',
    unit: 'mg/dL',
    status: 'warning',
    trend: 'up',
    icon: <Activity className="w-5 h-5" />,
    color: 'amber',
    history: [95, 98, 100, 102, 103, 104, 104],
  },
];

const APPOINTMENTS: Appointment[] = [
  {
    id: 'a1',
    doctor: 'Dr. Ashan Perera',
    specialty: 'Cardiologist',
    date: '2025-04-15',
    time: '10:30 AM',
    type: 'in-person',
    status: 'upcoming',
  },
  {
    id: 'a2',
    doctor: 'Dr. Malini Fernando',
    specialty: 'General Physician',
    date: '2025-04-22',
    time: '02:00 PM',
    type: 'virtual',
    status: 'upcoming',
  },
  {
    id: 'a3',
    doctor: 'Dr. Ruwan Jayasuriya',
    specialty: 'Endocrinologist',
    date: '2025-03-28',
    time: '11:00 AM',
    type: 'in-person',
    status: 'completed',
  },
  {
    id: 'a4',
    doctor: 'Dr. Chamari Silva',
    specialty: 'Neurologist',
    date: '2025-03-10',
    time: '09:00 AM',
    type: 'virtual',
    status: 'completed',
  },
];

const REPORTS: Report[] = [
  { id: 'r1', title: 'Full Blood Count (FBC)', date: '2025-04-01', type: 'Lab Report', status: 'ready' },
  { id: 'r2', title: 'Lipid Profile', date: '2025-04-01', type: 'Lab Report', status: 'ready' },
  { id: 'r3', title: 'Chest X-Ray', date: '2025-03-28', type: 'Imaging', status: 'ready' },
  { id: 'r4', title: 'HbA1c Test', date: '2025-04-10', type: 'Lab Report', status: 'pending' },
  { id: 'r5', title: 'ECG Analysis', date: '2025-03-15', type: 'Cardiology', status: 'ready' },
];

const NOTIFICATIONS: Notification[] = [
  { id: 'n1', message: 'Your HbA1c test results will be ready in 2 days.', type: 'info', time: '2h ago' },
  { id: 'n2', message: 'Blood glucose slightly elevated. Consider dietary review.', type: 'warning', time: '1d ago' },
  { id: 'n3', message: 'Appointment with Dr. Perera confirmed for Apr 15.', type: 'success', time: '2d ago' },
];

// ─── Helpers ───────────────────────────────────────────────────────────────────
const statusColor = {
  normal: 'text-emerald-400',
  warning: 'text-amber-400',
  critical: 'text-red-400',
};

const statusBg = {
  normal: 'bg-emerald-500/10 border-emerald-500/20',
  warning: 'bg-amber-500/10 border-amber-500/20',
  critical: 'bg-red-500/10 border-red-500/20',
};

const trendIcon = {
  up: <TrendingUp className="w-3.5 h-3.5" />,
  down: <TrendingDown className="w-3.5 h-3.5" />,
  stable: <Minus className="w-3.5 h-3.5" />,
};

// Mini sparkline component
const Sparkline: React.FC<{ data: number[]; color: string }> = ({ data, color }) => {
  const min = Math.min(...data);
  const max = Math.max(...data);
  const range = max - min || 1;
  const w = 80;
  const h = 28;
  const points = data
    .map((v, i) => `${(i / (data.length - 1)) * w},${h - ((v - min) / range) * h}`)
    .join(' ');

  const colorMap: Record<string, string> = {
    rose: '#f43f5e',
    cyan: '#06b6d4',
    orange: '#f97316',
    blue: '#3b82f6',
    violet: '#8b5cf6',
    amber: '#f59e0b',
  };

  return (
    <svg width={w} height={h} className="opacity-70">
      <polyline
        points={points}
        fill="none"
        stroke={colorMap[color] || '#06b6d4'}
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
};

// ─── UserDashboard ─────────────────────────────────────────────────────────────
const UserDashboard: React.FC = () => {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState<Tab>('overview');
  const [notifications, setNotifications] = useState(NOTIFICATIONS);
  const [showNotifications, setShowNotifications] = useState(false);

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  const dismissNotification = (id: string) => {
    setNotifications((prev) => prev.filter((n) => n.id !== id));
  };

  const tabs: { id: Tab; label: string; icon: React.ReactNode }[] = [
    { id: 'overview', label: 'Overview', icon: <Activity className="w-4 h-4" /> },
    { id: 'vitals', label: 'Health Vitals', icon: <Heart className="w-4 h-4" /> },
    { id: 'appointments', label: 'Appointments', icon: <Calendar className="w-4 h-4" /> },
    { id: 'reports', label: 'Reports', icon: <FileText className="w-4 h-4" /> },
  ];

  return (
    <div className="min-h-screen bg-slate-950 text-white">
      {/* Background */}
      <div className="fixed inset-0 bg-[linear-gradient(rgba(6,182,212,0.02)_1px,transparent_1px),linear-gradient(90deg,rgba(6,182,212,0.02)_1px,transparent_1px)] bg-[size:48px_48px] pointer-events-none" />

      {/* ── Header ── */}
      <header className="sticky top-0 z-30 border-b border-slate-800/80 bg-slate-950/90 backdrop-blur-md">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            {/* Logo */}
            <div className="flex items-center gap-2.5">
              <div className="w-8 h-8 bg-gradient-to-br from-cyan-500 to-blue-600 rounded-lg flex items-center justify-center shadow-lg shadow-cyan-500/25">
                <Shield className="w-4 h-4 text-white" strokeWidth={2.5} />
              </div>
              <span className="font-bold text-lg text-white">
                Medi<span className="text-cyan-400">SIEM</span>
              </span>
            </div>

            {/* Right */}
            <div className="flex items-center gap-3">
              {/* Notifications */}
              <div className="relative">
                <button
                  onClick={() => setShowNotifications(!showNotifications)}
                  className="relative p-2 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
                >
                  <Bell className="w-5 h-5" />
                  {notifications.length > 0 && (
                    <span className="absolute top-1.5 right-1.5 w-2 h-2 bg-cyan-500 rounded-full" />
                  )}
                </button>

                {showNotifications && (
                  <div className="absolute right-0 top-12 w-80 bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl overflow-hidden z-50">
                    <div className="px-4 py-3 border-b border-slate-800">
                      <p className="text-sm font-semibold text-white">Notifications</p>
                    </div>
                    {notifications.length === 0 ? (
                      <p className="text-sm text-slate-500 text-center py-6">All caught up!</p>
                    ) : (
                      <div className="divide-y divide-slate-800">
                        {notifications.map((n) => (
                          <div key={n.id} className="flex items-start gap-3 px-4 py-3 hover:bg-slate-800/50 transition-colors">
                            <span className="mt-0.5 flex-shrink-0">
                              {n.type === 'warning' && <AlertCircle className="w-4 h-4 text-amber-400" />}
                              {n.type === 'success' && <CheckCircle2 className="w-4 h-4 text-emerald-400" />}
                              {n.type === 'info' && <Info className="w-4 h-4 text-cyan-400" />}
                            </span>
                            <div className="flex-1 min-w-0">
                              <p className="text-xs text-slate-300 leading-relaxed">{n.message}</p>
                              <p className="text-xs text-slate-600 mt-1">{n.time}</p>
                            </div>
                            <button
                              onClick={() => dismissNotification(n.id)}
                              className="text-slate-600 hover:text-slate-400 transition-colors flex-shrink-0"
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
              <div className="flex items-center gap-2 px-3 py-1.5 rounded-xl bg-slate-800/60 border border-slate-700">
                <div className="w-6 h-6 rounded-full bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center">
                  <User className="w-3.5 h-3.5 text-white" />
                </div>
                <span className="text-sm text-slate-300 hidden sm:block">{user?.name}</span>
              </div>

              {/* Logout */}
              <button
                onClick={handleLogout}
                className="flex items-center gap-2 px-3 py-1.5 rounded-xl text-slate-400 hover:text-white hover:bg-slate-800 border border-transparent hover:border-slate-700 transition-all text-sm"
              >
                <LogOut className="w-4 h-4" />
                <span className="hidden sm:block">Logout</span>
              </button>
            </div>
          </div>
        </div>
      </header>

      {/* ── Main ── */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Page title */}
        <div className="mb-8">
          <h1 className="text-2xl font-bold text-white">
            Good morning, <span className="text-cyan-400">{user?.name?.split(' ')[0]}</span> 👋
          </h1>
          <p className="text-slate-500 text-sm mt-1">
            Here's an overview of your health status · Last updated: {new Date().toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' })}
          </p>
        </div>

        {/* Tabs */}
        <div className="flex gap-1 p-1 bg-slate-900 border border-slate-800 rounded-2xl mb-8 w-fit">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-medium transition-all ${
                activeTab === tab.id
                  ? 'bg-gradient-to-r from-cyan-500 to-blue-600 text-white shadow-lg shadow-cyan-500/25'
                  : 'text-slate-400 hover:text-white hover:bg-slate-800'
              }`}
            >
              {tab.icon}
              <span className="hidden sm:block">{tab.label}</span>
            </button>
          ))}
        </div>

        {/* ── OVERVIEW TAB ── */}
        {activeTab === 'overview' && (
          <div className="space-y-6">
            {/* Quick stats row */}
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
              {[
                { label: 'Active Alerts', value: '1', icon: <AlertCircle className="w-5 h-5" />, color: 'amber', sub: 'Blood glucose' },
                { label: 'Next Appointment', value: 'Apr 15', icon: <Calendar className="w-5 h-5" />, color: 'cyan', sub: 'Dr. Perera' },
                { label: 'Reports Ready', value: '4', icon: <FileText className="w-5 h-5" />, color: 'violet', sub: '1 pending' },
                { label: 'Health Score', value: '87%', icon: <Heart className="w-5 h-5" />, color: 'emerald', sub: 'Good condition' },
              ].map((stat) => (
                <div
                  key={stat.label}
                  className="p-5 rounded-2xl bg-slate-900/80 border border-slate-800 hover:border-slate-700 transition-colors"
                >
                  <div className={`w-9 h-9 rounded-xl flex items-center justify-center mb-3 ${
                    stat.color === 'amber' ? 'bg-amber-500/15 text-amber-400' :
                    stat.color === 'cyan' ? 'bg-cyan-500/15 text-cyan-400' :
                    stat.color === 'violet' ? 'bg-violet-500/15 text-violet-400' :
                    'bg-emerald-500/15 text-emerald-400'
                  }`}>
                    {stat.icon}
                  </div>
                  <p className="text-2xl font-bold text-white">{stat.value}</p>
                  <p className="text-xs text-slate-400 mt-0.5">{stat.label}</p>
                  <p className="text-xs text-slate-600 mt-1">{stat.sub}</p>
                </div>
              ))}
            </div>

            {/* Vitals summary */}
            <div>
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-base font-semibold text-white">Today's Vitals</h2>
                <button
                  onClick={() => setActiveTab('vitals')}
                  className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
                >
                  View all <ChevronRight className="w-3.5 h-3.5" />
                </button>
              </div>
              <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                {VITALS.map((v) => (
                  <VitalCard key={v.label} vital={v} compact />
                ))}
              </div>
            </div>

            {/* Next appointment + recent activity in 2 cols */}
            <div className="grid md:grid-cols-2 gap-4">
              {/* Upcoming */}
              <div className="p-5 rounded-2xl bg-slate-900/80 border border-slate-800">
                <div className="flex items-center justify-between mb-4">
                  <h2 className="text-base font-semibold text-white">Upcoming Appointments</h2>
                  <button onClick={() => setActiveTab('appointments')} className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1">
                    All <ChevronRight className="w-3.5 h-3.5" />
                  </button>
                </div>
                <div className="space-y-3">
                  {APPOINTMENTS.filter((a) => a.status === 'upcoming').map((a) => (
                    <AppointmentRow key={a.id} appointment={a} />
                  ))}
                </div>
              </div>

              {/* Recent Reports */}
              <div className="p-5 rounded-2xl bg-slate-900/80 border border-slate-800">
                <div className="flex items-center justify-between mb-4">
                  <h2 className="text-base font-semibold text-white">Recent Reports</h2>
                  <button onClick={() => setActiveTab('reports')} className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1">
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
          </div>
        )}

        {/* ── VITALS TAB ── */}
        {activeTab === 'vitals' && (
          <div className="space-y-6">
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-semibold text-white">Health Vitals</h2>
              <span className="text-xs text-slate-500 flex items-center gap-1.5">
                <Clock className="w-3.5 h-3.5" /> Updated today
              </span>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
              {VITALS.map((v) => (
                <VitalCard key={v.label} vital={v} />
              ))}
            </div>

            {/* Alert card for warning vitals */}
            {VITALS.filter((v) => v.status !== 'normal').length > 0 && (
              <div className="p-5 rounded-2xl bg-amber-500/8 border border-amber-500/20">
                <div className="flex items-start gap-3">
                  <AlertCircle className="w-5 h-5 text-amber-400 flex-shrink-0 mt-0.5" />
                  <div>
                    <p className="text-sm font-semibold text-amber-300 mb-1">Attention Required</p>
                    <p className="text-xs text-amber-400/70 leading-relaxed">
                      Your blood glucose is slightly above the normal range (70–100 mg/dL). Consider reviewing your dietary intake and consult your endocrinologist if it persists.
                    </p>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* ── APPOINTMENTS TAB ── */}
        {activeTab === 'appointments' && (
          <div className="space-y-6">
            <h2 className="text-lg font-semibold text-white">Your Appointments</h2>

            <div>
              <p className="text-xs font-semibold text-slate-500 uppercase tracking-widest mb-3">Upcoming</p>
              <div className="space-y-3">
                {APPOINTMENTS.filter((a) => a.status === 'upcoming').map((a) => (
                  <AppointmentCard key={a.id} appointment={a} />
                ))}
              </div>
            </div>

            <div>
              <p className="text-xs font-semibold text-slate-500 uppercase tracking-widest mb-3">Past</p>
              <div className="space-y-3 opacity-70">
                {APPOINTMENTS.filter((a) => a.status === 'completed').map((a) => (
                  <AppointmentCard key={a.id} appointment={a} />
                ))}
              </div>
            </div>
          </div>
        )}

        {/* ── REPORTS TAB ── */}
        {activeTab === 'reports' && (
          <div className="space-y-6">
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-semibold text-white">Medical Reports</h2>
              <span className="text-xs text-slate-500">{REPORTS.filter((r) => r.status === 'ready').length} ready to download</span>
            </div>
            <div className="space-y-3">
              {REPORTS.map((r) => (
                <ReportCard key={r.id} report={r} />
              ))}
            </div>
          </div>
        )}
      </main>
    </div>
  );
};

// ─── Sub-components ────────────────────────────────────────────────────────────

const VitalCard: React.FC<{ vital: Vital; compact?: boolean }> = ({ vital, compact }) => {
  const colorMap: Record<string, string> = {
    rose: 'bg-rose-500/10 text-rose-400 border-rose-500/20',
    cyan: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/20',
    orange: 'bg-orange-500/10 text-orange-400 border-orange-500/20',
    blue: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
    violet: 'bg-violet-500/10 text-violet-400 border-violet-500/20',
    amber: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
  };

  return (
    <div className={`rounded-2xl bg-slate-900/80 border transition-colors hover:border-slate-700 ${
      vital.status === 'warning' ? 'border-amber-500/30' : 'border-slate-800'
    } ${compact ? 'p-4' : 'p-5'}`}>
      <div className="flex items-start justify-between mb-3">
        <div className={`w-8 h-8 rounded-lg flex items-center justify-center border ${colorMap[vital.color]}`}>
          {vital.icon}
        </div>
        <span className={`flex items-center gap-1 text-xs font-medium ${statusColor[vital.status]}`}>
          {trendIcon[vital.trend]}
          {vital.status}
        </span>
      </div>
      <p className={`font-bold text-white ${compact ? 'text-xl' : 'text-2xl'}`}>
        {vital.value}
        <span className="text-sm font-normal text-slate-500 ml-1">{vital.unit}</span>
      </p>
      <p className="text-xs text-slate-400 mt-0.5">{vital.label}</p>
      {!compact && (
        <div className="mt-3 pt-3 border-t border-slate-800">
          <Sparkline data={vital.history} color={vital.color} />
          <p className="text-xs text-slate-600 mt-1">7-day trend</p>
        </div>
      )}
    </div>
  );
};

const AppointmentRow: React.FC<{ appointment: Appointment }> = ({ appointment }) => (
  <div className="flex items-center gap-3">
    <div className="w-8 h-8 rounded-xl bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center flex-shrink-0">
      <Calendar className="w-4 h-4 text-cyan-400" />
    </div>
    <div className="flex-1 min-w-0">
      <p className="text-sm text-white font-medium truncate">{appointment.doctor}</p>
      <p className="text-xs text-slate-500">{appointment.date} · {appointment.time}</p>
    </div>
    <span className={`text-xs px-2 py-0.5 rounded-full ${
      appointment.type === 'virtual'
        ? 'bg-violet-500/10 text-violet-400 border border-violet-500/20'
        : 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20'
    }`}>
      {appointment.type}
    </span>
  </div>
);

const AppointmentCard: React.FC<{ appointment: Appointment }> = ({ appointment }) => (
  <div className="flex items-center gap-4 p-4 rounded-2xl bg-slate-900/80 border border-slate-800 hover:border-slate-700 transition-colors">
    <div className="w-12 h-12 rounded-2xl bg-slate-800 flex flex-col items-center justify-center flex-shrink-0">
      <span className="text-xs text-slate-500 leading-none">
        {new Date(appointment.date).toLocaleString('default', { month: 'short' })}
      </span>
      <span className="text-lg font-bold text-white leading-tight">
        {new Date(appointment.date).getDate()}
      </span>
    </div>
    <div className="flex-1 min-w-0">
      <p className="text-sm font-semibold text-white">{appointment.doctor}</p>
      <p className="text-xs text-slate-400">{appointment.specialty}</p>
      <p className="text-xs text-slate-500 mt-1 flex items-center gap-1">
        <Clock className="w-3 h-3" />
        {appointment.time}
      </p>
    </div>
    <div className="flex flex-col items-end gap-2">
      <span className={`text-xs px-2 py-0.5 rounded-full border ${
        appointment.type === 'virtual'
          ? 'bg-violet-500/10 text-violet-400 border-violet-500/20'
          : 'bg-cyan-500/10 text-cyan-400 border-cyan-500/20'
      }`}>
        {appointment.type}
      </span>
      <span className={`text-xs px-2 py-0.5 rounded-full border ${
        appointment.status === 'upcoming'
          ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
          : 'bg-slate-700/50 text-slate-400 border-slate-700'
      }`}>
        {appointment.status}
      </span>
    </div>
  </div>
);

const ReportRow: React.FC<{ report: Report }> = ({ report }) => (
  <div className="flex items-center gap-3">
    <div className="w-8 h-8 rounded-xl bg-violet-500/10 border border-violet-500/20 flex items-center justify-center flex-shrink-0">
      <FileText className="w-4 h-4 text-violet-400" />
    </div>
    <div className="flex-1 min-w-0">
      <p className="text-sm text-white font-medium truncate">{report.title}</p>
      <p className="text-xs text-slate-500">{report.date}</p>
    </div>
    <span className={`text-xs px-2 py-0.5 rounded-full border ${
      report.status === 'ready'
        ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
        : 'bg-slate-700/50 text-slate-400 border-slate-700'
    }`}>
      {report.status}
    </span>
  </div>
);

const ReportCard: React.FC<{ report: Report }> = ({ report }) => (
  <div className="flex items-center gap-4 p-4 rounded-2xl bg-slate-900/80 border border-slate-800 hover:border-slate-700 transition-colors">
    <div className="w-10 h-10 rounded-xl bg-violet-500/10 border border-violet-500/20 flex items-center justify-center flex-shrink-0">
      <FileText className="w-5 h-5 text-violet-400" />
    </div>
    <div className="flex-1 min-w-0">
      <p className="text-sm font-semibold text-white">{report.title}</p>
      <p className="text-xs text-slate-400">{report.type} · {report.date}</p>
    </div>
    {report.status === 'ready' ? (
      <button className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 hover:bg-cyan-500/20 transition-colors text-xs font-medium">
        <Download className="w-3.5 h-3.5" />
        Download
      </button>
    ) : (
      <span className="flex items-center gap-1.5 text-xs text-slate-500">
        <Clock className="w-3.5 h-3.5" />
        Pending
      </span>
    )}
  </div>
);

export default UserDashboard;