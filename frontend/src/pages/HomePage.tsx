import React from 'react';
import { Link } from 'react-router-dom';
import {
  Shield, Activity, Brain, AlertTriangle, ChevronRight,
  CheckCircle, ArrowRight, Zap, Lock, Eye
} from 'lucide-react';

// ─── Animated grid background ─────────────────────────────────────────────────
const GridBg: React.FC = () => (
  <div className="absolute inset-0 overflow-hidden pointer-events-none">
    <div className="absolute inset-0 bg-[linear-gradient(rgba(6,182,212,0.03)_1px,transparent_1px),linear-gradient(90deg,rgba(6,182,212,0.03)_1px,transparent_1px)] bg-[size:48px_48px]" />
    <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[800px] h-[500px] bg-gradient-radial from-cyan-500/10 via-blue-600/5 to-transparent rounded-full blur-3xl" />
  </div>
);

// ─── Stat Card ────────────────────────────────────────────────────────────────
const StatCard: React.FC<{ value: string; label: string; color: string }> = ({ value, label, color }) => (
  <div className={`text-center p-6 rounded-2xl bg-slate-900/60 border border-slate-700/50 backdrop-blur`}>
    <div className={`text-3xl font-black ${color} mb-1`}>{value}</div>
    <div className="text-sm text-slate-400">{label}</div>
  </div>
);

// ─── Feature Card ─────────────────────────────────────────────────────────────
const FeatureCard: React.FC<{
  icon: React.ReactNode;
  title: string;
  desc: string;
  accent: string;
}> = ({ icon, title, desc, accent }) => (
  <div className={`group p-6 rounded-2xl bg-slate-900/60 border border-slate-800 hover:border-${accent}-500/40 backdrop-blur transition-all hover:shadow-lg hover:shadow-${accent}-500/5`}>
    <div className={`w-12 h-12 rounded-xl bg-${accent}-500/10 flex items-center justify-center mb-4 group-hover:bg-${accent}-500/20 transition-colors`}>
      {icon}
    </div>
    <h3 className="text-white font-semibold mb-2">{title}</h3>
    <p className="text-slate-400 text-sm leading-relaxed">{desc}</p>
  </div>
);

const HomePage: React.FC = () => {
  return (
    <div className="bg-slate-950 min-h-screen text-white">
      {/* ── Hero ── */}
      <section className="relative pt-32 pb-24 px-4 overflow-hidden">
        <GridBg />
        <div className="relative max-w-5xl mx-auto text-center">
          {/* Badge */}
          <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 text-xs font-medium mb-8">
            <span className="w-1.5 h-1.5 bg-cyan-400 rounded-full animate-pulse" />
            R26-CS-008 · SLIIT Research Project 2026
          </div>

          <h1 className="text-5xl md:text-6xl lg:text-7xl font-black leading-[1.05] mb-6">
            Next-Gen{' '}
            <span className="bg-gradient-to-r from-cyan-400 via-blue-400 to-cyan-300 bg-clip-text text-transparent">
              SIEM / IDS
            </span>
            <br />
            for Smart Hospitals
          </h1>

          <p className="text-lg text-slate-400 max-w-2xl mx-auto mb-10 leading-relaxed">
            Clinically aware alert prioritisation, life-critical incident response
            orchestration, and context-aware IP protection — purpose-built for healthcare.
          </p>

          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            <Link
              to="/register"
              className="flex items-center justify-center gap-2 px-7 py-3.5 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white font-semibold rounded-xl transition-all shadow-xl shadow-cyan-500/25 hover:shadow-cyan-500/40 hover:-translate-y-0.5"
            >
              Get Early Access <ChevronRight className="w-4 h-4" />
            </Link>
            <Link
              to="/about"
              className="flex items-center justify-center gap-2 px-7 py-3.5 bg-slate-800 hover:bg-slate-700 text-white font-semibold rounded-xl transition-all border border-slate-700"
            >
              Learn More <ArrowRight className="w-4 h-4" />
            </Link>
          </div>
        </div>
      </section>

      {/* ── Stats ── */}
      <section className="py-12 px-4">
        <div className="max-w-5xl mx-auto grid grid-cols-2 md:grid-cols-4 gap-4">
          <StatCard value="80%" label="Alert Fatigue Reduction" color="text-cyan-400" />
          <StatCard value="≤5%" label="Accidental Disruption Rate" color="text-emerald-400" />
          <StatCard value="3×" label="Faster Threat Response" color="text-blue-400" />
          <StatCard value="24/7" label="Clinical Monitoring" color="text-violet-400" />
        </div>
      </section>

      {/* ── Problem Statement ── */}
      <section className="py-20 px-4">
        <div className="max-w-5xl mx-auto">
          <div className="text-center mb-14">
            <h2 className="text-3xl md:text-4xl font-bold mb-4">
              The Problem with Traditional SIEM
            </h2>
            <p className="text-slate-400 max-w-2xl mx-auto">
              Healthcare environments are uniquely vulnerable. Standard security tools aren't built for hospitals.
            </p>
          </div>

          <div className="grid md:grid-cols-2 gap-6">
            {[
              {
                icon: <AlertTriangle className="w-5 h-5 text-amber-400" />,
                title: 'Alert Fatigue',
                desc: 'Thousands of low-context alerts overwhelm SOC analysts daily, causing critical threats to be missed.',
              },
              {
                icon: <Activity className="w-5 h-5 text-red-400" />,
                title: 'No Clinical Awareness',
                desc: 'Traditional SIEM treats all assets equally — an ICU ventilator and a printer get the same priority score.',
              },
              {
                icon: <Lock className="w-5 h-5 text-orange-400" />,
                title: 'Dangerous Auto-Responses',
                desc: 'SOAR playbooks may automatically isolate life-sustaining devices, directly endangering patient safety.',
              },
              {
                icon: <Eye className="w-5 h-5 text-rose-400" />,
                title: 'Missing IP Context',
                desc: 'No reputation intelligence about network entities leaves analysts blind to malicious sources.',
              },
            ].map((item) => (
              <div key={item.title} className="flex gap-4 p-5 rounded-2xl bg-slate-900/50 border border-slate-800">
                <div className="mt-0.5 flex-shrink-0">{item.icon}</div>
                <div>
                  <h3 className="font-semibold text-white mb-1">{item.title}</h3>
                  <p className="text-sm text-slate-400 leading-relaxed">{item.desc}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── Features ── */}
      <section className="py-20 px-4 bg-slate-900/30">
        <div className="max-w-6xl mx-auto">
          <div className="text-center mb-14">
            <h2 className="text-3xl md:text-4xl font-bold mb-4">
              Three Pillars of{' '}
              <span className="text-cyan-400">Clinical Security</span>
            </h2>
            <p className="text-slate-400 max-w-2xl mx-auto">
              Each component of MediSIEM is designed to address a specific gap in healthcare cybersecurity.
            </p>
          </div>

          <div className="grid md:grid-cols-3 gap-6">
            <FeatureCard
              icon={<Brain className="w-6 h-6 text-cyan-400" />}
              title="Clinical Alert Prioritisation"
              desc="CAS = TR × CC × TS — a multi-dimensional scoring model combining Technical Risk, Clinical Criticality, and Time Sensitivity."
              accent="cyan"
            />
            <FeatureCard
              icon={<Shield className="w-6 h-6 text-emerald-400" />}
              title="Life-Critical Orchestration"
              desc="Safety-first incident response with human-in-the-loop clinician approval before any action on life-sustaining devices."
              accent="emerald"
            />
            <FeatureCard
              icon={<Zap className="w-6 h-6 text-violet-400" />}
              title="Context-Aware IP Protection"
              desc="Dynamic IP reputation scoring with threat intelligence feeds enriches every alert with actionable context."
              accent="violet"
            />
          </div>
        </div>
      </section>

      {/* ── Technology Stack ── */}
      <section className="py-20 px-4">
        <div className="max-w-5xl mx-auto text-center">
          <h2 className="text-3xl font-bold mb-4">Built on Trusted Technology</h2>
          <p className="text-slate-400 mb-10">Open-source foundation with proprietary clinical intelligence.</p>
          <div className="flex flex-wrap justify-center gap-3">
            {['Wazuh SIEM', 'ELK Stack', 'Suricata IDS', 'Python', 'Scikit-learn', 'Isolation Forest', 'MISP Threat Intel', 'Blockchain Ledger', 'Shuffle SOAR', 'Kibana', 'Grafana', 'React'].map((tech) => (
              <span key={tech} className="px-4 py-2 rounded-full bg-slate-800 border border-slate-700 text-sm text-slate-300 hover:border-cyan-500/50 hover:text-cyan-400 transition-colors cursor-default">
                {tech}
              </span>
            ))}
          </div>
        </div>
      </section>

      {/* ── CTA ── */}
      <section className="py-24 px-4">
        <div className="max-w-3xl mx-auto text-center">
          <div className="relative p-10 rounded-3xl bg-gradient-to-br from-cyan-500/10 via-blue-600/10 to-violet-500/10 border border-cyan-500/20 overflow-hidden">
            <div className="absolute inset-0 bg-[linear-gradient(rgba(6,182,212,0.03)_1px,transparent_1px),linear-gradient(90deg,rgba(6,182,212,0.03)_1px,transparent_1px)] bg-[size:24px_24px]" />
            <div className="relative">
              <Shield className="w-14 h-14 text-cyan-400 mx-auto mb-5" />
              <h2 className="text-3xl font-bold mb-4">Protect Your Hospital Today</h2>
              <p className="text-slate-400 mb-8 max-w-xl mx-auto">
                Join the MediSIEM platform and bring clinical intelligence into your SOC.
              </p>
              <div className="flex flex-col sm:flex-row gap-4 justify-center">
                <Link
                  to="/register"
                  className="flex items-center justify-center gap-2 px-7 py-3.5 bg-gradient-to-r from-cyan-500 to-blue-600 text-white font-semibold rounded-xl hover:from-cyan-400 hover:to-blue-500 transition-all shadow-xl shadow-cyan-500/25"
                >
                  Create Free Account <ChevronRight className="w-4 h-4" />
                </Link>
                <Link
                  to="/pricing"
                  className="flex items-center justify-center gap-2 px-7 py-3.5 bg-slate-800 text-white font-semibold rounded-xl hover:bg-slate-700 transition-all border border-slate-700"
                >
                  View Pricing
                </Link>
              </div>
              <div className="mt-6 flex items-center justify-center gap-2 text-sm text-slate-500">
                <CheckCircle className="w-4 h-4 text-emerald-500" />
                <span>No credit card required · Free tier available</span>
              </div>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
};

export default HomePage;
