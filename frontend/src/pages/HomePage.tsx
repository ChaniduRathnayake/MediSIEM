import React from 'react';
import { Link } from 'react-router-dom';
import {
  Shield, Activity, Brain, AlertTriangle, ChevronRight,
  ArrowRight, Zap, Lock, Eye
} from 'lucide-react';

// ─── Stat ─────────────────────────────────────────────────────────────────────
const Stat: React.FC<{ value: string; label: string }> = ({ value, label }) => (
  <div className="flex-1 min-w-[140px] px-6 py-5 first:pl-0 last:pr-0">
    <div className="text-2xl font-bold text-slate-900 dark:text-white tabular-nums">{value}</div>
    <div className="text-xs text-slate-400 dark:text-slate-500 mt-1">{label}</div>
  </div>
);

// ─── Feature Card ─────────────────────────────────────────────────────────────
const FeatureCard: React.FC<{
  icon: React.ReactNode;
  title: string;
  desc: string;
}> = ({ icon, title, desc }) => (
  <div className="p-6 rounded-lg bg-white dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:border-slate-700 transition-colors">
    <div className="w-9 h-9 rounded-md bg-slate-100 dark:bg-slate-800 flex items-center justify-center mb-4">
      {icon}
    </div>
    <h3 className="text-slate-900 dark:text-white font-semibold mb-1.5 text-sm">{title}</h3>
    <p className="text-slate-500 dark:text-slate-400 text-sm leading-relaxed">{desc}</p>
  </div>
);

const HomePage: React.FC = () => {
  return (
    <div className="bg-white dark:bg-slate-950 min-h-screen text-slate-900 dark:text-white">
      {/* ── Hero ── */}
      <section className="pt-36 pb-20 px-4">
        <div className="max-w-4xl mx-auto text-center animate-fade-up">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-md border border-slate-200 dark:border-slate-800 text-slate-500 dark:text-slate-400 text-xs font-medium mb-7 tracking-wide">
            R26-CS-008 · SLIIT Research Project
          </div>

          <h1 className="text-4xl md:text-5xl lg:text-6xl font-bold leading-[1.1] mb-6 tracking-tight">
            Clinical-context <span className="text-cyan-400">SIEM &amp; IDS</span>
            <br />
            for hospital networks
          </h1>

          <p className="text-base md:text-lg text-slate-500 dark:text-slate-400 max-w-2xl mx-auto mb-10 leading-relaxed">
            Clinically aware alert prioritisation, life-critical incident response
            orchestration, and context-aware IP protection — purpose-built for healthcare.
          </p>

          <div className="flex flex-col sm:flex-row gap-3 justify-center">
            <Link
              to="/login"
              className="flex items-center justify-center gap-2 px-6 py-3 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold rounded-md transition-colors"
            >
              Sign In <ChevronRight className="w-4 h-4" />
            </Link>
            <Link
              to="/about"
              className="flex items-center justify-center gap-2 px-6 py-3 bg-transparent hover:bg-slate-100 dark:hover:bg-white/5 text-slate-900 dark:text-white font-semibold rounded-md transition-colors border border-slate-300 dark:border-slate-700"
            >
              Learn More <ArrowRight className="w-4 h-4" />
            </Link>
          </div>
        </div>
      </section>

      {/* ── Stats strip ── */}
      <section className="px-4 border-y border-slate-200 dark:border-slate-800">
        <div className="max-w-5xl mx-auto flex flex-wrap justify-center divide-x divide-slate-200 dark:divide-slate-800">
          <Stat value="80%" label="Alert fatigue reduction" />
          <Stat value="≤5%" label="Accidental disruption rate" />
          <Stat value="3×" label="Faster threat response" />
          <Stat value="24/7" label="Clinical monitoring" />
        </div>
      </section>

      {/* ── Problem Statement ── */}
      <section className="py-20 px-4">
        <div className="max-w-5xl mx-auto">
          <div className="max-w-2xl mb-12">
            <h2 className="text-2xl md:text-3xl font-bold mb-3">
              Traditional SIEM wasn't built for hospitals
            </h2>
            <p className="text-slate-500 dark:text-slate-400 leading-relaxed">
              Healthcare environments are uniquely vulnerable. Standard security tools
              have no concept of clinical risk.
            </p>
          </div>

          <div className="grid md:grid-cols-2 gap-px bg-slate-100 dark:bg-slate-800 rounded-lg overflow-hidden border border-slate-200 dark:border-slate-800">
            {[
              {
                icon: <AlertTriangle className="w-4 h-4 text-amber-400" />,
                title: 'Alert fatigue',
                desc: 'Thousands of low-context alerts overwhelm SOC analysts daily, causing critical threats to be missed.',
              },
              {
                icon: <Activity className="w-4 h-4 text-red-400" />,
                title: 'No clinical awareness',
                desc: 'Traditional SIEM treats all assets equally — an ICU ventilator and a printer get the same priority score.',
              },
              {
                icon: <Lock className="w-4 h-4 text-orange-400" />,
                title: 'Dangerous auto-responses',
                desc: 'SOAR playbooks may automatically isolate life-sustaining devices, directly endangering patient safety.',
              },
              {
                icon: <Eye className="w-4 h-4 text-slate-500 dark:text-slate-400" />,
                title: 'Missing IP context',
                desc: 'No reputation intelligence about network entities leaves analysts blind to malicious sources.',
              },
            ].map((item) => (
              <div key={item.title} className="flex gap-4 p-6 bg-white dark:bg-slate-950">
                <div className="mt-0.5 flex-shrink-0">{item.icon}</div>
                <div>
                  <h3 className="font-semibold text-slate-900 dark:text-white mb-1 text-sm">{item.title}</h3>
                  <p className="text-sm text-slate-500 dark:text-slate-400 leading-relaxed">{item.desc}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── Features ── */}
      <section className="py-20 px-4 bg-slate-50 dark:bg-slate-900/20 border-t border-slate-200 dark:border-slate-800">
        <div className="max-w-6xl mx-auto">
          <div className="max-w-2xl mb-12">
            <h2 className="text-2xl md:text-3xl font-bold mb-3">
              Three pillars of clinical security
            </h2>
            <p className="text-slate-500 dark:text-slate-400 leading-relaxed">
              Each component addresses a specific gap in healthcare cybersecurity —
              independently useful, more effective combined.
            </p>
          </div>

          <div className="grid md:grid-cols-3 gap-4">
            <FeatureCard
              icon={<Brain className="w-4.5 h-4.5 text-cyan-400" />}
              title="Clinical Alert Prioritisation"
              desc="CAS = TR × CC × TS — a multi-dimensional scoring model combining technical risk, clinical criticality, and time sensitivity."
            />
            <FeatureCard
              icon={<Shield className="w-4.5 h-4.5 text-emerald-400" />}
              title="Life-Critical Orchestration"
              desc="Safety-first incident response with human-in-the-loop clinician approval before any action on life-sustaining devices."
            />
            <FeatureCard
              icon={<Zap className="w-4.5 h-4.5 text-violet-400" />}
              title="Context-Aware IP Protection"
              desc="Dynamic IP reputation scoring with threat intelligence feeds enriches every alert with actionable context."
            />
          </div>
        </div>
      </section>

      {/* ── Technology Stack ── */}
      <section className="py-20 px-4">
        <div className="max-w-5xl mx-auto text-center">
          <h2 className="text-xl font-bold mb-2">Built on trusted technology</h2>
          <p className="text-slate-500 dark:text-slate-400 mb-8 text-sm">Open-source foundation with purpose-built clinical intelligence.</p>
          <div className="flex flex-wrap justify-center gap-2">
            {['Wazuh SIEM', 'ELK Stack', 'Suricata IDS', 'Python', 'Scikit-learn', 'Isolation Forest', 'MISP Threat Intel', 'Blockchain Ledger', 'Shuffle SOAR', 'Kibana', 'Grafana', 'React'].map((tech) => (
              <span key={tech} className="px-3 py-1.5 rounded-md bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-sm text-slate-500 dark:text-slate-400">
                {tech}
              </span>
            ))}
          </div>
        </div>
      </section>

      {/* ── CTA ── */}
      <section className="py-20 px-4 border-t border-slate-200 dark:border-slate-800">
        <div className="max-w-4xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-6 p-8 rounded-lg bg-white dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800">
          <div>
            <h2 className="text-xl font-bold mb-1">Sign in to the MediSIEM platform</h2>
            <p className="text-slate-500 dark:text-slate-400 text-sm">Bring clinical intelligence into your SOC workflow.</p>
          </div>
          <div className="flex gap-3 flex-shrink-0">
            <Link
              to="/login"
              className="flex items-center justify-center gap-2 px-5 py-2.5 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold rounded-md transition-colors text-sm"
            >
              Sign In <ChevronRight className="w-4 h-4" />
            </Link>
            <Link
              to="/pricing"
              className="flex items-center justify-center gap-2 px-5 py-2.5 bg-transparent hover:bg-slate-100 dark:hover:bg-white/5 text-slate-900 dark:text-white font-semibold rounded-md transition-colors border border-slate-300 dark:border-slate-700 text-sm"
            >
              View Pricing
            </Link>
          </div>
        </div>
      </section>
    </div>
  );
};

export default HomePage;
