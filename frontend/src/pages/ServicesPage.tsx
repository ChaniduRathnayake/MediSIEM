import React from 'react';
import { Link } from 'react-router-dom';
import { Brain, Shield, Zap, Network, BarChart3, Bell, ChevronRight, CheckCircle } from 'lucide-react';

type Accent = 'cyan' | 'emerald' | 'violet';

const accentText: Record<Accent, string> = {
  cyan: 'text-cyan-400',
  emerald: 'text-emerald-400',
  violet: 'text-violet-400',
};
const accentCheck: Record<Accent, string> = {
  cyan: 'text-cyan-500',
  emerald: 'text-emerald-500',
  violet: 'text-violet-500',
};
const accentPill: Record<Accent, string> = {
  cyan: 'bg-cyan-500/10 text-cyan-300 border-cyan-500/20',
  emerald: 'bg-emerald-500/10 text-emerald-300 border-emerald-500/20',
  violet: 'bg-violet-500/10 text-violet-300 border-violet-500/20',
};

const services: {
  icon: React.ReactNode;
  badge: string;
  title: string;
  subtitle: string;
  accent: Accent;
  description: string;
  formula: string;
  formulaDesc: string;
  features: string[];
  stack: string[];
  datasets: string[];
}[] = [
  {
    icon: <Brain className="w-5 h-5 text-cyan-400" />,
    badge: 'IT22061270',
    title: 'Clinical Alert Prioritisation',
    subtitle: 'Clinically Aware Alert Scoring',
    accent: 'cyan',
    description:
      'Introduces the Clinical Alert Score (CAS) — a multi-dimensional risk model that integrates technical risk, clinical device criticality, and time sensitivity to prioritise alerts in healthcare SIEM environments.',
    formula: 'CAS = TR × CC × TS',
    formulaDesc: 'Technical Risk × Clinical Criticality × Time Sensitivity',
    features: [
      'Clinical metadata enrichment for all alerts',
      'Isolation Forest anomaly detection',
      'K-Means device activity clustering',
      'Autoencoder telemetry analysis',
      'AI-based risk prediction pipeline',
      'SOC analyst-friendly dashboards',
    ],
    stack: ['Python', 'Scikit-learn', 'ELK Stack', 'Wazuh', 'Kibana'],
    datasets: ['CC IoMT Dataset (2024)', 'WUSTL EHMS Dataset (2020)', 'Aposemat 2023'],
  },
  {
    icon: <Shield className="w-5 h-5 text-emerald-400" />,
    badge: 'IT22086648',
    title: 'Life-Critical Incident Response',
    subtitle: 'Safety-First Orchestration',
    accent: 'emerald',
    description:
      'A smart hospital incident response framework that evaluates cybersecurity risks against potential patient harm. Ensures life-sustaining medical devices are never automatically disrupted without clinical approval.',
    formula: 'Disruption Rate ≤ 5%',
    formulaDesc: 'Target accidental disruption rate for life-critical assets',
    features: [
      'Security-vs-Life decision logic engine',
      'Human-in-the-Loop (HITL) clinician approval',
      'Blockchain immutable audit ledger',
      'Wazuh SIEM + Shuffle SOAR integration',
      'Scenario-based stress testing',
      'Mobile clinician notification workflow',
    ],
    stack: ['Wazuh', 'Shuffle SOAR', 'Blockchain', 'React', 'Node.js'],
    datasets: ['Advanced SIEM Dataset (Hugging Face)'],
  },
  {
    icon: <Zap className="w-5 h-5 text-violet-400" />,
    badge: 'IT22118240',
    title: 'Context-Aware IP Protection',
    subtitle: 'Dynamic IP Reputation Scoring',
    accent: 'violet',
    description:
      'A context-enriched IP classification and reputation scoring module that integrates threat intelligence feeds into every SIEM alert, giving SOC analysts clear context and recommended response actions.',
    formula: 'IP Score = Context × Reputation × Behaviour',
    formulaDesc: 'Multi-factor IP scoring model',
    features: [
      'Dynamic IP reputation scoring engine',
      'MISP threat intelligence integration',
      'Random Forest IP classification',
      'Isolation Forest anomaly detection',
      'SIEM alert enrichment pipeline',
      'Recommended response actions per alert',
    ],
    stack: ['Python', 'Scikit-learn', 'MISP', 'Wazuh', 'Elastic Stack'],
    datasets: ['UNSW-NB15 Augmented Dataset (CIC / UNB)'],
  },
];

const ServicesPage: React.FC = () => (
  <div className="bg-white dark:bg-slate-950 min-h-screen text-slate-900 dark:text-white pt-28">
    {/* ── Header ── */}
    <section className="py-16 px-4">
      <div className="max-w-3xl mx-auto">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-md border border-slate-200 dark:border-slate-800 text-slate-500 dark:text-slate-400 text-xs font-medium mb-6">
          <Network className="w-3.5 h-3.5" />
          Three Integrated Security Components
        </div>
        <h1 className="text-3xl md:text-4xl font-bold mb-5 tracking-tight">
          Platform <span className="text-cyan-400">services</span>
        </h1>
        <p className="text-base text-slate-500 dark:text-slate-400 leading-relaxed max-w-2xl">
          Each service is independently functional yet designed to integrate seamlessly,
          creating a comprehensive healthcare cybersecurity ecosystem.
        </p>
      </div>
    </section>

    {/* ── Service Cards ── */}
    <section className="py-6 px-4">
      <div className="max-w-6xl mx-auto space-y-6">
        {services.map((svc) => (
          <div
            key={svc.badge}
            className="rounded-lg bg-white dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800"
          >
            <div className="p-7">
              <div className="grid md:grid-cols-5 gap-8">
                {/* Left col */}
                <div className="md:col-span-3">
                  <div className="flex items-start gap-3.5 mb-5">
                    <div className="w-11 h-11 rounded-md bg-slate-100 dark:bg-slate-800 flex items-center justify-center flex-shrink-0">
                      {svc.icon}
                    </div>
                    <div>
                      <div className="text-xs font-mono text-slate-400 dark:text-slate-500 mb-1">{svc.badge}</div>
                      <h2 className="text-lg font-bold text-slate-900 dark:text-white">{svc.title}</h2>
                      <p className={`text-sm ${accentText[svc.accent]}`}>{svc.subtitle}</p>
                    </div>
                  </div>

                  <p className="text-slate-500 dark:text-slate-400 leading-relaxed mb-5 text-sm">{svc.description}</p>

                  {/* Formula */}
                  <div className="inline-block px-4 py-2.5 rounded-md bg-slate-100 dark:bg-slate-800/60 border border-slate-300 dark:border-slate-700 mb-5">
                    <div className="text-base font-mono font-semibold text-slate-800 dark:text-slate-200">{svc.formula}</div>
                    <div className="text-xs text-slate-400 dark:text-slate-500 mt-0.5">{svc.formulaDesc}</div>
                  </div>

                  {/* Features */}
                  <div className="grid sm:grid-cols-2 gap-2">
                    {svc.features.map((f) => (
                      <div key={f} className="flex items-start gap-2 text-sm text-slate-500 dark:text-slate-400">
                        <CheckCircle className={`w-3.5 h-3.5 ${accentCheck[svc.accent]} flex-shrink-0 mt-0.5`} />
                        {f}
                      </div>
                    ))}
                  </div>
                </div>

                {/* Right col */}
                <div className="md:col-span-2 space-y-4">
                  <div className="p-4 rounded-md bg-slate-100 dark:bg-slate-800/40 border border-slate-200 dark:border-slate-800">
                    <div className="text-xs text-slate-400 dark:text-slate-500 uppercase tracking-wider mb-3">Tech Stack</div>
                    <div className="flex flex-wrap gap-1.5">
                      {svc.stack.map((t) => (
                        <span key={t} className={`px-2.5 py-1 rounded-md text-xs font-medium border ${accentPill[svc.accent]}`}>
                          {t}
                        </span>
                      ))}
                    </div>
                  </div>

                  <div className="p-4 rounded-md bg-slate-100 dark:bg-slate-800/40 border border-slate-200 dark:border-slate-800">
                    <div className="text-xs text-slate-400 dark:text-slate-500 uppercase tracking-wider mb-3">Datasets</div>
                    <ul className="space-y-1.5">
                      {svc.datasets.map((d) => (
                        <li key={d} className="text-sm text-slate-500 dark:text-slate-400 flex items-start gap-2">
                          <BarChart3 className="w-3.5 h-3.5 mt-0.5 text-slate-400 dark:text-slate-600 flex-shrink-0" />
                          {d}
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>
    </section>

    {/* ── Integration ── */}
    <section className="py-16 px-4 border-t border-slate-200 dark:border-slate-800 mt-10">
      <div className="max-w-4xl mx-auto flex flex-col sm:flex-row items-center gap-8 p-8 rounded-lg bg-white dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800">
        <Bell className="w-8 h-8 text-cyan-400 flex-shrink-0" />
        <div className="flex-1">
          <h2 className="text-lg font-bold mb-2">All components work together</h2>
          <p className="text-slate-500 dark:text-slate-400 text-sm leading-relaxed">
            While each component can operate independently, the platform achieves maximum effectiveness
            when all three are integrated — creating a fully context-aware healthcare security ecosystem.
          </p>
        </div>
        <div className="flex gap-3 flex-shrink-0">
          <Link to="/pricing" className="flex items-center justify-center gap-2 px-5 py-2.5 bg-cyan-500 text-slate-950 font-semibold rounded-md hover:bg-cyan-400 transition-colors text-sm whitespace-nowrap">
            See Pricing <ChevronRight className="w-4 h-4" />
          </Link>
        </div>
      </div>
    </section>
  </div>
);

export default ServicesPage;
