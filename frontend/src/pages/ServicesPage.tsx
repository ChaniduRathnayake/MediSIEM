import React from 'react';
import { Link } from 'react-router-dom';
import { Brain, Shield, Zap, Network, BarChart3, Bell, ChevronRight, CheckCircle } from 'lucide-react';

const services = [
  {
    icon: <Brain className="w-7 h-7 text-cyan-400" />,
    badge: 'IT22061270',
    title: 'Clinical Alert Prioritisation',
    subtitle: 'Clinically Aware Alert Scoring',
    color: 'cyan',
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
    icon: <Shield className="w-7 h-7 text-emerald-400" />,
    badge: 'IT22086648',
    title: 'Life-Critical Incident Response',
    subtitle: 'Safety-First Orchestration',
    color: 'emerald',
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
    icon: <Zap className="w-7 h-7 text-violet-400" />,
    badge: 'IT22118240',
    title: 'Context-Aware IP Protection',
    subtitle: 'Dynamic IP Reputation Scoring',
    color: 'violet',
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
  <div className="bg-slate-950 min-h-screen text-white pt-24">
    {/* ── Header ── */}
    <section className="py-20 px-4 text-center relative overflow-hidden">
      <div className="absolute inset-0 bg-[linear-gradient(rgba(6,182,212,0.03)_1px,transparent_1px),linear-gradient(90deg,rgba(6,182,212,0.03)_1px,transparent_1px)] bg-[size:48px_48px] pointer-events-none" />
      <div className="relative max-w-3xl mx-auto">
        <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full bg-violet-500/10 border border-violet-500/20 text-violet-400 text-xs font-medium mb-6">
          <Network className="w-3.5 h-3.5" />
          Three Integrated Security Components
        </div>
        <h1 className="text-4xl md:text-5xl font-black mb-6">
          Platform{' '}
          <span className="bg-gradient-to-r from-cyan-400 to-violet-400 bg-clip-text text-transparent">
            Services
          </span>
        </h1>
        <p className="text-lg text-slate-400 leading-relaxed">
          Each service is independently functional yet designed to integrate seamlessly,
          creating a comprehensive healthcare cybersecurity ecosystem.
        </p>
      </div>
    </section>

    {/* ── Service Cards ── */}
    <section className="py-10 px-4">
      <div className="max-w-6xl mx-auto space-y-10">
        {services.map((svc, i) => (
          <div
            key={svc.badge}
            className={`rounded-3xl bg-slate-900/60 border border-slate-800 overflow-hidden`}
          >
            {/* Top bar */}
            <div className={`h-1 bg-gradient-to-r ${
              i === 0 ? 'from-cyan-500 to-blue-500' :
              i === 1 ? 'from-emerald-500 to-teal-500' :
              'from-violet-500 to-purple-500'
            }`} />

            <div className="p-8">
              <div className="grid md:grid-cols-5 gap-8">
                {/* Left col */}
                <div className="md:col-span-3">
                  <div className="flex items-start gap-4 mb-5">
                    <div className={`w-14 h-14 rounded-2xl bg-${svc.color}-500/10 flex items-center justify-center flex-shrink-0`}>
                      {svc.icon}
                    </div>
                    <div>
                      <div className={`text-xs font-mono text-${svc.color}-400 mb-1`}>{svc.badge}</div>
                      <h2 className="text-xl font-bold text-white">{svc.title}</h2>
                      <p className={`text-sm text-${svc.color}-400`}>{svc.subtitle}</p>
                    </div>
                  </div>

                  <p className="text-slate-400 leading-relaxed mb-6">{svc.description}</p>

                  {/* Formula */}
                  <div className={`inline-block px-5 py-3 rounded-xl bg-${svc.color}-500/10 border border-${svc.color}-500/20 mb-6`}>
                    <div className={`text-lg font-mono font-bold text-${svc.color}-300`}>{svc.formula}</div>
                    <div className="text-xs text-slate-400 mt-0.5">{svc.formulaDesc}</div>
                  </div>

                  {/* Features */}
                  <div className="grid sm:grid-cols-2 gap-2">
                    {svc.features.map((f) => (
                      <div key={f} className="flex items-start gap-2 text-sm text-slate-400">
                        <CheckCircle className={`w-4 h-4 text-${svc.color}-500 flex-shrink-0 mt-0.5`} />
                        {f}
                      </div>
                    ))}
                  </div>
                </div>

                {/* Right col */}
                <div className="md:col-span-2 space-y-5">
                  <div className="p-4 rounded-xl bg-slate-800/60 border border-slate-700/60">
                    <div className="text-xs text-slate-500 uppercase tracking-wider mb-3">Tech Stack</div>
                    <div className="flex flex-wrap gap-2">
                      {svc.stack.map((t) => (
                        <span key={t} className={`px-3 py-1 rounded-full text-xs font-medium bg-${svc.color}-500/10 text-${svc.color}-300 border border-${svc.color}-500/20`}>
                          {t}
                        </span>
                      ))}
                    </div>
                  </div>

                  <div className="p-4 rounded-xl bg-slate-800/60 border border-slate-700/60">
                    <div className="text-xs text-slate-500 uppercase tracking-wider mb-3">Datasets</div>
                    <ul className="space-y-1.5">
                      {svc.datasets.map((d) => (
                        <li key={d} className="text-sm text-slate-400 flex items-start gap-2">
                          <BarChart3 className="w-3.5 h-3.5 mt-0.5 text-slate-500 flex-shrink-0" />
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
    <section className="py-20 px-4">
      <div className="max-w-4xl mx-auto">
        <div className="p-8 rounded-3xl bg-gradient-to-br from-slate-900 to-slate-800 border border-slate-700 text-center">
          <Bell className="w-12 h-12 text-cyan-400 mx-auto mb-5" />
          <h2 className="text-2xl font-bold mb-4">All Components Work Together</h2>
          <p className="text-slate-400 mb-8 max-w-xl mx-auto leading-relaxed">
            While each component can operate independently, the platform achieves maximum effectiveness
            when all three are integrated — creating a fully context-aware healthcare security ecosystem.
          </p>
          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            <Link to="/pricing" className="flex items-center justify-center gap-2 px-7 py-3.5 bg-gradient-to-r from-cyan-500 to-blue-600 text-white font-semibold rounded-xl hover:from-cyan-400 hover:to-blue-500 transition-all shadow-xl shadow-cyan-500/20">
              See Pricing Plans <ChevronRight className="w-4 h-4" />
            </Link>
            <Link to="/register" className="flex items-center justify-center gap-2 px-7 py-3.5 bg-slate-700 text-white font-semibold rounded-xl hover:bg-slate-600 transition-all border border-slate-600">
              Start Free Trial
            </Link>
          </div>
        </div>
      </div>
    </section>
  </div>
);

export default ServicesPage;
