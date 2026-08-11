import React from 'react';
import { Link } from 'react-router-dom';
import { User, BookOpen, ArrowRight, ExternalLink } from 'lucide-react';

// ─── Team Member Card ─────────────────────────────────────────────────────────
const colorMap: Record<string, string> = {
  cyan: 'text-cyan-400',
  emerald: 'text-emerald-400',
  violet: 'text-violet-400',
};

const TeamCard: React.FC<{
  id: string;
  name: string;
  role: string;
  component: string;
  color: string;
  items: string[];
}> = ({ id, name, role, component, color, items }) => (
  <div className="p-6 rounded-lg bg-white dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:border-slate-700 transition-colors">
    <div className="flex items-start gap-3 mb-4">
      <div className="w-9 h-9 rounded-md bg-slate-100 dark:bg-slate-800 flex items-center justify-center flex-shrink-0">
        <User className={`w-4.5 h-4.5 ${colorMap[color]}`} />
      </div>
      <div>
        <div className="text-xs font-mono text-slate-400 dark:text-slate-500 mb-0.5">{id}</div>
        <h3 className="font-semibold text-slate-900 dark:text-white text-sm">{name}</h3>
        <p className="text-sm text-slate-500 dark:text-slate-400">{role}</p>
      </div>
    </div>
    <div className={`text-xs font-semibold uppercase tracking-wider ${colorMap[color]} mb-3`}>{component}</div>
    <ul className="space-y-1.5">
      {items.map((item) => (
        <li key={item} className="flex items-start gap-2 text-sm text-slate-500 dark:text-slate-400">
          <span className="w-1 h-1 rounded-full bg-slate-600 mt-2 flex-shrink-0" />
          {item}
        </li>
      ))}
    </ul>
  </div>
);

const AboutPage: React.FC = () => (
  <div className="bg-white dark:bg-slate-950 min-h-screen text-slate-900 dark:text-white pt-28">
    {/* ── Header ── */}
    <section className="py-16 px-4">
      <div className="max-w-3xl mx-auto">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-md border border-slate-200 dark:border-slate-800 text-slate-500 dark:text-slate-400 text-xs font-medium mb-6">
          <BookOpen className="w-3.5 h-3.5" />
          R26-CS-008 · Sri Lanka Institute of Information Technology
        </div>
        <h1 className="text-3xl md:text-4xl font-bold mb-5 tracking-tight">
          About <span className="text-cyan-400">MediSIEM</span>
        </h1>
        <p className="text-base text-slate-500 dark:text-slate-400 max-w-2xl leading-relaxed">
          A final-year research project at SLIIT developing a SIEM/IDS
          platform with clinical context awareness for smart hospitals.
        </p>
      </div>
    </section>

    {/* ── Project Overview ── */}
    <section className="py-12 px-4">
      <div className="max-w-5xl mx-auto">
        <div className="grid md:grid-cols-2 gap-10 items-start">
          <div>
            <h2 className="text-xl font-bold mb-4">The research problem</h2>
            <p className="text-slate-500 dark:text-slate-400 leading-relaxed mb-4 text-sm">
              Traditional SIEM and IDS platforms rely on rule-based detection and CVSS severity scores.
              In healthcare environments, this approach is dangerous — systems lack clinical awareness
              of medical device criticality, leading to high false-positive rates and alert fatigue.
            </p>
            <p className="text-slate-500 dark:text-slate-400 leading-relaxed mb-4 text-sm">
              Automated responses may accidentally disrupt life-critical devices such as ICU monitors,
              ventilators, and infusion pumps, directly endangering patient lives.
            </p>
            <p className="text-slate-500 dark:text-slate-400 leading-relaxed text-sm">
              MediSIEM addresses this by introducing clinical context at every layer of the security stack.
            </p>
          </div>

          <div className="rounded-lg border border-slate-200 dark:border-slate-800 divide-y divide-slate-200 dark:divide-slate-800 overflow-hidden">
            {[
              ['Project ID', 'R26-CS-008'],
              ['Institution', 'Sri Lanka Institute of Information Technology (SLIIT)'],
              ['Supervisor', 'Mr. Amila Senarathne'],
              ['Co-Supervisor', 'Ms. Ayesha Wijesooroya'],
            ].map(([label, value]) => (
              <div key={label} className="px-5 py-4 bg-white dark:bg-slate-900/60">
                <div className="text-xs text-slate-400 dark:text-slate-500 uppercase tracking-wider mb-1">{label}</div>
                <div className="font-medium text-slate-900 dark:text-white text-sm">{value}</div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>

    {/* ── Team ── */}
    <section className="py-16 px-4 bg-slate-50 dark:bg-slate-900/20 border-y border-slate-200 dark:border-slate-800">
      <div className="max-w-6xl mx-auto">
        <div className="mb-10">
          <h2 className="text-2xl font-bold mb-2">Research team</h2>
          <p className="text-slate-500 dark:text-slate-400 text-sm">Three independent but interconnected research components.</p>
        </div>
        <div className="grid md:grid-cols-3 gap-4">
          <TeamCard
            id="IT22061270"
            name="R.M.C.B. Rathnayake"
            role="Clinically Aware Alert Prioritisation"
            component="Component 1 — CAS Model"
            color="cyan"
            items={[
              'Clinical Alert Score (CAS) = TR × CC × TS',
              'Isolation Forest anomaly detection',
              'K-Means clustering for device groups',
              'Autoencoder telemetry analysis',
            ]}
          />
          <TeamCard
            id="IT22086648"
            name="W.D.S. Jayasinghe"
            role="Life-Critical Incident Response"
            component="Component 2 — HITL Orchestration"
            color="emerald"
            items={[
              'Security-vs-Life Decision Logic',
              'Human-in-the-loop clinician approval',
              'Blockchain immutable audit ledger',
              'Wazuh + Shuffle SOAR integration',
            ]}
          />
          <TeamCard
            id="IT22118240"
            name="Anjana K.O.A"
            role="Context-Aware IP Protection"
            component="Component 3 — IP Reputation"
            color="violet"
            items={[
              'Dynamic IP reputation scoring',
              'MISP threat intelligence feeds',
              'Random Forest classifier',
              'SIEM alert enrichment engine',
            ]}
          />
        </div>
      </div>
    </section>

    {/* ── References ── */}
    <section className="py-16 px-4">
      <div className="max-w-4xl mx-auto">
        <h2 className="text-xl font-bold mb-6">Credible evidence sources</h2>
        <div className="grid sm:grid-cols-2 gap-3">
          {[
            'UN News — Cyberattacks on Healthcare: A Global Threat',
            'CIS — Cyber Attacks in the Healthcare Sector',
            'Checkpoint — Cyberattacks on the Healthcare Sector',
            'CyberArk — What is Healthcare Cybersecurity?',
            'Crowdstrike — Cybersecurity in Healthcare',
            'PaloAlto — What Is Healthcare Cybersecurity?',
          ].map((ref) => (
            <div key={ref} className="flex items-start gap-3 p-3.5 rounded-lg bg-white dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800">
              <ExternalLink className="w-3.5 h-3.5 text-slate-400 dark:text-slate-500 mt-0.5 flex-shrink-0" />
              <span className="text-sm text-slate-500 dark:text-slate-400">{ref}</span>
            </div>
          ))}
        </div>
      </div>
    </section>

    {/* ── CTA ── */}
    <section className="py-16 px-4 border-t border-slate-200 dark:border-slate-800">
      <div className="max-w-4xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-6">
        <div>
          <h2 className="text-lg font-bold mb-1">Ready to explore the platform?</h2>
          <p className="text-slate-500 dark:text-slate-400 text-sm">Sign in to access the MediSIEM dashboard.</p>
        </div>
        <div className="flex gap-3 flex-shrink-0">
          <Link to="/login" className="flex items-center justify-center gap-2 px-5 py-2.5 bg-cyan-500 text-slate-950 font-semibold rounded-md hover:bg-cyan-400 transition-colors text-sm">
            Sign In <ArrowRight className="w-4 h-4" />
          </Link>
          <Link to="/services" className="flex items-center justify-center gap-2 px-5 py-2.5 bg-transparent text-slate-900 dark:text-white font-semibold rounded-md hover:bg-slate-100 dark:hover:bg-white/5 transition-colors border border-slate-300 dark:border-slate-700 text-sm">
            View Services
          </Link>
        </div>
      </div>
    </section>
  </div>
);

export default AboutPage;
