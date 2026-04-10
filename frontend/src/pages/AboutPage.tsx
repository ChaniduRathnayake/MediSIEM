import React from 'react';
import { Link } from 'react-router-dom';
import { Shield, User, BookOpen, ArrowRight, ExternalLink } from 'lucide-react';

// ─── Team Member Card ─────────────────────────────────────────────────────────
const TeamCard: React.FC<{
  id: string;
  name: string;
  role: string;
  component: string;
  color: string;
  items: string[];
}> = ({ id, name, role, component, color, items }) => (
  <div className={`p-6 rounded-2xl bg-slate-900/60 border border-slate-800 hover:border-${color}-500/40 transition-all group`}>
    <div className="flex items-start gap-4 mb-4">
      <div className={`w-12 h-12 rounded-xl bg-${color}-500/10 flex items-center justify-center flex-shrink-0`}>
        <User className={`w-6 h-6 text-${color}-400`} />
      </div>
      <div>
        <div className={`text-xs font-mono text-${color}-400 mb-0.5`}>{id}</div>
        <h3 className="font-bold text-white">{name}</h3>
        <p className="text-sm text-slate-400">{role}</p>
      </div>
    </div>
    <div className={`text-xs font-semibold uppercase tracking-wider text-${color}-400 mb-3`}>{component}</div>
    <ul className="space-y-1.5">
      {items.map((item) => (
        <li key={item} className="flex items-start gap-2 text-sm text-slate-400">
          <span className={`w-1 h-1 rounded-full bg-${color}-400 mt-2 flex-shrink-0`} />
          {item}
        </li>
      ))}
    </ul>
  </div>
);

const AboutPage: React.FC = () => (
  <div className="bg-slate-950 min-h-screen text-white pt-24">
    {/* ── Header ── */}
    <section className="py-20 px-4 text-center relative overflow-hidden">
      <div className="absolute inset-0 bg-[linear-gradient(rgba(6,182,212,0.03)_1px,transparent_1px),linear-gradient(90deg,rgba(6,182,212,0.03)_1px,transparent_1px)] bg-[size:48px_48px] pointer-events-none" />
      <div className="relative max-w-4xl mx-auto">
        <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full bg-blue-500/10 border border-blue-500/20 text-blue-400 text-xs font-medium mb-6">
          <BookOpen className="w-3.5 h-3.5" />
          R26-CS-008 · Sri Lanka Institute of Information Technology
        </div>
        <h1 className="text-4xl md:text-5xl font-black mb-6">
          About{' '}
          <span className="bg-gradient-to-r from-cyan-400 to-blue-400 bg-clip-text text-transparent">
            MediSIEM
          </span>
        </h1>
        <p className="text-lg text-slate-400 max-w-2xl mx-auto leading-relaxed">
          A final-year research project at SLIIT developing a next-generation SIEM/IDS
          platform with clinical context awareness for smart hospitals.
        </p>
      </div>
    </section>

    {/* ── Project Overview ── */}
    <section className="py-16 px-4">
      <div className="max-w-5xl mx-auto">
        <div className="grid md:grid-cols-2 gap-8 items-start">
          <div>
            <h2 className="text-2xl font-bold mb-4">The Research Problem</h2>
            <p className="text-slate-400 leading-relaxed mb-4">
              Traditional SIEM and IDS platforms rely on rule-based detection and CVSS severity scores.
              In healthcare environments, this approach is dangerous — systems lack clinical awareness
              of medical device criticality, leading to high false-positive rates and alert fatigue.
            </p>
            <p className="text-slate-400 leading-relaxed mb-4">
              Automated responses may accidentally disrupt life-critical devices such as ICU monitors,
              ventilators, and infusion pumps, directly endangering patient lives.
            </p>
            <p className="text-slate-400 leading-relaxed">
              MediSIEM solves this by introducing clinical context at every layer of the security stack.
            </p>
          </div>

          <div className="space-y-4">
            <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800">
              <div className="text-xs text-cyan-400 font-mono mb-1">PROJECT ID</div>
              <div className="font-bold text-white">R26-CS-008</div>
            </div>
            <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800">
              <div className="text-xs text-cyan-400 font-mono mb-1">INSTITUTION</div>
              <div className="font-bold text-white">Sri Lanka Institute of Information Technology (SLIIT)</div>
            </div>
            <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800">
              <div className="text-xs text-cyan-400 font-mono mb-1">SUPERVISOR</div>
              <div className="font-bold text-white">Mr. Amila Senarathne</div>
            </div>
            <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800">
              <div className="text-xs text-cyan-400 font-mono mb-1">CO-SUPERVISOR</div>
              <div className="font-bold text-white">Ms. Ayesha Wijesooroya</div>
            </div>
          </div>
        </div>
      </div>
    </section>

    {/* ── Team ── */}
    <section className="py-16 px-4 bg-slate-900/30">
      <div className="max-w-6xl mx-auto">
        <div className="text-center mb-12">
          <h2 className="text-3xl font-bold mb-3">Research Team</h2>
          <p className="text-slate-400">Three independent but interconnected research components.</p>
        </div>
        <div className="grid md:grid-cols-3 gap-6">
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
        <h2 className="text-2xl font-bold mb-8 text-center">Credible Evidence Sources</h2>
        <div className="grid sm:grid-cols-2 gap-4">
          {[
            'UN News — Cyberattacks on Healthcare: A Global Threat',
            'CIS — Cyber Attacks in the Healthcare Sector',
            'Checkpoint — Cyberattacks on the Healthcare Sector',
            'CyberArk — What is Healthcare Cybersecurity?',
            'Crowdstrike — Cybersecurity in Healthcare',
            'PaloAlto — What Is Healthcare Cybersecurity?',
          ].map((ref) => (
            <div key={ref} className="flex items-start gap-3 p-4 rounded-xl bg-slate-900/60 border border-slate-800 hover:border-slate-700 transition-colors">
              <ExternalLink className="w-4 h-4 text-cyan-500 mt-0.5 flex-shrink-0" />
              <span className="text-sm text-slate-400">{ref}</span>
            </div>
          ))}
        </div>
      </div>
    </section>

    {/* ── CTA ── */}
    <section className="py-16 px-4 text-center">
      <div className="max-w-2xl mx-auto">
        <Shield className="w-12 h-12 text-cyan-400 mx-auto mb-4" />
        <h2 className="text-2xl font-bold mb-4">Ready to Explore the Platform?</h2>
        <p className="text-slate-400 mb-7">Create an account to access the MediSIEM dashboard.</p>
        <div className="flex flex-col sm:flex-row gap-4 justify-center">
          <Link to="/register" className="flex items-center justify-center gap-2 px-7 py-3.5 bg-gradient-to-r from-cyan-500 to-blue-600 text-white font-semibold rounded-xl hover:from-cyan-400 hover:to-blue-500 transition-all shadow-xl shadow-cyan-500/20">
            Get Started <ArrowRight className="w-4 h-4" />
          </Link>
          <Link to="/services" className="flex items-center justify-center gap-2 px-7 py-3.5 bg-slate-800 text-white font-semibold rounded-xl hover:bg-slate-700 transition-all border border-slate-700">
            View Services
          </Link>
        </div>
      </div>
    </section>
  </div>
);

export default AboutPage;
