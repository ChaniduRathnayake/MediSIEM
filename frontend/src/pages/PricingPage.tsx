import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { CheckCircle, X, Zap, Shield, Building, ChevronRight } from 'lucide-react';

const plans = [
  {
    name: 'Starter',
    icon: <Zap className="w-5 h-5" />,
    color: 'slate',
    price: { monthly: 0, annual: 0 },
    desc: 'Perfect for small clinics and research trials.',
    badge: null,
    features: [
      { text: 'Up to 5 monitored devices', included: true },
      { text: 'Basic SIEM alert dashboard', included: true },
      { text: 'IP reputation scoring (basic)', included: true },
      { text: 'Community support', included: true },
      { text: 'Clinical Alert Score (CAS)', included: false },
      { text: 'Life-critical response engine', included: false },
      { text: 'HITL clinician approval workflow', included: false },
      { text: 'Blockchain audit ledger', included: false },
      { text: 'MISP threat intel feeds', included: false },
      { text: 'Priority SLA support', included: false },
    ],
    cta: 'Get Started Free',
    ctaLink: '/register',
    highlighted: false,
  },
  {
    name: 'Hospital',
    icon: <Shield className="w-5 h-5" />,
    color: 'cyan',
    price: { monthly: 15000, annual: 12000 },
    desc: 'For small-to-medium private hospitals in developing regions.',
    badge: 'Most Popular',
    features: [
      { text: 'Up to 200 monitored devices', included: true },
      { text: 'Full SIEM alert dashboard', included: true },
      { text: 'Dynamic IP reputation scoring', included: true },
      { text: 'Email & Slack support', included: true },
      { text: 'Clinical Alert Score (CAS)', included: true },
      { text: 'Life-critical response engine', included: true },
      { text: 'HITL clinician approval workflow', included: true },
      { text: 'Blockchain audit ledger', included: false },
      { text: 'MISP threat intel feeds', included: false },
      { text: 'Priority SLA support', included: false },
    ],
    cta: 'Start Free Trial',
    ctaLink: '/register',
    highlighted: true,
  },
  {
    name: 'Enterprise',
    icon: <Building className="w-5 h-5" />,
    color: 'violet',
    price: { monthly: 20000, annual: 17000 },
    desc: 'For public healthcare clusters and large hospital networks.',
    badge: 'Full Platform',
    features: [
      { text: 'Unlimited monitored devices', included: true },
      { text: 'Full SIEM alert dashboard', included: true },
      { text: 'Dynamic IP reputation scoring', included: true },
      { text: '24/7 dedicated support', included: true },
      { text: 'Clinical Alert Score (CAS)', included: true },
      { text: 'Life-critical response engine', included: true },
      { text: 'HITL clinician approval workflow', included: true },
      { text: 'Blockchain audit ledger', included: true },
      { text: 'MISP threat intel feeds', included: true },
      { text: 'Priority SLA support', included: true },
    ],
    cta: 'Contact Sales',
    ctaLink: '/register',
    highlighted: false,
  },
];

const PricingPage: React.FC = () => {
  const [annual, setAnnual] = useState(false);

  const formatPrice = (p: number) =>
    p === 0 ? 'Free' : `LKR ${p.toLocaleString()}`;

  return (
    <div className="bg-slate-950 min-h-screen text-white pt-24">
      {/* ── Header ── */}
      <section className="py-20 px-4 text-center relative overflow-hidden">
        <div className="absolute inset-0 bg-[linear-gradient(rgba(6,182,212,0.03)_1px,transparent_1px),linear-gradient(90deg,rgba(6,182,212,0.03)_1px,transparent_1px)] bg-[size:48px_48px] pointer-events-none" />
        <div className="relative max-w-3xl mx-auto">
          <h1 className="text-4xl md:text-5xl font-black mb-5">
            Simple,{' '}
            <span className="bg-gradient-to-r from-cyan-400 to-blue-400 bg-clip-text text-transparent">
              Transparent
            </span>{' '}
            Pricing
          </h1>
          <p className="text-lg text-slate-400 mb-8">
            Safety-as-a-Service — a fraction of enterprise SIEM costs, purpose-built for healthcare.
          </p>

          {/* Toggle */}
          <div className="inline-flex items-center gap-3 p-1.5 rounded-xl bg-slate-800 border border-slate-700">
            <button
              onClick={() => setAnnual(false)}
              className={`px-5 py-2 rounded-lg text-sm font-medium transition-all ${
                !annual ? 'bg-slate-700 text-white shadow' : 'text-slate-400 hover:text-white'
              }`}
            >
              Monthly
            </button>
            <button
              onClick={() => setAnnual(true)}
              className={`px-5 py-2 rounded-lg text-sm font-medium transition-all flex items-center gap-2 ${
                annual ? 'bg-slate-700 text-white shadow' : 'text-slate-400 hover:text-white'
              }`}
            >
              Annual
              <span className="px-2 py-0.5 bg-emerald-500/20 text-emerald-400 text-xs rounded-full font-semibold">
                Save 20%
              </span>
            </button>
          </div>
        </div>
      </section>

      {/* ── Plans ── */}
      <section className="py-10 px-4">
        <div className="max-w-6xl mx-auto grid md:grid-cols-3 gap-6 items-start">
          {plans.map((plan) => (
            <div
              key={plan.name}
              className={`relative rounded-3xl p-7 border transition-all ${
                plan.highlighted
                  ? 'bg-gradient-to-b from-cyan-950/60 to-slate-900/80 border-cyan-500/40 shadow-2xl shadow-cyan-500/10 scale-[1.02]'
                  : 'bg-slate-900/60 border-slate-800 hover:border-slate-700'
              }`}
            >
              {/* Badge */}
              {plan.badge && (
                <div className="absolute -top-3.5 left-1/2 -translate-x-1/2">
                  <span className="px-4 py-1 rounded-full bg-gradient-to-r from-cyan-500 to-blue-600 text-white text-xs font-bold shadow-lg shadow-cyan-500/30">
                    {plan.badge}
                  </span>
                </div>
              )}

              {/* Icon & Name */}
              <div className={`w-10 h-10 rounded-xl bg-${plan.color}-500/10 flex items-center justify-center text-${plan.color}-400 mb-4`}>
                {plan.icon}
              </div>
              <h3 className="text-xl font-bold text-white mb-1">{plan.name}</h3>
              <p className="text-sm text-slate-400 mb-5">{plan.desc}</p>

              {/* Price */}
              <div className="mb-6">
                <div className="flex items-end gap-1">
                  <span className="text-4xl font-black text-white">
                    {formatPrice(annual ? plan.price.annual : plan.price.monthly)}
                  </span>
                  {plan.price.monthly > 0 && (
                    <span className="text-slate-500 text-sm mb-1.5">/month</span>
                  )}
                </div>
                {annual && plan.price.monthly > 0 && (
                  <p className="text-xs text-emerald-400 mt-1">
                    Billed annually · Save LKR {((plan.price.monthly - plan.price.annual) * 12).toLocaleString()}/yr
                  </p>
                )}
              </div>

              {/* CTA */}
              <Link
                to={plan.ctaLink}
                className={`flex items-center justify-center gap-2 w-full py-3 rounded-xl font-semibold text-sm mb-7 transition-all ${
                  plan.highlighted
                    ? 'bg-gradient-to-r from-cyan-500 to-blue-600 text-white hover:from-cyan-400 hover:to-blue-500 shadow-lg shadow-cyan-500/25'
                    : 'bg-slate-800 text-white hover:bg-slate-700 border border-slate-700'
                }`}
              >
                {plan.cta} <ChevronRight className="w-4 h-4" />
              </Link>

              {/* Features */}
              <ul className="space-y-3">
                {plan.features.map((f) => (
                  <li key={f.text} className="flex items-start gap-2.5 text-sm">
                    {f.included ? (
                      <CheckCircle className="w-4 h-4 text-emerald-500 flex-shrink-0 mt-0.5" />
                    ) : (
                      <X className="w-4 h-4 text-slate-600 flex-shrink-0 mt-0.5" />
                    )}
                    <span className={f.included ? 'text-slate-300' : 'text-slate-600'}>
                      {f.text}
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </section>

      {/* ── Cost Breakdown ── */}
      <section className="py-20 px-4">
        <div className="max-w-4xl mx-auto">
          <h2 className="text-2xl font-bold text-center mb-10">Project Cost Structure</h2>
          <div className="grid sm:grid-cols-3 gap-5">
            {[
              { label: 'Total Project Cost', value: 'LKR 550,000', desc: 'Full platform development budget', color: 'text-white' },
              { label: 'Development', value: 'LKR 500,000', desc: 'Security-vs-Life logic & playbooks', color: 'text-cyan-400' },
              { label: 'Infrastructure', value: 'LKR 50,000', desc: 'Cloud gateways, datasets & notifications', color: 'text-violet-400' },
            ].map((item) => (
              <div key={item.label} className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 text-center">
                <div className="text-xs text-slate-500 uppercase tracking-wider mb-2">{item.label}</div>
                <div className={`text-2xl font-black mb-1 ${item.color}`}>{item.value}</div>
                <div className="text-xs text-slate-400">{item.desc}</div>
              </div>
            ))}
          </div>

          <div className="mt-8 p-6 rounded-2xl bg-slate-900/40 border border-slate-800 text-sm text-slate-400 leading-relaxed">
            <p className="font-semibold text-slate-200 mb-2">Revenue Model — "Safety-as-a-Service"</p>
            <p>
              A one-time <strong className="text-white">Setup Fee</strong> covers hospital-specific IoMT integration.
              Monthly <strong className="text-white">subscriptions (LKR 15,000 – 20,000/month)</strong> cover
              logic updates, threat intelligence feeds, and clinician push notification services —
              a fraction of enterprise SIEM licensing costs.
            </p>
          </div>
        </div>
      </section>

      {/* ── FAQ ── */}
      <section className="py-10 px-4 pb-24">
        <div className="max-w-3xl mx-auto">
          <h2 className="text-2xl font-bold text-center mb-10">Frequently Asked Questions</h2>
          <div className="space-y-4">
            {[
              {
                q: 'Can components be purchased separately?',
                a: 'Yes. Each of the three components (Alert Prioritisation, Incident Response, IP Protection) can be deployed independently and integrated progressively.',
              },
              {
                q: 'Is this built on open-source tools?',
                a: 'Yes. The platform is built on Wazuh, Shuffle, and the ELK stack. The proprietary "Safety Playbooks" and Clinical Decision Logic are kept as licensed assets.',
              },
              {
                q: 'Who is the target customer?',
                a: 'Public healthcare clusters and small-to-medium private hospitals in developing regions like Sri Lanka — particularly hospital IT managers concerned about ransomware on life-critical equipment.',
              },
              {
                q: 'Is patient data stored on the platform?',
                a: 'No. MediSIEM processes network security telemetry and device logs only. No patient health records (PHI) are ingested or stored.',
              },
            ].map((item) => (
              <div key={item.q} className="p-5 rounded-2xl bg-slate-900/60 border border-slate-800">
                <h4 className="font-semibold text-white mb-2">{item.q}</h4>
                <p className="text-sm text-slate-400 leading-relaxed">{item.a}</p>
              </div>
            ))}
          </div>
        </div>
      </section>
    </div>
  );
};

export default PricingPage;
