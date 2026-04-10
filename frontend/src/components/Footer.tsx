import React from 'react';
import { Link } from 'react-router-dom';
import { Shield, Mail, ExternalLink } from 'lucide-react';

const Footer: React.FC = () => (
  <footer className="bg-slate-950 border-t border-slate-800/60">
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
      <div className="grid grid-cols-1 md:grid-cols-4 gap-10">
        {/* Brand */}
        <div className="md:col-span-2">
          <Link to="/" className="flex items-center gap-2.5 mb-4">
            <div className="w-8 h-8 bg-gradient-to-br from-cyan-500 to-blue-600 rounded-lg flex items-center justify-center shadow-lg shadow-cyan-500/30">
              <Shield className="w-4.5 h-4.5 text-white" strokeWidth={2.5} />
            </div>
            <span className="font-bold text-lg text-white">
              Medi<span className="text-cyan-400">SIEM</span>
            </span>
          </Link>
          <p className="text-slate-400 text-sm leading-relaxed max-w-sm">
            Next-Generation SIEM/IDS platform purpose-built for smart hospitals.
            Clinically aware, life-critical safe, and context-intelligent.
          </p>
          <div className="flex items-center gap-3 mt-5">
            <a
              href="https://github.com"
              target="_blank"
              rel="noopener noreferrer"
              className="p-2 text-slate-500 hover:text-cyan-400 hover:bg-slate-800 rounded-lg transition-colors"
            >
              <span className="text-xs font-bold">GH</span>
            </a>
            <a
              href="mailto:contact@medisiem.lk"
              className="p-2 text-slate-500 hover:text-cyan-400 hover:bg-slate-800 rounded-lg transition-colors"
            >
              <Mail className="w-4 h-4" />
            </a>
          </div>
        </div>

        {/* Navigation */}
        <div>
          <h4 className="text-sm font-semibold text-slate-200 mb-4 uppercase tracking-wider">Platform</h4>
          <ul className="space-y-2.5">
            {[
              { label: 'Home', to: '/' },
              { label: 'About', to: '/about' },
              { label: 'Services', to: '/services' },
              { label: 'Pricing', to: '/pricing' },
            ].map((item) => (
              <li key={item.to}>
                <Link to={item.to} className="text-sm text-slate-400 hover:text-cyan-400 transition-colors">
                  {item.label}
                </Link>
              </li>
            ))}
          </ul>
        </div>

        {/* Research */}
        <div>
          <h4 className="text-sm font-semibold text-slate-200 mb-4 uppercase tracking-wider">Research</h4>
          <ul className="space-y-2.5 text-sm text-slate-400">
            <li className="flex items-start gap-1.5">
              <ExternalLink className="w-3.5 h-3.5 mt-0.5 text-cyan-500 flex-shrink-0" />
              <span>R26-CS-008 — SLIIT</span>
            </li>
            <li className="flex items-start gap-1.5">
              <ExternalLink className="w-3.5 h-3.5 mt-0.5 text-cyan-500 flex-shrink-0" />
              <span>Supervisor: Mr. Amila Senarathne</span>
            </li>
            <li className="flex items-start gap-1.5">
              <ExternalLink className="w-3.5 h-3.5 mt-0.5 text-cyan-500 flex-shrink-0" />
              <span>Co-Supervisor: Ms. Ayesha Wijesooroya</span>
            </li>
            <li>
              <Link to="/login" className="hover:text-cyan-400 transition-colors">Sign In</Link>
              {' · '}
              <Link to="/register" className="hover:text-cyan-400 transition-colors">Register</Link>
            </li>
          </ul>
        </div>
      </div>

      <div className="mt-10 pt-6 border-t border-slate-800 flex flex-col sm:flex-row items-center justify-between gap-3">
        <p className="text-xs text-slate-500">
          © {new Date().getFullYear()} MediSIEM — R26-CS-008 SLIIT Research Project. All rights reserved.
        </p>
        <p className="text-xs text-slate-600">
          Built with React · Vite · Tailwind CSS
        </p>
      </div>
    </div>
  </footer>
);

export default Footer;
