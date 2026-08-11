import React from 'react';
import { Link } from 'react-router-dom';
import { Shield, Mail, ExternalLink } from 'lucide-react';

const Footer: React.FC = () => (
  <footer className="bg-white dark:bg-slate-950 border-t border-slate-100 dark:border-slate-800/60">
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
      <div className="grid grid-cols-1 md:grid-cols-4 gap-10">
        {/* Brand */}
        <div className="md:col-span-2">
          <Link to="/" className="flex items-center gap-2.5 mb-4">
            <div className="w-7 h-7 bg-cyan-500 rounded-md flex items-center justify-center">
              <Shield className="w-4 h-4 text-slate-950" strokeWidth={2.5} />
            </div>
            <span className="font-semibold text-slate-900 dark:text-white">
              Medi<span className="text-cyan-400">SIEM</span>
            </span>
          </Link>
          <p className="text-slate-500 dark:text-slate-400 text-sm leading-relaxed max-w-sm">
            Clinical-context SIEM/IDS for hospital networks — alert prioritisation,
            life-critical incident response, and IP reputation scoring.
          </p>
          <div className="flex items-center gap-2 mt-5">
            <a
              href="https://github.com"
              target="_blank"
              rel="noopener noreferrer"
              className="p-2 text-slate-400 dark:text-slate-500 hover:text-slate-900 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-slate-800 rounded-md transition-colors"
            >
              <span className="text-xs font-bold">GH</span>
            </a>
            <a
              href="mailto:contact@medisiem.lk"
              className="p-2 text-slate-400 dark:text-slate-500 hover:text-slate-900 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-slate-800 rounded-md transition-colors"
            >
              <Mail className="w-4 h-4" />
            </a>
          </div>
        </div>

        {/* Navigation */}
        <div>
          <h4 className="text-sm font-semibold text-slate-700 dark:text-slate-200 mb-4 uppercase tracking-wider">Platform</h4>
          <ul className="space-y-2.5">
            {[
              { label: 'Home', to: '/' },
              { label: 'About', to: '/about' },
              { label: 'Services', to: '/services' },
              { label: 'Pricing', to: '/pricing' },
            ].map((item) => (
              <li key={item.to}>
                <Link to={item.to} className="text-sm text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white transition-colors">
                  {item.label}
                </Link>
              </li>
            ))}
          </ul>
        </div>

        {/* Research */}
        <div>
          <h4 className="text-sm font-semibold text-slate-700 dark:text-slate-200 mb-4 uppercase tracking-wider">Research</h4>
          <ul className="space-y-2.5 text-sm text-slate-500 dark:text-slate-400">
            <li className="flex items-start gap-1.5">
              <ExternalLink className="w-3.5 h-3.5 mt-0.5 text-slate-400 dark:text-slate-600 flex-shrink-0" />
              <span>R26-CS-008 — SLIIT</span>
            </li>
            <li className="flex items-start gap-1.5">
              <ExternalLink className="w-3.5 h-3.5 mt-0.5 text-slate-400 dark:text-slate-600 flex-shrink-0" />
              <span>Supervisor: Mr. Amila Senarathne</span>
            </li>
            <li className="flex items-start gap-1.5">
              <ExternalLink className="w-3.5 h-3.5 mt-0.5 text-slate-400 dark:text-slate-600 flex-shrink-0" />
              <span>Co-Supervisor: Ms. Ayesha Wijesooroya</span>
            </li>
            <li>
              <Link to="/login" className="hover:text-slate-900 dark:hover:text-white transition-colors">Sign In</Link>
            </li>
          </ul>
        </div>
      </div>

      <div className="mt-10 pt-6 border-t border-slate-200 dark:border-slate-800 flex flex-col sm:flex-row items-center justify-between gap-3">
        <p className="text-xs text-slate-400 dark:text-slate-500">
          © {new Date().getFullYear()} MediSIEM — R26-CS-008 SLIIT Research Project. All rights reserved.
        </p>
        <p className="text-xs text-slate-400 dark:text-slate-600">
          Built with React · Vite · Tailwind CSS
        </p>
      </div>
    </div>
  </footer>
);

export default Footer;
