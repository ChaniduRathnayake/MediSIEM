import React, { useState, useEffect } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { Shield, Menu, X, ChevronRight } from 'lucide-react';

const NAV_LINKS = [
  { label: 'Home', href: '/' },
  { label: 'About', href: '/about' },
  { label: 'Services', href: '/services' },
  { label: 'Pricing', href: '/pricing' },
];

// ─── CAS Demo Banner ──────────────────────────────────────────────────────────
const CasDemoBanner: React.FC = () => (
  <div
    style={{
      position: 'fixed',
      top: 0,
      left: 0,
      right: 0,
      zIndex: 60,
      height: '38px',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      padding: '0 1.5rem',
      background: 'linear-gradient(90deg, #0d1117 0%, #0f1f33 50%, #0d1117 100%)',
      borderBottom: '1px solid rgba(88,166,255,0.18)',
      overflow: 'hidden',
    }}
  >
    {/* Left accent line */}
    <div
      style={{
        position: 'absolute',
        left: 0,
        top: 0,
        bottom: 0,
        width: '3px',
        background: 'linear-gradient(180deg, #58a6ff, #bc8cff)',
      }}
    />

    {/* Left side */}
    <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
      {/* Pulsing dot */}
      <span
        style={{
          display: 'inline-block',
          width: '6px',
          height: '6px',
          borderRadius: '50%',
          background: '#3fb950',
          boxShadow: '0 0 6px #3fb950',
          animation: 'casBannerPulse 2.2s ease-in-out infinite',
        }}
      />
      {/* Live Demo pill */}
      <span
        style={{
          fontFamily: "'DM Mono', 'Courier New', monospace",
          fontSize: '9px',
          fontWeight: 500,
          letterSpacing: '0.14em',
          textTransform: 'uppercase',
          padding: '2px 9px',
          borderRadius: '20px',
          background: 'rgba(88,166,255,0.12)',
          border: '1px solid rgba(88,166,255,0.30)',
          color: '#58a6ff',
          whiteSpace: 'nowrap',
        }}
      >
        Live Demo
      </span>
      {/* Title */}
      <span
        style={{
          fontFamily: 'Georgia, serif',
          fontSize: '12px',
          fontWeight: 600,
          letterSpacing: '-0.01em',
          color: '#e6edf3',
        }}
      >
        CAAP —{' '}
        <span style={{ color: '#58a6ff' }}>CAS</span>{' '}
        Demo Presentation
      </span>
    </div>

    {/* Right side */}
    <div
      style={{
        fontSize: '10px',
        color: '#8b949e',
        letterSpacing: '0.05em',
        textTransform: 'uppercase',
        textAlign: 'right',
        lineHeight: 1.5,
      }}
    >
      <span style={{ color: '#e6edf3', fontWeight: 500 }}>
        Clinically Aware Alert Prioritization
      </span>
      {' · '}BSc (Hons) Cybersecurity · SLIIT · IT22061270
    </div>

    {/* Keyframe injection */}
    <style>{`
      @keyframes casBannerPulse {
        0%, 100% { opacity: 1; box-shadow: 0 0 6px #3fb950; }
        50%       { opacity: 0.45; box-shadow: 0 0 2px #3fb950; }
      }
    `}</style>
  </div>
);

// ─── Navbar ───────────────────────────────────────────────────────────────────
const Navbar: React.FC = () => {
  const [open, setOpen] = useState(false);
  const [scrolled, setScrolled] = useState(false);
  const location = useLocation();

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 20);
    window.addEventListener('scroll', onScroll);
    return () => window.removeEventListener('scroll', onScroll);
  }, []);

  useEffect(() => { setOpen(false); }, [location.pathname]);

  return (
    <>
      {/* CAS Demo banner — always rendered above the nav */}
      <CasDemoBanner />

      <header
        className={`fixed left-0 right-0 z-50 transition-all duration-300 ${
          scrolled
            ? 'bg-slate-950/95 backdrop-blur-md shadow-lg shadow-cyan-500/5 border-b border-slate-800'
            : 'bg-transparent'
        }`}
        style={{ top: '38px' }}   /* sit directly below the 38px banner */
      >
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            {/* Logo */}
            <Link to="/" className="flex items-center gap-2.5 group">
              <div className="relative">
                <div className="w-8 h-8 bg-gradient-to-br from-cyan-500 to-blue-600 rounded-lg flex items-center justify-center shadow-lg shadow-cyan-500/30 group-hover:shadow-cyan-500/50 transition-shadow">
                  <Shield className="w-4.5 h-4.5 text-white" strokeWidth={2.5} />
                </div>
                <span className="absolute -top-0.5 -right-0.5 w-2 h-2 bg-emerald-400 rounded-full animate-pulse" />
              </div>
              <span className="font-bold text-lg text-white tracking-tight">
                Medi<span className="text-cyan-400">SIEM</span>
              </span>
            </Link>

            {/* Desktop Nav */}
            <nav className="hidden md:flex items-center gap-1">
              {NAV_LINKS.map((link) => {
                const active = location.pathname === link.href;
                return (
                  <Link
                    key={link.href}
                    to={link.href}
                    className={`px-4 py-2 rounded-lg text-sm font-medium transition-all duration-200 ${
                      active
                        ? 'text-cyan-400 bg-cyan-500/10'
                        : 'text-slate-400 hover:text-white hover:bg-slate-800'
                    }`}
                  >
                    {link.label}
                  </Link>
                );
              })}
            </nav>

            {/* CTA Buttons */}
            <div className="hidden md:flex items-center gap-3">
              <Link
                to="/login"
                className="px-4 py-2 text-sm font-medium text-slate-300 hover:text-white transition-colors"
              >
                Sign In
              </Link>
              <Link
                to="/register"
                className="flex items-center gap-1.5 px-4 py-2 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white text-sm font-semibold rounded-lg transition-all shadow-lg shadow-cyan-500/25 hover:shadow-cyan-500/40"
              >
                Get Started <ChevronRight className="w-3.5 h-3.5" />
              </Link>
            </div>

            {/* Mobile Toggle */}
            <button
              onClick={() => setOpen(!open)}
              className="md:hidden p-2 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition-colors"
              aria-label="Toggle menu"
            >
              {open ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
            </button>
          </div>
        </div>

        {/* Mobile Menu */}
        {open && (
          <div className="md:hidden bg-slate-950/98 backdrop-blur-md border-t border-slate-800 px-4 py-4 space-y-1">
            {NAV_LINKS.map((link) => {
              const active = location.pathname === link.href;
              return (
                <Link
                  key={link.href}
                  to={link.href}
                  className={`block px-4 py-3 rounded-lg text-sm font-medium transition-colors ${
                    active ? 'text-cyan-400 bg-cyan-500/10' : 'text-slate-400 hover:text-white hover:bg-slate-800'
                  }`}
                >
                  {link.label}
                </Link>
              );
            })}
            <div className="pt-3 border-t border-slate-800 flex flex-col gap-2">
              <Link
                to="/login"
                className="block px-4 py-3 text-sm font-medium text-slate-300 hover:text-white rounded-lg hover:bg-slate-800 transition-colors"
              >
                Sign In
              </Link>
              <Link
                to="/register"
                className="block px-4 py-3 bg-gradient-to-r from-cyan-500 to-blue-600 text-white text-sm font-semibold rounded-lg text-center"
              >
                Get Started
              </Link>
            </div>
          </div>
        )}
      </header>

      {/* Push page content below banner + nav (38px + 64px = 102px) */}
      <div style={{ height: '102px' }} />
    </>
  );
};

export default Navbar;
