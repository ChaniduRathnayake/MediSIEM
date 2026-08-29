import React from 'react';
import { BrowserRouter, Routes, Route, Navigate, useLocation } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';
import { ThemeProvider } from './context/ThemeContext';
import { ToastProvider } from './context/ToastContext';
import { NotificationCenterProvider } from './context/NotificationCenterContext';

// Pages
import HomePage from './pages/HomePage';
import LoginPage from './pages/LoginPage';
import ResetPasswordPage from './pages/ResetPasswordPage';
import AboutPage from './pages/AboutPage';
import ServicesPage from './pages/ServicesPage';
import PricingPage from './pages/PricingPage';
import AdminDashboard from './pages/dashboard/AdminDashboard';
import UserDashboard from './pages/dashboard/UserDashboard';
import Wallboard from './pages/dashboard/Wallboard';
import ClinicianPage from './pages/ClinicianPage';
import DevBombPage from './pages/DevBombPage';

// Components
import Navbar from './components/Navbar';
import Footer from './components/Footer';
import AiChatWidget from './components/AiChatWidget';

// ─── Route Guards ──────────────────────────────────────────────────────────────

/** Redirects unauthenticated users to /login. Clinician accounts are a
 * single-purpose role confined to /clinician (see models/User.js on the
 * backend) — any other private route bounces them there instead of
 * rendering, so this guard doubles as the frontend half of that restriction
 * (the backend independently refuses clinician-role calls to every other
 * role-gated endpoint, so this isn't the only thing enforcing it). */
const PrivateRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { isAuthenticated, isLoading, user } = useAuth();
  const location = useLocation();

  if (isLoading) return <FullPageSpinner />;
  if (!isAuthenticated) return <Navigate to="/login" replace />;
  if (user?.role === 'clinician' && location.pathname !== '/clinician') {
    return <Navigate to="/clinician" replace />;
  }
  return <>{children}</>;
};

/** Redirects non-admins to /dashboard (or clinicians straight to /clinician) */
const AdminRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { isAuthenticated, isLoading, user } = useAuth();

  if (isLoading) return <FullPageSpinner />;
  if (!isAuthenticated) return <Navigate to="/login" replace />;
  if (user?.role === 'clinician') return <Navigate to="/clinician" replace />;
  if (user?.role !== 'admin') return <Navigate to="/dashboard" replace />;
  return <>{children}</>;
};

/** Redirects already-authenticated users away from auth pages */
const PublicOnlyRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { isAuthenticated, isLoading, user } = useAuth();

  if (isLoading) return <FullPageSpinner />;
  if (isAuthenticated) {
    const target = user?.role === 'admin' ? '/admin' : user?.role === 'clinician' ? '/clinician' : '/dashboard';
    return <Navigate to={target} replace />;
  }
  return <>{children}</>;
};

// ─── Full-page spinner ─────────────────────────────────────────────────────────
const FullPageSpinner: React.FC = () => (
  <div className="min-h-screen bg-white dark:bg-slate-950 flex items-center justify-center">
    <div className="flex flex-col items-center gap-4">
      <div className="w-10 h-10 border-2 border-cyan-500/30 border-t-cyan-500 rounded-full animate-spin" />
      <p className="text-slate-500 text-sm tracking-widest uppercase">Loading</p>
    </div>
  </div>
);

// ─── Layout wrappers ───────────────────────────────────────────────────────────

/** Public pages get Navbar + Footer */
const PublicLayout: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <>
    <Navbar />
    <main>{children}</main>
    <Footer />
  </>
);

/** Dashboard pages are full-screen, no public nav/footer — the floating AI assistant
 * is available on both (but not on the bare /wallboard route, which stays chrome-free). */
const DashboardLayout: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <>
    {children}
    <AiChatWidget />
  </>
);

// ─── App ───────────────────────────────────────────────────────────────────────
const AppRoutes: React.FC = () => (
  <Routes>
    {/* ── Public routes ── */}
    <Route
      path="/home"
      element={
        <PublicLayout>
          <HomePage />
        </PublicLayout>
      }
    />
    <Route
      path="/about"
      element={
        <PublicLayout>
          <AboutPage />
        </PublicLayout>
      }
    />
    <Route
      path="/services"
      element={
        <PublicLayout>
          <ServicesPage />
        </PublicLayout>
      }
    />
    <Route
      path="/pricing"
      element={
        <PublicLayout>
          <PricingPage />
        </PublicLayout>
      }
    />

    {/* ── Auth routes (redirect if already logged in) ── */}
    <Route
      path="/"
      element={
        <PublicOnlyRoute>
          <LoginPage />
        </PublicOnlyRoute>
      }
    />
    <Route
      path="/login"
      element={
        <PublicOnlyRoute>
          <LoginPage />
        </PublicOnlyRoute>
      }
    />
    <Route path="/reset-password/:token" element={<ResetPasswordPage />} />

    {/* ── Protected: patient/user dashboard ── */}
    <Route
      path="/dashboard"
      element={
        <PrivateRoute>
          <DashboardLayout>
            <UserDashboard />
          </DashboardLayout>
        </PrivateRoute>
      }
    />

    {/* ── Protected: admin-only dashboard ── */}
    <Route
      path="/admin"
      element={
        <AdminRoute>
          <DashboardLayout>
            <AdminDashboard />
          </DashboardLayout>
        </AdminRoute>
      }
    />

    {/* ── Protected: SOC wallboard (admin + SOC analyst) — bare, no dashboard/public chrome ── */}
    <Route
      path="/wallboard"
      element={
        <PrivateRoute>
          <Wallboard />
        </PrivateRoute>
      }
    />

    {/* ── Protected: clinician Tier 3 approval view — bare, mobile-friendly, no
        dashboard chrome. Requires login but no specific role to view — every
        authenticated role can reach this page; the actual approve/deny call
        is separately role-gated server-side
        (backend/routes/lifeCriticalOrchestration.js's allowRoles). The
        dedicated 'clinician' role is the mirror image: it can view this page
        and nothing else — PrivateRoute above redirects it here from every
        other private route. ── */}
    <Route
      path="/clinician"
      element={
        <PrivateRoute>
          <ClinicianPage />
        </PrivateRoute>
      }
    />

    {/* ── Dev-only: wipes the entire alert backlog for a clean demo reset. Bare, no
        auth guard — matches backend/routes/dev.js, which is itself disabled in
        production. Not linked from anywhere; reached by typing the URL. ── */}
    <Route path="/devbomb" element={<DevBombPage />} />

    {/* ── Fallback ── */}
    <Route path="*" element={<Navigate to="/" replace />} />
  </Routes>
);

const App: React.FC = () => (
  <ThemeProvider>
    <BrowserRouter>
      <AuthProvider>
        <ToastProvider>
          <NotificationCenterProvider>
            <AppRoutes />
          </NotificationCenterProvider>
        </ToastProvider>
      </AuthProvider>
    </BrowserRouter>
  </ThemeProvider>
);

export default App;