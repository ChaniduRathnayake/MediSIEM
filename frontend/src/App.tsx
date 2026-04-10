import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';

// Pages
import HomePage from './pages/HomePage';
import LoginPage from './pages/LoginPage';
import RegisterPage from './pages/RegisterPage';
import AboutPage from './pages/AboutPage';
import ServicesPage from './pages/ServicesPage';
import PricingPage from './pages/PricingPage';
import AdminDashboard from './pages/dashboard/AdminDashboard';
import UserDashboard from './pages/dashboard/UserDashboard';

// Components
import Navbar from './components/Navbar';
import Footer from './components/Footer';

// ─── Route Guards ──────────────────────────────────────────────────────────────

/** Redirects unauthenticated users to /login */
const PrivateRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { isAuthenticated, isLoading } = useAuth();

  if (isLoading) return <FullPageSpinner />;
  if (!isAuthenticated) return <Navigate to="/login" replace />;
  return <>{children}</>;
};

/** Redirects non-admins to /dashboard */
const AdminRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { isAuthenticated, isLoading, user } = useAuth();

  if (isLoading) return <FullPageSpinner />;
  if (!isAuthenticated) return <Navigate to="/login" replace />;
  if (user?.role !== 'admin') return <Navigate to="/dashboard" replace />;
  return <>{children}</>;
};

/** Redirects already-authenticated users away from auth pages */
const PublicOnlyRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { isAuthenticated, isLoading, user } = useAuth();

  if (isLoading) return <FullPageSpinner />;
  if (isAuthenticated) {
    return <Navigate to={user?.role === 'admin' ? '/admin' : '/dashboard'} replace />;
  }
  return <>{children}</>;
};

// ─── Full-page spinner ─────────────────────────────────────────────────────────
const FullPageSpinner: React.FC = () => (
  <div className="min-h-screen bg-slate-950 flex items-center justify-center">
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

/** Dashboard pages are full-screen, no public nav/footer */
const DashboardLayout: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <>{children}</>
);

// ─── App ───────────────────────────────────────────────────────────────────────
const AppRoutes: React.FC = () => (
  <Routes>
    {/* ── Public routes ── */}
    <Route
      path="/"
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
      path="/login"
      element={
        <PublicOnlyRoute>
          <LoginPage />
        </PublicOnlyRoute>
      }
    />
    <Route
      path="/register"
      element={
        <PublicOnlyRoute>
          <RegisterPage />
        </PublicOnlyRoute>
      }
    />

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

    {/* ── Fallback ── */}
    <Route path="*" element={<Navigate to="/" replace />} />
  </Routes>
);

const App: React.FC = () => (
  <BrowserRouter>
    <AuthProvider>
      <AppRoutes />
    </AuthProvider>
  </BrowserRouter>
);

export default App;