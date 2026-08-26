import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.jsx'
import ClinicianView from './pages/ClinicianView.jsx'

// Minimal path-based routing — no router dependency needed for two routes.
// "/clinician" (and anything nested under it) renders the standalone
// clinician-facing approval view; everything else renders the SOC
// dashboard. Vite's dev server and `vite preview` both fall back to
// index.html for unknown paths (default SPA appType), so this works with
// a plain browser navigation to http://localhost:5173/clinician too.
const isClinicianRoute = window.location.pathname.startsWith('/clinician')

createRoot(document.getElementById('root')).render(
  <StrictMode>
    {isClinicianRoute ? <ClinicianView /> : <App />}
  </StrictMode>,
)
