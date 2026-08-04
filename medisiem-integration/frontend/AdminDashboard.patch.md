# Wiring AdminDashboard.tsx to live alerts

Your current file hardcodes `MOCK_ALERTS` and maps it straight into `<AlertRow>`.
Three small changes:

## 1. Imports — add near the top

```tsx
import { useLiveAlerts } from '../../hooks/useLiveAlerts';
```

## 2. Remove the MOCK_ALERTS constant, replace with the hook inside the component

```tsx
const AdminDashboard: React.FC = () => {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const { alerts, connected, loading, error } = useLiveAlerts(); // ← new
  ...
```

## 3. Where you render the table, swap `MOCK_ALERTS.map(...)` for the live data
and adapt field names (the enriched shape differs slightly from your mock):

```tsx
<div className="flex items-center gap-2 text-xs text-slate-500 mb-2">
  <span className={`w-2 h-2 rounded-full ${connected ? 'bg-emerald-500' : 'bg-red-500'}`} />
  {connected ? 'Live' : 'Reconnecting…'}
</div>

<table>
  <thead>{/* unchanged */}</thead>
  <tbody>
    {loading && <tr><td colSpan={5}>Loading alerts…</td></tr>}
    {error && <tr><td colSpan={5} className="text-red-400">{error}</td></tr>}
    {alerts.map((a) => (
      <AlertRow
        key={a.id}
        severity={a.CAS >= 8 ? 'CRITICAL' : a.CAS >= 6 ? 'HIGH' : a.CAS >= 4 ? 'MEDIUM' : 'LOW'}
        device={a.agent}
        event={a.label !== 'Unclassified' ? a.label : a.ruleDescription}
        cas={a.CAS}
        time={new Date(a.timestamp).toLocaleTimeString()}
        status={a.action === 'Immediate' ? 'Open' : a.action === 'Investigate' ? 'Investigating' : 'Resolved'}
      />
    ))}
  </tbody>
</table>
```

No changes needed to `AlertRow` itself — the field names/types line up with what it already expects.
