// Small inline badges shared by every alert view — kept as one component so
// the "what counts as life-critical" / MITRE-formatting logic lives in one place.
import React from 'react';
import { HeartPulse, Target } from 'lucide-react';
import { EnrichedAlert } from '../services/alertsApi';

export const isLifeCriticalDevice = (a: Pick<EnrichedAlert, 'deviceCriticality'>): boolean =>
  a.deviceCriticality === 'critical';

export const LifeCriticalBadge: React.FC<{ className?: string }> = ({ className = '' }) => (
  <span
    title="This alert's device is tagged 'critical' in the medical device inventory"
    className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded-full bg-red-500/10 border border-red-500/30 text-red-400 text-[10px] font-semibold uppercase tracking-wide whitespace-nowrap ${className}`}
  >
    <HeartPulse className="w-2.5 h-2.5" /> Life-critical device
  </span>
);

export const MitreBadge: React.FC<{ mitre: EnrichedAlert['mitre']; className?: string }> = ({ mitre, className = '' }) => {
  if (!mitre || mitre.id.length === 0) return null;
  const tooltip = [
    mitre.technique.length ? `Technique: ${mitre.technique.join(', ')}` : null,
    mitre.tactic.length ? `Tactic: ${mitre.tactic.join(', ')}` : null,
  ].filter(Boolean).join(' · ');

  return (
    <span
      title={tooltip || undefined}
      className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded-full bg-violet-500/10 border border-violet-500/30 text-violet-400 dark:text-violet-300 text-[10px] font-semibold whitespace-nowrap ${className}`}
    >
      <Target className="w-2.5 h-2.5" /> {mitre.id.join(', ')}
    </span>
  );
};

// Convenience wrapper for the common case of showing both together.
const AlertContextBadges: React.FC<{ alert: Pick<EnrichedAlert, 'deviceCriticality' | 'mitre'>; className?: string }> = ({ alert, className = '' }) => {
  if (!isLifeCriticalDevice(alert) && !alert.mitre?.id?.length) return null;
  return (
    <span className={`inline-flex items-center gap-1.5 flex-wrap ${className}`}>
      {isLifeCriticalDevice(alert) && <LifeCriticalBadge />}
      {alert.mitre && <MitreBadge mitre={alert.mitre} />}
    </span>
  );
};

export default AlertContextBadges;
