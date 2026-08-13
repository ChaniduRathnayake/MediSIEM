// frontend/src/pages/dashboard/AlertDetailsModal.tsx
//
// "100% of the alert" in one place — every field the backend actually sent,
// not just the curated subset the table row shows. Two shapes come through
// here (EnrichedAlert from the ML/CAS pipeline, WazuhAlertRow from the raw
// Wazuh Indexer), so this renders whichever one it's given plus a raw-JSON
// fallback so nothing is ever truly hidden, even fields added later that
// this component doesn't know to label yet.
import React, { useState } from 'react';
import { X, ChevronDown, ChevronRight, Terminal, MapPin, Tag, ShieldCheck, Brain, Info } from 'lucide-react';
import type { EnrichedAlert } from '../../services/alertsApi';
import type { WazuhAlertRow } from './complianceApi';
import { casToSeverity } from '../../utils/chartData';
import type { Severity } from '../../utils/chartData';

type Props =
  | { kind: 'ml'; alert: EnrichedAlert; onClose: () => void }
  | { kind: 'wazuh'; alert: WazuhAlertRow; onClose: () => void };

const SEV_CLASS: Record<Severity, string> = {
  CRITICAL: 'text-red-500 dark:text-red-400 bg-red-500/10 border-red-500/30',
  HIGH: 'text-orange-500 dark:text-orange-400 bg-orange-500/10 border-orange-500/30',
  MEDIUM: 'text-amber-600 dark:text-amber-400 bg-amber-500/10 border-amber-500/30',
  LOW: 'text-blue-500 dark:text-blue-400 bg-blue-500/10 border-blue-500/30',
};

const wazuhSeverity = (level: number | null): Severity => {
  const l = level ?? 0;
  if (l >= 12) return 'CRITICAL';
  if (l >= 8) return 'HIGH';
  if (l >= 5) return 'MEDIUM';
  return 'LOW';
};

const KeyValueGrid: React.FC<{ rows: [string, React.ReactNode][] }> = ({ rows }) => (
  <dl className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-2.5">
    {rows.map(([label, value]) => (
      <div key={label} className="flex items-center justify-between gap-4 py-1 border-b border-slate-100 dark:border-slate-800/60 text-sm">
        <dt className="text-slate-400 dark:text-slate-500 flex-shrink-0">{label}</dt>
        <dd className="text-slate-900 dark:text-white text-right break-all font-mono text-xs">{value}</dd>
      </div>
    ))}
  </dl>
);

const SectionTitle: React.FC<{ icon: React.ReactNode; children: React.ReactNode }> = ({ icon, children }) => (
  <h3 className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
    {icon} {children}
  </h3>
);

const BadgeRow: React.FC<{ items: string[]; empty?: string }> = ({ items, empty = '—' }) =>
  items.length === 0 ? (
    <span className="text-xs text-slate-400 dark:text-slate-600">{empty}</span>
  ) : (
    <div className="flex flex-wrap gap-1.5">
      {items.map((it) => (
        <span key={it} className="text-xs px-1.5 py-0.5 rounded border border-slate-300 dark:border-slate-700 bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300">
          {it}
        </span>
      ))}
    </div>
  );

const RawJson: React.FC<{ data: unknown }> = ({ data }) => {
  const [open, setOpen] = useState(false);
  return (
    <div>
      <button
        onClick={() => setOpen((v) => !v)}
        className="flex items-center gap-1 text-xs text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white transition-colors"
      >
        {open ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
        Raw JSON (every field the backend sent)
      </button>
      {open && (
        <pre className="mt-2 p-3 rounded-lg bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-800 text-xs text-slate-500 dark:text-slate-400 overflow-x-auto max-h-80 overflow-y-auto whitespace-pre">
          {JSON.stringify(data, null, 2)}
        </pre>
      )}
    </div>
  );
};

// A Wazuh alert's `data` field carries whatever the decoder pulled out —
// srcip/dstip/srcport/dstport when the rule is network-related. Surfaced
// explicitly (not just buried in the generic field list) since "source /
// destination" is exactly what an analyst looks for first.
function extractNetworkFields(data: Record<string, unknown> | null): { source: string | null; destination: string | null } {
  if (!data) return { source: null, destination: null };
  const srcIp = data.srcip ?? data.src_ip ?? null;
  const srcPort = data.srcport ?? data.src_port ?? null;
  const dstIp = data.dstip ?? data.dst_ip ?? null;
  const dstPort = data.dstport ?? data.dst_port ?? null;
  const source = srcIp ? `${srcIp}${srcPort ? ':' + srcPort : ''}` : null;
  const destination = dstIp ? `${dstIp}${dstPort ? ':' + dstPort : ''}` : null;
  return { source: source as string | null, destination: destination as string | null };
}

const MlAlertBody: React.FC<{ alert: EnrichedAlert }> = ({ alert }) => {
  const severity = casToSeverity(alert.CAS);
  return (
    <div className="space-y-5">
      <div>
        <SectionTitle icon={<Info className="w-3.5 h-3.5" />}>Identity &amp; timing</SectionTitle>
        <KeyValueGrid
          rows={[
            ['Alert ID', alert.id],
            ['Timestamp', new Date(alert.timestamp).toLocaleString()],
            ['Severity', <span key="s" className={`px-2 py-0.5 rounded border font-bold ${SEV_CLASS[severity]}`}>{severity}</span>],
            ['Action', alert.action],
            ['Status', alert.assignedTo ? `Assigned to ${alert.assignedTo.name}` : 'Unassigned'],
          ]}
        />
      </div>

      <div>
        <SectionTitle icon={<MapPin className="w-3.5 h-3.5" />}>Source &amp; asset</SectionTitle>
        <KeyValueGrid
          rows={[
            ['Source IP', alert.src_ip ?? '— not captured for this alert —'],
            ['Destination', 'not tracked — this pipeline classifies per-device behavior, not connection pairs'],
            ['Device', alert.agent],
            ['Device type', alert.deviceType ?? '— not onboarded in the medical device inventory —'],
            ['Device criticality', alert.deviceCriticality ?? '—'],
            ['Department', alert.department],
            ['Cluster', alert.cluster],
          ]}
        />
      </div>

      {alert.mitre && alert.mitre.id.length > 0 && (
        <div>
          <SectionTitle icon={<Tag className="w-3.5 h-3.5" />}>MITRE ATT&amp;CK mapping</SectionTitle>
          <KeyValueGrid
            rows={[
              ['Technique ID', alert.mitre.id.join(', ')],
              ['Technique', alert.mitre.technique.join(', ') || '—'],
              ['Tactic', alert.mitre.tactic.join(', ') || '—'],
            ]}
          />
        </div>
      )}

      <div>
        <SectionTitle icon={<Brain className="w-3.5 h-3.5" />}>Why it's classified this way</SectionTitle>
        <div className="grid grid-cols-5 gap-2 mb-3">
          {([
            ['TR', alert.TR_score, 'Threat Risk — RF classification confidence'],
            ['CC', alert.CC_score, 'Clinical Criticality — how life-critical this device is'],
            ['TS', alert.TS_score, 'Time Sensitivity — Isolation Forest anomaly + time of day'],
            ['AE', alert.AE_score, 'Active Exploitation — known-exploited CVE match'],
            ['TC', alert.TC_score, 'Temporal Context — shift-based rule'],
          ] as [string, number, string][]).map(([label, value, hint]) => (
            <div key={label} className="px-2 py-2 rounded-lg bg-slate-100 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-800" title={hint}>
              <div className="text-[10px] text-slate-500 uppercase tracking-wider">{label}</div>
              <div className="text-sm font-mono text-slate-900 dark:text-white mt-0.5">{value.toFixed(1)}</div>
            </div>
          ))}
        </div>
        <KeyValueGrid
          rows={[
            ['Clinical Alert Score', alert.CAS.toFixed(2)],
            ['Label', alert.label],
            ['Confidence', typeof alert.confidence === 'number' ? `${(alert.confidence * 100).toFixed(1)}%` : 'n/a (rule.level fallback)'],
          ]}
        />
        <p className="text-xs text-slate-500 dark:text-slate-400 mt-2">
          <span className="text-slate-400 dark:text-slate-500">Explanation: </span>{alert.explanation}
        </p>
      </div>

      <div>
        <SectionTitle icon={<Tag className="w-3.5 h-3.5" />}>Matched detection rules</SectionTitle>
        <BadgeRow items={(alert.matchedRules ?? []).map((r) => r.name)} empty="No custom rule matched — ML detection only" />
      </div>

      {alert.flow && (
        <div>
          <SectionTitle icon={<Terminal className="w-3.5 h-3.5" />}>Raw flow features (all 45, as scored)</SectionTitle>
          <div className="overflow-x-auto rounded-lg border border-slate-200 dark:border-slate-800">
            <table className="w-full text-xs">
              <tbody>
                {Object.entries(alert.flow).map(([k, v], i) => (
                  <tr key={k} className={i % 2 === 0 ? 'bg-slate-50 dark:bg-slate-900/40' : ''}>
                    <td className="py-1 px-2.5 text-slate-500 dark:text-slate-400 whitespace-nowrap">{k}</td>
                    <td className="py-1 px-2.5 text-slate-900 dark:text-white font-mono text-right">{String(v)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      <RawJson data={alert} />
    </div>
  );
};

const WazuhAlertBody: React.FC<{ alert: WazuhAlertRow }> = ({ alert }) => {
  const severity = wazuhSeverity(alert.ruleLevel);
  const { source, destination } = extractNetworkFields(alert.data);
  const complianceBadges: { label: string; values: string[] }[] = [
    { label: 'HIPAA', values: alert.compliance?.hipaa ?? [] },
    { label: 'PCI-DSS', values: alert.compliance?.pciDss ?? [] },
    { label: 'GDPR', values: alert.compliance?.gdpr ?? [] },
    { label: 'NIST 800-53', values: alert.compliance?.nist80053 ?? [] },
    { label: 'TSC', values: alert.compliance?.tsc ?? [] },
    { label: 'GPG13', values: alert.compliance?.gpg13 ?? [] },
  ].filter((c) => c.values.length > 0);

  return (
    <div className="space-y-5">
      <div>
        <SectionTitle icon={<Info className="w-3.5 h-3.5" />}>Identity &amp; timing</SectionTitle>
        <KeyValueGrid
          rows={[
            ['Alert ID', alert.id],
            ['Timestamp', alert.timestamp ? new Date(alert.timestamp).toLocaleString() : '—'],
            ['Severity', <span key="s" className={`px-2 py-0.5 rounded border font-bold ${SEV_CLASS[severity]}`}>{severity}</span>],
            ['Rule ID', alert.ruleId ?? '—'],
            ['Rule level', alert.ruleLevel ?? '—'],
            ['Fired recently', alert.ruleFiredTimes !== null ? `${alert.ruleFiredTimes}x` : '—'],
          ]}
        />
      </div>

      <div>
        <SectionTitle icon={<MapPin className="w-3.5 h-3.5" />}>Source &amp; destination</SectionTitle>
        <KeyValueGrid
          rows={[
            ['Agent', `${alert.agentName ?? '—'} (#${alert.agentId ?? '—'})`],
            ['Agent IP', alert.agentIp ?? '—'],
            ['Source (from log)', source ?? '— not present in this alert\'s decoded fields —'],
            ['Destination (from log)', destination ?? '— not present in this alert\'s decoded fields —'],
            ['Location', alert.location ?? '—'],
            ['Decoder', alert.decoder ?? '—'],
          ]}
        />
      </div>

      <div>
        <SectionTitle icon={<Terminal className="w-3.5 h-3.5" />}>Raw log</SectionTitle>
        <pre className="text-xs font-mono text-slate-700 dark:text-slate-300 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg px-3 py-2 whitespace-pre-wrap break-all">
          {alert.fullLog ?? '— not captured for this alert —'}
        </pre>
      </div>

      <div>
        <SectionTitle icon={<Info className="w-3.5 h-3.5" />}>Full description</SectionTitle>
        <p className="text-xs text-slate-500 dark:text-slate-400">{alert.ruleDescription ?? '—'}</p>
      </div>

      {alert.data && Object.keys(alert.data).length > 0 && (
        <div>
          <SectionTitle icon={<Info className="w-3.5 h-3.5" />}>Decoded fields</SectionTitle>
          <KeyValueGrid rows={Object.entries(alert.data).map(([k, v]) => [k, String(v)])} />
        </div>
      )}

      <div>
        <SectionTitle icon={<Tag className="w-3.5 h-3.5" />}>Rule groups</SectionTitle>
        <BadgeRow items={alert.ruleGroups} />
      </div>

      {complianceBadges.length > 0 && (
        <div>
          <SectionTitle icon={<ShieldCheck className="w-3.5 h-3.5" />}>Compliance mapping</SectionTitle>
          <div className="flex flex-wrap gap-1.5">
            {complianceBadges.map((c) => (
              <span
                key={c.label}
                title={c.values.join(', ')}
                className="text-xs px-1.5 py-0.5 rounded border border-violet-500/30 bg-violet-500/10 text-violet-600 dark:text-violet-400"
              >
                {c.label} ({c.values.join(', ')})
              </span>
            ))}
          </div>
        </div>
      )}

      <RawJson data={alert} />
    </div>
  );
};

const AlertDetailsModal: React.FC<Props> = (props) => {
  const { onClose } = props;
  const title = props.kind === 'ml'
    ? (props.alert.label !== 'Unclassified' ? props.alert.label : props.alert.ruleDescription)
    : (props.alert.ruleDescription ?? 'Alert details');
  const subtitle = props.kind === 'ml' ? `${props.alert.agent} · CAS ${props.alert.CAS.toFixed(1)}` : `${props.alert.agentName ?? 'Unknown agent'} · level ${props.alert.ruleLevel ?? '—'}`;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center px-4 bg-black/60 backdrop-blur-sm" onClick={onClose}>
      <div
        className="w-full max-w-3xl rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-2xl overflow-hidden max-h-[88vh] flex flex-col"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-200 dark:border-slate-800 flex-shrink-0">
          <div className="min-w-0">
            <h2 className="text-sm font-bold text-slate-900 dark:text-white truncate">{title}</h2>
            <p className="text-xs text-slate-400 dark:text-slate-500 mt-0.5">{subtitle}</p>
          </div>
          <button onClick={onClose} className="text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white transition-colors flex-shrink-0 ml-3">
            <X className="w-4 h-4" />
          </button>
        </div>
        <div className="px-6 py-5 overflow-y-auto">
          {props.kind === 'ml' ? <MlAlertBody alert={props.alert} /> : <WazuhAlertBody alert={props.alert} />}
        </div>
      </div>
    </div>
  );
};

export default AlertDetailsModal;
