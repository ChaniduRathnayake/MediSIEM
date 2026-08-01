// Comprehensive per-agent details — everything the Wazuh API exposes about one
// agent: core metadata, syscollector inventory (hardware/OS/network/software/
// processes/ports), and security state (vulnerabilities/SCA/FIM).
import React, { useEffect, useState } from 'react';
import {
  X, Loader2, AlertCircle, Info, Server, Cpu, Network, Package,
  Activity, ShieldAlert, ClipboardCheck, FileSearch,
} from 'lucide-react';
import {
  WazuhAgent, WazuhAgentDetails, WazuhConfig,
  normalizeAgentStatus, formatOs, getAgentDetails,
} from './wazuhApi';

type SectionKey = 'overview' | 'hardware' | 'network' | 'software' | 'processes' | 'vulnerabilities' | 'sca' | 'fim';

// Last line of defense: this modal renders whatever shape the live Wazuh API
// happens to return, which varies by OS/version in ways no static type can fully
// pin down. If a section still hits something unrenderable, fail that section
// only — never take the whole dashboard down to a white screen.
class SectionErrorBoundary extends React.Component<
  { resetKey: string; children: React.ReactNode },
  { error: Error | null }
> {
  state: { error: Error | null } = { error: null };
  static getDerivedStateFromError(error: Error) { return { error }; }
  componentDidUpdate(prev: { resetKey: string }) {
    if (prev.resetKey !== this.props.resetKey && this.state.error) this.setState({ error: null });
  }
  render() {
    if (this.state.error) {
      return (
        <div className="flex items-start gap-2 p-4 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-xs">
          <AlertCircle className="w-3.5 h-3.5 flex-shrink-0 mt-0.5" />
          <span>Couldn't render this section — the data returned an unexpected shape. ({this.state.error.message})</span>
        </div>
      );
    }
    return this.props.children;
  }
}

const statusMeta: Record<ReturnType<typeof normalizeAgentStatus>, { dot: string; label: string; online: boolean }> = {
  active:          { dot: 'bg-emerald-400', label: 'Active',          online: true },
  disconnected:    { dot: 'bg-red-400',     label: 'Disconnected',    online: false },
  never_connected: { dot: 'bg-slate-600',   label: 'Never Connected', online: false },
  pending:         { dot: 'bg-amber-400',   label: 'Pending',         online: false },
};

const formatKB = (kb?: number): string => {
  if (kb === undefined || kb === null) return '—';
  if (kb >= 1024 * 1024) return `${(kb / (1024 * 1024)).toFixed(1)} GB`;
  if (kb >= 1024) return `${(kb / 1024).toFixed(1)} MB`;
  return `${kb} KB`;
};

const formatDate = (v?: string): string => {
  if (!v) return '—';
  const d = new Date(v);
  return isNaN(d.getTime()) ? v : d.toLocaleString();
};

// Real Wazuh responses vary by OS/version in ways our types can't fully pin down
// (e.g. Windows FIM entries return `perm` as a nested ACL object instead of a
// string). Rendering an object directly as a React child crashes to a white
// screen, so every raw field goes through this before hitting JSX.
function safe(v: unknown): React.ReactNode {
  if (v === null || v === undefined || v === '') return '—';
  if (typeof v === 'string' || typeof v === 'number') return v;
  if (typeof v === 'boolean') return v ? 'Yes' : 'No';
  if (Array.isArray(v)) return v.length === 0 ? '—' : v.map(safe).join(', ');
  if (typeof v === 'object') {
    try { return JSON.stringify(v); } catch { return String(v); }
  }
  return String(v);
}

// ─── Small building blocks ───────────────────────────────────────────────────────
const SectionUnavailable: React.FC<{ message?: string }> = ({ message }) => (
  <div className="flex items-start gap-2 p-4 rounded-lg bg-slate-800/40 border border-slate-800 text-slate-500 text-xs">
    <Info className="w-3.5 h-3.5 flex-shrink-0 mt-0.5" />
    <span>{message || 'Not available — this module may not be enabled on the manager, or no data has been collected yet for this agent.'}</span>
  </div>
);

const SimpleTable: React.FC<{
  columns: string[];
  rows: React.ReactNode[][];
  empty?: string;
  shownCount?: number;
  totalCount?: number;
}> = ({ columns, rows, empty = 'No data', shownCount, totalCount }) => (
  <div>
    <div className="overflow-x-auto rounded-lg border border-slate-800">
      <table className="w-full text-xs">
        <thead>
          <tr className="border-b border-slate-800 bg-slate-800/40">
            {columns.map((c) => (
              <th key={c} className="py-2 px-3 text-left font-medium text-slate-500 whitespace-nowrap">{c}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.length === 0 ? (
            <tr><td colSpan={columns.length} className="py-8 text-center text-slate-500">{empty}</td></tr>
          ) : rows.map((r, i) => (
            <tr key={i} className="border-b border-slate-800/60 last:border-0 hover:bg-slate-800/30 transition-colors">
              {r.map((cell, j) => <td key={j} className="py-2 px-3 text-slate-300 whitespace-nowrap">{cell}</td>)}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
    {totalCount !== undefined && shownCount !== undefined && totalCount > shownCount && (
      <p className="text-xs text-slate-600 mt-2">Showing {shownCount} of {totalCount}</p>
    )}
  </div>
);

const KeyValueGrid: React.FC<{ rows: [string, React.ReactNode][] }> = ({ rows }) => (
  <dl className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-2.5">
    {rows.map(([label, value]) => (
      <div key={label} className="flex items-center justify-between gap-4 py-1 border-b border-slate-800/60 text-sm">
        <dt className="text-slate-500 flex-shrink-0">{label}</dt>
        <dd className="text-white text-right break-all">{value}</dd>
      </div>
    ))}
  </dl>
);

const severityBadgeClass = (severity?: string): string => {
  const s = String(severity ?? '').toLowerCase();
  if (s === 'critical') return 'text-red-400 bg-red-500/10 border-red-500/30';
  if (s === 'high') return 'text-orange-400 bg-orange-500/10 border-orange-500/30';
  if (s === 'medium') return 'text-amber-400 bg-amber-500/10 border-amber-500/30';
  return 'text-blue-400 bg-blue-500/10 border-blue-500/30';
};

// ─── Main modal ───────────────────────────────────────────────────────────────
const AgentDetailsModal: React.FC<{
  agent: WazuhAgent;
  config: WazuhConfig;
  onClose: () => void;
}> = ({ agent, config, onClose }) => {
  const [details, setDetails] = useState<WazuhAgentDetails | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [section, setSection] = useState<SectionKey>('overview');

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError('');
    getAgentDetails(config, agent.id)
      .then((d) => { if (!cancelled) setDetails(d); })
      .catch((err: unknown) => { if (!cancelled) setError(err instanceof Error ? err.message : 'Failed to load agent details.'); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [agent.id, config]);

  const meta = statusMeta[normalizeAgentStatus(agent.status)];

  const sections: { id: SectionKey; label: string; icon: React.ReactNode }[] = [
    { id: 'overview', label: 'Overview', icon: <Server className="w-3.5 h-3.5" /> },
    { id: 'hardware', label: 'Hardware & OS', icon: <Cpu className="w-3.5 h-3.5" /> },
    { id: 'network', label: 'Network', icon: <Network className="w-3.5 h-3.5" /> },
    { id: 'software', label: 'Software', icon: <Package className="w-3.5 h-3.5" /> },
    { id: 'processes', label: 'Processes', icon: <Activity className="w-3.5 h-3.5" /> },
    { id: 'vulnerabilities', label: 'Vulnerabilities', icon: <ShieldAlert className="w-3.5 h-3.5" /> },
    { id: 'sca', label: 'SCA', icon: <ClipboardCheck className="w-3.5 h-3.5" /> },
    { id: 'fim', label: 'FIM', icon: <FileSearch className="w-3.5 h-3.5" /> },
  ];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center px-4 bg-black/60 backdrop-blur-sm" onClick={onClose}>
      <div
        className="w-full max-w-4xl rounded-2xl bg-slate-900 border border-slate-800 shadow-2xl overflow-hidden max-h-[88vh] flex flex-col"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 flex-shrink-0">
          <div>
            <h2 className="text-sm font-bold text-white flex items-center gap-2">
              <span className={`w-2 h-2 rounded-full ${meta.dot}`} />
              {agent.name}
              <span className="text-slate-600 font-mono text-xs font-normal">#{agent.id}</span>
            </h2>
            <p className="text-xs text-slate-500 mt-0.5">{meta.label} · {agent.ip ?? 'no IP'} · {formatOs(agent.os)}</p>
          </div>
          <button onClick={onClose} className="text-slate-400 hover:text-white transition-colors flex-shrink-0">
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Section tabs */}
        <div className="flex gap-1 px-6 py-2.5 border-b border-slate-800 overflow-x-auto flex-shrink-0">
          {sections.map((s) => (
            <button
              key={s.id}
              onClick={() => setSection(s.id)}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium whitespace-nowrap transition-all ${
                section === s.id
                  ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20'
                  : 'text-slate-400 hover:text-white hover:bg-slate-800 border border-transparent'
              }`}
            >
              {s.icon} {s.label}
            </button>
          ))}
        </div>

        {/* Body */}
        <div className="px-6 py-5 overflow-y-auto">
        <SectionErrorBoundary resetKey={section}>
          {section === 'overview' ? (
            <KeyValueGrid rows={[
              ['ID', agent.id],
              ['Name', agent.name],
              ['Status', (
                <span className="flex items-center gap-1.5 justify-end">
                  <span className={`w-1.5 h-1.5 rounded-full ${meta.dot}`} />
                  <span className={meta.online ? 'text-emerald-400' : 'text-slate-300'}>{meta.label}</span>
                </span>
              )],
              ['IP Address', agent.ip ?? '—'],
              ['OS', formatOs(agent.os)],
              ['OS Platform', agent.os?.platform ?? '—'],
              ['OS Architecture', agent.os?.arch ?? '—'],
              ['OS Codename', agent.os?.codename ?? '—'],
              ['Agent Version', agent.version ?? '—'],
              ['Groups', agent.group && agent.group.length > 0 ? agent.group.join(', ') : '—'],
              ['Group Sync Status', agent.group_config_status ?? '—'],
              ['Manager', agent.manager ?? '—'],
              ['Cluster Node', agent.node_name ?? '—'],
              ['Registered', formatDate(agent.dateAdd)],
              ['Last Keep-Alive', formatDate(agent.lastKeepAlive)],
            ]} />
          ) : loading ? (
            <div className="flex items-center justify-center gap-2 py-16 text-slate-500 text-sm">
              <Loader2 className="w-4 h-4 animate-spin" /> Loading {sections.find((s) => s.id === section)?.label.toLowerCase()}…
            </div>
          ) : error ? (
            <div className="flex items-center gap-2 px-4 py-4 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-sm">
              <AlertCircle className="w-4 h-4 flex-shrink-0" /> {error}
            </div>
          ) : !details ? (
            <SectionUnavailable />
          ) : section === 'hardware' ? (
            <div className="space-y-5">
              <div>
                <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Hardware</h3>
                {details.hardware.ok && details.hardware.item ? (
                  <KeyValueGrid rows={[
                    ['CPU', safe(details.hardware.item.cpu?.name)],
                    ['CPU Cores', safe(details.hardware.item.cpu?.cores)],
                    ['CPU Speed', details.hardware.item.cpu?.mhz ? `${details.hardware.item.cpu.mhz} MHz` : '—'],
                    ['Total RAM', formatKB(details.hardware.item.ram?.total)],
                    ['Free RAM', formatKB(details.hardware.item.ram?.free)],
                    ['RAM Usage', details.hardware.item.ram?.usage !== undefined ? `${details.hardware.item.ram.usage}%` : '—'],
                    ['Board Serial', safe(details.hardware.item.board_serial)],
                  ]} />
                ) : (
                  <SectionUnavailable message={details.hardware.error} />
                )}
              </div>
              <div>
                <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Operating System</h3>
                {details.os.ok && details.os.item ? (
                  <KeyValueGrid rows={[
                    ['Hostname', safe(details.os.item.hostname)],
                    ['OS Name', safe(details.os.item.os?.name)],
                    ['Platform', safe(details.os.item.os?.platform)],
                    ['Version', safe(details.os.item.os?.version ?? details.os.item.version)],
                    ['Codename', safe(details.os.item.os?.codename)],
                    ['Architecture', safe(details.os.item.architecture)],
                    ['Kernel / Sysname', safe(details.os.item.sysname)],
                    ['Release', safe(details.os.item.release)],
                  ]} />
                ) : (
                  <SectionUnavailable message={details.os.error} />
                )}
              </div>
            </div>
          ) : section === 'network' ? (
            <div className="space-y-5">
              <div>
                <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                  Interfaces {details.netiface.ok && `(${details.netiface.total})`}
                </h3>
                {details.netiface.ok ? (
                  <SimpleTable
                    columns={['Name', 'Adapter', 'State', 'Type', 'MTU', 'RX', 'TX']}
                    rows={details.netiface.items.map((n) => [
                      safe(n.name), safe(n.adapter), safe(n.state), safe(n.type),
                      safe(n.mtu), n.rx?.bytes !== undefined ? `${(n.rx.bytes / 1024).toFixed(0)} KB` : '—',
                      n.tx?.bytes !== undefined ? `${(n.tx.bytes / 1024).toFixed(0)} KB` : '—',
                    ])}
                  />
                ) : <SectionUnavailable message={details.netiface.error} />}
              </div>
              <div>
                <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                  IP Addresses {details.netaddr.ok && `(${details.netaddr.total})`}
                </h3>
                {details.netaddr.ok ? (
                  <SimpleTable
                    columns={['Interface', 'Protocol', 'Address', 'Netmask', 'Broadcast']}
                    rows={details.netaddr.items.map((n) => [
                      safe(n.iface), safe(n.proto), safe(n.address), safe(n.netmask), safe(n.broadcast),
                    ])}
                  />
                ) : <SectionUnavailable message={details.netaddr.error} />}
              </div>
              <div>
                <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                  Gateways {details.netproto.ok && `(${details.netproto.total})`}
                </h3>
                {details.netproto.ok ? (
                  <SimpleTable
                    columns={['Interface', 'Type', 'Gateway', 'DHCP']}
                    rows={details.netproto.items.map((n) => [safe(n.iface), safe(n.type), safe(n.gateway), safe(n.dhcp)])}
                  />
                ) : <SectionUnavailable message={details.netproto.error} />}
              </div>
              <div>
                <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                  Listening / Active Ports {details.ports.ok && `(${details.ports.total})`}
                </h3>
                {details.ports.ok ? (
                  <SimpleTable
                    columns={['Local', 'Remote', 'Protocol', 'State', 'PID', 'Process']}
                    rows={details.ports.items.slice(0, 100).map((p) => [
                      p.local ? `${p.local.ip ?? '*'}:${p.local.port ?? '—'}` : '—',
                      p.remote ? `${p.remote.ip ?? '*'}:${p.remote.port ?? '—'}` : '—',
                      safe(p.protocol), safe(p.state), safe(p.pid), safe(p.process),
                    ])}
                    shownCount={Math.min(100, details.ports.items.length)}
                    totalCount={details.ports.total}
                  />
                ) : <SectionUnavailable message={details.ports.error} />}
              </div>
            </div>
          ) : section === 'software' ? (
            details.packages.ok ? (
              <SimpleTable
                columns={['Name', 'Version', 'Vendor', 'Architecture', 'Installed']}
                rows={details.packages.items.slice(0, 150).map((p) => [
                  safe(p.name), safe(p.version), safe(p.vendor), safe(p.architecture), formatDate(p.install_time),
                ])}
                empty="No installed packages reported"
                shownCount={Math.min(150, details.packages.items.length)}
                totalCount={details.packages.total}
              />
            ) : <SectionUnavailable message={details.packages.error} />
          ) : section === 'processes' ? (
            details.processes.ok ? (
              <SimpleTable
                columns={['PID', 'Name', 'State', 'Priority', 'Memory (KB)', 'Started']}
                rows={details.processes.items.slice(0, 150).map((p) => [
                  safe(p.pid), safe(p.name), safe(p.state), safe(p.priority), safe(p.vm_size), formatDate(p.start_time),
                ])}
                empty="No running processes reported"
                shownCount={Math.min(150, details.processes.items.length)}
                totalCount={details.processes.total}
              />
            ) : <SectionUnavailable message={details.processes.error} />
          ) : section === 'vulnerabilities' ? (
            details.vulnerabilities.ok ? (
              <SimpleTable
                columns={['CVE', 'Severity', 'Package', 'Version']}
                rows={details.vulnerabilities.items.map((v) => [
                  safe(v.cve),
                  <span key="s" className={`text-xs font-bold px-2 py-0.5 rounded border ${severityBadgeClass(v.severity)}`}>
                    {String(v.severity ?? '—').toUpperCase()}
                  </span>,
                  safe(v.package?.name), safe(v.package?.version),
                ])}
                empty="No vulnerabilities found for this agent"
                shownCount={details.vulnerabilities.items.length}
                totalCount={details.vulnerabilities.total}
              />
            ) : <SectionUnavailable message={details.vulnerabilities.error} />
          ) : section === 'sca' ? (
            details.sca.ok ? (
              <SimpleTable
                columns={['Policy', 'Description', 'Pass', 'Fail', 'Invalid', 'Score', 'Last Scan']}
                rows={details.sca.items.map((p) => [
                  safe(p.name ?? p.policy_id), safe(p.description),
                  <span key="p" className="text-emerald-400">{p.pass ?? 0}</span>,
                  <span key="f" className="text-red-400">{p.fail ?? 0}</span>,
                  safe(p.invalid ?? 0),
                  p.score !== undefined ? `${p.score}%` : '—',
                  formatDate(p.end_scan),
                ])}
                empty="No SCA policy results for this agent"
              />
            ) : <SectionUnavailable message={details.sca.error} />
          ) : section === 'fim' ? (
            details.fim.ok ? (
              <SimpleTable
                columns={['File', 'Event', 'Owner', 'Permissions', 'Modified', 'SHA256']}
                rows={details.fim.items.slice(0, 150).map((f) => [
                  <span key="f" className="font-mono">{safe(f.file)}</span>,
                  safe(f.event), safe(f.uname), safe(f.perm), formatDate(f.mtime),
                  typeof f.sha256 === 'string' && f.sha256 ? `${f.sha256.slice(0, 12)}…` : '—',
                ])}
                empty="No file integrity monitoring events for this agent"
                shownCount={Math.min(150, details.fim.items.length)}
                totalCount={details.fim.total}
              />
            ) : <SectionUnavailable message={details.fim.error} />
          ) : null}
        </SectionErrorBoundary>
        </div>
      </div>
    </div>
  );
};

export default AgentDetailsModal;
