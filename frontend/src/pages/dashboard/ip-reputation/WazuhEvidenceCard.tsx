// Port of components/WazuhEvidence.jsx — embedded inside InvestigationView,
// shows Wazuh-indexed alerts (source or destination = investigated IP).
import React from 'react';
import type { WazuhEvidenceResult } from './ipReputationApi';
import { SectionCard, DataRow, MetricTile, Badge, EmptyNotice, fmtDateTime, toneOf } from './shared';

const WazuhEvidenceCard: React.FC<{ data: WazuhEvidenceResult | null }> = ({ data }) => {
  if (!data) {
    return (
      <SectionCard title="Wazuh Evidence">
        <EmptyNotice>Wazuh correlation has not been loaded.</EmptyNotice>
      </SectionCard>
    );
  }

  return (
    <SectionCard
      eyebrow="WAZUH + SURICATA CORRELATION"
      title="Wazuh Evidence"
      subtitle="Alerts indexed by Wazuh where the investigated IP appears as a source or destination."
      right={<Badge tone={toneOf(data.status)}>{data.status || 'unknown'}</Badge>}
    >
      {!data.available ? (
        <EmptyNotice>Wazuh evidence is currently unavailable.{data.error ? ` ${data.error}` : ''}</EmptyNotice>
      ) : data.matched_alert_count === 0 ? (
        <EmptyNotice>No Wazuh alerts were found for this IP.</EmptyNotice>
      ) : (
        <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4">
            <MetricTile label="Matched Alerts" value={data.matched_alert_count} />
            <MetricTile label="Suricata Alerts" value={data.suricata_alert_count ?? 0} />
            <MetricTile label="Highest Wazuh Level" value={data.highest_rule_level ?? '—'} />
            <MetricTile label="Latest Alert" value={fmtDateTime(data.latest_alert_timestamp)} />
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-4">
            <div>
              <p className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wide mb-2">Top Wazuh Rules</p>
              {data.top_rules?.length ? (
                data.top_rules.map((rule, index) => (
                  <DataRow key={`${rule.description}-${index}`} label={rule.description} value={rule.count} />
                ))
              ) : (
                <p className="text-sm text-slate-400 dark:text-slate-500">No rule summary available.</p>
              )}
            </div>

            <div>
              <p className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wide mb-2">Evidence Interpretation</p>
              <p className="text-xs text-slate-400 dark:text-slate-500 mb-2">
                Wazuh alerts are treated as a separate local security evidence source. Their presence does not by itself prove
                that an IP is malicious.
              </p>
              <p className="text-xs text-slate-400 dark:text-slate-500">
                Rule level, Suricata signature, local ML evidence, external reputation and healthcare context should be
                correlated before making an operational decision.
              </p>
            </div>
          </div>

          <p className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wide mb-2">Recent Wazuh Alerts</p>
          <div className="overflow-x-auto -mx-1">
            <table className="w-full min-w-[720px]">
              <thead>
                <tr className="text-xs text-slate-400 dark:text-slate-500 uppercase tracking-wider border-b border-slate-200 dark:border-slate-800">
                  <th className="py-2 px-2 text-left">Time</th>
                  <th className="py-2 px-2 text-left">Flow</th>
                  <th className="py-2 px-2 text-left">Rule</th>
                  <th className="py-2 px-2 text-left">Signature</th>
                  <th className="py-2 px-2 text-left">Level</th>
                </tr>
              </thead>
              <tbody>
                {data.alerts?.slice(0, 10).map((alert) => (
                  <tr key={alert.document_id} className="border-b border-slate-100 dark:border-slate-800/60 last:border-0 text-sm">
                    <td className="py-2 px-2 text-slate-500 dark:text-slate-400 whitespace-nowrap">{fmtDateTime(alert.timestamp)}</td>
                    <td className="py-2 px-2">
                      <span className="font-medium text-slate-900 dark:text-white">{alert.src_ip || '—'}</span>
                      <br />
                      <span className="text-xs text-slate-400 dark:text-slate-500">
                        → {alert.dest_ip || '—'} • {alert.app_proto || alert.protocol || 'unknown'}
                      </span>
                    </td>
                    <td className="py-2 px-2">
                      <span className="font-medium text-slate-900 dark:text-white">{alert.wazuh_rule?.id || '—'}</span>
                      <br />
                      <span className="text-xs text-slate-400 dark:text-slate-500">{alert.wazuh_rule?.description || '—'}</span>
                    </td>
                    <td className="py-2 px-2">
                      {alert.suricata_alert?.signature || '—'}
                      <br />
                      <span className="text-xs text-slate-400 dark:text-slate-500">{alert.suricata_alert?.category || '—'}</span>
                    </td>
                    <td className="py-2 px-2 text-slate-500 dark:text-slate-400">{alert.wazuh_rule?.level ?? '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </SectionCard>
  );
};

export default WazuhEvidenceCard;
