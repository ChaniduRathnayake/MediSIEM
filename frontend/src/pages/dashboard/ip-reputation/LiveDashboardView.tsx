import React, {
  useCallback,
  useEffect,
  useMemo,
  useState,
} from 'react';

import {
  getLiveCorrelationFeed,
} from './ipReputationApi';

import type {
  LiveCorrelationFeedItem,
  LiveCorrelationFeedResult,
} from './ipReputationApi';


const REFRESH_MS = 5000;


interface Props {
  onInvestigate: (ip: string) => void;
}


function fmt(
  value: number | null | undefined,
  suffix = '',
): string {
  if (
    value === null ||
    value === undefined ||
    Number.isNaN(Number(value))
  ) {
    return 'Unavailable';
  }

  return `${Number(value).toFixed(2)}${suffix}`;
}


function fmtDate(value?: string | null): string {
  if (!value) return '—';

  // Keep original MedShield-style timestamp presentation.
  return value;
}


function RiskBadge({
  level,
}: {
  level?: string | null;
}) {
  const risk = level || 'Unknown';

  const styles: Record<string, string> = {
    Critical:
      'border-red-500/30 bg-red-500/10 text-red-600 dark:text-red-400',

    High:
      'border-orange-500/30 bg-orange-500/10 text-orange-600 dark:text-orange-400',

    Medium:
      'border-amber-500/30 bg-amber-500/10 text-amber-600 dark:text-amber-400',

    Low:
      'border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400',

    Minimal:
      'border-cyan-500/30 bg-cyan-500/10 text-cyan-600 dark:text-cyan-400',
  };

  return (
    <span
      className={`inline-flex rounded-full border px-2.5 py-1 text-[11px] font-semibold ${
        styles[risk] ||
        'border-slate-300 bg-slate-100 text-slate-500 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-400'
      }`}
    >
      {risk}
    </span>
  );
}


function StatusCard({
  label,
  value,
  helper,
  connected,
}: {
  label: string;
  value: React.ReactNode;
  helper?: string;
  connected?: boolean;
}) {
  return (
    <div className="rounded-xl border border-slate-200 bg-white px-5 py-4 shadow-sm dark:border-slate-800 dark:bg-slate-900">

      <div className="text-[11px] font-semibold uppercase tracking-wide text-slate-400">
        {label}
      </div>

      <div className="mt-2 flex items-center gap-2">

        {connected !== undefined && (
          <span
            className={`h-2.5 w-2.5 rounded-full ${
              connected
                ? 'bg-emerald-500'
                : 'bg-red-500'
            }`}
          />
        )}

        <div className="text-2xl font-bold text-slate-900 dark:text-white">
          {value}
        </div>

      </div>

      {helper && (
        <div className="mt-1 text-[10px] text-slate-400">
          {helper}
        </div>
      )}

    </div>
  );
}


const LiveDashboardView: React.FC<Props> = ({
  onInvestigate,
}) => {

  const [feed, setFeed] =
    useState<LiveCorrelationFeedResult | null>(null);

  const [loading, setLoading] =
    useState(true);

  const [error, setError] =
    useState('');

  const [lastUpdated, setLastUpdated] =
    useState<Date | null>(null);


  const load = useCallback(
    async (silent = false) => {

      if (!silent) {
        setLoading(true);
      }

      try {

        const data =
          await getLiveCorrelationFeed(
            1000,
            200,
          );

        setFeed(data);
        setError('');
        setLastUpdated(new Date());

      } catch (err: unknown) {

        setError(
          err instanceof Error
            ? err.message
            : 'Unable to load MedShield live intelligence.',
        );

      } finally {

        if (!silent) {
          setLoading(false);
        }
      }
    },
    [],
  );


  useEffect(() => {

    void load(false);

    const timer =
      window.setInterval(
        () => void load(true),
        REFRESH_MS,
      );

    return () =>
      window.clearInterval(timer);

  }, [load]);


  const items =
    feed?.items || [];


  const sortedItems =
    useMemo(() => {

      return [...items].sort(
        (a, b) => {

          const suspiciousDiff =
            Number(b.suspicious) -
            Number(a.suspicious);

          if (suspiciousDiff !== 0) {
            return suspiciousDiff;
          }

          const peakDiff =
            Number(b.max_mirs || 0) -
            Number(a.max_mirs || 0);

          if (peakDiff !== 0) {
            return peakDiff;
          }

          return String(
            b.latest_timestamp || '',
          ).localeCompare(
            String(
              a.latest_timestamp || '',
            ),
          );
        },
      );

    }, [items]);


  return (
    <div className="space-y-5">


      {/* ===================================================
          ORIGINAL MEDSHIELD STYLE HEADER
         =================================================== */}

      <div className="flex flex-col gap-3 md:flex-row md:items-end md:justify-between">

        <div>

          <div className="text-[10px] font-bold uppercase tracking-[0.22em] text-cyan-600 dark:text-cyan-400">
            Live Detected IP Intelligence
          </div>

          <h2 className="mt-1 text-xl font-semibold text-slate-900 dark:text-white">
            Real-time ML IP Monitor
          </h2>

          <p className="mt-1 text-xs text-slate-400 dark:text-slate-500">
            Public IPs observed in Suricata flow telemetry
            and scored by MedShield ML.
          </p>

        </div>


        <div className="flex items-center gap-3">

          <div className="text-right">

            <div className="text-xs font-medium text-slate-600 dark:text-slate-300">
              Auto-refresh 5s
            </div>

            <div className="mt-0.5 text-[10px] text-slate-400">
              {lastUpdated
                ? `Last update ${lastUpdated.toLocaleTimeString()}`
                : 'Waiting for feed'}
            </div>

          </div>


          <button
            type="button"
            onClick={() => void load(false)}
            className="rounded-lg border border-cyan-500/30 bg-cyan-500/10 px-3 py-2 text-xs font-semibold text-cyan-700 transition hover:bg-cyan-500/20 dark:text-cyan-300"
          >
            Refresh
          </button>

        </div>

      </div>


      {/* ===================================================
          ORIGINAL FOUR KPI CARDS
         =================================================== */}

      <div className="grid grid-cols-2 gap-3 xl:grid-cols-4">

        <StatusCard
          label="Records scanned"
          value={feed?.records_scanned ?? 0}
          helper="Recent MedShield correlation records"
        />

        <StatusCard
          label="Public IPs"
          value={feed?.unique_public_ips ?? 0}
          helper="Unique public addresses detected"
        />

        <StatusCard
          label="Suspicious"
          value={feed?.suspicious_count ?? 0}
          helper="Require analyst attention"
        />

        <StatusCard
          label="Feed Status"
          value={
            feed?.available
              ? 'Connected'
              : 'Offline'
          }
          connected={Boolean(feed?.available)}
          helper="MedShield live correlation feed"
        />

      </div>


      {error && (
        <div className="rounded-xl border border-red-500/30 bg-red-500/10 p-4 text-xs text-red-600 dark:text-red-300">
          {error}
        </div>
      )}


      {/* ===================================================
          ORIGINAL COMPACT TABLE
         =================================================== */}

      <section className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm dark:border-slate-800 dark:bg-slate-900">


        {loading && !feed ? (

          <div className="p-10 text-center text-sm text-slate-400">
            Loading live MedShield intelligence...
          </div>

        ) : sortedItems.length === 0 ? (

          <div className="p-10 text-center text-sm text-slate-400">
            No public IP evidence is currently available.
          </div>

        ) : (

          <div className="overflow-x-auto">

            <table className="w-full min-w-[1180px] text-xs">

              <thead className="bg-slate-50 text-[10px] uppercase tracking-wide text-slate-400 dark:bg-slate-950/60">

                <tr>

                  <th className="px-4 py-3 text-left">
                    IP
                  </th>

                  <th className="px-4 py-3 text-left">
                    Last Seen
                  </th>

                  <th className="px-4 py-3 text-right">
                    Flows
                  </th>

                  <th className="px-4 py-3 text-right">
                    Latest MIRS
                  </th>

                  <th className="px-4 py-3 text-right">
                    Peak MIRS
                  </th>

                  <th className="px-4 py-3 text-right">
                    APS
                  </th>

                  <th className="px-4 py-3 text-right">
                    RF
                  </th>

                  <th className="px-4 py-3 text-right">
                    IF
                  </th>

                  <th className="px-4 py-3 text-center">
                    Peak Risk
                  </th>

                  <th className="px-4 py-3 text-center">
                    Action
                  </th>

                </tr>

              </thead>


              <tbody className="divide-y divide-slate-100 dark:divide-slate-800">

                {sortedItems.map(
                  (
                    item: LiveCorrelationFeedItem,
                  ) => (

                    <tr
                      key={item.ip}
                      className={`transition ${
                        item.suspicious
                          ? 'bg-amber-500/[0.025] hover:bg-amber-500/[0.06]'
                          : 'hover:bg-slate-50 dark:hover:bg-slate-800/40'
                      }`}
                    >


                      {/* IP */}

                      <td className="px-4 py-3">

                        <div className="max-w-[270px] truncate font-mono text-[11px] font-semibold text-slate-900 dark:text-slate-100">
                          {item.ip}
                        </div>

                        {item.suspicious && (
                          <div className="mt-1 text-[9px] font-semibold uppercase tracking-wide text-amber-600 dark:text-amber-400">
                            Suspicious
                          </div>
                        )}

                      </td>


                      {/* timestamp */}

                      <td className="whitespace-nowrap px-4 py-3 text-[10px] text-slate-500 dark:text-slate-400">
                        {fmtDate(
                          item.latest_timestamp,
                        )}
                      </td>


                      {/* flows */}

                      <td className="px-4 py-3 text-right font-semibold text-slate-900 dark:text-white">
                        {item.flow_count}
                      </td>


                      {/* latest MIRS */}

                      <td className="px-4 py-3 text-right font-medium text-slate-700 dark:text-slate-200">
                        {fmt(
                          item.latest_mirs,
                        )}
                      </td>


                      {/* peak MIRS */}

                      <td className="px-4 py-3 text-right font-semibold text-cyan-600 dark:text-cyan-400">
                        {fmt(
                          item.max_mirs,
                        )}
                      </td>


                      {/* APS */}

                      <td className="px-4 py-3 text-right">

                        {item.latest_aps == null ? (

                          <span className="text-slate-400">
                            Unavailable
                          </span>

                        ) : (

                          <span className="font-semibold text-indigo-600 dark:text-indigo-400">
                            {fmt(
                              item.latest_aps,
                              '%',
                            )}
                          </span>

                        )}

                      </td>


                      {/* RF */}

                      <td className="px-4 py-3 text-right font-medium text-slate-700 dark:text-slate-200">
                        {fmt(
                          item.latest_rf_attack_probability,
                          '%',
                        )}
                      </td>


                      {/* IF */}

                      <td className="px-4 py-3 text-right font-medium text-violet-600 dark:text-violet-400">
                        {fmt(
                          item.latest_if_anomaly_score,
                          '%',
                        )}
                      </td>


                      {/* risk */}

                      <td className="px-4 py-3 text-center">

                        <RiskBadge
                          level={
                            item.risk_band ||
                            item.latest_risk_level
                          }
                        />

                      </td>


                      {/* investigate */}

                      <td className="px-4 py-3 text-center">

                        <button
                          type="button"
                          onClick={() =>
                            onInvestigate(
                              item.ip,
                            )
                          }
                          className="rounded-lg border border-cyan-500/30 bg-cyan-500/10 px-3 py-1.5 text-[11px] font-semibold text-cyan-700 transition hover:bg-cyan-500/20 dark:text-cyan-300"
                        >
                          Investigate
                        </button>

                      </td>

                    </tr>
                  ),
                )}

              </tbody>

            </table>

          </div>
        )}

      </section>
</div>
  );
};


export default LiveDashboardView;

