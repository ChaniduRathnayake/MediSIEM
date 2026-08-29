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

import { isIPv4 } from './shared';


const REFRESH_MS = 5000;

const PAGE_SIZE = 200;


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

  // The collector stores this as a raw ISO string with microsecond
  // precision (e.g. "2026-08-29T14:12:26.788927+0530") — accurate, but not
  // something an analyst should have to parse at a glance. Render it as
  // "2026-08-29 02:11 PM" instead; fall back to the raw string if it's ever
  // something Date can't parse.
  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return value;
  }

  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');

  const hours24 = date.getHours();
  const minutes = String(date.getMinutes()).padStart(2, '0');
  const ampm = hours24 >= 12 ? 'PM' : 'AM';
  const hours12 = String(hours24 % 12 || 12).padStart(2, '0');

  return `${year}-${month}-${day} ${hours12}:${minutes} ${ampm}`;
}


// Windowed page-number list with ellipsis gaps, e.g. [1, '…', 4, 5, 6, '…', 42]
// — showing every page button once the feed has hundreds of them would make
// the pager itself the thing that needs scrolling.
function pageNumbers(
  current: number,
  total: number,
): (number | 'ellipsis')[] {

  if (total <= 7) {
    return Array.from(
      { length: total },
      (_, i) => i + 1,
    );
  }

  const pages: (number | 'ellipsis')[] = [1];

  if (current > 3) {
    pages.push('ellipsis');
  }

  const start = Math.max(2, current - 1);
  const end = Math.min(total - 1, current + 1);

  for (let i = start; i <= end; i++) {
    pages.push(i);
  }

  if (current < total - 2) {
    pages.push('ellipsis');
  }

  pages.push(total);

  return pages;
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

  const [page, setPage] =
    useState(1);


  const load = useCallback(
    async (silent = false) => {

      if (!silent) {
        setLoading(true);
      }

      try {

        // The backend now scopes "live" to a rolling time window (default
        // 30 minutes) rather than a fixed count of most-recent events, so a
        // single high-volume flow or a burst of broadcast noise can no
        // longer crowd every other recently-active public IP out of the
        // feed. max_items stays high since it only affects how many of the
        // (already-fetched) unique IPs get returned, not how much is
        // scanned.
        const data =
          await getLiveCorrelationFeed(
            30,
            2000,
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


  // IPv6 addresses currently dominate this feed (the collector's Suricata
  // telemetry sees far more IPv6 flow noise than IPv4), which buries the
  // IPv4 activity analysts actually care about — filter down to IPv4-only
  // here rather than on the backend so this stays a display concern and
  // doesn't touch what the collector scans or scores.
  const items =
    (feed?.items || []).filter((item) => isIPv4(item.ip));


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


  const totalPages =
    Math.max(
      1,
      Math.ceil(sortedItems.length / PAGE_SIZE),
    );

  // Clamped rather than stored back into state — the feed refreshes every
  // 5s and the live IP count can shrink between polls, so this just falls
  // back to the last valid page on render instead of needing an effect to
  // keep `page` in sync with data it doesn't control.
  const currentPage =
    Math.min(page, totalPages);

  const pageStart =
    (currentPage - 1) * PAGE_SIZE;

  const pageItems =
    sortedItems.slice(
      pageStart,
      pageStart + PAGE_SIZE,
    );


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
            Public IPv4 addresses observed in Suricata flow telemetry
            and scored by MedShield ML. IPv6 flows are scored too but
            filtered out of this view.
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

      <section id="live-overview" className="scroll-mt-20 space-y-3">

        <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">
          Overview
        </h3>

        <div className="grid grid-cols-2 gap-3 xl:grid-cols-4">

          <StatusCard
            label="Records scanned"
            value={feed?.records_scanned ?? 0}
            helper={`Last ${feed?.window_minutes ?? 30} min of MedShield correlation records`}
          />

          <StatusCard
            label="Public IPv4s"
            value={items.length}
            helper="Unique public IPv4 addresses detected"
          />

          <StatusCard
            label="Suspicious"
            value={items.filter((item) => item.suspicious).length}
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

      </section>


      {error && (
        <div className="rounded-xl border border-red-500/30 bg-red-500/10 p-4 text-xs text-red-600 dark:text-red-300">
          {error}
        </div>
      )}


      {/* ===================================================
          ORIGINAL COMPACT TABLE
         =================================================== */}

      <section id="live-feed" className="scroll-mt-20 space-y-3">

        <div className="flex items-center justify-between">
          <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">
            Live Feed
          </h3>
          <span className="text-[11px] text-slate-400">
            {sortedItems.length > PAGE_SIZE
              ? `${pageStart + 1}–${Math.min(pageStart + PAGE_SIZE, sortedItems.length)} of ${sortedItems.length} IPv4s`
              : `${sortedItems.length} ${sortedItems.length === 1 ? 'IPv4' : 'IPv4s'}`}
            {items.some((item) => item.suspicious) ? ` · ${items.filter((item) => item.suspicious).length} suspicious` : ''}
          </span>
        </div>

        <div className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm dark:border-slate-800 dark:bg-slate-900">


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

                {pageItems.map(
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

        {totalPages > 1 && (

          <div className="flex flex-wrap items-center justify-between gap-3 border-t border-slate-200 px-4 py-3 dark:border-slate-800">

            <span className="text-[11px] text-slate-400">
              Page {currentPage} of {totalPages}
            </span>

            <div className="flex items-center gap-1">

              <button
                type="button"
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={currentPage === 1}
                className="rounded-md border border-slate-300 px-2.5 py-1 text-[11px] font-medium text-slate-600 transition hover:bg-slate-100 disabled:cursor-not-allowed disabled:opacity-40 dark:border-slate-700 dark:text-slate-300 dark:hover:bg-slate-800"
              >
                Prev
              </button>

              {pageNumbers(currentPage, totalPages).map(
                (entry, idx) =>
                  entry === 'ellipsis' ? (
                    <span
                      key={`ellipsis-${idx}`}
                      className="px-1.5 text-[11px] text-slate-400"
                    >
                      …
                    </span>
                  ) : (
                    <button
                      key={entry}
                      type="button"
                      onClick={() => setPage(entry)}
                      className={`min-w-[28px] rounded-md border px-2.5 py-1 text-[11px] font-medium transition ${
                        entry === currentPage
                          ? 'border-cyan-500/30 bg-cyan-500/10 text-cyan-700 dark:text-cyan-300'
                          : 'border-slate-300 text-slate-600 hover:bg-slate-100 dark:border-slate-700 dark:text-slate-300 dark:hover:bg-slate-800'
                      }`}
                    >
                      {entry}
                    </button>
                  ),
              )}

              <button
                type="button"
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                disabled={currentPage === totalPages}
                className="rounded-md border border-slate-300 px-2.5 py-1 text-[11px] font-medium text-slate-600 transition hover:bg-slate-100 disabled:cursor-not-allowed disabled:opacity-40 dark:border-slate-700 dark:text-slate-300 dark:hover:bg-slate-800"
              >
                Next
              </button>

            </div>

          </div>
        )}

        </div>

      </section>
</div>
  );
};


export default LiveDashboardView;

