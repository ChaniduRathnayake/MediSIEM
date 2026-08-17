import React from 'react';
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from 'recharts';

export interface DonutSlice {
  name: string;
  value: number;
  color: string;
}

// Generic donut used for any name/value/color breakdown (severity mix,
// online/offline devices, etc.) — SeverityDonutChart is a thin wrapper
// around this for the Severity-typed call sites. onSliceClick is optional —
// pages that don't have a matching filter to react to just omit it and get
// a purely decorative chart, same as before.
const DonutChart: React.FC<{ data: DonutSlice[]; centerLabel?: string; onSliceClick?: (name: string) => void }> = ({
  data,
  centerLabel = 'Total',
  onSliceClick,
}) => {
  const total = data.reduce((sum, d) => sum + d.value, 0);
  const clickable = !!onSliceClick;

  return (
    <div className="w-full h-full flex items-center gap-4">
      <div className="relative flex-1 h-full min-w-0">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={data}
              dataKey="value"
              nameKey="name"
              innerRadius="62%"
              outerRadius="90%"
              paddingAngle={2}
              strokeWidth={0}
              onClick={onSliceClick ? (entry) => onSliceClick(String(entry.name)) : undefined}
              style={clickable ? { cursor: 'pointer' } : undefined}
            >
              {data.map((d) => (
                <Cell key={d.name} fill={d.color} />
              ))}
            </Pie>
            <Tooltip
              contentStyle={{
                background: 'var(--chart-tooltip-bg)',
                border: '1px solid var(--chart-tooltip-border)',
                borderRadius: 8,
                fontSize: 12,
                color: 'var(--chart-tooltip-text)',
              }}
            />
          </PieChart>
        </ResponsiveContainer>
        <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-xl font-bold text-slate-900 dark:text-white">{total}</span>
          <span className="text-[10px] text-slate-500 uppercase tracking-wide">{centerLabel}</span>
        </div>
      </div>
      {/* The pie slices themselves (above) are mouse-only — recharts doesn't
          expose a clean way to make individual SVG <Cell>s focusable/keyboard-
          activatable. This legend offers the same filtering action as real
          <button>s instead, so a keyboard-only user isn't locked out of it
          entirely, even though the chart itself stays mouse-only. */}
      <ul className="flex-shrink-0 space-y-1.5">
        {data.map((d) =>
          clickable ? (
            <li key={d.name}>
              <button
                type="button"
                onClick={() => onSliceClick!(d.name)}
                aria-label={`Filter by ${d.name} (${d.value})`}
                className="flex items-center gap-2 text-xs w-full text-left cursor-pointer hover:opacity-70 transition-opacity"
              >
                <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ backgroundColor: d.color }} />
                <span className="text-slate-500 dark:text-slate-400">{d.name}</span>
                <span className="text-slate-900 dark:text-white font-medium ml-auto">{d.value}</span>
              </button>
            </li>
          ) : (
            <li key={d.name} className="flex items-center gap-2 text-xs">
              <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ backgroundColor: d.color }} />
              <span className="text-slate-500 dark:text-slate-400">{d.name}</span>
              <span className="text-slate-900 dark:text-white font-medium ml-auto">{d.value}</span>
            </li>
          )
        )}
      </ul>
    </div>
  );
};

export default DonutChart;
