import React from 'react';

const ChartCard: React.FC<{
  title: string;
  subtitle?: string;
  right?: React.ReactNode;
  height?: number;
  empty?: boolean;
  emptyLabel?: string;
  children: React.ReactNode;
  className?: string;
}> = ({ title, subtitle, right, height = 220, empty, emptyLabel = 'No data yet', children, className = '' }) => (
  <div className={`p-5 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 ${className}`}>
    <div className="flex items-start justify-between mb-4 gap-3">
      <div>
        <h3 className="text-sm font-semibold text-slate-900 dark:text-white">{title}</h3>
        {subtitle && <p className="text-xs text-slate-500 dark:text-slate-500 mt-0.5">{subtitle}</p>}
      </div>
      {right}
    </div>
    {empty ? (
      <div className="flex items-center justify-center text-xs text-slate-400 dark:text-slate-600" style={{ height }}>
        {emptyLabel}
      </div>
    ) : (
      <div style={{ height }}>{children}</div>
    )}
  </div>
);

export default ChartCard;
