import React from 'react';
import { Radio } from 'lucide-react';

const ChartCard: React.FC<{
  title: string;
  subtitle?: string;
  right?: React.ReactNode;
  height?: number;
  empty?: boolean;
  emptyLabel?: string;
  children: React.ReactNode;
  className?: string;
}> = ({ title, subtitle, right, height = 220, empty, emptyLabel = 'Waiting for data', children, className = '' }) => (
  <div className={`p-4 rounded-lg bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 ${className}`}>
    <div className="flex items-start justify-between mb-3 gap-3">
      <div>
        <h3 className="text-[13px] font-semibold text-slate-900 dark:text-white">{title}</h3>
        {subtitle && <p className="text-[11px] text-slate-400 dark:text-slate-500 mt-0.5">{subtitle}</p>}
      </div>
      {right}
    </div>
    {empty ? (
      <div className="flex flex-col items-center justify-center gap-2 text-slate-300 dark:text-slate-700" style={{ height }}>
        <Radio className="w-5 h-5" strokeWidth={1.5} />
        <span className="text-xs text-slate-400 dark:text-slate-600">{emptyLabel}</span>
      </div>
    ) : (
      <div style={{ height }}>{children}</div>
    )}
  </div>
);

export default ChartCard;
