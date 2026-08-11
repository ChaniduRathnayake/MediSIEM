import React from 'react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import type { TimeBucket } from '../../utils/chartData';
import { SEVERITY_COLORS } from '../../utils/chartData';

const AlertsTimelineChart: React.FC<{ data: TimeBucket[] }> = ({ data }) => (
  <ResponsiveContainer width="100%" height="100%">
    <AreaChart data={data} margin={{ top: 4, right: 8, left: -20, bottom: 0 }}>
      <defs>
        {Object.entries(SEVERITY_COLORS).map(([key, color]) => (
          <linearGradient key={key} id={`fill-${key}`} x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor={color} stopOpacity={0.35} />
            <stop offset="95%" stopColor={color} stopOpacity={0.02} />
          </linearGradient>
        ))}
      </defs>
      <CartesianGrid strokeDasharray="3 3" stroke="var(--chart-grid)" vertical={false} />
      <XAxis
        dataKey="time"
        tick={{ fontSize: 11, fill: 'var(--chart-axis)' }}
        tickLine={false}
        axisLine={{ stroke: 'var(--chart-grid)' }}
        interval="preserveStartEnd"
        minTickGap={40}
      />
      <YAxis tick={{ fontSize: 11, fill: 'var(--chart-axis)' }} tickLine={false} axisLine={false} width={28} allowDecimals={false} />
      <Tooltip
        contentStyle={{
          background: 'var(--chart-tooltip-bg)',
          border: '1px solid var(--chart-tooltip-border)',
          borderRadius: 8,
          fontSize: 12,
          color: 'var(--chart-tooltip-text)',
        }}
        labelStyle={{ color: 'var(--chart-tooltip-text)', fontWeight: 600, marginBottom: 4 }}
      />
      <Area type="monotone" dataKey="CRITICAL" stackId="sev" stroke={SEVERITY_COLORS.CRITICAL} fill="url(#fill-CRITICAL)" strokeWidth={1.5} />
      <Area type="monotone" dataKey="HIGH" stackId="sev" stroke={SEVERITY_COLORS.HIGH} fill="url(#fill-HIGH)" strokeWidth={1.5} />
      <Area type="monotone" dataKey="MEDIUM" stackId="sev" stroke={SEVERITY_COLORS.MEDIUM} fill="url(#fill-MEDIUM)" strokeWidth={1.5} />
      <Area type="monotone" dataKey="LOW" stackId="sev" stroke={SEVERITY_COLORS.LOW} fill="url(#fill-LOW)" strokeWidth={1.5} />
    </AreaChart>
  </ResponsiveContainer>
);

export default AlertsTimelineChart;
