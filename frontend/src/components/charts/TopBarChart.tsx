import React from 'react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Cell, ResponsiveContainer } from 'recharts';
import type { CountEntry } from '../../utils/chartData';

const TopBarChart: React.FC<{ data: CountEntry[]; color?: string; colorOf?: (entry: CountEntry) => string }> = ({
  data,
  color = '#06b6d4',
  colorOf,
}) => (
  <ResponsiveContainer width="100%" height="100%">
    <BarChart data={data} layout="vertical" margin={{ top: 4, right: 16, left: 8, bottom: 0 }}>
      <CartesianGrid strokeDasharray="3 3" stroke="var(--chart-grid)" horizontal={false} />
      <XAxis type="number" tick={{ fontSize: 11, fill: 'var(--chart-axis)' }} tickLine={false} axisLine={false} allowDecimals={false} />
      <YAxis
        type="category"
        dataKey="label"
        tick={{ fontSize: 11, fill: 'var(--chart-axis)' }}
        tickLine={false}
        axisLine={false}
        width={100}
      />
      <Tooltip
        cursor={{ fill: 'var(--chart-grid)', opacity: 0.4 }}
        contentStyle={{
          background: 'var(--chart-tooltip-bg)',
          border: '1px solid var(--chart-tooltip-border)',
          borderRadius: 8,
          fontSize: 12,
          color: 'var(--chart-tooltip-text)',
        }}
      />
      <Bar dataKey="value" radius={[0, 4, 4, 0]} maxBarSize={16}>
        {data.map((entry) => (
          <Cell key={entry.label} fill={colorOf ? colorOf(entry) : color} />
        ))}
      </Bar>
    </BarChart>
  </ResponsiveContainer>
);

export default TopBarChart;
