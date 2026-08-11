import React from 'react';
import DonutChart from './DonutChart';
import type { SeverityCount, Severity } from '../../utils/chartData';

const SeverityDonutChart: React.FC<{ data: SeverityCount[]; onSeverityClick?: (severity: Severity) => void }> = ({
  data,
  onSeverityClick,
}) => (
  <DonutChart data={data} onSliceClick={onSeverityClick ? (name) => onSeverityClick(name as Severity) : undefined} />
);

export default SeverityDonutChart;
